# Meshtastic MQTT broker

An MQTT broker for Meshtastic uplink, built on [MQTTnet](https://github.com/dotnet/MQTTnet) (C# / .NET 10).
Unlike a generic broker with ACLs, it understands Meshtastic packets: it parses every `ServiceEnvelope`,
decrypts it with the key of its channel, and only lets through what a real node would have sent.

Fork of the abandoned [meshtastic/mqtt](https://github.com/meshtastic/mqtt) boilerplate, hardened to be
exposed on the internet:

- **Config file**, no hardcoded secrets. The certificate, key and password committed upstream are removed
  (they remain in git history; they were always public, are expired, and must never be reused).
- **Real authentication**: users with PBKDF2-SHA256 password hashes, compared in constant time.
- **No downlink by default**: a user may subscribe only to filters listed in its `subscribe_allow`.
  The public `meshdev` user gets none.
- **Publish ACL**: a user may publish only to topics matching its `publish_allow`. Empty or missing = no publish.
- **Packet filtering on publish**: drops empty, malformed, plaintext and undecryptable packets; lets through
  map reports only after checking they are real `MapReport`s.
- **Limits and dedupe**: per-IP connection cap and connect rate, a publish payload cap, a per-client publish
  rate, a cross-gateway dedupe and a per-node packet rate (see [Limits and dedupe](#limits-and-dedupe)).
- **Auth bans**: an address that fails to log in too often is banned for a while, inside the broker itself
  (no system fail2ban, no nftables, no host changes) (see [Auth bans](#auth-bans)).
- **No message content in logs**, ever. Logs carry topic, client id, `from`, packet id and portnum.
- Plain MQTT on port 1883. No TLS in this version.

## What it does with each connection

| Hook | Rule |
|---|---|
| Connect | Username and password are checked against `users`. Unknown user or wrong password → `BadUserNameOrPassword` (MQTT 3.1.1 return code 4), logged with username and remote IP, never the password. A reconnect with an existing client id takes over the old session, but only for the **same user**: a client id held by a live or persisted session of another user is refused with `ClientIdentifierNotValid` (3.1.1 return code 2) and the session owner stays connected. The id is free again once that session is gone. If the password-check queue is full (see `limits`), the client gets `ServerBusy` (3.1.1 return code 3, "server unavailable") and retries. An address that failed too many logins is banned: the socket is closed at the accept, and a CONNECT that arrives after the ban is refused with `Banned` (0x8A) before the password is checked (see [Auth bans](#auth-bans)). |
| Subscribe | The requested filter is granted only if **every** topic it can match is covered by the `subscribe_allow` filters of the user that **created the session** (bound at connect time, so a reused session never changes hands). Real MQTT wildcard semantics, not prefix matching. An empty or missing list denies everything. `#` and `+` never grant `$`-topics such as `$SYS/#`. Refusal → MQTT 5 reason `Not authorized` (135); on MQTT 3.1.1 → `0x80`. |
| Publish | First the publish ACL (below), then the limits and the packet filter (below). A refused publish is dropped, never forwarded, and the client stays connected. Accepted messages are re-published with `retain` cleared (firmware never retains), so nothing enters the retained-message store. |

Before any of this, every packet's declared length is checked against `limits.max_packet_size` while its
fixed header is still being read; a larger one closes the connection before the broker allocates it
(also for clients that have not authenticated yet).

### Publish ACL

Each user has `publish_allow`, a list of MQTT topic filters. A PUBLISH is accepted only if its topic name
matches at least one of them, with standard MQTT matching: `+` is exactly one level, `#` is that level and
everything below it (so `msh/EU_868/2/e/#` also matches `msh/EU_868/2/e`, which the packet filter then drops),
and a filter starting with a wildcard never matches a `$` topic such as `$SYS/...`. Topics are case-sensitive.

- **Empty or missing = no publish at all.** This is a breaking change for configs written before the publish
  ACL existed: give `meshdev` (and any user that must publish) an explicit list, as in
  [`config.example.yaml`](config.example.yaml).
- The list is the one of the user that **created the session** (bound at connect time, like `subscribe_allow`),
  not the username of the current connection. A session with no owner publishes nothing.
- An invalid filter (`#` not last, `+` or `#` inside a level, empty) stops the broker at startup.
- A topic name containing `+` or `#` is a protocol error (wildcards are for filters only); MQTTnet does not reject it
  on the server side, so the broker drops it as `invalid topic name`.
- A refused publish is dropped and counted under `not in publish_allow` (see [Logs](#logs)); it is logged per
  packet only at `debug`, so a node configured with the wrong root topic cannot flood the log. The client is
  **not** disconnected (the firmware would just reconnect in a loop). On MQTT 5 a QoS 1/2 publish is answered
  with reason code `Not authorized` (135), or `Topic name invalid` (144) for a wildcard in the topic name;
  MQTT 3.1.1 acknowledgements carry no reason code.

The root topic for the Spanish mesh is `msh/EU_868`, the root the community guide tells every node to set
(`meshtastic-es-community.github.io`, `docs/mapas.md`). It is also what the firmware writes for region EU_868
(`AdminModule.cpp` → `MQTT::applyRegionRootTopic()`), but only while the node points at the default
`mqtt.meshtastic.org` server with the default root; a node configured for another broker keeps whatever root it
was given, so the root must be set by hand. The example config allows `meshdev` exactly `msh/EU_868/2/e/#` and
`msh/EU_868/2/map/`.

### Publish filtering

A message that passed the publish ACL is forwarded only if it is either a map report (next section) or a
channel packet for which all of these hold:

1. The topic is `<root>/2/e/<channel>/<gateway>` (root may have several levels, e.g. `msh/EU_868`).
   `/2/json/` and anything else is dropped, and so is any `/2/map...` topic other than the exact map-report topic.
2. The payload is a valid `ServiceEnvelope` with a `packet`, `channel_id` and `gateway_id`.
3. `channel_id` equals the `<channel>` segment of the topic (exact match).
4. The `<gateway>` segment of the topic equals the `gateway_id` of the envelope, and it is `!` followed by
   8 lowercase hex digits (the firmware's `NodeDB::getNodeId()`, the same string in the topic and in the
   envelope).
5. The packet has non-zero `from` and `id` and carries an `encrypted` payload of 1-256 bytes
   (plaintext `decoded` packets are dropped).
6. Channel packets: the key is looked up **by channel name** (`channels`, falling back to `default_psk`).
   The lookup is case-sensitive, like the firmware: the channel hash covers the exact name, so `Test` and
   `test` are different channels and a `test` channel not listed under `channels` uses `default_psk`.
   The packet is decrypted with AES-CTR exactly as the firmware does; it counts as decryptable when the
   result parses as `Data` with a portnum other than `UNKNOWN_APP` (the firmware's own test in
   `Router.cpp perhapsDecode()`). Keys are never tried one after another.
   Undecryptable packets are dropped when `drop_undecryptable: true` (default).
7. PKI direct messages: see below.

The firmware's channel hash (`MeshPacket.channel`) is also computed for the configured key. A mismatch
is logged at `debug` level only; it never causes a drop.

### Map reports

Nodes with "map reporting" enabled publish a `MapReport` (name, hardware, firmware, region, preset, approximate
position) for map dashboards. Checked in the firmware (`src/mqtt/MQTT.cpp`, `MQTT::perhapsReportToMap()`), the
topic is exactly `<root>/2/map/` — trailing slash included, no channel or gateway level — and the payload is a
`ServiceEnvelope` whose packet is **decoded** (plaintext, never encrypted), `portnum = MAP_REPORT_APP` (73), with the
`MapReport` protobuf as payload, `from` = the reporting node, `channel_id` = its primary channel and
`gateway_id` = `!` + 8 lowercase hex digits of its node number. The firmware leaves the packet id at 0.

A message on `<root>/2/map/` is forwarded only if all of these hold, each failure being its own drop reason:

1. The payload parses as a `ServiceEnvelope` with a packet whose `from` is not 0.
2. The packet is decoded, not encrypted.
3. Its portnum is `MAP_REPORT_APP`.
4. Its payload is non-empty and parses as a `MapReport`.
5. `gateway_id` equals `!%08x` of `from` (a node only reports itself).

No channel key is involved (the topic names no channel and the packet is plaintext), and there is no separate
flag: whoever has the map topic in `publish_allow` may send map reports. `<root>/2/map` (no slash) and
`<root>/2/map/<anything>` are dropped; the firmware never publishes there.

### PKI direct messages (`drop_pki`)

Checked in the firmware (`src/mqtt/MQTT.cpp`, `MQTT::onSend()`): a packet that is PKI-encrypted
(Curve25519 + AES-CCM, end to end between two nodes) is uplinked **still encrypted**, with
`channel_id = "PKI"` on topic `<root>/2/e/PKI/<gateway>`, and only when the gateway has
"encryption enabled" on its MQTT module. Gateways subscribe to `<root>/2/e/PKI/+` and accept those
packets for downlink even though they cannot decrypt them either.

The broker can never decrypt them, so they get their own flag instead of falling under
`drop_undecryptable`:

- `drop_pki: true` (default) drops them. The broker is uplink-only for now, so nothing would consume
  them; dropping them means they are not exposed to every future downlink subscriber, and their
  metadata (who DMs whom) is not republished.
- `drop_pki: false` passes them through opaquely (only if they look like PKI packets: unicast,
  channel hash 0, longer than the 12-byte CCM tag + nonce). Turn this on if downlink gateways should
  deliver DMs across MQTT.

## Configuration

The config is YAML. Pass its path as the only argument, or set `MESHTASTIC_MQTT_CONFIG`
(the Docker image defaults to `/config/config.yaml`). The broker refuses to start, listing every
problem, if the file is invalid: unknown keys (typos are errors, not ignored), a key written twice,
an empty `true`/`false` value and an empty PSK are all errors.

Start from [`config.example.yaml`](config.example.yaml).

| Key | Default | Meaning |
|---|---|---|
| `listener.bind_address` | `0.0.0.0` | IPv4 or IPv6 literal to listen on (`::` = IPv6 only). |
| `listener.port` | `1883` | TCP port (plain MQTT). |
| `log_level` | `information` | `verbose`, `debug`, `information`, `warning`, `error`, `fatal`. See [Logs](#logs). |
| `drop_undecryptable` | `true` | Drop channel packets that do not decrypt with their channel's key. Must be `true` or `false` if present. |
| `drop_pki` | `true` | Drop PKI-encrypted DMs (see above). Must be `true` or `false` if present. |
| `default_psk` | `AQ==` | Base64 PSK for any channel not listed under `channels`. |
| `channels` | empty | Map of channel name → base64 PSK. Names are **case-sensitive** (exact match, like the firmware's channel hash). |
| `users[].username` | required | Case-sensitive. |
| `users[].password_hash` | required | `pbkdf2-sha256$<iterations>$<salt>$<hash>`, see below. |
| `users[].subscribe_allow` | empty | MQTT topic filters this user may subscribe within. Empty = no subscribe at all. |
| `users[].publish_allow` | empty | MQTT topic filters a PUBLISH topic of this user must match (see [Publish ACL](#publish-acl)). Empty = no publish at all. |
| `limits.max_packet_size` | `4096` | Largest MQTT packet accepted, in bytes (Remaining Length). Checked before the packet is allocated; a larger one closes the connection. Range 512-1048576. |
| `limits.communication_timeout_seconds` | `10` | How long a new connection may take to send CONNECT, and a write may stall (MQTTnet's default is 100). |
| `limits.auth_queue_timeout_seconds` | `3` | How long a login may wait for a password-hashing slot before it is answered "server busy". |
| `limits.auth_max_pending` | `64` | Distinct password checks that may run or wait at once (separately for configured users and for unknown usernames). Further logins get "server busy" without hashing. Range 1-100000. |
| `limits.auth_max_pending_per_user` | `4` | Distinct password checks one configured username may have pending at once; the rest get "server busy". Usernames are served in turn. Range 1-100000. |
| `limits.max_connections_per_ip` | `16` | Connections one IP address may hold open at once. Applied when the connection is accepted, before any MQTT byte is read; over the cap the socket is closed at once. `0` turns the cap off. Range 0-100000. |
| `limits.connect_rate_per_ip_per_minute` | `30` | Connections one IP address may open per minute (token bucket, with the burst below). Applied on accept, so it bounds a flood of CONNECTs and password guesses from one address. `0` turns the rate off. Range 0-1000000. |
| `limits.connect_burst_per_ip` | `10` | Burst of the per-IP connect rate: how many connections one address may open at once. `0` turns the rate off. Range 0-1000000. |
| `limits.max_payload_size` | `512` | Largest publish payload accepted, in bytes. Checked in the publish hook, after the publish ACL and before the packet is parsed. Range 64-`max_packet_size`. |
| `limits.publish_rate_per_client_per_minute` | `120` | Publishes one client may send per minute (token bucket, with the burst below). The key is the user that owns the session plus the client id. `0` turns the rate off. Range 0-1000000. |
| `limits.publish_burst_per_client` | `60` | Burst of the per-client publish rate: how many publishes one client may send at once. `0` turns the rate off. Range 0-1000000. |
| `limits.dedupe_window_seconds` | `120` | How long a packet is remembered for the cross-gateway dedupe. `0` turns the dedupe off, and then every copy of a packet counts separately against the per-`from` budget. Range 0-86400. |
| `limits.dedupe_max_gateways_per_packet` | `32` | How many gateways may send the same packet before the further copies are dropped. One copy per gateway is kept. Range 1-100000. |
| `limits.dedupe_max_entries` | `200000` | How many packets are remembered for the dedupe at once; the oldest are evicted when the cap is hit. The real memory ceiling is this cap **times** `dedupe_max_gateways_per_packet` (see [Limits and dedupe](#limits-and-dedupe)). Range 1-10000000. |
| `limits.packet_rate_per_from_per_minute` | `30` | Packets one node (the packet's `from`) may send per minute (token bucket, with the burst below). A packet is charged once, on its first copy. `0` turns the rate off. Range 0-1000000. |
| `limits.packet_burst_per_from` | `15` | Burst of the per-node packet rate: how many packets one node may send at once. `0` turns the rate off. Range 0-1000000. |
| `limits.auth_fail_max_per_ip` | `10` | Failed logins one IP address may make before it is banned. Only a wrong password (or an unknown user, or an unsupported authentication method) counts. `0` turns the bans off. Range 0-100000. |
| `limits.auth_fail_window_seconds` | `600` | How long the failed logins of one IP address are counted. The window starts with the first failure; when it has passed, the next failure starts a new one. Range 10-86400. |
| `limits.auth_ban_seconds` | `3600` | How long a banned IP address is refused. The bans live in memory: a restart forgets them. Range 60-604800. |
| `limits.auth_ban_exempt` | empty | IP ranges (CIDR, IPv4 or IPv6) whose failed logins are never counted and which are never banned. An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) matches the IPv4 ranges. |
| `limits.max_tracked_entries` | `100000` | How many entries the bounded tables may hold at once: the per-IP, the per-client and the per-node rate tables, the table of failed logins and the table of bans. The dedupe table has its own cap (`dedupe_max_entries`). Range 1000-10000000. |
| `limits.rate_idle_expiry_seconds` | `600` | How long an entry of a rate table survives without being used, in seconds: the per-IP, the per-client and the per-node rate tables. Range 60-86400. |

### Limits

`max_packet_size` defaults to 4096 bytes. The largest thing a node uplinks is a `ServiceEnvelope` around a
`MeshPacket` whose encrypted part is at most 256 bytes, plus channel and gateway ids: a few hundred bytes.
The firmware's MQTT client buffer is 1024 bytes (`src/mqtt/MQTT.cpp`, `setBufferSize(1024, 1024)`), so it
cannot send anything larger. 4096 leaves room for long topics and MQTT 5 properties. MQTTnet itself has no
such limit and would allocate whatever a client announces (up to 256 MB) before reading it, which is why
the check runs in the broker's own TCP listener, on the raw bytes.

Logins pay PBKDF2 only when the password is not already known (see below). Those checks run in two
queues, one for configured usernames and one for unknown usernames, each bounded by `auth_max_pending`
and `auth_queue_timeout_seconds`, so a flood of bad logins can neither grow memory without bound nor keep
legitimate users waiting. Within the configured-users queue, checks are grouped by username and the usernames
are served in turn (round-robin), and one username may have at most `auth_max_pending_per_user` distinct
checks pending; beyond that its logins get "server busy" at once. Wrong passwords for the public `meshdev`
user therefore delay another user's cold login by at most one check, however many guesses arrive and however
many times each guess is sent. Simultaneous logins with the same username and password (a fleet of `meshdev`
nodes reconnecting after a broker restart) share one PBKDF2 computation, and within a username the check with
the most logins waiting on it runs first, so the real `meshdev` password jumps ahead of an attacker's guesses.
What the queue cannot do is tell a lone cold `meshdev` login from a guess before hashing it: while `meshdev`'s
own checks are all taken by guesses, that login is told "server busy" and retries. Limiting such a flood is a
per-IP job (the per-IP connect rate, below).

### Limits and dedupe

The `limits` section has two families of keys: the ones in [Limits](#limits) bound what one packet or one
login may do, the ones below bound what one address, one client or one node may do. All of them have a
default, are validated with a range at startup, and `0` means "off" wherever the table says so.

**Per IP address** (applied in the broker's own TCP listener, when the connection is accepted, before a
single MQTT byte is read):

- `max_connections_per_ip` (16) caps how many connections one address may hold open at once. Over the cap
  the socket is closed at once; the counter is given back on every close path, so it never leaks.
- `connect_rate_per_ip_per_minute` (30) with the burst `connect_burst_per_ip` (10) is a token bucket: it
  bounds how often one address may open a connection, and with it a flood of CONNECTs or password guesses.
  The token is taken at the accept, so an address that only opens sockets and never speaks MQTT is bounded
  too. This is what keeps a single-address flood from filling the password-hashing queue of the real
  `meshdev` user and delaying a cold login from another address.

**Per client** (the user that owns the session plus the client id):

- `publish_rate_per_client_per_minute` (120) with the burst `publish_burst_per_client` (60) bounds how many
  publishes one client may send. The budget dies with the session, and an idle client is forgotten.
- `max_payload_size` (512) is the largest publish payload the broker looks at, in bytes. It is checked after
  the publish ACL and before anything is parsed.

**Per node** (the packet's `from`) and **per packet** (the cross-gateway dedupe):

- `packet_rate_per_from_per_minute` (30) with the burst `packet_burst_per_from` (15) bounds how many packets
  one node may send. A packet is charged **once**, on its first accepted copy, never once per gateway, and the
  verdict is sticky: a packet whose first copy was refused is refused for every later copy too.
- The dedupe is keyed by (`from`, packet id) and keeps **one copy per gateway** (the dashboards use each
  gateway's copy to show who heard a packet and at what SNR, so collapsing to one copy per packet would lose
  information). A copy from a gateway that already sent the packet is dropped
  (`duplicate from the same gateway`); a copy from a new gateway is accepted while fewer than
  `dedupe_max_gateways_per_packet` (32) gateways have sent it, and dropped above that
  (`too many gateways for one packet`). A packet is forgotten `dedupe_window_seconds` (120) after it was
  first seen, and the table never holds more than `dedupe_max_entries` (200000) packets: the oldest are
  evicted. Map reports carry no packet id and are not deduplicated; each one is charged as one packet of its
  node.
- The **real memory ceiling of the dedupe is `dedupe_max_entries` × `dedupe_max_gateways_per_packet`**, not
  the entry cap alone: every packet keeps a set of the gateways that sent it. The gateways are kept as
  their node numbers (4 bytes each), not as strings, so with the defaults 200000 packets × 32 gateways =
  6.4 million gateway numbers (about 26 MB of raw values). The overhead is on top of that: the set of
  gateways of one packet, the entry and the tables around it were **measured** in a Debug test host
  on .NET 10, arm64: **~0.86 KB per packet, ~169 MB with the defaults** (approximate: the order of
  magnitude is what matters, and the object layout is the same in Release), not the few MB the entry
  cap suggests. Lower
  `dedupe_max_entries` or `dedupe_max_gateways_per_packet` if the broker runs with a small memory limit.
- `dedupe_window_seconds: 0` turns the dedupe **off**: the copies of one packet can no longer be told
  apart, so **every copy counts separately against the per-`from` budget** (a packet heard by 5 gateways
  costs the node 5 packets, not 1).
- The caps of the bounded tables are configuration, not constants: `max_tracked_entries` (100000) is the cap
  of the per-IP, the per-client and the per-node rate tables, of the table of failed logins and of the
  table of bans, and `rate_idle_expiry_seconds` (600) is how long an entry of a rate table survives without
  being used. The rate tables keep their entries in the order of their last use, so the entry evicted
  when one of them is full is the least recently used one (not the first inserted), and the sweep that
  forgets the idle entries only visits the entries it forgets.

The order of the checks in the publish hook is fixed: **publish ACL → payload cap → per-client rate →
packet filter (including the gateway binding) → dedupe → per-node rate**. Every refusal is counted under
its own reason, logged per packet at `debug` only, and never disconnects the client. On MQTT 5 a refused
publish is answered with reason code `Quota exceeded` (151) for the payload cap, the per-client publish rate
and the per-node packet rate, with `Not authorized` (135) for the publish ACL, and with **no** reason code
for the packet filter and the dedupe (those copies are dropped, but the client is not told why); MQTT 3.1.1
acknowledgements carry no reason code at all.

The packet filter also checks the **gateway binding**: on `<root>/2/e/<channel>/<gateway>` the gateway level
of the topic must be the `gateway_id` of the envelope, and it must be `!` followed by 8 lowercase hex digits
(`NodeDB::getNodeId()`, the same string the firmware puts in both places, `src/mqtt/MQTT.cpp` `onSend()`).
A topic whose gateway is something else is dropped (`gateway in topic does not match gateway_id`).

Every table the broker keeps (per IP, per client, per node, per packet) has a hard entry cap
(`max_tracked_entries`, or `dedupe_max_entries` for the dedupe) and an idle expiry
(`rate_idle_expiry_seconds`; the per-IP connection counter dies with its connection instead), and the
evictions are counted (and counted again in the periodic summary, see [Logs](#logs)), so a flood of
forged ids cannot grow the memory without bound.

#### Residual risks

- **A client can restart its per-client budget by reconnecting.** The publish budget belongs to the
  session, so a client that reconnects gets a full one again. The per-IP connect rate is what bounds it:
  with the defaults (30 connections per minute per address and a burst of 60 publishes), one address can
  spend about **30 × 60 = 1800 publishes per minute**. Lower `connect_rate_per_ip_per_minute` or lower
  `publish_burst_per_client` if that is too much.
- **With public credentials, a forged `from` can use up a real node's budget.** `meshdev`/`large4cats` are
  public, so anyone can put any `from` in an envelope header and spend that node's per-node packet budget.
  The per-client and per-IP limits bound how much of that an attacker can do at once, but they cannot tell
  a forged `from` from a real one.
- **Clients behind one address share the limits.** A CGNAT, a VPN or a tunnel puts many nodes behind one
  IP address: they share the connection cap and the connect rate, and the fleet may be cut. Tune those
  values (or set them to `0`) for the networks the real nodes use.
- **Distributed floods are not covered here.** One address per flood is bounded (the per-IP limits above
  and the [auth bans](#auth-bans) below); a flood from many addresses is not. That needs an upstream
  firewall (or a rate limit at the edge) in front of the broker.

### Auth bans

An address that fails to log in too often is banned for a while. The ban lives **inside the broker**: no
system fail2ban, no nftables, no changes to the host.

- Only a **failed password check** counts: a wrong password, an unknown user or an unsupported
  authentication method. A full password queue ("server busy"), a client-id conflict, a connection
  refused at the accept and a connection refused because the address is already banned are not password
  failures and are not counted.
- The failures of one address are counted in a window: `auth_fail_max_per_ip` (10) failures within
  `auth_fail_window_seconds` (600) since the first failure of the window. When the window has passed, the
  next failure starts a new one. **A successful login does not reset the counter**: with the public
  `meshdev` credentials an attacker could interleave a correct login between the guesses, and the honest
  nodes behind the same address would keep the guesses alive.
- The `auth_fail_max_per_ip`-th failure bans the address for `auth_ban_seconds` (3600) and clears its
  counter. There is no escalation: every ban lasts the same.
- A banned address is refused **at the accept**, before a single MQTT byte is read and before it takes a
  slot or a token of the per-IP limits, and **at the CONNECT**, before the password is checked: the answer
  is reason code `Banned` (0x8A) on MQTT 5. The second refusal is the one that matters for a client that
  was already connected when the ban started.
- The sessions that were already connected are **left alone**: behind a CGNAT or a VPN many honest nodes
  share one address, and cutting them would cost more than the attack is worth.
- `auth_ban_exempt` is a list of CIDR ranges (IPv4 and IPv6) whose failures are never counted and which
  are never banned. An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) matches the IPv4 ranges.
- The bans are in memory: **a restart forgets them**. There is no manual unban.

The tables behind it are bounded (`max_tracked_entries`, 100000 addresses each): the failed logins are
evicted in the order of their windows (the oldest window first), the bans evict the one that ends
soonest, and the evictions are counted in the periodic summary.

#### Residual risks

- **The ban is per IP address.** A flood from many addresses is not covered by the broker: the per-IP
  limits bound one address at a time, and a flood that rotates addresses needs an upstream firewall in
  front of the broker.
- **Behind a CGNAT or a VPN many nodes share one address.** One misconfigured node (a wrong password in a
  loop, a firmware that sends a stale one) can get the whole address banned, and with it the honest nodes
  behind it. Use `auth_ban_exempt` for those networks, or raise `auth_fail_max_per_ip`.
- **An IPv6 attacker can rotate addresses inside a /64.** The broker keys the ban by the address, not by
  the /64, so a client with a whole prefix can walk through it.
- **The bans are lost on a restart.** A broker that restarts often (a crash loop) hands the attacker a
  fresh start.

### Logs

Logs never contain passwords or message payloads. At the default `information` level:

- Connections, granted subscriptions and the startup line: Information. The startup line lists every
  limit of the configuration, and the limits are also a structured property of the line (`LimitValues`),
  so a log store keeps the limits of that run as data and not only as text. The keys of that object
  keep the order of the line, and the address is written as it is, so the line reads without quotes.
- Failed logins: Warning, one line per attempt with username and remote IP. The broker counts the
  failures itself and bans the address (see [Auth bans](#auth-bans)): the Warnings are for the operators.
  Refused authentication methods, client-id conflicts and "server busy" refusals are also Warning with
  username and IP.
- A ban is one Warning when it starts: `Banned {RemoteIp} for {Seconds} s after {Failures} authentication
  failures`. The connections of a banned address are Debug (one per connection) and are counted in the
  summary as `banned IP`.
- A refused SUBSCRIBE: one Warning per packet (count of refused filters and the first one), however many
  filters it carries.
- Dropped publishes: one Information line every 60 s with the number of refusals and evictions per reason,
  only when something was refused. The line is `Refused or evicted {Total} in the last 60 s: {reason}:
  {count}, ...`: it counts more than dropped publishes, so it does not call them all publishes. The counts
  per reason are also a structured property of the line (`Drops`), so a log store can filter by them, and
  its keys keep the order of the text of the line.
  Publishes refused by the publish ACL are counted there too (`not in publish_allow`, `invalid topic
  name`), and so are the ones refused by the limits and the dedupe
  (`payload larger than max_payload_size`, `publish rate exceeded for the client`,
  `duplicate from the same gateway`, `too many gateways for one packet`, `packet rate exceeded for the node`)
  and the connections refused at the accept (`too many connections from one IP`,
  `too many connection attempts from one IP`, `banned IP`). Each dropped packet is logged individually
  only at `debug`.
- Evictions from the bounded tables are counted in the same summary, one reason per table:
  `evicted: dedupe table full`, `evicted: per-node rate table full`, `evicted: per-client rate table full`,
  `evicted: per-IP connection table full`, `evicted: per-IP rate table full`,
  `evicted: auth failure table full` and `evicted: auth ban table full`. A non-zero count means a
  cap was reached (a flood of forged ids, most likely) and the oldest entries of that table were dropped:
  the least recently used ones in the rate tables (they keep their entries in the order of their last
  use), the oldest ones in the dedupe, the connections and the failed logins.

`debug` also logs every accepted packet (topic, client, `from`, packet id, portnum).

### Channel keys

PSKs use the same encoding as the firmware and the apps (base64). Expansion follows
`Channels::getKey()` in the firmware:

- 1 byte `0` (`AA==`): no encryption. An empty value is a config error (the firmware reads an empty
  key on a secondary channel as "use the primary channel's key", so it is ambiguous); write `AA==`.
- 1 byte `N ≥ 1`: the default key with its last byte increased by `N-1`
  (`AQ==` = default key, `Ag==` = default + 1, `VA==` = byte 84).
- 2-15 bytes are zero-padded to 16 (AES-128), 17-31 to 32 (AES-256); 16 and 32 are used as is.

Base64 is case sensitive: `VA==` (84) and `Va==` (85) are different keys.

Spanish mesh channels (source: meshtastic-es-community.github.io):

| Channel | Key |
|---|---|
| `SFNarrow`, `Iberia`, provincial channels (`Madrid`, `Barcelona`, `Zaragoza`, …) | `AQ==` (default, no entry needed) |
| `Test`, `Bots` | `Ag==` |
| `Valencia` | `VA==` |

### Password hashes

Passwords are stored as PBKDF2-HMAC-SHA256 (600 000 iterations by default, 16-byte random salt).
PBKDF2 rather than bcrypt because it is built into .NET (no extra crypto dependency), FIPS-approved,
and does not truncate long passwords the way bcrypt does at 72 bytes.

Generate a hash (reads one line from stdin, prints the hash):

```bash
docker run --rm -i meshtastic-mqtt hash-password
# or interactively, with the password hidden:
docker run --rm -it meshtastic-mqtt hash-password
```

Without Docker: `dotnet run --project src/Meshtastic.Mqtt -- hash-password`.

The firmware-default `meshdev` / `large4cats` credentials are public by design; the hash in
`config.example.yaml` is for that password.

Logins are rate-friendly: a password verified once is remembered (as a SHA-256 digest, one per
configured user) so thousands of nodes reconnecting with `meshdev` do not each pay PBKDF2. Failed
and unknown-user logins always pay the full cost, in bounded queues (see [Limits](#limits)).

## Running with Docker

```bash
docker build -t meshtastic-mqtt .
cp config.example.yaml config.yaml   # edit it; config.yaml is git-ignored
docker run -d --name meshtastic-mqtt \
  -p 1883:1883 \
  -v "$PWD/config.yaml:/config/config.yaml:ro" \
  --read-only \
  --memory 512m \
  --log-opt max-size=10m --log-opt max-file=3 \
  meshtastic-mqtt
docker logs -f meshtastic-mqtt
```

- The image runs as the non-root `app` user (uid 1654); the config only needs to be world-readable
  or readable by that uid.
- `--memory 512m` caps the container, and `--log-opt` caps the JSON log files Docker keeps on the host
  (3 × 10 MB). Keep both when exposing the broker to the internet.
- Logs go to stdout as compact JSON (Serilog CLEF), one event per line.
- Multi-arch: the official .NET base images are multi-platform, so a plain `docker build` works on
  amd64 and arm64 hosts; `docker buildx build --platform linux/amd64,linux/arm64 .` builds both.

### Tests

```bash
docker build --target test .                    # whole suite in the SDK image
# or, with the SDK installed:
dotnet test --solution Meshtastic.Mqtt.sln
```

Test fixtures (`tests/Meshtastic.Mqtt.Tests/Fixtures/*.bin`) are real-format envelopes produced by
`make_fixtures.py` with hand-written protobuf and OpenSSL AES-CTR, independently of the broker code.
`longfast_real.bin` wraps a packet captured on the public mesh.

## Not in this version

TLS. The fail2ban-style bans are in this version, inside the broker (see [Auth bans](#auth-bans)): no
system fail2ban, no nftables. The rate limits per IP, per client and per node, the cross-gateway dedupe
and the publish payload cap are in [Limits and dedupe](#limits-and-dedupe); the payload cap acts in the
publish hook, after the ACL, because the packet has already been read by then (the `max_packet_size`
check is the one that acts while the packet is being read).

## Ideas for MQTT mesh moderation

- "Zero hopping" certain packets
- Blocking or rate-limiting certain portnums
- Fail2ban style connection moderation (per-IP bans are in this version; a ban list shared between
  brokers is not)
- Banning from known bad actors list

## License

GPL-3.0, see [LICENSE](LICENSE).
