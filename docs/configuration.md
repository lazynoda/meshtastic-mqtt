# Configuration

Every key of the broker's YAML file: its type, its default, the range it accepts and when to change it.

[Back to the README](../README.md)

The config is YAML. Pass its path as the only argument, or set `MESHTASTIC_MQTT_CONFIG` (the Docker image
defaults to `/config/config.yaml`). The broker refuses to start, listing **every** problem it found, if the
file is invalid:

- an unknown key is an error, not something that is ignored: a typo stops the broker;
- a key written twice is an error (the YAML parser rejects it);
- an empty value for `drop_undecryptable` or `drop_pki` is an error: write `true` or `false`;
- an empty PSK is an error: write the base64 key (`"AA=="` means no encryption);
- a value outside its range is an error, and the message names the key and the range;
- an invalid topic filter, a duplicate username, an invalid CIDR range or a `max_payload_size` larger than
  `max_packet_size` are errors too.

Start from [`config.example.yaml`](../config.example.yaml): it is a working configuration with every key
written out and commented.

## The listener

| Key | Type | Default | Range | What it does | When to change it |
|---|---|---|---|---|---|
| `listener.bind_address` | string | `0.0.0.0` | an IPv4 or IPv6 literal | The address the broker binds. `::` listens on IPv6 only: the listener never binds both families at once. | When the host has an address the broker must not listen on, or when the host has no IPv4 at all. |
| `listener.port` | int | `1883` | 1-65535 | The TCP port of the plain MQTT listener. | When 1883 is taken on the host, or when the broker sits behind a port mapping. |

## The top-level keys

| Key | Type | Default | Range | What it does | When to change it |
|---|---|---|---|---|---|
| `log_level` | string | `information` | `verbose`, `debug`, `information`, `warning`, `error`, `fatal` (the case does not matter) | The lowest level that is written. | `debug` while you look for a node that does not appear; `warning` on a host where the log is read by a machine. See [Logging](logging.md). |
| `drop_undecryptable` | bool | `true` | `true` or `false` | Drop the channel packets that do not decrypt with the key configured for their channel (a private channel, a wrong key, garbage). | `false` only when you must see the packets of a channel whose key you do not have: they are then forwarded undecrypted. See [Packet filtering](packet-filtering.md#drop_undecryptable-and-drop_pki). |
| `drop_pki` | bool | `true` | `true` or `false` | Drop the PKI-encrypted direct messages, which the broker can never decrypt. | `false` when a downlink gateway must deliver the direct messages across MQTT. See [Packet filtering](packet-filtering.md#drop_undecryptable-and-drop_pki). |
| `default_psk` | string (base64) | `AQ==` | a base64 PSK of at most 32 bytes; an empty value is an error | The key of every channel that is not listed under `channels`. `AQ==` is the firmware default key. | When a channel is not listed under `channels` and does not use the firmware default key. |
| `channels` | map of name to base64 PSK | empty | names: not empty, not only whitespace, and no `/`, `+` or `#`; values: a non-empty base64 PSK of at most 32 bytes | The keys of the channels, by their exact name. The lookup is case-sensitive, like the firmware's channel hash. | When a channel of the mesh uses a key other than `default_psk`. See [Channel keys](packet-filtering.md#channel-keys). |
| `users` | list of objects | at least one user is required | - | The users the broker accepts, and their ACLs. | When a user is added or removed, or when its ACLs change. |
| `limits` | map of int (and one list) | the defaults of the tables below | see the tables below | The limits of the broker: the packet sizes, the rates, the bans and the caps of the tables. | See [Limits and dedupe](limits-and-dedupe.md). |

## The channel keys

`channels` is a map: the name of the channel is the key, the base64 PSK is the value. The name is the one
the firmware sends in `channel_id` and in the topic, and it is **case-sensitive**: the firmware hashes the
exact name, so `Test` and `test` are two different channels and a `test` that is not listed here uses
`default_psk`.

```yaml
channels:
  Test: "Ag=="
  Bots: "Ag=="
  Valencia: "VA=="
```

An empty value is an error: the firmware reads an empty key on a secondary channel as "use the primary
channel's key", so an empty value here would be ambiguous. Write `"AA=="` for "no encryption".

The single-byte keys follow the firmware's expansion: `AQ==` is the default key, `Ag==` the default key plus
one, and so on. The full rules are in [Channel keys](packet-filtering.md#channel-keys).

## The users

Each entry of the `users` list is one user the broker accepts.

| Key | Type | Default | Range | What it does | When to change it |
|---|---|---|---|---|---|
| `users[].username` | string | required | unique, case-sensitive | The name a client sends in CONNECT. | Never for the public user: it is the name the nodes of the mesh use. |
| `users[].password_hash` | string | required | `pbkdf2-sha256$<iterations>$<salt>$<hash>`, with 100000-10000000 iterations, a salt of at least 16 bytes and a hash of exactly 32 bytes, all base64 | The hash of the password of the user. The plain password is never in the file. | When the password changes. See [Password hashes](security.md#password-hashes). |
| `users[].subscribe_allow` | list of topic filters | empty | valid MQTT topic filters | The filters the user may subscribe to. An empty or missing list denies every subscription. | When a dashboard or a gateway needs to read. See [The ACLs](security.md#the-acls). |
| `users[].publish_allow` | list of topic filters | empty | valid MQTT topic filters | The filters a PUBLISH topic of the user must match. An empty or missing list denies every publish. | When a user must uplink. See [The ACLs](security.md#the-acls). |

An invalid filter (`#` that is not the last level, a `+` or a `#` inside a level, an empty filter) stops the
broker at startup, with the name of the user and the filter in the message.

## The limits

In the YAML file the keys of this section are nested under `limits:` (see `config.example.yaml`); this
page and the validation messages of the broker name them `limits.<key>`. The startup line shows the value
the broker will use, one `key=value` per entry. `0` means "off" for the keys whose row says so.

### Packets and authentication

| Key | Type | Default | Range | What it does | When to change it |
|---|---|---|---|---|---|
| `limits.max_packet_size` | int | 4096 | 512-1048576 | The largest MQTT packet the broker accepts, counted as the fixed header's Remaining Length. The check runs while the header is read, before MQTTnet allocates the body, so it also bounds the packets of the clients that have not authenticated yet. A larger packet closes the connection. | Rarely: 4096 is far above what a node sends. Raise it only for a client that needs MQTT 5 properties or a very long topic. |
| `limits.communication_timeout_seconds` | int | 10 | 1-300 | How long a client may take to send CONNECT, and how long a write may stall (MQTTnet's own default is 100). | When the nodes of the mesh are on a slow link. |
| `limits.auth_queue_timeout_seconds` | int | 3 | 1-60 | How long a login may wait for a password-hashing slot before it is answered "server busy". | When the logins of a cold fleet wait too long. |
| `limits.auth_max_pending` | int | 64 | 1-100000 | How many distinct password checks may run or wait at once, per lane: the configured usernames have one lane and the unknown usernames another. The logins over the cap are answered "server busy" without hashing anything. | When a cold fleet of thousands of nodes reconnects at once and its logins are refused. |
| `limits.auth_max_pending_per_user` | int | 4 | 1-100000 | How many distinct password checks one configured username may have pending at once. The usernames are served in turn, so the guesses of one user cannot delay the login of another. | Rarely. It is the budget of one username, and a fleet that shares `meshdev` shares this budget. |

### Per IP address

| Key | Type | Default | Range | What it does | When to change it |
|---|---|---|---|---|---|
| `limits.max_connections_per_ip` | int | 16 | 0-100000 (0 = off) | How many connections one address may hold open at once. The check runs when the connection is accepted, before a byte of MQTT is read; over the cap the socket is closed at once. | When many nodes share one address (a CGNAT, a VPN): raise it, or set it to 0. |
| `limits.connect_rate_per_ip_per_minute` | int | 30 | 0-1000000 (0 = off) | How many connections one address may open per minute (a token bucket, with the burst below). The token is taken at the accept, so a flood of sockets is bounded too. | When the fleet behind one address reconnects in a wave. |
| `limits.connect_burst_per_ip` | int | 10 | 0-1000000 (0 = off) | The burst of the connect rate: how many connections one address may open at once. | Together with the rate above. |

### Per client

| Key | Type | Default | Range | What it does | When to change it |
|---|---|---|---|---|---|
| `limits.max_payload_size` | int | 512 | 64 to `max_packet_size` | The largest publish payload the broker looks at, in bytes. The check runs in the publish hook, after the publish ACL and before anything is parsed. | Rarely: a firmware envelope is a few hundred bytes at most. |
| `limits.publish_rate_per_client_per_minute` | int | 120 | 0-1000000 (0 = off) | How many publishes one client may send per minute (a token bucket, with the burst below). The key is the user that owns the session plus the client id, and the budget dies with the session. | When a client publishes more than two messages a second and the client rate is what refuses it. |
| `limits.publish_burst_per_client` | int | 60 | 0-1000000 (0 = off) | The burst of the publish rate: how many publishes one client may send at once. | Together with the rate above. |

### Per node and the dedupe

| Key | Type | Default | Range | What it does | When to change it |
|---|---|---|---|---|---|
| `limits.dedupe_window_seconds` | int | 120 | 0-86400 (0 = off) | How long a packet is remembered for the cross-gateway dedupe. With 0 the dedupe is off, and then every copy of a packet counts separately against the per-node budget. | When the gateways of the mesh relay the same packet for longer than the window. |
| `limits.dedupe_max_gateways_per_packet` | int | 32 | 1-100000 | How many gateways may send the same packet before the further copies are dropped. One copy per gateway is kept, on purpose. | When more than 32 gateways hear the same packet (a repeater-heavy area). |
| `limits.dedupe_max_entries` | int | 200000 | 1-10000000 | How many packets the dedupe remembers at once; the oldest are evicted when the cap is hit. The real memory ceiling is this cap **times** `dedupe_max_gateways_per_packet`. | When the broker runs with a small memory limit: see [The memory of the dedupe](limits-and-dedupe.md#the-memory-of-the-dedupe). |
| `limits.packet_rate_per_from_per_minute` | int | 30 | 0-1000000 (0 = off) | How many packets one node (the packet's `from`) may send per minute (a token bucket, with the burst below). A packet is charged once, on its first copy, and the verdict is sticky. | When the nodes of the mesh send more than 30 packets a minute on a busy channel. |
| `limits.packet_burst_per_from` | int | 15 | 0-1000000 (0 = off) | The burst of the packet rate: how many packets one node may send at once. | Together with the rate above. |

### Bans

| Key | Type | Default | Range | What it does | When to change it |
|---|---|---|---|---|---|
| `limits.auth_fail_max_per_ip` | int | 10 | 0-100000 (0 = off) | How many failed logins one address may make before it is banned. Only a wrong password, an unknown user or an unsupported authentication method counts. | When the fleet behind one address has nodes with a stale password. See [Auth bans](auth-bans.md). |
| `limits.auth_fail_window_seconds` | int | 600 | 10-86400 | How long the failed logins of one address are counted. The window starts with the first failure; when it has passed, the next failure starts a new one. | Rarely. |
| `limits.auth_ban_seconds` | int | 3600 | 60-604800 | How long a banned address is refused. The bans live in memory: a restart forgets them. | When an address comes back shortly after its ban ended. |
| `limits.auth_ban_exempt` | list of strings | empty | IPv4 or IPv6 CIDR ranges; a single address without a prefix is a range of one | The ranges whose failed logins are never counted and which are never banned. An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) matches the IPv4 ranges. | For the networks the real nodes share (a CGNAT, a VPN, a tunnel). |

### Tables

| Key | Type | Default | Range | What it does | When to change it |
|---|---|---|---|---|---|
| `limits.max_tracked_entries` | int | 100000 | 1000-10000000 | How many entries the bounded tables may hold at once: the per-IP, the per-client and the per-node rate tables, the table of failed logins and the table of bans. The dedupe has its own cap. | When the broker is small and the memory matters. |
| `limits.rate_idle_expiry_seconds` | int | 600 | 60-86400 | How long an entry of a rate table survives without being used: the per-IP, the per-client and the per-node rate tables. | When a client that publishes once a day should not keep a budget for ever. |

## See also

- [Security](security.md): the authentication, the ACLs, the client-id ownership and the packet-size cap.
- [Packet filtering](packet-filtering.md): what the broker accepts on the wire and what it drops.
- [Limits and dedupe](limits-and-dedupe.md): what every limit does, the tables and their memory.
- [Auth bans](auth-bans.md): the bans for the addresses that fail to log in.
- [Operations](operations.md): where the file lives, how to hash a password, how to run the tests.
