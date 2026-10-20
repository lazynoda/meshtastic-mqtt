# Limits and dedupe

Every limit of the broker, what it bounds, and the memory the tables behind them use.

[Back to the README](../README.md)

The `limits` section has two families of keys: the ones that bound what one packet or one login may do, and
the ones that bound what one address, one client or one node may do. All of them have a default, are
validated with a range at startup, and `0` means "off" wherever the table says so. The full reference of
the keys is in [Configuration](configuration.md#the-limits); this page says what they do.

## The limits

`max_packet_size` defaults to 4096 bytes. The largest thing a node uplinks is a `ServiceEnvelope` around
a `MeshPacket` whose encrypted part is at most 256 bytes, plus channel and gateway ids: a few hundred
bytes. The firmware's MQTT client buffer is 1024 bytes (`src/mqtt/MQTT.cpp`, `setBufferSize(1024, 1024)`),
so it cannot send anything larger. 4096 leaves room for long topics and MQTT 5 properties. MQTTnet itself
has no such limit and would allocate whatever a client announces (up to 256 MB) before reading it, which
is why the check runs in the broker's own TCP listener, on the raw bytes (see
[The packet-size cap](security.md#the-packet-size-cap)).

Logins pay PBKDF2 only when the password is not already known, and the checks run in two bounded
queues, one for the configured usernames and one for the unknown usernames. What that queue does, and
what it cannot do, is in [The password queue](security.md#the-password-queue). Limiting a flood of bad
logins is a per-IP job (the per-IP connect rate, below).

### How the token buckets work here

The rates of this broker are **token buckets**. A bucket holds at most `burst` tokens and refills them at
`rate / 60` tokens per second:

- the first use of a key starts with a **full** bucket, so a client may burst at once;
- every use takes one token, and a use that finds the bucket empty is refused;
- the refill is computed from the monotonic clock, so a wall-clock step (NTP) neither extends nor cuts the
  budget;
- a rate of 0, or a burst of 0, turns the whole bucket off.

The three buckets of the broker are the per-address connect rate, the per-client publish rate and the
per-node packet rate.

## Per IP address

The per-IP limits are applied in the broker's own TCP listener, when the connection is accepted, **before
a single MQTT byte is read**:

- `max_connections_per_ip` (16) caps how many connections one address may hold open at once. Over the cap
  the socket is closed at once; the counter is given back on every close path, so it never leaks.
- `connect_rate_per_ip_per_minute` (30) with the burst `connect_burst_per_ip` (10) is a token bucket: it
  bounds how often one address may open a connection, and with it a flood of CONNECTs or password guesses.
  The token is taken at the accept, so an address that only opens sockets and never speaks MQTT is bounded
  too. This is what keeps a single-address flood from filling the password-hashing queue of the real
  `meshdev` user and delaying a cold login from another address.

## Per client

The key of the per-client limits is the user that owns the session plus the client id, and the budget
dies with the session:

- `publish_rate_per_client_per_minute` (120) with the burst `publish_burst_per_client` (60) bounds how many
  publishes one client may send. The budget dies with the session, and an idle client is forgotten.
- `max_payload_size` (512) is the largest publish payload the broker looks at, in bytes. It is checked
  after the publish ACL and before anything is parsed.

On MQTT 5 a publish refused by the payload cap or by the per-client rate is answered with the reason
code `Quota exceeded` (151); on MQTT 3.1.1 the acknowledgement carries no reason code.

## Per node and the dedupe

- `packet_rate_per_from_per_minute` (30) with the burst `packet_burst_per_from` (15) bounds how many
  packets one node may send. A packet is charged **once**, on its first copy, never once per gateway, and
  the verdict is sticky: a packet whose first copy was refused is refused for every later copy too. On
  MQTT 5 a publish refused by this rate is answered with the reason code `Quota exceeded` (151).
- The dedupe is keyed by (`from`, packet id) and keeps **one copy per gateway** (the dashboards use each
  gateway's copy to show who heard a packet and at what SNR, so collapsing to one copy per packet would
  lose information). A copy from a gateway that already sent the packet is dropped
  (`duplicate from the same gateway`); a copy from a new gateway is accepted while fewer than
  `dedupe_max_gateways_per_packet` (32) gateways have sent it, and dropped above that
  (`too many gateways for one packet`). A packet is forgotten `dedupe_window_seconds` (120) after it was
  first seen, and the table never holds more than `dedupe_max_entries` (200000) packets: the oldest are
  evicted. Map reports carry no packet id and are not deduplicated; each one is charged as one packet of
  its node.
- The **real memory ceiling of the dedupe is `dedupe_max_entries` x `dedupe_max_gateways_per_packet`**, not
  the entry cap alone: every packet keeps a set of the gateways that sent it. The gateways are kept as
  their node numbers (4 bytes each), not as strings, so with the defaults 200000 packets x 32 gateways =
  6.4 million gateway numbers (about 26 MB of raw values). The overhead is on top of that: the set of
  gateways of one packet, the entry and the tables around it were **measured** in a Debug test host on
  .NET 10, arm64: **~0.86 KB per packet, ~169 MB with the defaults** (approximate: the order of magnitude
  is what matters, and the object layout is the same in Release), not the few MB the entry cap suggests.
  Lower `dedupe_max_entries` or `dedupe_max_gateways_per_packet` if the broker runs with a small memory
  limit.
- `dedupe_window_seconds: 0` turns the dedupe **off**: the copies of one packet can no longer be told
  apart, so **every copy counts separately against the per-`from` budget** (a packet heard by 5 gateways
  costs the node 5 packets, not 1).

## The bounded tables

The caps of the bounded tables are configuration, not constants: `max_tracked_entries` (100000) is the cap
of the per-IP, the per-client and the per-node rate tables, of the table of failed logins and of the
table of bans, and `rate_idle_expiry_seconds` (600) is how long an entry of a rate table survives without
being used.

The tables do not all forget their entries the same way:

| Table | Cap | When an entry is forgotten |
|---|---|---|
| The per-IP rate table (the connect rate) | `max_tracked_entries` | After `rate_idle_expiry_seconds` without a use. The order is the order of the last use, so the entry evicted when the table is full is the least recently used one. |
| The per-client rate table (the publish rate) | `max_tracked_entries` | After `rate_idle_expiry_seconds` without a use, or when the session of the client is deleted. The order is the order of the last use. |
| The per-node rate table (the packet rate) | `max_tracked_entries` | After `rate_idle_expiry_seconds` without a use. The order is the order of the last use. |
| The dedupe table | `dedupe_max_entries` | `dedupe_window_seconds` after the packet was first seen. The order is the insertion order, so the oldest packet is the first one to go. |
| The table of connections per IP | `max_tracked_entries` | When the last connection of the address is closed. The order is the insertion order. |
| The table of failed logins | `max_tracked_entries` | `auth_fail_window_seconds` after the first failure of the window. The order is the order of the windows, so the oldest window is the first one to go. |
| The table of bans | `max_tracked_entries` | `auth_ban_seconds` after the ban started. The ban that ends soonest is the one that is evicted first. |

The sweep that forgets the idle entries only visits the entries it forgets: the tables keep their entries
in an order, and the sweep stops at the first entry that is still alive. A sweep costs what it expires,
not what the table holds.

Every eviction is counted, and the counts are in the periodic summary (see
[Logging](logging.md#the-60-s-summary)), so an operator sees that a cap was reached:

- `evicted: dedupe table full`
- `evicted: per-node rate table full`
- `evicted: per-client rate table full`
- `evicted: per-IP connection table full`
- `evicted: per-IP rate table full`
- `evicted: auth failure table full`
- `evicted: auth ban table full`

A non-zero count means a cap was reached (a flood of forged ids, most likely) and the oldest entries of
that table were dropped.

## The memory of the dedupe

The numbers of this section are the measured ones, not an estimate: the set of gateways of one packet, the
entry and the tables around it were measured in a Debug test host on .NET 10, arm64, at **~0.86 KB per
packet**, so the defaults of 200000 packets come to **~169 MB**. The figure is approximate: the order of
magnitude is what matters, and the object layout is the same in Release.

The raw values are 6.4 million gateway numbers (4 bytes each, about 26 MB); the rest is the overhead of
the objects.

To stay under a memory limit, lower one of the two caps:

- `dedupe_max_entries` bounds how many packets are remembered;
- `dedupe_max_gateways_per_packet` bounds how many gateways each of them keeps.

The product of the two is the real ceiling. For example, `dedupe_max_entries: 20000` with
`dedupe_max_gateways_per_packet: 8` is a product of 160000, 40 times smaller than the 6400000 of the
defaults.

## Sizing the broker for 2000-3000 nodes

The defaults are meant for a mesh of that size. The arithmetic:

- **Connections.** The nodes are behind their own connections, and the per-IP limits only matter when
  many of them share one address (a CGNAT, a VPN, a tunnel). When they do, the default
  `max_connections_per_ip` of 16 is too small and `connect_rate_per_ip_per_minute` of 30 too small as well:
  raise them, or set them to 0 and rely on the [auth bans](auth-bans.md) for the addresses that guess.
- **The dedupe.** The window of 120 seconds holds the packets of the last two minutes. A node that sends
  one packet every ten minutes puts 0.2 packets in that window, so a mesh of 2500 nodes puts about 500
  packets in it: a few hundred kilobytes, not the 169 MB of the worst case. Even the worst case the
  per-node rate allows (30 packets a minute from every node of the mesh) is 150000 packets in the window,
  which is under the `dedupe_max_entries` cap of 200000 but close to it.
- **The per-node rate.** 30 packets per minute is far above what a node sends, and a packet is charged
  once no matter how many gateways relayed it.
- **The per-client rate.** 120 publishes per minute with a burst of 60 is far above the traffic of one
  node, and the budget dies with the session.
- **The password queue.** The whole fleet shares the public `meshdev` credentials, so all the nodes that
  reconnect together share one PBKDF2 computation: the reconnect storm after a broker restart is one
  check, not one check per node. The per-user budget of 4 pending checks is therefore not a problem for
  the honest fleet, and it is what keeps the guesses of an attacker out of the way.

## Residual risks

- **A client can restart its per-client budget by reconnecting.** The publish budget belongs to the
  session, so a client that reconnects gets a full one again. The per-IP connect rate is what bounds it:
  with the defaults (30 connections per minute per address and a burst of 60 publishes), one address can
  spend about **30 x 60 = 1800 publishes per minute**. Lower `connect_rate_per_ip_per_minute` or lower
  `publish_burst_per_client` if that is too much.
- **With public credentials, a forged `from` can use up a real node's budget.** `meshdev`/`large4cats` are
  public, so anyone can put any `from` in an envelope header and spend that node's per-node packet budget.
  The per-client and per-IP limits bound how much of that an attacker can do at once, but they cannot tell
  a forged `from` from a real one.
- **Clients behind one address share the limits.** A CGNAT, a VPN or a tunnel puts many nodes behind one
  IP address: they share the connection cap and the connect rate, and the fleet may be cut. Tune those
  values (or set them to `0`) for the networks the real nodes use.
- **Distributed floods are not covered here.** One address per flood is bounded (the per-IP limits above
  and the [auth bans](auth-bans.md) below); a flood from many addresses is not. That needs an upstream
  firewall (or a rate limit at the edge) in front of the broker.

## See also

- [Configuration](configuration.md#the-limits): the keys, their ranges and their defaults.
- [Auth bans](auth-bans.md): the bans and the table of failed logins.
- [Logging](logging.md): the periodic summary with the counts and the evictions.
