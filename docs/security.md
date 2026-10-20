# Security

How the broker authenticates a client, what it lets a client subscribe and publish, and the two limits
that protect the listener itself.

[Back to the README](../README.md)

## Authentication

A client sends a username and a password in CONNECT. The broker compares the password with the hash
configured for that user, and never keeps the password: only the hash is in the config file, and the
password is not written to the log.

### The hashes

Passwords are stored as PBKDF2-HMAC-SHA256, written as
`pbkdf2-sha256$<iterations>$<salt>$<hash>`:

- **600 000 iterations** by default (the OWASP Password Storage Cheat Sheet's work factor for
  PBKDF2-HMAC-SHA256; the broker accepts 100 000 to 10 000 000);
- a **16-byte random salt** per user, in base64;
- a **32-byte hash**, in base64;
- the comparison is **constant time** (`CryptographicOperations.FixedTimeEquals`), so a wrong password
  cannot be found one byte at a time.

PBKDF2 rather than bcrypt: it is built into .NET (no extra crypto dependency to vet and keep patched), it
is FIPS-approved, and unlike bcrypt it does not truncate long passwords at 72 bytes.

The plain password is never accepted as a `password_hash`: the config validator only accepts the encoded
form, and the error message never echoes the value.

### The success cache

A password that verified once is remembered, so thousands of nodes that reconnect with the public
`meshdev` credentials do not each pay for a PBKDF2 computation:

- the cache holds the **SHA-256 digest of the password**, one entry per configured user, so its size is
  bounded by the config file and not by the number of clients;
- a later login with the same password is a constant-time digest comparison;
- a wrong password, and every login with an unknown username, always pay the full PBKDF2 cost.

### The password queue

PBKDF2 is deliberately slow, so the checks run in two bounded schedulers instead of one:

- **two lanes**: the configured usernames have one lane with several workers, the unknown usernames have
  their own lane with a single worker. A flood of made-up usernames can therefore never delay a
  configured user. The price is at most one more core busy with PBKDF2 while both lanes are saturated.
- **one check per (username, password)**: a cold reconnect storm of `meshdev` nodes pays PBKDF2 once, and
  all of them share the result. The success cache is checked again when a check starts.
- **round-robin between the usernames**: the checks are grouped by username and the groups are served in
  turn, so the wrong passwords of the public `meshdev` user delay the cold login of another user by at
  most one check, however many guesses arrive and however many times each guess is sent.
- **a budget per username**: one configured username may have at most `limits.auth_max_pending_per_user`
  distinct checks pending (4 by default). The logins over the budget are answered "server busy" at once.
- **a budget per lane**: a lane holds at most `limits.auth_max_pending` distinct checks (64 by default).
  A check that has not started within `limits.auth_queue_timeout_seconds` is answered "server busy"
  without running PBKDF2 at all.
- **the most awaited check runs first**: inside one username, the check with the most logins waiting on it
  goes first, so the real `meshdev` password jumps ahead of an attacker's guesses.

What the queue cannot do is tell a lone cold `meshdev` login from a guess before hashing it: while
`meshdev`'s own checks are all taken by guesses, that login is told "server busy" and retries. Limiting
such a flood is a per-IP job, and that is what the per-IP connect rate is for.

A login that is answered "server busy" gets the MQTT 5 reason code `Server busy` (3.1.1 return code 3,
"server unavailable"). It is **not** a password failure: it does not count towards the ban of the address
(see [Auth bans](auth-bans.md#what-counts-as-a-failure)).

## The ACLs

Both ACLs are lists of MQTT topic filters, per user. **An empty or missing list denies everything**: no
filter means no access, not "everything".

The ACLs are evaluated against the user that **created the session**, bound at connect time. A session
that is reused (`CleanSession=false`) keeps its owner, and a session with no owner at all publishes and
subscribes nothing.

### Subscribe

A subscription is granted only if **every** topic the requested filter can match is also covered by one
of the `subscribe_allow` filters of the owner. This is subset logic, not prefix matching:

| `subscribe_allow` | A filter that is granted | A filter that is refused |
|---|---|---|
| `msh/EU_868/2/e/#` | `msh/EU_868/2/e/#`, `msh/EU_868/2/e/Test/#`, `msh/EU_868/2/e/+`, `msh/EU_868/2/e` | `msh/#`, `msh/+/2/e/#`, `msh/EU_868/#`, `msh/EU_868/2/x/#` |
| `msh/EU_868/2/map/` | `msh/EU_868/2/map/` | `msh/EU_868/2/map/#`, `msh/EU_868/2/map` |

Two more rules of the MQTT specification are honoured:

- a filter whose first level is a wildcard never matches a `$` topic, so `#` and `+` never grant
  `$SYS/#`;
- the topics are **case-sensitive**.

A refused subscription answers with the MQTT 5 reason code `Not authorized` (135), and with `0x80` on
MQTT 3.1.1. The client stays connected. A refused SUBSCRIBE is one Warning per packet, with the number of
refused filters and the first one, however many filters the packet carries.

### Publish

A PUBLISH is accepted only if its topic name matches at least one of the `publish_allow` filters of the
owner, with the standard MQTT matching: `+` is exactly one level, `#` is that level and everything below
it, and a filter that starts with a wildcard never matches a `$` topic.

- `msh/EU_868/2/e/#` also matches `msh/EU_868/2/e`, which the packet filter then drops, because a channel
  packet needs a channel and a gateway level;
- `msh/EU_868/2/map/` matches the map report topic exactly, trailing slash included.

A refused publish is dropped and counted under `not in publish_allow` (see [Logging](logging.md#the-drop-reasons)).
It is logged per packet only at `debug`, so a node configured with the wrong root topic cannot flood the
log, and **the client is not disconnected**: the firmware would reconnect in a loop. On MQTT 5 a QoS 1
or QoS 2 publish is answered with the reason code `Not authorized` (135), or `Topic name invalid` (144)
when the topic name carries a wildcard; the acknowledgements of MQTT 3.1.1 carry no reason code at all.

A topic name that contains `+` or `#` is a protocol error, because wildcards are for filters only.
MQTTnet 5.2 does not reject it on the server side, so the broker drops it as `invalid topic name`.

The root topic of the Spanish mesh is `msh/EU_868`, the root the community guide tells every node to set
(`meshtastic-es-community.github.io`, `docs/mapas.md`). The example config allows `meshdev` exactly
`msh/EU_868/2/e/#` and `msh/EU_868/2/map/`.

## Client-id ownership

A client id belongs to the user that claimed it:

- a CONNECT with an id that is **not** claimed is claimed by the user that authenticates with it;
- a CONNECT with an id that is **already claimed by the same user** takes over the old session, which is
  what a node that reconnects does;
- a CONNECT with an id that is **claimed by another user** is refused with `ClientIdentifierNotValid`
  (MQTT 3.1.1 return code 2), and the session of the owner stays connected;
- the id is free again once that session is gone. A claim whose session disappeared is released by the
  broker, and a sweep removes the claims that were never turned into a session, so no id stays locked for
  good.

On MQTT 5 a CONNECT with an empty client id is accepted and the broker assigns one (`auto-` followed by
the 8 random bytes in hex), so a client that has no id still gets the right answer when its password is
wrong.

## The packet-size cap

Before anything else, every packet's declared length is checked against `limits.max_packet_size` while
its fixed header is still being read. A larger one closes the connection **before the broker allocates
it**, and that includes the clients that have not authenticated yet.

The check lives in the broker's own TCP listener, on the raw bytes, and not in a hook, because MQTTnet
5.2 reads the fixed header and then allocates `new byte[RemainingLength]` (up to 256 MB) before the body
arrives and before any hook runs: a few unauthenticated sockets sending `10 FF FF FF 7F` would exhaust
the memory. The broker replaces MQTTnet's stock TCP adapter with the same plumbing plus a channel
decorator that watches the byte stream and ends the connection as soon as a declared length exceeds the
limit. MQTTnet has no server-side size option, so there was nowhere else to put it.

A connection closed by the cap is one Warning:

```
Connection closed: packet length 70000 exceeds limits.max_packet_size 4096 from "203.0.113.7"
```

The address is in quotes because Serilog renders a string property as a quoted string.

The default of 4096 bytes is far above what a node sends: the largest thing a node uplinks is a
`ServiceEnvelope` around a `MeshPacket` whose encrypted part is at most 256 bytes, plus the channel and
gateway ids, and the firmware's own MQTT client buffer is 1024 bytes (`src/mqtt/MQTT.cpp`,
`setBufferSize(1024, 1024)`). 4096 leaves room for long topics and MQTT 5 properties.

## Retain is always cleared

The firmware never publishes a retained message. The broker clears the `retain` flag of every message it
accepts, so a public publisher cannot fill the retained-message store with one entry per topic it
invents, and nothing the broker forwards is ever stored as retained.

## Password hashes

Generate a hash (it reads one line from stdin and prints the hash):

```bash
docker run --rm -i meshtastic-mqtt hash-password
# or interactively, with the password hidden:
docker run --rm -it meshtastic-mqtt hash-password
```

Without Docker: `dotnet run --project src/Meshtastic.Mqtt -- hash-password`.

The firmware-default `meshdev` / `large4cats` credentials are public by design; the hash in
`config.example.yaml` is for that password.

## See also

- [Packet filtering](packet-filtering.md): what the broker accepts once the ACL has let a publish through.
- [Auth bans](auth-bans.md): what the broker does with the addresses that keep guessing.
- [Configuration](configuration.md): the keys of the config file.
