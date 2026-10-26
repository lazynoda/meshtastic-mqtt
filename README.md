# Meshtastic MQTT broker

[![License](https://img.shields.io/github/license/lazynoda/meshtastic-mqtt)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![MQTTnet](https://img.shields.io/badge/MQTTnet-5-blue)](https://github.com/dotnet/MQTTnet)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-lazynoda-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/lazynoda)

An MQTT broker for a Meshtastic mesh, built on [MQTTnet](https://github.com/dotnet/MQTTnet) (C# / .NET 10).
It is not a generic broker with a few rules on top: it parses every `ServiceEnvelope` it receives,
decrypts it with the key of its channel, and forwards only what a real node would have sent. The mesh it
serves is uplink only in practice: the public `meshdev` user of the example config may publish and may
not subscribe, so the nodes that use the public credentials get nothing back.

Fork of the abandoned [meshtastic/mqtt](https://github.com/meshtastic/mqtt) boilerplate, hardened to be
exposed on the internet. Upstream shipped its certificate, its key and its password in the repository,
and the broker forwarded whatever a client published. This fork replaces the hardcoded secrets with a
config file, and adds real authentication, per-user ACLs, Meshtastic packet filtering and the abuse
limits that a public port 1883 listener needs. The secrets of upstream are gone from the code, but they
remain in the git history: they were always public, they are expired, and they must never be reused.

## Features

### Security

- [Authentication](docs/security.md#authentication) with PBKDF2-SHA256 password hashes, compared in constant time.
- [Subscribe and publish ACLs](docs/security.md#the-acls) per user: an empty list means no access at all.
- [No downlink by default](docs/security.md#the-acls): a user only gets the filters of its own `subscribe_allow`, and the public `meshdev` user gets none.
- [Client-id ownership](docs/security.md#client-id-ownership): an id held by another user's session is refused.
- [A packet-size cap](docs/security.md#the-packet-size-cap) in the TCP listener, before the packet is allocated.
- [The retain flag is always cleared](docs/security.md#retain-is-always-cleared), so nothing enters the retained-message store.

### Packet filtering

- [Channel keys](docs/packet-filtering.md#channel-keys) by the exact channel name, like the firmware.
- [The packets the broker cannot open are forwarded unchanged](docs/packet-filtering.md#the-packets-the-broker-cannot-open) per user, on by default, and the PKI packets are dropped by default.
- [Packet filters](docs/filters.md) per user, per gateway and per node, in a file that is reloaded without a restart.
- [Empty, malformed and plaintext packets are dropped](docs/packet-filtering.md#publish-filtering).
- [The `/json/` and the malformed topics are dropped](docs/packet-filtering.md#topics-the-broker-drops).
- [Map reports are validated](docs/packet-filtering.md#map-reports) before they are forwarded.
- [The gateway of the topic must match the envelope](docs/packet-filtering.md#gateway-binding).

### Abuse limits

- [A cap and a rate per IP address](docs/limits-and-dedupe.md#per-ip-address), applied before a byte is read.
- [A payload cap and a publish rate per client](docs/limits-and-dedupe.md#per-client).
- [A packet rate per node and a cross-gateway dedupe](docs/limits-and-dedupe.md#per-node-and-the-dedupe).
- [In-broker bans](docs/auth-bans.md) for the addresses that fail to log in too often, with no fail2ban and no nftables.
- [Every table is bounded](docs/limits-and-dedupe.md#the-bounded-tables), so the memory cannot grow without bound.
  The regular expressions of the packet filters run on [Google RE2](docs/filters.md#the-regular-expressions),
  with a fixed memory budget per pattern.

### Operations

- [One YAML config file](docs/configuration.md), no secret in the image.
- [A multi-arch Docker image](docs/operations.md#running-with-docker) that runs as a non-root user.
- [Logs without payloads](docs/logging.md), a startup line with every limit and a 60 s summary of the refusals.
- [No message content in the logs](docs/logging.md#what-is-logged-at-each-level), ever: a line carries the topic, the client id, the `from`, the packet id and the portnum.
- [Plain MQTT on port 1883](docs/operations.md#hardening-a-public-1883-listener), and no TLS in this version.

## What happens to a connection

- **Connect**: the username and the password are checked against `users`. A wrong password is refused
  with `BadUserNameOrPassword` and counted for the [ban](docs/auth-bans.md) of the address. A client id
  that belongs to a session of another user is refused. A full password queue is refused with
  `ServerBusy`, and the client retries.
- **Subscribe**: the filter is granted only if every topic it can match is covered by the
  `subscribe_allow` of the user that created the session. An empty list denies everything.
- **Publish**: the publish ACL, then the limits, then the packet filter, then the [filters](docs/filters.md) of the rules file. A refused publish is dropped,
  never forwarded, and the client stays connected; a packet the broker cannot open is forwarded unchanged,
  unless the user drops those packets (see [Packet filtering](docs/packet-filtering.md#the-packets-the-broker-cannot-open)).

The rules of the three hooks are in [Architecture](docs/architecture.md#what-it-does-with-each-connection).

## Quick start

Build the image first (the commands below use it):

```bash
docker build -t meshtastic-mqtt .
```

Hash the password of a user (the command reads it from stdin and prints the hash for the config):

```bash
docker run --rm -i meshtastic-mqtt hash-password
```

Write the config. Everything has a default except the users, so this is a working configuration:

```yaml
users:
  - username: meshdev
    password_hash: "pbkdf2-sha256$600000$iqngz3pWU8HFZn8xIv8/IQ==$ZhdEPkHgqnG2zbHe26j6U598nTyFTA8J/Kzm7WCxDuA="
    publish_allow:
      - "msh/EU_868/2/e/#"
      - "msh/EU_868/2/map/"
```

The hash above is the one of the public `large4cats` password, the one the firmware uses by default. A
node that uplinks to this broker needs the username `meshdev`, the password `large4cats`, the root topic
`msh/EU_868` and TLS off: see [Node setup](docs/node-setup.md).

Run it, with the config mounted read-only:

```bash
cp config.example.yaml config.yaml   # or write the snippet above
docker run -d --name meshtastic-mqtt \
  -p 1883:1883 \
  -v "$PWD/config.yaml:/config/config.yaml:ro" \
  --read-only \
  --memory 512m \
  --log-opt max-size=10m --log-opt max-file=3 \
  meshtastic-mqtt
docker logs -f meshtastic-mqtt
```

The startup line says what the broker is running with, and the 60 s summary says what it refused.

## Documentation

| Page | What is in it |
|---|---|
| [Configuration](docs/configuration.md) | Every key of the config file: its type, its default, its range and when to change it. |
| [Security](docs/security.md) | The authentication, the subscribe and publish ACLs, the client-id ownership, the packet-size cap and the password hashes. |
| [Packet filtering](docs/packet-filtering.md) | The topics the broker accepts, the channel keys, the map reports, the gateway binding and the order of the checks. |
| [Filters](docs/filters.md) | The rules that drop the packets of a user, a gateway or a node, and how the file is reloaded. |
| [Limits and dedupe](docs/limits-and-dedupe.md) | Every limit, the token buckets, the cross-gateway dedupe, the bounded tables and the residual risks. |
| [Auth bans](docs/auth-bans.md) | What counts as a failed login, the window, the ban, the exemptions and the residual risks. |
| [Logging](docs/logging.md) | What is written at each level, the startup line, the 60 s summary and every drop reason. |
| [Operations](docs/operations.md) | Building, running, hashing a password, running the tests, upgrading and hardening. |
| [Node setup](docs/node-setup.md) | What the owner of a node has to set so that its packets reach the broker. |
| [Architecture](docs/architecture.md) | The path of a connection, the tables the broker keeps, the concurrency and the future ideas. |

## Not in this version

TLS. The fail2ban-style bans are in this version, inside the broker (see [Auth bans](docs/auth-bans.md)):
no system fail2ban, no nftables. The rate limits per IP, per client and per node, the cross-gateway
dedupe and the publish payload cap are in [Limits and dedupe](docs/limits-and-dedupe.md); the payload cap
acts in the publish hook, after the ACL, because the packet has already been read by then (the
`max_packet_size` check is the one that acts while the packet is being read).

There is no downlink for the public user either: the broker does support subscriptions, but the `meshdev`
user of `config.example.yaml` has no `subscribe_allow`, so a node that uses the public credentials gets
nothing back.

## License

GPL-3.0, see [LICENSE](LICENSE).
