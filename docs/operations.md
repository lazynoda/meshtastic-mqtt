# Operations

Building, running, upgrading and hardening the broker.

[Back to the README](../README.md)

## Running with Docker

```bash
docker build -t meshtastic-mqtt .
cp config.example.yaml config.yaml   # edit it; config.yaml is git-ignored
mkdir -p filters                    # the rules file lives here (see "Blocking a node")
: > filters/filters.yaml            # an empty file means no rules
docker run -d --name meshtastic-mqtt \
  -p 1883:1883 \
  -v "$PWD/config.yaml:/config/config.yaml:ro" \
  -v "$PWD/filters:/etc/meshtastic-mqtt:ro" \
  --read-only \
  --memory 512m \
  --log-opt max-size=10m --log-opt max-file=3 \
  meshtastic-mqtt
docker logs -f meshtastic-mqtt
```

- The image runs as the non-root `app` user (uid 1654); the config only needs to be world-readable
  or readable by that uid.
- `--memory 512m` caps the container, and `--log-opt` caps the JSON log files Docker keeps on the host
  (3 x 10 MB). Keep both when exposing the broker to the internet.
- Logs go to stdout as compact JSON (Serilog CLEF), one event per line.
- Multi-arch: the official .NET base images are multi-platform, so a plain `docker build` works on
  amd64 and arm64 hosts; `docker buildx build --platform linux/amd64,linux/arm64 .` builds both.
- The rules file of the [packet filters](filters.md) is mounted **through its directory**, and the
  broker only reads it, so the read-only mount is fine. The rules are changed on the host (see
  [Blocking a node](#blocking-a-node-while-the-broker-runs)).
- The rules file starts **empty**, and an empty file means no rules: every packet that passes the
  other checks is forwarded. [`filters.example.yaml`](../filters.example.yaml) is an illustration of
  every feature of the rules file, **not a starting point**: copied as it is, it drops every text
  message and every packet the broker cannot open. Copy the rules you need, not the example.

The image needs one thing: a config file. There is no other secret in it, and nothing is baked into the
image.

## Where the config file lives

The broker takes the path of its config in two ways:

- as the **only argument**: `Meshtastic.Mqtt [config.yaml]`, which from the sources is
  `dotnet run --project src/Meshtastic.Mqtt -- /etc/meshtastic-mqtt/config.yaml`;
- in the **environment variable** `MESHTASTIC_MQTT_CONFIG`.

The Docker image runs `dotnet Meshtastic.Mqtt.dll` and sets `MESHTASTIC_MQTT_CONFIG=/config/config.yaml`,
so mounting the file at `/config/config.yaml` is enough. With no path and no variable the broker prints
its usage and exits with the code 2.

The file is read once, at startup. A change of the config needs a restart of the broker, and a restart
forgets the [auth bans](auth-bans.md#the-state-is-in-memory-only) and the counters of the rate tables.

An invalid file is refused with a message that lists every problem it found, and the broker exits with
the code 1 without listening:

```
Invalid config '/config/config.yaml':
- limits.max_payload_size: 4097 is not an integer between 64 and 4096
- users[meshdev].publish_allow: '#' must be a whole level and the last one: 'msh/#/e'
```

## Hashing a password

The config never holds a password, only a hash. The `hash-password` command reads a password from stdin
and prints the hash to put in the config file:

```bash
docker run --rm -i meshtastic-mqtt hash-password
# or interactively, with the password hidden:
docker run --rm -it meshtastic-mqtt hash-password
```

Without Docker: `dotnet run --project src/Meshtastic.Mqtt -- hash-password`.

The output is a single line, in the form the config expects:

```
pbkdf2-sha256$600000$<salt>$<hash>
```

The salt and the hash are base64. The firmware-default `meshdev` / `large4cats` credentials are public
by design; the hash in `config.example.yaml` is the one of that password, and it needs no hashing.

See [Password hashes](security.md#password-hashes) for the parameters.

## Blocking a node while the broker runs

The rules file of the [packet filters](filters.md) is the way to stop the packets of a node, of a
gateway or of a user without touching the config and without a restart. The file is checked every
`reload_check_seconds` seconds, and a `SIGHUP` reloads it at once.

**The file has to be mounted through its directory, not as a single file.** A bind mount of one file
keeps the inode it had when the mount was made, so a file that is replaced atomically on the host is
not seen by the container: the broker would keep reading the old file. Mount the directory instead
(the broker only reads the file, so a read-only mount is fine) and point the config at it:

```yaml
filters:
  file: /etc/meshtastic-mqtt/filters.yaml
  reload_check_seconds: 5
```

```bash
docker run -d --name meshtastic-mqtt \
  -p 1883:1883 \
  -v "$PWD/config.yaml:/config/config.yaml:ro" \
  -v "$PWD/filters:/etc/meshtastic-mqtt:ro" \
  --read-only \
  meshtastic-mqtt
```

The rule that blocks a node goes in the `nodes:` section of the file:

```yaml
nodes:
  "!deadbeef":
    - name: block-deadbeef
      topics:
        deny: ["#"]
```

It drops **every** packet of the node `!deadbeef`, whatever the channel and whatever the gateway
uploads it: `#` matches every topic. The rule does not need an opened packet, so it also drops the
packets of the channels whose key the broker does not have (the ones it would otherwise forward
unchanged).

The file is edited **on the host**, and it is replaced **atomically**: the broker reads the whole file
when it changes, so a file that is written in place could be read half-written. Edit a copy next to it
and move the copy over the old one (a rename is atomic):

```bash
# the rules of the file, as the broker sees them
docker exec meshtastic-mqtt cat /etc/meshtastic-mqtt/filters.yaml

# a copy of the file, with the new rule added to its nodes: section
cp "$PWD/filters/filters.yaml" "$PWD/filters/filters.yaml.new"
vi "$PWD/filters/filters.yaml.new"

# the new file in place, in one step
mv "$PWD/filters/filters.yaml.new" "$PWD/filters/filters.yaml"

# reload the rules now, without waiting for the next check
docker kill --signal=HUP meshtastic-mqtt
```

Without the `SIGHUP`, the new rules are in force at the next check, `reload_check_seconds` seconds
later (5 by default). The packets the node sends after the reload are dropped, with the reason
`filtered: block-deadbeef` in the 60 s summary.

A file that is not valid does not replace the rules that are in force: the broker keeps them and
writes one Warning with every problem and its line. Fix the file and reload again.

To block an **address** instead of a node, use the [auth bans](auth-bans.md). To refuse a **user** at
the door, use its `publish_allow`.

## Running the tests

```bash
docker build --target test .                    # whole suite in the SDK image
# or, with the SDK installed:
dotnet test --solution Meshtastic.Mqtt.sln
```

Test fixtures (`tests/Meshtastic.Mqtt.Tests/Fixtures/*.bin`) are real-format envelopes produced by
`make_fixtures.py` with hand-written protobuf and OpenSSL AES-CTR, independently of the broker code.
`longfast_real.bin` wraps a packet captured on the public mesh.

The suite covers the config, the authentication, the ACLs, the packet filter, the limits, the dedupe, the
bans and the logs. It also checks that the configuration reference of `docs/` does not drift from the
code: a key that is added to the config classes and not to `docs/configuration.md` fails the build.

## Upgrading

The config file is the only thing that has to change between the versions of this broker, and there have
been **two breaking changes** so far:

- **The publish ACL.** A config written before the publish ACL existed has no `publish_allow` for its
  users, and an empty or missing list means **no publish at all**. Such a config starts, the nodes
  connect, and nothing is forwarded: the broker counts every publish as `not in publish_allow` and the
  60 s summary says so. Give every user that must publish an explicit list, as in
  [`config.example.yaml`](../config.example.yaml).
- **The removed `drop_undecryptable`.** The global flag is gone: it moved to `users[].forward_unopened`,
  with the **inverted** meaning. A config that still has `drop_undecryptable` does not start, and the
  error says so:

  ```
  Invalid config '/config/config.yaml':
  drop_undecryptable: removed; it moved to users[].forward_unopened, with the inverted meaning: forward_unopened: true (the default) forwards the packets the broker cannot open, and false drops them
  ```

  Delete the key and decide per user: `forward_unopened: true` (the default) forwards the packets the
  broker cannot open, unchanged, and `forward_unopened: false` drops them, as `drop_undecryptable: true`
  did. The key belongs to a user, not to the broker: two users of the same broker can have two different
  policies.

Every other key has a default, so a config that does not mention it keeps working: the limits, the bans
and the packet filter are on with their defaults, and a config written for an older version of the
broker does not have to be rewritten.

The upgrade itself:

1. change the config (the [configuration reference](configuration.md) says what every key does);
2. restart the broker;
3. read the startup line: it shows every limit the broker is running with, so a mistake is visible at
   once.

Nothing has to be migrated: the state of the broker is in memory, and a restart forgets the bans and the
counters.

## Hardening a public 1883 listener

The broker is built to be exposed to the internet, but a few things are still the operator's job:

- **The credentials travel in clear.** This version has no TLS, so the password of the users is sent in
  the clear on port 1883. The public `meshdev` credentials are public anyway, but a user of your own
  deserves a private path: put the broker behind a VPN, or behind a reverse proxy that terminates TLS, or
  keep it on a network the nodes of the mesh can reach without the internet. With a TLS-terminating proxy
  in front of it, the broker itself still speaks plain MQTT: the nodes need TLS **on** and the port of
  the proxy (the firmware uses 8883 with TLS when the address has no port), and the proxy forwards to the
  broker on 1883.
- **Keep the firewall in front of it.** The broker bounds one address at a time (the per-IP limits and the
  bans), but a flood from many addresses is not covered. A rate limit at the edge is the answer.
- **Keep the container small.** `--memory` and `--log-opt` as in the run command above. Every table of the
  broker grows with the number of distinct clients, nodes and addresses it sees, but all of them are
  bounded (see [The bounded tables](limits-and-dedupe.md#the-bounded-tables)), and the dedupe is by far
  the largest one (see [The memory of the dedupe](limits-and-dedupe.md#the-memory-of-the-dedupe)).
- **Keep the container read-only** (`--read-only`): the broker writes nothing to its filesystem.
- **Mount the config read-only** and keep it out of git: it holds the password hashes.
- **Watch the 60 s summary.** It counts the refusals per reason, and the reasons that matter are
  `banned IP`, `not in publish_allow` and the evictions (see [Logging](logging.md#the-drop-reasons)).
- **Do not give the broker any other port.** It listens on 1883 and on nothing else.

## See also

- [Configuration](configuration.md): the keys of the config file.
- [Filters](filters.md): the rules that drop the packets of a user, a gateway or a node.
- [Logging](logging.md): what the broker writes and how to read it.
- [Node setup](node-setup.md): what the nodes of the mesh have to be told.
