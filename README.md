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
- **Packet filtering on publish**: drops empty, malformed, plaintext and undecryptable packets.
- **No message content in logs**, ever. Logs carry topic, client id, `from`, packet id and portnum.
- Plain MQTT on port 1883. No TLS in this version.

## What it does with each connection

| Hook | Rule |
|---|---|
| Connect | Username and password are checked against `users`. Unknown user or wrong password → `BadUserNameOrPassword` (MQTT 3.1.1 return code 4), logged with username and remote IP, never the password. A reconnect with an existing client id takes over the old session, but only for the **same user**: a client id held by a live or persisted session of another user is refused with `ClientIdentifierNotValid` (3.1.1 return code 2) and the session owner stays connected. The id is free again once that session is gone. If the password-check queue is full (see `limits`), the client gets `ServerBusy` (3.1.1 return code 3, "server unavailable") and retries. |
| Subscribe | The requested filter is granted only if **every** topic it can match is covered by the `subscribe_allow` filters of the user that **created the session** (bound at connect time, so a reused session never changes hands). Real MQTT wildcard semantics, not prefix matching. An empty or missing list denies everything. `#` and `+` never grant `$`-topics such as `$SYS/#`. Refusal → MQTT 5 reason `Not authorized` (135); on MQTT 3.1.1 → `0x80`. |
| Publish | See below. Accepted messages are re-published with `retain` cleared (firmware never retains), so nothing enters the retained-message store. |

Before any of this, every packet's declared length is checked against `limits.max_packet_size` while its
fixed header is still being read; a larger one closes the connection before the broker allocates it
(also for clients that have not authenticated yet).

### Publish filtering

A message is forwarded only if all of these hold:

1. The topic is `<root>/2/e/<channel>/<gateway>` (root may have several levels, e.g. `msh/ES`).
   `/2/json/`, `/2/map/` and anything else is dropped.
2. The payload is a valid `ServiceEnvelope` with a `packet`, `channel_id` and `gateway_id`.
3. `channel_id` equals the `<channel>` segment of the topic (exact match).
4. The packet has non-zero `from` and `id` and carries an `encrypted` payload of 1-256 bytes
   (plaintext `decoded` packets are dropped).
5. Channel packets: the key is looked up **by channel name** (`channels`, falling back to `default_psk`).
   The lookup is case-sensitive, like the firmware: the channel hash covers the exact name, so `Test` and
   `test` are different channels and a `test` channel not listed under `channels` uses `default_psk`.
   The packet is decrypted with AES-CTR exactly as the firmware does; it counts as decryptable when the
   result parses as `Data` with a portnum other than `UNKNOWN_APP` (the firmware's own test in
   `Router.cpp perhapsDecode()`). Keys are never tried one after another.
   Undecryptable packets are dropped when `drop_undecryptable: true` (default).
6. PKI direct messages: see below.

The firmware's channel hash (`MeshPacket.channel`) is also computed for the configured key. A mismatch
is logged at `debug` level only; it never causes a drop.

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
| `log_level` | `information` | `verbose`, `debug`, `information`, `warning`, `error`, `fatal`. `debug` also logs every accepted packet. |
| `drop_undecryptable` | `true` | Drop channel packets that do not decrypt with their channel's key. Must be `true` or `false` if present. |
| `drop_pki` | `true` | Drop PKI-encrypted DMs (see above). Must be `true` or `false` if present. |
| `default_psk` | `AQ==` | Base64 PSK for any channel not listed under `channels`. |
| `channels` | empty | Map of channel name → base64 PSK. Names are **case-sensitive** (exact match, like the firmware's channel hash). |
| `users[].username` | required | Case-sensitive. |
| `users[].password_hash` | required | `pbkdf2-sha256$<iterations>$<salt>$<hash>`, see below. |
| `users[].subscribe_allow` | empty | MQTT topic filters this user may subscribe within. Empty = no subscribe at all. |
| `limits.max_packet_size` | `4096` | Largest MQTT packet accepted, in bytes (Remaining Length). Checked before the packet is allocated; a larger one closes the connection. Range 512-1048576. |
| `limits.communication_timeout_seconds` | `10` | How long a new connection may take to send CONNECT, and a write may stall (MQTTnet's default is 100). |
| `limits.auth_queue_timeout_seconds` | `3` | How long a login may wait for a password-hashing slot before it is answered "server busy". |
| `limits.auth_max_pending` | `64` | Logins that may run or wait for password hashing at once (separately for configured users and for unknown usernames). Further logins get "server busy" without hashing. |

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
legitimate users waiting. Simultaneous logins with the same username and password (a fleet of `meshdev`
nodes reconnecting after a broker restart) share one PBKDF2 computation, and the check with the most logins
waiting on it runs first, so the real `meshdev` password jumps ahead of an attacker's one-off guesses.

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

Publish ACLs, rate limits per IP/client/node, duplicate suppression, fail2ban-style bans and TLS. See the
"Ideas" list below for where this is heading. A payload cap for publishes belongs in the packet-size check
above (it must act while the packet is read), not in the publish hook, which runs after allocation.

## Ideas for MQTT mesh moderation

- Rate-limiting a packet we've heard before
- Rate-limiting packets per node
- "Zero hopping" certain packets
- Blocking or rate-limiting certain portnums
- Fail2ban style connection moderation
- Banning from known bad actors list

## License

GPL-3.0, see [LICENSE](LICENSE).
