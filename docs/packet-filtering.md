# Packet filtering

What the broker accepts on the wire, what it drops, and in which order it checks.

[Back to the README](../README.md)

A message that passed the publish ACL (see [The ACLs](security.md#the-acls)) is forwarded only if it is
either a map report or a channel packet, and only if every check below holds. The broker is not a generic
broker with a few rules: it parses every `ServiceEnvelope`, decrypts it with the key of its channel, and
only lets through what a real node would have sent.

## Publish filtering

A channel packet is forwarded only if all of these hold:

1. The topic is `<root>/2/e/<channel>/<gateway>` (the root may have several levels, for example
   `msh/EU_868`). `/2/json/` and anything else is dropped, and so is any `/2/map...` topic other than the
   exact map-report topic.
2. The payload is a valid `ServiceEnvelope` with a `packet`, a `channel_id` and a `gateway_id`.
3. The `channel_id` equals the `<channel>` level of the topic (exact match).
4. The `<gateway>` level of the topic equals the `gateway_id` of the envelope, and it is `!` followed by
   8 lowercase hex digits (the firmware's `NodeDB::getNodeId()`, the same string in the topic and in the
   envelope).
5. The packet has a non-zero `from` and a non-zero `id`, and it carries an `encrypted` payload of 1 to 256
   bytes (a plaintext `decoded` packet is dropped).
6. The key of the channel is looked up **by channel name** (`channels`, falling back to `default_psk`) and
   the packet decrypts with it, **or the user that published it forwards the packets the broker cannot
   open**. The lookup is case-sensitive, like the firmware: the channel hash covers the exact name, so
   `Test` and `test` are different channels, and a `test` channel that is not listed under `channels` uses
   `default_psk`. A packet that does not decrypt is forwarded unchanged, unless that user has
   `forward_unopened: false`, which drops it with the reason
   `undecryptable with the key configured for this channel` (see
   [The packets the broker cannot open](#the-packets-the-broker-cannot-open)).
7. The packet is not a PKI direct message, unless `drop_pki` is `false` (see below).

A map report is forwarded only if it passes its own checks (see [Map reports](#map-reports)).

Each of the sections below explains one of these checks.

## The topics the broker accepts

There are exactly two shapes of topic the broker accepts:

| Topic | What it carries |
|---|---|
| `<root>/2/e/<channel>/<gateway>` | A channel packet, in a `ServiceEnvelope`. The root may have several levels, for example `msh/EU_868`. |
| `<root>/2/map/` | A map report. The trailing slash is part of the topic: the firmware builds it as `root + "/2/map/"`, so the last level is empty and there is no channel or gateway level. |

The `<gateway>` level is the node id of the gateway that sent the packet: `!` followed by 8 lowercase hex
digits, which is what the firmware's `NodeDB::getNodeId()` writes. The same string is in the topic and in
the `gateway_id` of the envelope.

The topics the firmware uses are:

- `<root>/2/e/<channel>/<gateway>` for the channel packets;
- `<root>/2/e/PKI/<gateway>` for the PKI direct messages;
- `<root>/2/map/` for the map reports.

## Channel keys

The key of a channel packet is looked up **by the channel name**, in the `channels` section of the config,
and falls back to `default_psk` when the name is not listed. The lookup is **case-sensitive**, like the
firmware: the channel hash covers the exact name, so `Test` and `test` are two different channels, and a
`test` that is not listed under `channels` uses `default_psk`.

The packet is then decrypted with AES-CTR exactly as the firmware does (the nonce is the packet id and the
sender's node number). It counts as decryptable when the result parses as a `Data` with a portnum other
than `UNKNOWN_APP`, which is the firmware's own test (`Router.cpp`, `perhapsDecode()`). **The keys are
never tried one after another**: the channel of the topic names the one key that is used.

The firmware also computes a channel hash for the configured key and sends it in clear in
`MeshPacket.channel`. The broker computes it too, and a mismatch is logged at `debug` level only: it never
causes a drop.

### The PSKs

PSKs use the same encoding as the firmware and the apps (base64). The expansion follows
`Channels::getKey()` in the firmware:

- 1 byte `0` (`AA==`): no encryption. An empty value is a config error (the firmware reads an empty key on
  a secondary channel as "use the primary channel's key", so it is ambiguous); write `AA==`.
- 1 byte `N >= 1`: the default key with its last byte increased by `N-1` (`AQ==` is the default key,
  `Ag==` is the default key plus one, `VA==` is the byte 84).
- 2-15 bytes are zero-padded to 16 (AES-128), 17-31 to 32 (AES-256); 16 and 32 are used as is.

Base64 is case sensitive: `VA==` (84) and `Va==` (85) are different keys.

The channels of the Spanish mesh (source: meshtastic-es-community.github.io):

| Channel | Key |
|---|---|
| `SFNarrow`, `Iberia`, provincial channels (`Madrid`, `Barcelona`, `Zaragoza`, ...) | `AQ==` (default, no entry needed) |
| `Test`, `Bots` | `Ag==` |
| `Valencia` | `VA==` |

## The packets the broker cannot open

A channel packet whose key the broker does not have is **forwarded unchanged**: the bytes the client
published reach the subscribers as they are, and the broker does not read them. It is a private channel,
a wrong key or garbage, and it happens when a channel of the mesh is not listed under `channels` (the
broker then only has `default_psk`) or when the key of the channel does not open the packet.

What happens to those packets is decided **per user**, with `users[].forward_unopened`:

| `forward_unopened` | What the broker does with a packet it cannot open |
|---|---|
| `true` (the default) | It forwards the packet unchanged, and it writes one `debug` line per packet. |
| `false` | It drops the packet, with the reason `undecryptable with the key configured for this channel`. |

The user is the one that **owns the session**, the same identity the publish ACL uses, never the
`username` of the PUBLISH.

A forwarded packet is not a refusal: **every other check still applies to it**, in the same order as to
any other packet (the publish ACL, the topic layout and its root, the `/json/` block, the channel of the
topic, the gateway binding, the size caps, the rates and the dedupe). Only the verdict of the decryption
changes. The packet is not counted in the 60 s summary, and the `debug` line says the channel, the
`from`, the id of the packet and why it was not opened (no key for the channel, or a key that does not
open it).

With `forward_unopened: false` the packet is dropped with the reason `undecryptable with the key
configured for this channel`, and the drop is counted in the 60 s summary like any other.

## drop_pki

A packet that is PKI-encrypted (Curve25519 and AES-CCM, end to end between two nodes) is uplinked
**still encrypted**, with `channel_id = "PKI"` on the topic `<root>/2/e/PKI/<gateway>`, and only when the
gateway has "encryption enabled" on its MQTT module. The gateways subscribe to `<root>/2/e/PKI/+` and
accept those packets for downlink even though they cannot decrypt them either.

The broker can never decrypt them, so they have their own flag instead of falling under
`forward_unopened`:

- `drop_pki: true` (the default) drops them. The broker is uplink-only, so nothing would consume them;
  dropping them means they are not exposed to every future downlink subscriber, and their metadata (who
  talks to whom) is not republished.
- `drop_pki: false` passes them through opaquely, but only if they look like PKI packets: unicast, channel
  hash 0, and longer than the 12-byte CCM tag and nonce. A packet that fails those tests is dropped as
  `malformed PKI packet`.

Turn it on if downlink gateways should deliver the direct messages across MQTT.

## Topics the broker drops

Everything that is not one of the two accepted shapes is dropped:

- **`/2/json/`**: the JSON output of the firmware is not a `ServiceEnvelope`, so it is dropped. With the
  ACL of `config.example.yaml` (`publish_allow: msh/EU_868/2/e/#` and `msh/EU_868/2/map/`) a JSON topic
  does not even reach the packet filter: the publish ACL runs first, so it is counted as
  `not in publish_allow`. A user whose `publish_allow` covers the JSON topic gets the reason
  `unsupported topic (expected <root>/2/e/<channel>/<gateway>)`. Leave the JSON output of the node off: it
  only adds traffic the broker drops (see [Node setup](node-setup.md#what-not-to-do)).
- **any other topic** under a root: the same reason.
- **a malformed map topic**: `<root>/2/map` without the trailing slash, or `<root>/2/map/<anything>`, is
  dropped with `unsupported map topic (expected <root>/2/map/)`. The firmware never publishes there.
- **a topic that is not a topic name**: a topic name with a `+` or a `#` is a protocol error and is
  dropped as `invalid topic name` before the ACL is even looked at.
- **an empty payload**: dropped as `empty payload`.
- **a payload that is not a protobuf**: dropped as `malformed protobuf`.

## Gateway binding

On `<root>/2/e/<channel>/<gateway>` the gateway level of the topic must be the `gateway_id` of the
envelope, and it must be `!` followed by 8 lowercase hex digits (`NodeDB::getNodeId()`, the same string
the firmware puts in both places, `src/mqtt/MQTT.cpp`, `onSend()`). A topic whose gateway is something
else is dropped with the reason `gateway in topic does not match gateway_id`.

That string is checked exactly: another id, upper case hex, a missing `!` or a zero-width character glued
to it are all refused. What the check guarantees is that the topic and the envelope agree and that the id
has the format the firmware writes: a topic whose gateway level is not in that format, or does not equal
the `gateway_id` of the envelope, is refused.

It does **not** authenticate the gateway or the sender: both the gateway level of the topic and the
`gateway_id` of the envelope are written by the publisher, so a client with the public credentials can put
any gateway id in both places. The `from` of the packet is not bound to the gateway either (see the
residual risk "a forged `from`" in
[Limits and dedupe](limits-and-dedupe.md#residual-risks)).

## Map reports

Nodes with "map reporting" enabled publish a `MapReport` (name, hardware, firmware, region, preset,
approximate position) for the map dashboards. Checked in the firmware (`src/mqtt/MQTT.cpp`,
`MQTT::perhapsReportToMap()`), the topic is exactly `<root>/2/map/`, and the payload is a `ServiceEnvelope`
whose packet is **decoded** (plaintext, never encrypted), with `portnum = MAP_REPORT_APP` (73), the
`MapReport` protobuf as its payload, `from` = the reporting node, `channel_id` = its primary channel and
`gateway_id` = `!` + 8 lowercase hex digits of its node number. The firmware leaves the packet id at 0.

A message on `<root>/2/map/` is forwarded only if all of these hold, each failure being its own drop
reason:

1. The payload parses as a `ServiceEnvelope` with a packet whose `from` is not 0
   (`map report: malformed protobuf`, `map report: envelope without packet`, `map report: packet without from`).
2. The packet is decoded, not encrypted (`map report: packet is not decoded`).
3. Its portnum is `MAP_REPORT_APP` (`map report: portnum is not MAP_REPORT_APP`).
4. Its payload is non-empty and parses as a `MapReport`
   (`map report: payload is not a MapReport`).
5. `gateway_id` equals `!%08x` of `from`, so a node only reports itself
   (`map report: gateway_id is not the sender (from)`).

No channel key is involved (the topic names no channel and the packet is plaintext), and there is no
separate flag: whoever has the map topic in `publish_allow` may send map reports.

## The order of the checks in the publish hook

The order is fixed, and every refusal is counted under its own reason, logged per packet at `debug` only,
and never disconnects the client:

1. **The publish ACL**: an invalid topic name (`invalid topic name`), a publish without a session owner
   (`publish without a session owner`), and a topic that is not in `publish_allow`
   (`not in publish_allow`).
2. **The payload cap**: `payload larger than max_payload_size`.
3. **The per-client publish rate**: `publish rate exceeded for the client`.
4. **The packet filter**: everything of this page.
5. **The cross-gateway dedupe and the per-node packet rate**: `duplicate from the same gateway`,
   `too many gateways for one packet` and `packet rate exceeded for the node`.
6. **The retain flag is cleared** and the message is forwarded.

On MQTT 5 a refused publish is answered with reason code `Quota exceeded` (151) for the payload cap, the
per-client publish rate and the per-node packet rate, with `Not authorized` (135) for the publish ACL, and
with **no** reason code for the packet filter and the dedupe (those copies are dropped, but the client is
not told why); MQTT 3.1.1 acknowledgements carry no reason code at all.

Inside the packet filter, the checks of a channel packet are in this order:

1. The payload is not empty (`empty payload`).
2. The topic is the map report topic, and then the checks of a map report apply.
3. The topic is `<root>/2/e/<channel>/<gateway>` (`unsupported topic ...`).
4. The payload parses as a `ServiceEnvelope` (`malformed protobuf`).
5. The envelope has a packet (`envelope without packet`).
6. The envelope has a `channel_id` and a `gateway_id` (`envelope without channel_id or gateway_id`).
7. The packet has a non-zero `from` and a non-zero `id` (`packet without from or id`).
8. The packet carries an `encrypted` payload of 1-256 bytes (`packet is not encrypted`,
   `encrypted payload size N outside N-N`); a plaintext `decoded` packet is dropped.
9. The `channel_id` of the envelope equals the `<channel>` level of the topic
   (`channel_id does not match the topic`).
10. The `<gateway>` level of the topic equals the `gateway_id` of the envelope, and it is a node id
    (`gateway in topic does not match gateway_id`).
11. The channel of the packet is `PKI` (then the PKI checks apply), or it is a channel packet: the key is
    looked up by name and the packet is decrypted. A packet that does not decrypt is forwarded unchanged
    when the user that published it forwards those packets
    ([The packets the broker cannot open](#the-packets-the-broker-cannot-open)), and dropped with the
    reason `undecryptable with the key configured for this channel` when it does not.

## See also

- [Security](security.md): the ACLs that come before all of this.
- [Limits and dedupe](limits-and-dedupe.md): the payload cap, the per-client rate and the per-node rate.
- [Logging](logging.md): every reason string of this page, as the counters show them.
- [Node setup](node-setup.md): how a node has to be configured for its packets to be accepted.
