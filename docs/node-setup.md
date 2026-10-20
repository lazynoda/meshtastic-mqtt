# Node setup

What a node owner has to set on the node so that its packets reach the broker.

[Back to the README](../README.md)

This page is for the people who own the nodes of the mesh. It describes the settings of the **Meshtastic
firmware** (the app on the phone or the CLI), not the settings of the broker.

## What to set on the node

In the MQTT module settings of the node (the app on the phone or the CLI):

| Setting | Value | Why |
|---|---|---|
| MQTT server | the address of the broker, for example `broker.example.org` or `broker.example.org:1883` | The firmware's default is `mqtt.meshtastic.org`, the public server of the project. Do not leave it there if you want your packets on this broker. The module has no port setting of its own: the port is part of the address, and without one the firmware uses 1883 (8883 with TLS). |
| Username | `meshdev` | The public user of the broker, which may publish and may not subscribe. |
| Password | `large4cats` | The public password of that user. The community guide (`meshtastic-es-community.github.io`, `docs/mapas.md`) uses the same pair. |
| TLS | **off** | This version of the broker has no TLS. A node with TLS on cannot connect. |
| Encryption enabled | **on** | The broker only accepts encrypted channel packets (see [Encryption](#encryption)). |
| Root topic | `msh/EU_868` | The root the broker expects, and the one the community guide tells every node to set. It has to be set by hand (see [below](#the-root-topic-has-to-be-set-by-hand)). |
| JSON output | **off** | The broker drops the JSON topics (see [What not to do](#what-not-to-do)). |
| Map reporting | on | The broker accepts the map reports (see [Map reports](#map-reports)). |
| Uplink enabled | on, per channel | Only the channels with "Uplink enabled" are uplinked. |
| Downlink enabled | it does not matter | The public `meshdev` user gets nothing back (see [Uplink only](#uplink-only)). |
| Proxy to client | on with Bluetooth, off with Wi-Fi | With "proxy to client" the node sends its MQTT through the phone app instead of its own connection. The community guide recommends it for the nodes that use Bluetooth. |

With the public `meshdev` user of `config.example.yaml` the broker is **uplink only**: it never sends a
message to a node, so a node with the broker as its MQTT server is a sensor that reports, not a participant
of a chat over MQTT. A user with a `subscribe_allow` of its own does get what it subscribed to.

## The root topic has to be set by hand

The root topic of a node is the first levels of every topic it publishes. For this mesh it is
`msh/EU_868`, and the broker's `publish_allow` for the public user is exactly:

```yaml
publish_allow:
  - "msh/EU_868/2/e/#"
  - "msh/EU_868/2/map/"
```

A node with another root publishes on topics that are not in that list, so the broker drops every one of
them.

**The node does not learn it.** The firmware's own MQTT client (PubSubClient, MQTT 3.1.1) publishes with
QoS 0, so there is no acknowledgement at all, and a 3.1.1 acknowledgement would carry no reason code
anyway. The broker drops the publish, the client stays connected, and the node carries on as if nothing
had happened. With "proxy to client" the phone app publishes for the node, and the broker behaves the
same.

The only sign of it is on the broker: the 60 s summary counts the refusals under `not in publish_allow`
(see [Logging](logging.md#the-drop-reasons)).

**Do not rely on the firmware to set it for you.** The firmware knows the region and can rewrite the
root to `msh/<REGION>`, but only under conditions that do not hold for a node that points at another
server:

- since firmware 2.8.1, the root is rewritten only when the server is still the default
  `mqtt.meshtastic.org` (or empty) **and** the root is still a default one (`msh` or `msh/<any region>`);
  a node that points at another server keeps the root it was given;
- in firmware 2.7 and in 2.8.0, the root was rewritten when the region changed and the root started with
  `msh`, whatever the server was.

Either way, set `msh/EU_868` by hand, and check it after a firmware update.

## Uplink only

The broker gives the public `meshdev` user of `config.example.yaml` **no** subscription at all, so
nothing ever comes back to a node: with the public credentials there is no downlink. The "Downlink
enabled" switch of a channel is therefore useless for those nodes, and their MQTT traffic is one way. A
user that has a `subscribe_allow` of its own does get the messages it subscribed to.

Two firmware details that shape what a node uplinks:

- on a public server the firmware only uplinks the packets of the **other** nodes whose owner allowed it
  (the "OK to MQTT" bit of the sender);
- the firmware skips the range-test and the detection-sensor packets when it talks to the default
  server.

## Map reports

With "Map reporting" on, the node publishes a `MapReport` (name, hardware, firmware, region, preset and
approximate position) for the map dashboards:

- the module setting `map_reporting_enabled` turns it on;
- the settings `publish_interval_secs`, `position_precision` and `should_report_location` are in
  `map_report_settings`;
- the firmware only sends a report when `should_report_location` is set, and it clamps a position
  precision outside 12-15 bits to the default;
- the report is **plaintext**, on the topic `<root>/2/map/` (with the trailing slash), and its packet id
  is 0.

The broker accepts it only if it really is a map report of the sending node (see
[Map reports](packet-filtering.md#map-reports)). The position it carries is an approximate one: the
firmware reduces the position to `position_precision` bits (12 to 15; a value outside that range is
replaced by the default) before it publishes the report.

## Encryption

"Encryption enabled" has to stay **on**. With it off, the firmware uploads the **decoded** (plaintext)
packet, and the broker drops it: a channel packet has to carry an encrypted payload of 1 to 256 bytes.

The channel key is the one of the channel, and the broker knows the keys of the channels of the mesh (see
[Channel keys](packet-filtering.md#channel-keys)). A packet of a channel whose key the broker does not
have is forwarded unchanged, as every packet the broker cannot open is (per user, on by default; see
[The packets the broker cannot open](packet-filtering.md#the-packets-the-broker-cannot-open)).

## What not to do

- **Do not turn the JSON output on.** In firmware 2.7 the JSON output published extra messages on
  `<root>/2/json/...` (on the ESP32; on the nRF52 only when it was built with `NRF52_USE_JSON`). The
  broker drops those topics, so they are traffic for nothing. In firmware 2.8 the JSON support on MQTT
  was removed and the setting is ignored; leave it off in any case.
- **Do not turn the encryption off.** See [Encryption](#encryption).
- **Do not leave the default server.** A node that still points at `mqtt.meshtastic.org` sends its
  packets to the public server of the project, not to this broker.
- **Do not expect a downlink with the public credentials.** The public `meshdev` user of
  `config.example.yaml` gets nothing back, whatever the "Downlink enabled" switch says.

## See also

- [Packet filtering](packet-filtering.md): what the broker does with what a node publishes.
- [Security](security.md): the credentials and the ACLs they are bound to.
