# Logging

What the broker writes, at which level, and what an operator can do with it.

[Back to the README](../README.md)

Logs never contain passwords or message payloads. A log line carries the topic, the client id, the
`from` of the packet, its id and its portnum, and nothing else about the packet. The client-supplied
strings (a client id, a user name, a topic) are truncated to 128 characters and their control characters
are replaced before they are written.

The logs go to stdout as compact JSON (Serilog CLEF), one event per line.

## What is logged at each level

The level is set with `log_level` (see [Configuration](configuration.md#the-top-level-keys)). The default
is `information`.

| Level | What the broker writes |
|---|---|
| `verbose` | Everything below, and nothing of its own. |
| `debug` | Every accepted packet and every dropped packet, one line each: the topic, the client, the `from`, the packet id and the portnum. Never the payload. Also the packets the broker could not open and forwarded unchanged (one line per packet, with the channel and why it was not opened), the connections refused at the accept (the connection cap, the connect rate and a banned address), the refused subscriptions (one line per refused filter), the release of a client id, the bans that end and the channel hash mismatches. |
| `information` | The connections that succeed, the subscriptions that are granted, the startup line, the 60 s summary and the shutdown. |
| `warning` | The failed logins (one line per attempt, with the username and the address), the CONNECTs that are refused (an unsupported authentication method, a full password queue, a client id that belongs to another user), the refused subscriptions (one Warning per SUBSCRIBE packet, however many filters it carries), the bans that start and the connections closed because of the packet-size cap. |
| `error` | The failures of the broker itself: a hook that threw, a connection that could not be handled, a client attached to a session of another user. |
| `fatal` | The listener could not start. The broker stops with the exit code 1. |

The per-packet lines are `debug` on purpose: a public publisher, or a node with the wrong root topic,
must not be able to flood the log. What the operator sees at `information` is the **60 s summary**, which
counts the refusals per reason.

## The startup line

One Information line tells the operator what the broker is running with: the address, the port, the
number of users, the number of channel keys, the `drop_pki` flag and **every limit of the configuration**.

This is the line that `config.example.yaml` produces (one user, three channel keys and every limit at its
default; the exempt ranges are empty, so they read as `[]`):

```
Listening on 0.0.0.0:1883 (plain MQTT). 1 user(s), 3 channel key(s), drop_pki=True, limits: max_packet_size=4096, communication_timeout_seconds=10, auth_queue_timeout_seconds=3, auth_max_pending=64, auth_max_pending_per_user=4, max_connections_per_ip=16, connect_rate_per_ip_per_minute=30, connect_burst_per_ip=10, max_payload_size=512, publish_rate_per_client_per_minute=120, publish_burst_per_client=60, dedupe_window_seconds=120, dedupe_max_gateways_per_packet=32, dedupe_max_entries=200000, packet_rate_per_from_per_minute=30, packet_burst_per_from=15, auth_fail_max_per_ip=10, auth_fail_window_seconds=600, auth_ban_seconds=3600, auth_ban_exempt=[], max_tracked_entries=100000, rate_idle_expiry_seconds=600
```

The limits are attached to the line as the structured property `LimitValues`, a JSON object whose keys
keep the order of the text, so a log store keeps the limits of that run as data and not only as text. The
text of the limits is in the property `Limits`.

The address is written as a literal, so the line reads without quotes around it.

## The 60 s summary

Every 60 seconds the broker writes one Information line with the number of refusals and evictions per
reason, and only when something was refused:

```
Refused or evicted 3 in the last 60 s: banned IP: 2, duplicate from the same gateway: 1
```

The line counts more than dropped publishes, so it does not call them all publishes: a refused connection
and an eviction are in the same count. The reasons are sorted, so the line is stable.

Two properties carry the same information in two shapes:

- `Breakdown` is the text of the breakdown, as it is written in the line;
- `Drops` is the same breakdown as a JSON object, whose keys keep the order of the text, so a log store
  can filter by them.

The counters are reset by the summary: the next one counts what happened after it. When nothing was
refused, the broker writes nothing at all.

## The drop reasons

Every refusal and every eviction has its own reason, and that string is the key of the `Drops` object.
These are all of them, as the code writes them:

| Reason | What it means |
|---|---|
| `invalid topic name` | The topic name of the publish is empty, holds a NUL character, is longer than 65535 bytes, or carries a `+` or a `#`. |
| `publish without a session owner` | The session has no owner, so nothing is published for it. |
| `not in publish_allow` | The topic is not in the `publish_allow` of the owner. |
| `payload larger than max_payload_size` | The publish is larger than the payload cap. |
| `publish rate exceeded for the client` | The client used up its publish budget. |
| `duplicate from the same gateway` | This gateway already sent this packet. |
| `too many gateways for one packet` | Too many gateways have already sent this packet. |
| `packet rate exceeded for the node` | The node used up its packet budget. |
| `empty payload` | The publish carries no payload. |
| `unsupported topic (expected <root>/2/e/<channel>/<gateway>)` | The topic is not one of the two shapes the broker accepts. A `/2/json/` topic lands here only when the `publish_allow` of the user covers it; with the ACL of `config.example.yaml` it is counted as `not in publish_allow` instead. |
| `unsupported map topic (expected <root>/2/map/)` | A map topic that is not exactly `<root>/2/map/`. |
| `malformed protobuf` | The payload is not a `ServiceEnvelope`. |
| `envelope without packet` | The envelope has no packet. |
| `envelope without channel_id or gateway_id` | The envelope has no channel or no gateway. |
| `packet without from or id` | The packet has no `from` or no `id`. |
| `packet is not encrypted` | The packet carries a plaintext payload. |
| `encrypted payload size N outside N-N` | The encrypted part is empty or too long. |
| `channel_id does not match the topic` | The channel of the envelope is not the channel of the topic. |
| `gateway in topic does not match gateway_id` | The gateway of the topic is not the gateway of the envelope. |
| `undecryptable with the key configured for this channel` | The packet does not decrypt with the key of its channel, and the user that published it drops those packets (`users[].forward_unopened: false`). When the user forwards them, the packet is not a refusal: it is not counted here. |
| `malformed PKI packet` | The PKI packet is not a unicast with a channel hash of 0, or its payload is 12 bytes or less. |
| `PKI DM (drop_pki: true)` | The PKI direct message is dropped, as the config says. |
| `map report: malformed protobuf` | The map report is not a `ServiceEnvelope`. |
| `map report: envelope without packet` | The map report has no packet. |
| `map report: packet without from` | The map report has no `from`. |
| `map report: packet is not decoded` | The map report is encrypted. |
| `map report: portnum is not MAP_REPORT_APP` | The map report is not a map report. |
| `map report: payload is not a MapReport` | The payload of the map report is not a `MapReport`. |
| `map report: gateway_id is not the sender (from)` | The map report claims a gateway that is not the sender. |
| `too many connections from one IP` | The address is at its connection cap. |
| `too many connection attempts from one IP` | The address is over its connect rate. |
| `banned IP` | The address is banned. |
| `internal error (<exception type>)` | The packet filter threw while it inspected the publish, for example `internal error (InvalidOperationException)`. It is a key of its own, one per exception type. |
| `internal error` | The publish hook itself threw. The publish is dropped and the client stays connected. |
| `evicted: dedupe table full` | The dedupe table hit its cap. |
| `evicted: per-node rate table full` | The per-node rate table hit its cap. |
| `evicted: per-client rate table full` | The per-client rate table hit its cap. |
| `evicted: per-IP connection table full` | The table of connections per address hit its cap. |
| `evicted: per-IP rate table full` | The per-address connect rate table hit its cap. |
| `evicted: auth failure table full` | The table of failed logins hit its cap. |
| `evicted: auth ban table full` | The table of bans hit its cap. |

The numbers inside a reason are collapsed to `N`, so `encrypted payload size 300 outside 1-256` is
counted as `encrypted payload size N outside N-N`. The set of keys stays small and fixed. The only
exception is a number **between two slashes**: it is part of the shape of the reason (the fixed `/2/` of
the topic format) and not a value, so it is kept. `unsupported topic (expected <root>/2/e/<channel>/<gateway>)`
and `unsupported map topic (expected <root>/2/map/)` keep their `/2/` in the key.

The per-packet `debug` line keeps the real numbers: it says `encrypted payload size 300 outside 1-256`,
with the numbers the packet really had.

An eviction count above zero means a cap was reached and the oldest entries of that table were dropped.
See [The bounded tables](limits-and-dedupe.md#the-bounded-tables).

## The packets the broker could not open

A channel packet the broker cannot open (a channel whose key it does not have, a wrong key) is forwarded
unchanged when the user that published it has `users[].forward_unopened: true` (the default). That is not
a refusal: it is not counted in the 60 s summary, and it is never a Warning. It is one `debug` line per
packet, like this one:

```
Forwarded an unopened packet on "msh/EU_868/2/e/Private/!1a2b3c4d" from "node-1": no key is configured for this channel (channel "Private", from "!1a2b3c4d", id 268435458)
```

The line names the channel, the `from`, the id of the packet and why it was not opened: no key for the
channel, or a key that does not open it. It never carries the payload.

When the user drops those packets (`users[].forward_unopened: false`), they are dropped like any other
refusal: one `debug` line per packet and a count in the 60 s summary under
`undecryptable with the key configured for this channel`.

## The JSON output

The console sink writes the Serilog compact JSON format (CLEF): one event per line, with the timestamp
`@t`, the rendered message `@m`, the id of the event `@i` and the level `@l` (which is left out for the
Information events). The id is a hash of the message template, written as 8 hex digits in a string.

The two events below were captured from a running broker; the run used `auth_fail_max_per_ip: 3` and
`auth_ban_seconds: 60`, and the only change is the address of the banned client, which is a documentation
address:

```json
{"@t":"2026-10-20T11:39:16.9144126Z","@m":"Refused or evicted 3 in the last 60 s: banned IP: 2, duplicate from the same gateway: 1","@i":"8a115f9b","Total":3,"Seconds":60,"Breakdown":"banned IP: 2, duplicate from the same gateway: 1","Drops":{"banned IP":2,"duplicate from the same gateway":1}}
{"@t":"2026-10-20T11:38:24.2412066Z","@m":"Banned \"203.0.113.7\" for 60 s after 3 authentication failures","@i":"db1c532a","@l":"Warning","RemoteIp":"203.0.113.7","Seconds":60,"Failures":3}
```

The address of the ban is in quotes in the message, because Serilog renders a string property as a quoted
string. The properties of an event are in the order of the message template, but that order is not part
of the format.

The two structured objects keep a guaranteed order: the keys of `Drops` are in the order of the text of
the line, and the keys of `LimitValues` are in the order of the startup line.

## Grepping and alerting

The log is JSON, so `jq` and every log store can read it. A few examples:

```bash
# every failed login
docker logs meshtastic-mqtt | jq -c 'select(."@m" | startswith("Authentication failed"))'

# the reasons of the last summary
docker logs meshtastic-mqtt | jq -c 'select(.Drops) | .Drops'

# the warnings only
docker logs meshtastic-mqtt | jq -c 'select(."@l" == "Warning")'
```

What is worth an alert:

- **`banned IP` in the summary**: somebody is guessing the password from that address.
- **a count of `not in publish_allow`**: a node is publishing on a topic the broker does not accept,
  which is almost always a wrong root topic (see [Node setup](node-setup.md#the-root-topic-has-to-be-set-by-hand)).
- **an eviction count above zero**: a cap was reached, most likely because of forged ids.
- **a `Warning` per failed login**: the same, one line at a time.

The 60 s summary is the line to watch: it is written only when something was refused, and it counts
everything that was refused, per reason.

## See also

- [Operations](operations.md): how to run the broker and where the logs go.
- [Limits and dedupe](limits-and-dedupe.md): what each limit bounds.
