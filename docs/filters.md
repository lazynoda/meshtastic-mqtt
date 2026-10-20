# Packet filters

The rules that decide which packets of the mesh reach the subscribers: by user, by gateway and by node.

[Back to the README](../README.md)

The filters live in their own YAML file, next to the config but apart from it. The config says where
the file is and how often it is checked; the file holds the rules. A file that is not valid is never
loaded: the broker keeps the rules it had and says why in one Warning.

Everything on this page is in English, and the node ids are the documentation ones (`!a1b2c3d4`,
`!deadbeef`).

## The file

The config points at the file:

```yaml
filters:
  file: /etc/meshtastic-mqtt/filters.yaml   # optional; no `filters` section = no filters
  reload_check_seconds: 5                   # 1..3600, default 5
```

Without the section the broker has no filters: every packet that passes the other checks is forwarded.
The file itself is optional too: an empty file is no rules.

[`filters.example.yaml`](../filters.example.yaml) is a working file with every key written out and
commented. It is an **illustration of every feature, not a starting point**: copied as it is, it drops
every text message of every user and every packet the broker cannot open (the channels whose key it
does not have and every direct message in PKI), and it stops the packets of the public channels that
are not in its lists. The quick start of [Operations](operations.md#running-with-docker) starts with
an empty file instead: an empty file means no rules.

## The three scopes

The file has three optional maps, and each key of a map is a list of rules:

```yaml
users:      { meshdev: [ ... ], "*": [ ... ] }
gateways:   { "!a1b2c3d4": [ ... ], "*": [ ... ] }
nodes:      { "!deadbeef": [ ... ], "*": [ ... ] }
```

| Scope | The key is | The rules apply to |
|---|---|---|
| `users` | the name of a user of the config, or `"*"` | the packets the **session owner** publishes, the same identity the publish ACL uses (never the `username` of the PUBLISH). A user that is not in the config is a load error. |
| `gateways` | a node id (`!` and 8 lowercase hex digits), or `"*"` | the packets the **gateway of the topic** sends. The gateway is already bound to the envelope of the packet. |
| `nodes` | a node id (`!` and 8 lowercase hex digits), or `"*"` | the packets the **node that sent them** sends, whatever gateway uploaded them. The node is the `from` of the cleartext header of the packet. |

## How the rules combine

A packet must pass **every** rule of **every** scope that applies to it:

- the rules of its user, and the rules of `users."*"`;
- the rules of its gateway, and the rules of `gateways."*"`;
- the rules of its node, and the rules of `nodes."*"`;

**any rule that fails drops the packet.** The rules have no order and there is no "first match": a rule
is not a filter that stops at the first hit, it is a condition the packet has to satisfy. A rule that
needs a packet the broker could open (see [Unopened packets](#unopened-packets)) is the exception, and
only for the packets the broker could not open.

## A rule

A rule has a `name` and one or more constraints. The `name` is required, it is unique in the whole
file, and it holds 1 to 64 characters of `A-Z`, `a-z`, `0-9`, `_`, `.` and `-`. The name is what the
log and the 60 s summary show, so it should say what the rule does (`block-node-1`).

```yaml
- name: block-node-1
  channels:  { allow: [ ... ] }      # the channel of the packet
  topics:    { allow: [ ... ] }      # the topic of the publish
  portnums:  { allow: [ ... ] }      # the portnum of the packet
  drop_if:   [ ... ]                 # the conditions that drop the packet
  unopened:  drop                    # what happens to a packet the broker could not open
```

A rule with no constraint is a load error, and so is a rule with two constraints of the same kind.

### channels

The channel of the packet: the `channel_id` of the envelope, which is also the `<channel>` level of the
topic. The lookup is **case-sensitive**, like the key of the channel in the config: `Iberia` and
`iberia` are two different channels.

- `allow`: the channel of the packet has to be in the list.
- `deny`: the channel of the packet must not be in the list.

`PKI` is a valid name: it is the channel of the direct messages (which the broker never opens, see
[Unopened packets](#unopened-packets)). A **map report has no channel**: an `allow` list is not
satisfied by it and a `deny` list is.

### topics

The MQTT topic of the publish, with the same wildcards as the ACLs: `+` is one level, `#` is that
level and everything below it. The matcher is the one of the publish ACL, so `msh/EU_868/2/e/#` covers
`msh/EU_868/2/e/Test/!1a2b3c4d`.

- `allow`: the topic has to match at least one filter of the list.
- `deny`: the topic must not match any filter of the list.

### portnums

The portnum of the packet: the name the firmware writes (`TEXT_MESSAGE_APP`) or its number.

- `allow`: the portnum of the packet has to be in the list.
- `deny`: the portnum of the packet must not be in the list.

A name that is not a portnum of the firmware is a load error, and so is a number outside the range of
the firmware (0 to 511). A number inside the range is accepted even when the firmware has no name for
it.

### drop_if

A list of conditions. The packet **fails the rule if any condition is true**. A condition is a map:

```yaml
- field: payload.text        # the path of the field to read
  op: regex                  # the operator
  value: "buy[ ]+now"        # the value to compare with
  portnum: TEXT_MESSAGE_APP  # optional: the condition only applies to that portnum
```

The `portnum` key is optional: a condition with it only applies to the packets of that portnum, and it
is false for every other packet. A `payload.` condition needs it (the payload is decoded as the
message of its portnum).

## The operators

| `op` | What it does | The field may be |
|---|---|---|
| `eq` | the value of the field is the value | text, number, boolean, enum |
| `ne` | the value of the field is not the value | text, number, boolean, enum |
| `in` | the value of the field is one of the values of a list | text, number, boolean, enum |
| `contains` | the text of the field holds the value | text |
| `regex` | the text of the field matches the pattern | text |
| `lt` | the value of the field is smaller than the value | number |
| `le` | the value of the field is not bigger than the value | number |
| `gt` | the value of the field is bigger than the value | number |
| `ge` | the value of the field is not smaller than the value | number |

The operator and the type of the field have to agree: a `regex` on a number is a load error, and so is
a `lt` on a text. The values are checked too: the value of a number field has to be a number, the value
of a boolean field `true` or `false`, and the value of an enum field the name of a value of the enum
or its number.

The value compared with `data.portnum` has to be a portnum of the firmware (0 to 511), whatever the
operator is (`eq`, `ne`, `in`, `lt`, `le`, `gt` or `ge`): a value outside the range is a load error.

An enum is compared by its name (`TEXT_MESSAGE_APP`) or by its number (`67`).

The numbers are compared **exactly**, whatever their size: a 64-bit unsigned field with the high bit
put (`payload.host_metrics.freemem_bytes`, a `uint64`) is compared with the value of the rule as it
is, and the comparison never fails with an overflow. A whole number of the file is between
-9223372036854775808 and 18446744073709551615; a value outside that range is a load error.

A **field that is not there** makes the condition false, with one exception: `ne` is then **true**. A
field that is not there is a message field that is not set, a field of a `oneof` that is not the one of
the packet, or a proto3 field with an explicit presence that is not set.

### The regular expressions

The pattern is a .NET regular expression, with two limits:

- the engine runs **without backtracking** (`RegexOptions.NonBacktracking`), so a pattern cannot make the
  broker hang, and the constructs it does not support (the lookarounds, the backreferences) are a load
  error;
- the pattern is at most 512 characters long, and it is given up if it does not finish in time.

The same pattern is **compiled once** and shared by every condition that uses it, so a rule that
repeats a pattern (and an alias that repeats a rule) costs nothing extra. A file may not hold more
than 1000 **distinct** patterns, and compiling them may not allocate more than 128 MiB: see
[The bounds](#the-bounds) and [The memory of the regular expressions](#the-memory-of-the-regular-expressions).

## The paths of the fields

The path of a field has one of three prefixes, and the parts after it are the fields of a protobuf, in
their `snake_case` names.

| Prefix | What it reads | Needs an opened packet |
|---|---|---|
| `packet.` | the cleartext header of the `MeshPacket`: `from`, `to`, `id`, `hop_limit`, `hop_start`, `want_ack`, `via_mqtt`, `channel`, `rx_time`, `priority`, ... | no |
| `data.` | the decoded `Data`: `portnum`, `want_response`, `dest`, `source`, `request_id`, `reply_id`, `emoji`, `bitfield`, ... | yes |
| `payload.` | the payload, decoded as the message of its portnum (see the table below) | yes |

A nested path uses dots: `payload.device_metrics.battery_level`, `payload.long_name`.

The paths are checked when the file is read: a field that does not exist, a repeated field and a bytes
field are all load errors. A repeated field and a bytes field cannot be read at all, and the only
exception is the text of a `TEXT_MESSAGE_APP`.

### The portnum and its message

| Portnum | The payload is decoded as | What can be read |
|---|---|---|
| `TEXT_MESSAGE_APP` | the text of the message (it is not a protobuf) | `payload.text` |
| `POSITION_APP` | `Position` | `payload.latitude_i`, `payload.longitude_i`, `payload.altitude`, ... |
| `NODEINFO_APP` | `User` | `payload.long_name`, `payload.short_name`, `payload.hw_model`, ... |
| `TELEMETRY_APP` | `Telemetry` | `payload.device_metrics.battery_level`, `payload.device_metrics.voltage`, ... |
| `WAYPOINT_APP` | `Waypoint` | `payload.name`, `payload.desc`, `payload.lat_i`, ... |
| `NEIGHBORINFO_APP` | `NeighborInfo` | `payload.node_id`, `payload.snr`, ... |
| `MAP_REPORT_APP` | `MapReport` | `payload.long_name`, `payload.short_name`, `payload.role`, ... |
| `ROUTING_APP` | `Routing` | `payload.route_request.id`, `payload.route_reply.id`, ... |

A `payload.` condition needs a `portnum`, and it has to be one of these: the payload of another
portnum is not a message the filter knows.

## Unopened packets

The header of a packet is in clear: only its payload is encrypted. So the broker can always read the
`packet.` fields, even for a packet it cannot open (a channel whose key it does not have, a wrong key,
or a direct message).

A rule that has `portnums`, or a condition that reads `data.` or `payload.`, needs a packet the broker
could open. Such a rule **has to say what happens to a packet the broker could not open**:

```yaml
- name: only-text
  portnums:
    allow: [TEXT_MESSAGE_APP]
  unopened: drop     # an unopened packet fails the rule: it is dropped
```

```yaml
- name: no-spam
  drop_if:
    - field: payload.text
      op: regex
      value: "buy[ ]+now"
      portnum: TEXT_MESSAGE_APP
  unopened: allow    # an unopened packet skips the constraints that need an open packet
```

- `unopened: drop`: the unopened packet **fails the rule**, and it is dropped.
- `unopened: allow`: the unopened packet **skips the constraints that need an opened packet** (the
  `portnums` and the `data.` and `payload.` conditions) and is judged on the rest of the rule only.

A rule that does not need an opened packet may declare `unopened` too: with `drop`, every unopened
packet of that scope fails the rule.

A rule that needs an opened packet and does not say which of the two it wants is a load error: nobody
writes a global rule on the content of the packets and kills all the traffic the broker cannot read
without knowing it.

## Where the filter runs

The filter runs in the publish hook, **after the verdict of the decryption** (and after the policy of
`users[].forward_unopened`) and **before the cross-gateway dedupe and the per-node rate**. So:

- a copy that a filter drops spends no dedupe entry and no budget of the node;
- a copy that a filter allows, from another gateway, still passes the dedupe and the budget;
- the publish ACL, the topic checks, the gateway binding and the size caps all run before the filter.

A filtered publish is dropped like every other drop: the client stays connected, and the
acknowledgement carries no reason code.

## The logs

A filtered packet is a drop:

- it is counted in the 60 s summary under the reason `filtered: <rule name>`, with the name of the rule
  whole (a name may hold digits: `filtered: block-node-1`);
- it is written at `debug` level, one line per packet, with the scope and its key, the name of the
  rule, the channel, the `from`, the id of the packet and the gateway:

  ```
  Dropped publish on "msh/EU_868/2/e/Test/!1a2b3c4d" from "node-1": filtered: only-iberia-and-sfnarrow (scope gateway, key !1a2b3c4d, channel Test, from "!deadbeef", id 536870914, gateway !1a2b3c4d)
  ```

- **the line never carries the payload, the text of the message or the value that matched.** Nothing
  above `debug` is written for a filtered packet.

## The hot reload

The file is checked every `reload_check_seconds` seconds (the default is 5). The check looks at the
size and the time of the file, and it reads and hashes the content only when one of them changed, and
at least once a minute, so a file that is edited with the same size and the same time is still seen.
The hash of the content is what makes the check work with a bind mount and with a file that is
replaced atomically.

A `SIGHUP` reloads it at once, and it always reads the content of the file: an edit that keeps its
size and its time is applied at once too.

Only one check runs at a time: the timer and the `SIGHUP` of the operator may ask for a reload at the
same moment, and the file is read once and the reload line is written once.

**The file has to be mounted through its directory, not as a single file.** A bind mount of one file
keeps the inode it had when the mount was made, so a file that is replaced atomically on the host is
not seen by the container. Mount the directory (the broker only reads the file, so a read-only mount
is fine), point the config at it and change it on the host:

```bash
docker run -d --name meshtastic-mqtt \
  -v "$PWD/config.yaml:/config/config.yaml:ro" \
  -v "$PWD/filters:/etc/meshtastic-mqtt:ro" \
  meshtastic-mqtt
```

```yaml
filters:
  file: /etc/meshtastic-mqtt/filters.yaml
  reload_check_seconds: 5
```

The file is edited on the host and replaced atomically (edit a copy next to it, then move the copy
over the old one), and the rules are in force at once with a `SIGHUP`:

```bash
cp "$PWD/filters/filters.yaml" "$PWD/filters/filters.yaml.new"
vi "$PWD/filters/filters.yaml.new"
mv "$PWD/filters/filters.yaml.new" "$PWD/filters/filters.yaml"
docker kill --signal=HUP meshtastic-mqtt
```

See [Operations](operations.md#blocking-a-node-while-the-broker-runs) for the whole procedure.

When the file changed, it is read and checked **as a whole** and compiled into an immutable set of
rules, which then replaces the old one in a single step: a packet that is judged at that moment sees
the old rules or the new ones, never a mix.

- A valid file: one Information line,

  ```
  Filters reloaded: 12 rules (3 user, 5 gateway, 4 node rules), sha256 1a2b3c4d
  ```

  The three numbers are the rules of each kind (they add up to the total) and the hash is the first
  eight hex digits of the SHA-256 of the file. One rule is written "1 rule" and more than one is
  written "2 rules".

- A file that cannot be read or is not valid: the rules that are in force stay in force, and one
  Warning is written with every problem of the file and the line it is on:

  ```
  The filters were not reloaded, the rules that are in force stay in force: /etc/meshtastic-mqtt/filters.yaml:12: users.meshdev[0] (rule 'no-text'): 'channels' has both 'allow' and 'deny' (a constraint is one or the other)
  ```

  A file with more than 20 problems lists the first 20 of them and counts the rest in one line
  (`... and 9979 more errors`), so a broken file does not write a megabyte of log.

  The Warning is written once: it is not repeated until the file changes again.

- At startup, a file that is missing or is not valid is a start error: the broker does not start, like
  with an invalid config.

## The bounds

The file may not grow without bound:

| Bound | The limit |
|---|---|
| the rules of the file | 10000 |
| the conditions of the file | 100000 |
| the values the file compiles | 1000000 |
| the distinct patterns of the regular expressions | 1000 |
| the memory the regex patterns allocate when compiled | 128 MiB (134217728 bytes) |
| the size of the file | 1 MiB (1048576 bytes) |
| the items of a list | 1000 |
| the characters of a text value | 512 |
| the characters of the pattern of a regular expression | 512 |
| the characters of the name of a rule | 64 |

The values the file compiles are the items of the lists of `channels`, `topics` and `portnums` and the
values of the operator `in`, summed over every rule of the file.

The bounds are counted **after the aliases of the YAML are expanded**, so an alias that multiplies the
rules, the conditions or the values of the file does not escape them: a small file that holds a
million values through its aliases is a load error too. The file is checked while it is compiled and
the load stops at the first bound it goes over, so a file that is over a bound is not loaded at all.
The memory of the patterns is measured while they are compiled, and the load stops at the pattern
that crosses it.

A file that is bigger is a load error, and the message names the bound, its limit and the count the
file reached:

```
filters.yaml: the file holds more than 1000000 compiled values (the budget of compiled values is 1000000, the file has 1000001)
filters.yaml: the file holds more than 1000 regex patterns (the budget of regex patterns is 1000, the file has 1001)
filters.yaml:401: users.meshdev[0] (rule 'r0'): the regex patterns of the file allocate more than 134217728 bytes when compiled (the budget of regex memory is 134217728 bytes, the file reached 135402920 bytes at the pattern '(?i)buy (cheap|free) [a-z]+ now 99')
```

The evaluation itself is cheap: when no rule applies to a packet, nothing is read and nothing is
allocated. The payload of a packet is decoded **at most once**, and only when a rule that applies needs
it.

### The memory of the regular expressions

The cost of a compiled pattern depends on its **shape**, so it is measured and not counted. What was
measured on the review VM (.NET 10, arm64, a Debug test host; the numbers are approximate):

| The shape of the pattern | The heap it keeps | The bytes it allocates when compiled |
|---|---|---|
| a literal (`spam0`) | 0.12-0.19 MB | 0.19-0.27 MB |
| a repetition or a class (`buy[ ]+now-0`) | 0.33-0.36 MB | 0.55 MB |
| a case-insensitive alternation (`(?i)buy (cheap\|free) [a-z]+ now 0`) | 0.78 MB | 1.32 MB |

So the cost of a pattern is between 0.1 MB and 0.8 MB, and the bytes it allocates when it is
compiled are about 1.4 to 2 times what it keeps in memory. The file is refused when compiling its
distinct patterns allocates more than **128 MiB (134217728 bytes)**, or when it holds more than
**1000 distinct patterns**. The memory budget is the one that is reached first in practice: a few
hundred cheap literals, or about a hundred patterns of the costliest shape.

The identical patterns are compiled **once**: a rule that repeats a pattern (and an alias that
repeats a rule) costs nothing extra, and the memory of the file is the memory of its distinct
patterns.

A `contains` condition holds about 0.2 KB, so **use `contains` where a regular expression is not
needed**: it is the same rule without the memory.

These bounds are the only promise about the memory: the lazy cache that the engine grows while it
matches a text is not counted by them.

## Examples

### 1. A gateway may only send two channels

```yaml
gateways:
  "!a1b2c3d4":
    - name: only-iberia-and-sfnarrow
      channels:
        allow: [Iberia, SFNarrow]
```

Every packet of the gateway `!a1b2c3d4` on another channel is dropped, with the reason
`filtered: only-iberia-and-sfnarrow`.

### 2. A node may only send two kinds of packet, whatever the gateway

```yaml
nodes:
  "!deadbeef":
    - name: only-position-and-text
      portnums:
        allow: [POSITION_APP, TEXT_MESSAGE_APP]
      unopened: drop
```

The rule is about the node, not about the gateway: it holds for every copy of the packets of
`!deadbeef`, whichever gateway uploaded them.

### 3. A user may not publish text messages

```yaml
users:
  meshdev:
    - name: no-text
      portnums:
        deny: [TEXT_MESSAGE_APP]
      unopened: drop
```

The user is the one that **owns the session**, the same identity the publish ACL uses.

### 4. Two scopes that have to agree

```yaml
users:
  meshdev:
    - name: user-allows-iberia
      channels:
        allow: [Iberia]
gateways:
  "!a1b2c3d4":
    - name: gateway-denies-iberia
      channels:
        deny: [Iberia]
```

The user allows the channel and the gateway denies it: the packet is dropped. The packet has to pass
every rule of every scope, so a rule that allows is not enough.

### 5. A rule on the topics

```yaml
users:
  "*":
    - name: no-private-channel
      topics:
        deny: ["msh/EU_868/2/e/Private/#"]
```

The wildcards are the ones of the ACLs: `+` is one level and `#` is everything below it.

### 6. An anti-spam rule on the text of the messages

```yaml
users:
  "*":
    - name: no-spam
      drop_if:
        - field: payload.text
          op: regex
          value: "buy[ ]+now"
          portnum: TEXT_MESSAGE_APP
      unopened: allow
```

The rule reads the text of the messages, so it needs a packet the broker could open. With
`unopened: allow` the packets the broker cannot read (a private channel, a wrong key) are not dropped
by this rule: they have no text to read.

### 7. A node with a low battery is dropped

```yaml
nodes:
  "!deadbeef":
    - name: low-battery
      drop_if:
        - field: payload.device_metrics.battery_level
          op: lt
          value: 20
          portnum: TELEMETRY_APP
      unopened: allow
```

## See also

- [Packet filtering](packet-filtering.md): what the broker accepts on the wire and the order of the checks.
- [Configuration](configuration.md): the `filters` section of the config.
- [Logging](logging.md): the reason of a filtered packet and the line of the reload.
- [Operations](operations.md): how to block a node while the broker runs.
- [Security](security.md): the ACLs that run before the filters.
