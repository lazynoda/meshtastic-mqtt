# Auth bans

An address that fails to log in too often is banned for a while, inside the broker.

[Back to the README](../README.md)

The ban lives **inside the broker**: no system fail2ban, no nftables, no changes to the host. It is
counted, applied and forgotten by the broker itself, and it is configured with the `limits` section.

## What counts as a failure

Only a **failed password check** counts:

| Refusal | Counts as a failure |
|---|---|
| A wrong password | yes |
| An unknown user | yes |
| An unsupported authentication method | yes |
| A full password queue ("server busy") | no |
| A client-id conflict | no |
| A connection refused at the accept (the connection cap, the connect rate) | no |
| A connection refused because the address is already banned | no |

The reason code decides: `BadUserNameOrPassword` and `BadAuthenticationMethod` are the two that count.
A login that was never checked (the "server busy" of a full queue) is not a failure, because nothing was
verified.

Every failed login is one Warning in the log, with the username and the address of the client, whether it
is counted for the ban or not: a login of an exempt address is logged too, and so is a password check that
was already running when the ban started (the Warning is written first, and the counter is not touched
afterwards). A CONNECT that arrives **after** the ban is not a failed login at all: it is refused before
the password is checked, and that refusal is logged at `debug` only. The Warnings are for the operators:
the broker counts the failures itself.

## The window, the ban and the exemptions

- The failures of one address are counted in a **window**: `auth_fail_max_per_ip` (10) failures within
  `auth_fail_window_seconds` (600) since the first failure of the window. When the window has passed, the
  next failure starts a new one.
- **A successful login does not reset the counter**: with the public `meshdev` credentials an attacker
  could interleave a correct login between the guesses, and the honest nodes behind the same address would
  keep the guesses alive.
- The `auth_fail_max_per_ip`-th failure **bans the address** for `auth_ban_seconds` (3600) and clears its
  counter. There is no escalation: every ban lasts the same.
- The ban is one Warning when it starts:
  ```
  Banned "203.0.113.7" for 60 s after 3 authentication failures
  ```
  (the line was captured with `auth_fail_max_per_ip: 3` and `auth_ban_seconds: 60`; with the defaults it
  reads `Banned "203.0.113.7" for 3600 s after 10 authentication failures`. The address is in quotes
  because Serilog renders a string property as a quoted string.)
- `auth_ban_exempt` is a list of CIDR ranges (IPv4 and IPv6) whose failures are never counted and which
  are never banned. An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) matches the IPv4 ranges. A single
  address without a prefix is a range of one.
- A range that cannot be parsed is a configuration error, not a range that is silently dropped: the
  broker refuses to start and says which range it could not read.

The tables behind it are bounded (`max_tracked_entries`, 100000 addresses each): the failed logins are
evicted in the order of their windows (the oldest window first), the bans evict the one that ends soonest,
and the evictions are counted in the periodic summary (see [Logging](logging.md#the-60-s-summary)).

## What a banned address sees

There are two refusals, and they happen in different places:

1. **At the accept**, before a single MQTT byte is read and before the connection takes a slot or a token
   of the per-IP limits: the socket is closed at once. The client sees the end of the stream without a
   CONNACK, whatever protocol version it speaks.
2. **At the CONNECT**, before the password is checked: the CONNACK carries the MQTT 5 reason code
   `Banned` (0x8A). MQTT 3.1.1 has no "banned" code, so MQTTnet converts it to the return code 5
   ("not authorized"), and a 3.1.1 client cannot tell a ban from another authorization refusal. The ban
   is cheaper than a password check: the password of a banned address is never verified.

The second refusal is the one that matters for a client that was already connected when the ban started.

The **sessions that were already connected are left alone**: behind a CGNAT or a VPN many honest nodes
share one address, and cutting them would cost more than the attack is worth. A session that is already
connected keeps working, and it may keep publishing.

The firmware's MQTT client speaks MQTT 3.1.1, so a node behind a banned address sees its connection
refused and reconnects in a loop until the ban ends. The broker counts those refusals as `banned IP` in
the periodic summary.

## The state is in memory only

**A restart forgets every ban.** There is no manual unban, and no ban list on disk: the failed logins and
the bans live in memory, and the broker forgets them when it stops.

The tables also forget themselves: the failures whose window has passed and the bans that have ended are
swept away, so a flood of failures from many rotating addresses leaves nothing behind. A sweep runs when
the clock has moved far enough or after enough counted failures, never on every one of them.

## Networks that share an address

A CGNAT, a VPN or a tunnel puts many nodes behind one IP address, and the broker cannot tell them apart:
they share the connection cap, the connect rate and the ban.

- One misconfigured node (a wrong password in a loop, a firmware that sends a stale one) can get the
  whole address banned, and with it the honest nodes behind it.
- `auth_ban_exempt` is the way out: list the ranges the real nodes share, and their failures are never
  counted and they are never banned.
- `auth_fail_max_per_ip` can be raised for the same reason, and `auth_ban_seconds` shortened so that a
  ban does not last an hour.
- The per-IP limits have the same problem: see
  [Limits and dedupe](limits-and-dedupe.md#residual-risks).

## Residual risks

- **The ban is per IP address.** A flood from many addresses is not covered by the broker: the per-IP
  limits bound one address at a time, and a flood that rotates addresses needs an upstream firewall in
  front of the broker.
- **Behind a CGNAT or a VPN many nodes share one address.** One misconfigured node (a wrong password in a
  loop, a firmware that sends a stale one) can get the whole address banned, and with it the honest nodes
  behind it. Use `auth_ban_exempt` for those networks, or raise `auth_fail_max_per_ip`.
- **An IPv6 attacker can rotate addresses inside a /64.** The broker keys the ban by the address, not by
  the /64, so a client with a whole prefix can walk through it.
- **The bans are lost on a restart.** A broker that restarts often (a crash loop) hands the attacker a
  fresh start.

## See also

- [Security](security.md): the authentication, and what the "server busy" refusal means.
- [Limits and dedupe](limits-and-dedupe.md): the per-IP limits and the table of failed logins.
- [Logging](logging.md): the Warning of a ban, and the `banned IP` count of the summary.
