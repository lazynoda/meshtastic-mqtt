# Architecture

How a connection travels through the broker, what the broker keeps in memory, and what runs where.

[Back to the README](../README.md)

## The connection path

1. **The accept loop.** The broker does not use MQTTnet's stock TCP adapter: it uses its own
   (`PacketSizeLimitedTcpAdapter`) so that two things can be done before a single MQTT byte is read.
   When a socket is accepted, the address is looked up: a banned address is closed at once, before it
   takes a slot or a token of the per-IP limits, and then the per-IP limits are applied (the connection
   cap and the connect rate). A refused connection is closed with a clean shutdown, so the client sees the
   end of the stream.
2. **The size guard.** The channel is wrapped in a decorator that follows the MQTT framing on the read
   side: as soon as a declared Remaining Length exceeds `limits.max_packet_size`, the connection is ended
   and the packet is never allocated. MQTTnet would allocate up to 256 MB before any hook runs (see
   [The packet-size cap](security.md#the-packet-size-cap)).
3. **The connect validation.** MQTTnet reads the CONNECT and calls the broker's hook
   (`ValidatingConnectionAsync`). The hook refuses a banned address (`Banned`, 0x8A) before the password
   is checked, refuses an unsupported authentication method, asks the authenticator for the password,
   and then claims the client id for the user that authenticated.
4. **The authentication.** The authenticator answers `Success`, `Failed` or `Busy` (the password queue is
   full or the wait timed out). `Failed` becomes `BadUserNameOrPassword` and is counted as a failure for
   the ban of the address; `Busy` becomes `ServerBusy` and is not.
5. **The session.** MQTTnet creates the session (or reuses the one of the client id) and the broker
   stores the owner of the session and the token of its claim in it. The owner is what the subscribe and
   publish ACLs are evaluated against, and it never changes hands.
6. **The hooks.** Every SUBSCRIBE and every PUBLISH goes through the broker's hooks: the subscribe hook
   applies the ACL of the owner, and the publish hook applies the publish ACL, the payload cap, the
   per-client rate, the packet filter, the filters of the rules file and the packet gate, in that order
   (see [The order of the checks](packet-filtering.md#the-order-of-the-checks-in-the-publish-hook)).

## What it does with each connection

| Hook | Rule |
|---|---|
| Connect | Username and password are checked against `users`. Unknown user or wrong password → `BadUserNameOrPassword` (MQTT 3.1.1 return code 4), logged with username and remote IP, never the password. A reconnect with an existing client id takes over the old session, but only for the **same user**: a client id held by a live or persisted session of another user is refused with `ClientIdentifierNotValid` (3.1.1 return code 2) and the session owner stays connected. The id is free again once that session is gone. If the password-check queue is full (see `limits`), the client gets `ServerBusy` (3.1.1 return code 3, "server unavailable") and retries. An address that failed too many logins is banned: the socket is closed at the accept, and a CONNECT that arrives after the ban is refused with `Banned` (0x8A) before the password is checked (see [Auth bans](auth-bans.md)). |
| Subscribe | The requested filter is granted only if **every** topic it can match is covered by the `subscribe_allow` filters of the user that **created the session** (bound at connect time, so a reused session never changes hands). Real MQTT wildcard semantics, not prefix matching. An empty or missing list denies everything. `#` and `+` never grant `$`-topics such as `$SYS/#`. Refusal → MQTT 5 reason `Not authorized` (135); on MQTT 3.1.1 → `0x80`. |
| Publish | First the publish ACL (below), then the limits, the packet filter and the filters of the rules file (below). A refused publish is dropped, never forwarded, and the client stays connected. Accepted messages are re-published with `retain` cleared (firmware never retains), so nothing enters the retained-message store. |

Before any of this, every packet's declared length is checked against `limits.max_packet_size` while its
fixed header is still being read; a larger one closes the connection before the broker allocates it
(also for clients that have not authenticated yet).

## The tables the broker keeps

Every table the broker keeps about the clients has a hard entry cap and an idle expiry, so a flood of
forged ids cannot grow the memory without bound. The details are in
[The bounded tables](limits-and-dedupe.md#the-bounded-tables).

| Table | What it holds | Bound |
|---|---|---|
| The connections per address | How many connections one address holds open | `max_tracked_entries`; the entry dies with its last connection |
| The connect rates per address | The token bucket of every address that opened a connection | `max_tracked_entries`, `rate_idle_expiry_seconds` |
| The publish rates per client | The token bucket of every client that published | `max_tracked_entries`, `rate_idle_expiry_seconds`; the entry dies with the session |
| The packet rates per node | The token bucket of every node that sent a packet | `max_tracked_entries`, `rate_idle_expiry_seconds` |
| The dedupe | The packets of the window, with the gateways that sent them | `dedupe_max_entries`, `dedupe_window_seconds` |
| The failed logins | The failures of every address, with the start of their window | `max_tracked_entries`, `auth_fail_window_seconds` |
| The bans | The addresses that are banned, with the moment the ban ends | `max_tracked_entries`, `auth_ban_seconds` |
| The claims of the client ids | Which user holds which client id | The sessions of the server, plus the claims of the last 30 seconds |

The claims are the only table without a configured cap: it is bounded by the sessions of the server plus
the claims taken in the last 30 seconds (the gap between the connect hook and the session being created),
plus the 64 inserts that trigger a sweep.

## Concurrency

MQTTnet runs the handlers of the connections **concurrently**: one task per connection. The packets of one
connection are read in a single loop and handled one after another (a publish is awaited before the next
packet is read), while the connections run in parallel. Everything the broker shares is therefore
protected:

- **One lock per component.** Every table is only read and changed under a lock, so a token is never
  taken twice and never lost. The locks are not one per table but one per component: the `ConnectionGuard`
  has one for its table of connections and calls a `TokenBucketTable` that has its own; the
  `AuthBanManager` has one for both its table of failed logins and its table of bans; the `PacketGate` has
  one for the dedupe table and its per-node `TokenBucketTable` has its own; the `ClientRateTable` has its
  own; and the claims of the client ids are locked on the claim dictionary.
- **The packet filter is pure.** It takes a topic and a payload and returns a verdict: no state, no lock,
  and it never throws (a failure is a drop, not an exception).
- **The rules of the filters file are immutable.** The broker holds one reference to the set of rules and
  replaces it in one step when the file changes, so a packet that is judged at that moment sees the old
  rules or the new ones, never a mix, and the readers never lock.
- **The crypto is per call.** The AES-CTR of the channel decryption creates its own `Aes` instance
  instead of sharing a static cipher, because two packets that decrypt at the same time, on two
  connections, would corrupt each other with a shared one.
- **The claims are sequenced.** Every CONNECT gets a token with a growing number, so a late event (a
  `ClientConnected` that arrives after the client was already replaced) cannot overwrite a newer claim.
- **The log is written outside the locks.** The Warning of a ban is written after the lock of the tables
  is released, so a slow log cannot hold up the other logins.
- **The counters are concurrent.** The drop counters are a concurrent dictionary, and the summary takes
  the counts out and resets them, so a count is never lost and never counted twice.
- **The clocks are monotonic.** Every rate, window and ban is computed from a `TimeProvider` (the
  monotonic tick count), so a wall-clock step (NTP) neither extends nor cuts a budget. The tests drive it
  with a fake clock and never sleep.

## Future ideas

The ideas that were on the list of the README of the first versions, kept here so that they are not
lost:

- "Zero hopping" certain packets
- Blocking or rate-limiting certain portnums
- Fail2ban style connection moderation (per-IP bans are in this version; a ban list shared between
  brokers is not)
- Banning from known bad actors list

## See also

- [Security](security.md): the authentication and the ACLs.
- [Packet filtering](packet-filtering.md): what the publish hook accepts.
- [Filters](filters.md): the rules of the file that drops the packets of a user, a gateway or a node.
- [Limits and dedupe](limits-and-dedupe.md): the tables and their caps.
