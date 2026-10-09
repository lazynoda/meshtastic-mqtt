using System.Buffers;
using System.Net;
using System.Security.Cryptography;
using MQTTnet.Formatter;
using MQTTnet.Packets;
using MQTTnet.Protocol;
using MQTTnet.Server;
using Serilog;

namespace Meshtastic.Mqtt;

/// <summary>The three MQTTnet hooks: connect (auth), subscribe (ACL), publish (packet filter).</summary>
/// <remarks>
/// Every handler catches its own exceptions and fails closed. Logs never contain passwords or
/// message payloads; client-supplied strings are trimmed before logging.
///
/// Log levels: authentication failures and refused connections are Warning, one line per attempt with
/// username and IP (fail2ban reads them). A refused SUBSCRIBE is one Warning per packet. Dropped publishes are
/// Debug per packet, plus an Information summary per drop reason every 60 s (see <see cref="DropCounters"/>).
/// </remarks>
public sealed class BrokerHooks
{
    /// <summary>
    /// SessionItems key holding the user that authenticated when the session was created. MQTTnet reuses a
    /// session (subscriptions included) on a CleanSession=false reconnect and reports the user of the CONNECT
    /// that created it, so the subscribe ACL is evaluated against this bound owner, never against the request.
    /// </summary>
    internal const string OwnerKey = "meshtastic-mqtt.owner";

    /// <summary>SessionItems key holding the claim token of the CONNECT that created the session.</summary>
    internal const string ClaimTokenKey = "meshtastic-mqtt.claim";

    /// <summary>
    /// How long a client id stays reserved for a user that passed authentication but has not finished connecting.
    /// Covers the gap between the connect hook and MQTTnet creating the session. Settable for tests.
    /// </summary>
    internal TimeSpan PendingClaimLifetime { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// A sweep of the claim table runs on the first insert after this many inserts, or after
    /// <see cref="PendingClaimLifetime"/> has passed since the last sweep, whichever comes first.
    /// </summary>
    internal const int SweepEveryInserts = 64;

    readonly ILogger _log;
    readonly Authenticator _authenticator;
    readonly PacketInspector _inspector;
    readonly Dictionary<string, IReadOnlyCollection<string>> _subscribeAllow = new(StringComparer.Ordinal);

    // Client id -> user owning it, mirroring MQTTnet's session store. A claim is taken (pending) when a CONNECT
    // passes authentication, marked connected when MQTTnet reports the client connected, and removed when its
    // session is deleted.
    // - SessionDeleted releases the claim that tracks the deleted session (same token), and any same-user claim
    //   that is still pending: MQTTnet reuses the old session (and its token) on a CleanSession=false reconnect,
    //   so a reconnect that dies before ClientConnected ends with the old session's token and a pending claim of
    //   the same user, which the vanished session no longer protects.
    // - ClientConnected runs after the CONNACK, so the client it reports may already have been replaced or have
    //   died. Tokens are sequenced: it never overwrites a newer connected claim, and it takes its own claim back
    //   when the session it was attached to is no longer the server's session for the id.
    // - Safety net for whatever neither event covers (persistent sessions expire lazily, without an event): on
    //   insert, every SweepEveryInserts inserts or once per PendingClaimLifetime, claims older than the lifetime
    //   whose id has no session in the server are removed. A conflicting CONNECT also replaces such a claim at
    //   once, so no client id is ever locked out for good.
    // Bound: sessions in the server + claims taken in the last PendingClaimLifetime + SweepEveryInserts.
    readonly Dictionary<string, ClientIdClaim> _claims = new(StringComparer.Ordinal);
    int _insertsSinceSweep;
    long _lastSweepTicks = Environment.TickCount64;
    MqttServer? _server;

    // CreatedTicks is Environment.TickCount64 (monotonic): a wall-clock step does not age or rejuvenate claims.
    sealed record ClientIdClaim(string User, ClaimToken Token, long CreatedTicks, bool Connected);

    /// <summary>Identity of one accepted CONNECT; a later CONNECT always has a higher sequence.</summary>
    sealed class ClaimToken
    {
        static long _last;
        public readonly long Sequence = Interlocked.Increment(ref _last);
    }

    public BrokerHooks(BrokerConfig config, ILogger log, int? maxConcurrentKdf = null, DropCounters? drops = null)
    {
        _log = log;
        var users = config.Users ?? [];
        var limits = config.Limits ?? new LimitsConfig();
        _authenticator = new Authenticator(users, maxConcurrentKdf,
            TimeSpan.FromSeconds(limits.AuthQueueTimeoutSeconds ?? LimitsConfig.DefaultAuthQueueTimeoutSeconds),
            limits.AuthMaxPending ?? LimitsConfig.DefaultAuthMaxPending,
            limits.AuthMaxPendingPerUser ?? LimitsConfig.DefaultAuthMaxPendingPerUser);
        _inspector = new PacketInspector(config);
        Drops = drops ?? new DropCounters(log, start: false);
        foreach (var user in users)
            _subscribeAllow[user.Username] = (user.SubscribeAllow ?? []).ToArray();
    }

    internal DropCounters Drops { get; }

    internal Authenticator Authenticator => _authenticator;

    /// <summary>Points session lookups at <paramref name="server"/> without subscribing to its events (for tests).</summary>
    internal void UseServerForLookups(MqttServer server) => _server = server;

    public void Attach(MqttServer server)
    {
        _server = server;
        server.ValidatingConnectionAsync += ValidateConnectionAsync;
        server.ClientConnectedAsync += OnClientConnectedAsync;
        server.SessionDeletedAsync += OnSessionDeletedAsync;
        server.InterceptingInboundPacketAsync += InterceptInboundPacketAsync;
        server.InterceptingSubscriptionAsync += InterceptSubscriptionAsync;
        server.InterceptingPublishAsync += InterceptPublishAsync;
    }

    public async Task ValidateConnectionAsync(ValidatingConnectionEventArgs args)
    {
        var remoteIp = "unknown";
        try
        {
            remoteIp = (args.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? args.RemoteEndPoint?.ToString() ?? "unknown";

            // MQTT 5 requires the server to accept an empty client id and assign one (3.1.1 lets the server
            // refuse it, and MQTTnet does). Assign it up front so a bad password still reports as such.
            if (string.IsNullOrEmpty(args.ClientId) && args.ProtocolVersion == MqttProtocolVersion.V500)
                args.AssignedClientIdentifier = "auto-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
            if (!string.IsNullOrEmpty(args.AuthenticationMethod))
            {
                args.ReasonCode = MqttConnectReasonCode.BadAuthenticationMethod;
                _log.Warning("Connection refused: unsupported authentication method {AuthMethod} for user {Username} from {RemoteIp}",
                    Trim(args.AuthenticationMethod), Trim(args.UserName), remoteIp);
                return;
            }

            // MQTTnet does not expose a per-connection token here (args.CancellationToken is the server's);
            // the authenticator's own queue timeout bounds the wait instead.
            var auth = await _authenticator.AuthenticateAsync(args.UserName, args.RawPassword, args.CancellationToken).ConfigureAwait(false);
            if (auth == AuthResult.Busy)
            {
                // Not an authentication failure (the password was not checked), so worded differently for fail2ban.
                args.ReasonCode = MqttConnectReasonCode.ServerBusy;
                _log.Warning("Connection refused: password check queue full, retry later (user {Username} from {RemoteIp}, client {ClientId})",
                    Trim(args.UserName), remoteIp, Trim(args.ClientId));
                return;
            }
            if (auth != AuthResult.Success)
            {
                args.ReasonCode = MqttConnectReasonCode.BadUserNameOrPassword;
                _log.Warning("Authentication failed for user {Username} from {RemoteIp} (client {ClientId})",
                    Trim(args.UserName), remoteIp, Trim(args.ClientId));
                return;
            }

            // An empty 3.1.1 client id is refused by MQTTnet after this hook; there is nothing to claim.
            var clientId = args.AssignedClientIdentifier ?? args.ClientId;
            if (!string.IsNullOrEmpty(clientId))
            {
                var token = await TryClaimClientIdAsync(clientId, args.UserName!).ConfigureAwait(false);
                if (token is null)
                {
                    args.ReasonCode = MqttConnectReasonCode.ClientIdentifierNotValid;
                    _log.Warning("Connection refused: client id {ClientId} belongs to a session of another user (user {Username} from {RemoteIp})",
                        Trim(clientId), Trim(args.UserName), remoteIp);
                    return;
                }
                // Only used when MQTTnet creates a new session; a reused session keeps its own (same) owner.
                args.SessionItems[OwnerKey] = args.UserName;
                args.SessionItems[ClaimTokenKey] = token;
            }

            args.ReasonCode = MqttConnectReasonCode.Success;
            _log.Information("Client {ClientId} connected as {Username} from {RemoteIp}",
                Trim(args.AssignedClientIdentifier ?? args.ClientId), args.UserName, remoteIp);
        }
        catch (Exception ex)
        {
            args.ReasonCode = MqttConnectReasonCode.UnspecifiedError;
            _log.Error("Connection check failed for user {Username} from {RemoteIp} (client {ClientId}): {Error}",
                Trim(args.UserName), remoteIp, Trim(args.ClientId), ex.GetType().Name);
        }
    }

    /// <summary>
    /// Reserves <paramref name="clientId"/> for <paramref name="user"/> and returns the claim token, or null if
    /// the id belongs to another user whose session exists (connected or persisted) or whose connect is still in
    /// progress. Same-user takeover is always allowed.
    /// </summary>
    async Task<ClaimToken?> TryClaimClientIdAsync(string clientId, string user)
    {
        var token = new ClaimToken();
        ClientIdClaim? seen;
        bool sweep;
        lock (_claims)
        {
            if (!_claims.TryGetValue(clientId, out seen) || seen.User == user)
            {
                sweep = Insert(clientId, new ClientIdClaim(user, token, Environment.TickCount64, false));
                seen = null;
            }
            else
            {
                sweep = false;
            }
        }

        if (seen is not null)
        {
            // Held by another user: only a dead claim (its session is gone) may be replaced.
            var alive = await SessionExistsAsync(clientId).ConfigureAwait(false);
            lock (_claims)
            {
                if (!_claims.TryGetValue(clientId, out var current) || !ReferenceEquals(current, seen))
                    return null;   // changed while we looked; the client retries
                if (alive || (!current.Connected && !IsStale(current, Environment.TickCount64)))
                    return null;
                sweep = Insert(clientId, new ClientIdClaim(user, token, Environment.TickCount64, false));
            }
        }

        if (sweep)
        {
            try
            {
                await SweepAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Housekeeping must not refuse a login; the next sweep will try again.
                _log.Debug("Claim sweep skipped: {Error}", ex.GetType().Name);
            }
        }
        return token;
    }

    bool IsStale(ClientIdClaim claim, long now) => now - claim.CreatedTicks >= (long)PendingClaimLifetime.TotalMilliseconds;

    /// <summary>Stores a claim and says whether a sweep is due (see <see cref="SweepEveryInserts"/>). Caller holds the lock.</summary>
    bool Insert(string clientId, ClientIdClaim claim)
    {
        _claims[clientId] = claim;
        if (++_insertsSinceSweep < SweepEveryInserts && claim.CreatedTicks - _lastSweepTicks < (long)PendingClaimLifetime.TotalMilliseconds)
            return false;
        _insertsSinceSweep = 0;
        _lastSweepTicks = claim.CreatedTicks;
        return true;
    }

    /// <summary>
    /// Removes every claim older than <see cref="PendingClaimLifetime"/> whose client id has no session in the server,
    /// pending or connected. Younger claims are left alone: they may be in the gap between the connect hook and the
    /// session being created.
    /// </summary>
    async Task SweepAsync()
    {
        var sessions = new HashSet<string>(StringComparer.Ordinal);
        if (_server is not null)
        {
            foreach (var session in await _server.GetSessionsAsync().ConfigureAwait(false))
                sessions.Add(session.Id);
        }
        int swept, left;
        lock (_claims)
        {
            var now = Environment.TickCount64;
            List<string>? stale = null;
            foreach (var (id, c) in _claims)
            {
                if (IsStale(c, now) && !sessions.Contains(id))
                    (stale ??= []).Add(id);
            }
            if (stale is null)
                return;
            foreach (var id in stale)
                _claims.Remove(id);
            swept = stale.Count;
            left = _claims.Count;
        }
        _log.Debug("Swept {Swept} client id claim(s) without a session; {Claims} reserved", swept, left);
    }

    /// <summary>Whether MQTTnet holds a live or persisted, non-expired session for the client id.</summary>
    async Task<bool> SessionExistsAsync(string clientId)
    {
        if (_server is null)
            return true;   // not attached: fail closed
        foreach (var session in await _server.GetSessionsAsync().ConfigureAwait(false))
        {
            if (session.Id != clientId)
                continue;
            // Same expiry rule as MQTTnet's MqttSessionsStorage.TryGetSession(), which drops expired sessions
            // lazily and without a SessionDeleted event.
            var expires = session.ExpiryInterval is > 0 and < uint.MaxValue && session.DisconnectedTimestamp.HasValue;
            return !expires || DateTime.UtcNow <= session.DisconnectedTimestamp!.Value.AddSeconds(session.ExpiryInterval);
        }
        return false;
    }

    internal async Task OnClientConnectedAsync(ClientConnectedEventArgs args)
    {
        try
        {
            var owner = args.SessionItems?[OwnerKey] as string;
            if (owner is not null && owner == args.UserName)
            {
                // Mark the claim connected with the session's token (an older one when a CleanSession=false reconnect
                // reused the session, so that SessionDeleted can match it later). The claim is (re)written rather than
                // only updated because a SessionDeleted for this user's previous session may have released the pending
                // claim while this connect was in flight. A connected claim with a newer token belongs to a later
                // CONNECT for this id and is left alone: this event runs after the CONNACK, so the client it reports
                // may already have been taken over.
                if (args.SessionItems![ClaimTokenKey] is not ClaimToken sessionToken)
                    return;
                lock (_claims)
                {
                    if (!_claims.TryGetValue(args.ClientId, out var claim)
                        || (claim.User == owner && (!claim.Connected || claim.Token.Sequence <= sessionToken.Sequence)))
                    {
                        _claims[args.ClientId] = new ClientIdClaim(owner, sessionToken, Environment.TickCount64, true);
                    }
                }
                // The client may also have died already (its session deleted and SessionDeleted fired before the
                // write above). A claim written after that would have nothing left to release it, so it is taken back
                // unless the session this connection was attached to is still the server's session for the id.
                if (!await IsCurrentSessionAsync(args.ClientId, args.SessionItems).ConfigureAwait(false))
                {
                    lock (_claims)
                    {
                        if (_claims.TryGetValue(args.ClientId, out var claim) && ReferenceEquals(claim.Token, sessionToken))
                            _claims.Remove(args.ClientId);
                    }
                }
                return;
            }

            // Defence in depth: a connection attached to a session of another user (only possible through a race
            // in session handling) is cut before its receive and send loops start.
            _log.Error("Client {ClientId} ({Username}) was attached to a session owned by {Owner}; disconnecting it",
                Trim(args.ClientId), Trim(args.UserName), Trim(owner));
            if (_server is not null)
            {
                await _server.DisconnectClientAsync(args.ClientId,
                    new MqttServerClientDisconnectOptions { ReasonCode = MqttDisconnectReasonCode.NotAuthorized }).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _log.Error("Connected-client check failed for client {ClientId}: {Error}", Trim(args.ClientId), ex.GetType().Name);
        }
    }

    /// <summary>Whether the server's session for the client id is the one holding <paramref name="items"/>.</summary>
    async Task<bool> IsCurrentSessionAsync(string clientId, System.Collections.IDictionary items)
    {
        if (_server is null)
            return true;
        foreach (var session in await _server.GetSessionsAsync().ConfigureAwait(false))
        {
            if (session.Id == clientId)
                return ReferenceEquals(session.Items, items);
        }
        return false;
    }

    internal Task OnSessionDeletedAsync(SessionDeletedEventArgs args)
    {
        var token = args.SessionItems?[ClaimTokenKey] as ClaimToken;
        lock (_claims)
        {
            if (args.Id is null || !_claims.TryGetValue(args.Id, out var claim))
                return Task.CompletedTask;
            // Token match: the session the claim tracked. Same-user pending claim: a reconnect of the owner that
            // reused this session and died before ClientConnected; nothing is left to protect. Same-user connected
            // claim no newer than the deleted session's connect: its own session was replaced without an event and
            // the replacement has now gone too. A newer connected same-user claim has a session of its own and stays.
            var release = ReferenceEquals(claim.Token, token)
                || (claim.User == args.UserName && (!claim.Connected || (token is not null && claim.Token.Sequence <= token.Sequence)));
            if (!release)
                return Task.CompletedTask;
            _claims.Remove(args.Id);
            _log.Debug("Client id {ClientId} released by {Username}; {Claims} reserved", Trim(args.Id), Trim(args.UserName), _claims.Count);
        }
        return Task.CompletedTask;
    }

    /// <summary>Number of client ids currently reserved (for tests).</summary>
    internal int ClaimCount
    {
        get
        {
            lock (_claims)
                return _claims.Count;
        }
    }

    /// <summary>Whether the client id is currently reserved (for tests).</summary>
    internal bool HasClaim(string clientId)
    {
        lock (_claims)
            return _claims.ContainsKey(clientId);
    }

    /// <summary>
    /// Sees each SUBSCRIBE once, before MQTTnet asks <see cref="InterceptSubscriptionAsync"/> about every filter in
    /// it, and logs refused filters as one line per packet (a single SUBSCRIBE can carry thousands of filters).
    /// The decision itself is taken per filter by the same function in <see cref="InterceptSubscriptionAsync"/>.
    /// </summary>
    public Task InterceptInboundPacketAsync(InterceptingPacketEventArgs args)
    {
        try
        {
            if (args.Packet is not MqttSubscribePacket subscribe)
                return Task.CompletedTask;
            var owner = args.SessionItems?[OwnerKey] as string;
            var refused = 0;
            string? first = null;
            string? firstReason = null;
            foreach (var topicFilter in subscribe.TopicFilters)
            {
                var (code, reason) = Evaluate(owner, topicFilter.Topic);
                if (code is null)
                    continue;
                refused++;
                first ??= topicFilter.Topic;
                firstReason ??= reason;
            }
            if (refused > 0)
            {
                _log.Warning("Subscribe refused for {Username} (client {ClientId}): {Refused} of {Total} filter(s), first {Filter}: {Reason}",
                    Trim(owner ?? args.UserName), Trim(args.ClientId), refused, subscribe.TopicFilters.Count, Trim(first), firstReason);
            }
        }
        catch (Exception ex)
        {
            _log.Error("Subscribe logging failed for client {ClientId}: {Error}", Trim(args.ClientId), ex.GetType().Name);
        }
        return Task.CompletedTask;
    }

    /// <summary>Null code = allowed; otherwise the refusal reason code and text.</summary>
    (MqttSubscribeReasonCode? Code, string Reason) Evaluate(string? owner, string? filter)
    {
        if (!TopicFilter.IsValid(filter, out _))
            return (MqttSubscribeReasonCode.TopicFilterInvalid, "invalid topic filter");
        var allow = owner is not null && _subscribeAllow.TryGetValue(owner, out var list) ? list : [];
        return TopicFilter.IsAllowed(allow, filter) ? (null, "allowed") : (MqttSubscribeReasonCode.NotAuthorized, "not in subscribe_allow");
    }

    public Task InterceptSubscriptionAsync(InterceptingSubscriptionEventArgs args)
    {
        try
        {
            var filter = args.TopicFilter?.Topic;
            // The user bound to the session at connect time, not args.UserName (see OwnerKey).
            var owner = args.SessionItems?[OwnerKey] as string;
            var (code, reason) = Evaluate(owner, filter);
            if (code is not null)
            {
                Deny(args, code.Value, reason);
                return Task.CompletedTask;
            }

            args.ProcessSubscription = true;
            _log.Information("Subscription {Filter} granted to {Username} (client {ClientId})",
                Trim(filter), owner, Trim(args.ClientId));
        }
        catch (Exception ex)
        {
            Deny(args, MqttSubscribeReasonCode.UnspecifiedError, ex.GetType().Name);
        }
        return Task.CompletedTask;
    }

    void Deny(InterceptingSubscriptionEventArgs args, MqttSubscribeReasonCode code, string reason)
    {
        args.ProcessSubscription = false;
        args.Response.ReasonCode = code;
        // The per-packet Warning is written by InterceptInboundPacketAsync.
        _log.Debug("Subscription {Filter} refused for {Username} (client {ClientId}): {Reason}",
            Trim(args.TopicFilter?.Topic), Trim(args.UserName), Trim(args.ClientId), reason);
    }

    public Task InterceptPublishAsync(InterceptingPublishEventArgs args)
    {
        try
        {
            var message = args.ApplicationMessage;
            var topic = message?.Topic;
            var payload = message is null ? [] : message.Payload.ToArray();
            var result = _inspector.Inspect(topic, payload);

            if (!result.Accepted)
            {
                args.ProcessPublish = false;
                Drops.Increment(result.Reason);
                _log.Debug("Dropped publish on {Topic} from {ClientId}: {Reason} (from {From}, id {PacketId})",
                    Trim(topic), Trim(args.ClientId), result.Reason, NodeId(result.From), result.PacketId);
                return Task.CompletedTask;
            }

            // Firmware never publishes retained packets. Refusing retain keeps public publishers from
            // filling the retained-message store with one entry per topic they invent.
            message!.Retain = false;
            args.ProcessPublish = true;
            _log.Debug("Accepted publish on {Topic} from {ClientId}: {Reason} (from {From}, id {PacketId}, portnum {Portnum})",
                Trim(topic), Trim(args.ClientId), result.Reason, NodeId(result.From), result.PacketId, result.Portnum);
            if (result.ChannelHashMatches == false)
            {
                _log.Debug("Channel hash mismatch on {Topic}: packet hash differs from the configured key for {Channel}",
                    Trim(topic), result.Channel);
            }
        }
        catch (Exception ex)
        {
            args.ProcessPublish = false;
            Drops.Increment("internal error");
            _log.Error("Publish check failed for client {ClientId}: {Error}", Trim(args.ClientId), ex.GetType().Name);
        }
        return Task.CompletedTask;
    }

    static string NodeId(uint node) => $"!{node:x8}";

    /// <summary>Bounds and de-controls client-supplied strings before they reach the log.</summary>
    internal static string Trim(string? value, int max = 128)
    {
        if (value is null)
            return "(none)";
        var clean = new string(value.Select(c => char.IsControl(c) ? '?' : c).Take(max).ToArray());
        return value.Length > max ? clean + "…" : clean;
    }
}
