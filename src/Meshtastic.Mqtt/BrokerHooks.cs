using System.Buffers;
using System.Net;
using System.Security.Cryptography;
using MQTTnet.Formatter;
using MQTTnet.Protocol;
using MQTTnet.Server;
using Serilog;

namespace Meshtastic.Mqtt;

/// <summary>The three MQTTnet hooks: connect (auth), subscribe (ACL), publish (packet filter).</summary>
/// <remarks>
/// Every handler catches its own exceptions and fails closed. Logs never contain passwords or
/// message payloads; client-supplied strings are trimmed before logging.
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
    const string ClaimTokenKey = "meshtastic-mqtt.claim";

    /// <summary>
    /// How long a client id stays reserved for a user that passed authentication but has not finished connecting.
    /// Covers the gap between the connect hook and MQTTnet creating the session.
    /// </summary>
    static readonly TimeSpan PendingClaimLifetime = TimeSpan.FromSeconds(30);

    readonly ILogger _log;
    readonly Authenticator _authenticator;
    readonly PacketInspector _inspector;
    readonly Dictionary<string, IReadOnlyCollection<string>> _subscribeAllow = new(StringComparer.Ordinal);

    // Client id -> user owning it, mirroring MQTTnet's session store. A claim is taken when a CONNECT passes
    // authentication and removed when its session is deleted (SessionDeleted, matched by token so that a late
    // event for an old session cannot drop a newer claim). A claim whose session has vanished without an event
    // (persistent sessions expire lazily) is detected on the next conflicting CONNECT and replaced, so a client
    // id can never be locked out for good. Bounded by the number of sessions, not by what clients send.
    readonly Dictionary<string, ClientIdClaim> _claims = new(StringComparer.Ordinal);
    MqttServer? _server;

    sealed record ClientIdClaim(string User, object Token, DateTime CreatedUtc, bool Connected);

    public BrokerHooks(BrokerConfig config, ILogger log, int? maxConcurrentKdf = null)
    {
        _log = log;
        var users = config.Users ?? [];
        _authenticator = new Authenticator(users, maxConcurrentKdf);
        _inspector = new PacketInspector(config);
        foreach (var user in users)
            _subscribeAllow[user.Username] = (user.SubscribeAllow ?? []).ToArray();
    }

    public void Attach(MqttServer server)
    {
        _server = server;
        server.ValidatingConnectionAsync += ValidateConnectionAsync;
        server.ClientConnectedAsync += OnClientConnectedAsync;
        server.SessionDeletedAsync += OnSessionDeletedAsync;
        server.InterceptingSubscriptionAsync += InterceptSubscriptionAsync;
        server.InterceptingPublishAsync += InterceptPublishAsync;
    }

    public async Task ValidateConnectionAsync(ValidatingConnectionEventArgs args)
    {
        try
        {
            var remoteIp = (args.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? args.RemoteEndPoint?.ToString() ?? "unknown";

            // MQTT 5 requires the server to accept an empty client id and assign one (3.1.1 lets the server
            // refuse it, and MQTTnet does). Assign it up front so a bad password still reports as such.
            if (string.IsNullOrEmpty(args.ClientId) && args.ProtocolVersion == MqttProtocolVersion.V500)
                args.AssignedClientIdentifier = "auto-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
            if (!string.IsNullOrEmpty(args.AuthenticationMethod))
            {
                args.ReasonCode = MqttConnectReasonCode.BadAuthenticationMethod;
                _log.Warning("Connection refused: unsupported authentication method {AuthMethod} from {RemoteIp}",
                    Trim(args.AuthenticationMethod), remoteIp);
                return;
            }

            if (!await _authenticator.AuthenticateAsync(args.UserName, args.RawPassword, args.CancellationToken).ConfigureAwait(false))
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
            _log.Error("Connection check failed for client {ClientId}: {Error}", Trim(args.ClientId), ex.GetType().Name);
        }
    }

    /// <summary>
    /// Reserves <paramref name="clientId"/> for <paramref name="user"/> and returns the claim token, or null if
    /// the id belongs to another user whose session exists (connected or persisted) or whose connect is still in
    /// progress. Same-user takeover is always allowed.
    /// </summary>
    async Task<object?> TryClaimClientIdAsync(string clientId, string user)
    {
        var token = new object();
        ClientIdClaim? seen;
        lock (_claims)
        {
            if (!_claims.TryGetValue(clientId, out seen) || seen.User == user)
            {
                _claims[clientId] = new ClientIdClaim(user, token, DateTime.UtcNow, false);
                return token;
            }
        }

        // Held by another user: only a dead claim (its session is gone) may be replaced.
        var alive = await SessionExistsAsync(clientId).ConfigureAwait(false);
        lock (_claims)
        {
            if (!_claims.TryGetValue(clientId, out var current) || !ReferenceEquals(current, seen))
                return null;   // changed while we looked; the client retries
            if (alive || (!current.Connected && DateTime.UtcNow - current.CreatedUtc < PendingClaimLifetime))
                return null;
            _claims[clientId] = new ClientIdClaim(user, token, DateTime.UtcNow, false);
            return token;
        }
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

    async Task OnClientConnectedAsync(ClientConnectedEventArgs args)
    {
        try
        {
            var owner = args.SessionItems?[OwnerKey] as string;
            if (owner is not null && owner == args.UserName)
            {
                // The session in use may be an older one (CleanSession=false reuse): track its token.
                var sessionToken = args.SessionItems![ClaimTokenKey];
                lock (_claims)
                {
                    if (sessionToken is not null && _claims.TryGetValue(args.ClientId, out var claim) && claim.User == owner)
                        _claims[args.ClientId] = claim with { Token = sessionToken, Connected = true };
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

    Task OnSessionDeletedAsync(SessionDeletedEventArgs args)
    {
        var token = args.SessionItems?[ClaimTokenKey];
        lock (_claims)
        {
            if (args.Id is not null && token is not null && _claims.TryGetValue(args.Id, out var claim) && ReferenceEquals(claim.Token, token))
                _claims.Remove(args.Id);
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

    public Task InterceptSubscriptionAsync(InterceptingSubscriptionEventArgs args)
    {
        try
        {
            var filter = args.TopicFilter?.Topic;
            if (!TopicFilter.IsValid(filter, out _))
            {
                Deny(args, MqttSubscribeReasonCode.TopicFilterInvalid, "invalid topic filter");
                return Task.CompletedTask;
            }

            // The user bound to the session at connect time, not args.UserName (see OwnerKey).
            var owner = args.SessionItems?[OwnerKey] as string;
            var allow = owner is not null && _subscribeAllow.TryGetValue(owner, out var list) ? list : [];
            if (!TopicFilter.IsAllowed(allow, filter))
            {
                Deny(args, MqttSubscribeReasonCode.NotAuthorized, "not in subscribe_allow");
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
        _log.Warning("Subscription {Filter} refused for {Username} (client {ClientId}): {Reason}",
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
                _log.Information("Dropped publish on {Topic} from {ClientId}: {Reason} (from {From}, id {PacketId})",
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
