using System.Buffers;
using System.Net;
using System.Security.Cryptography;
using MQTTnet.Formatter;
using MQTTnet.Protocol;
using MQTTnet.Server;
using Serilog;

namespace Meshtastic.Mqtt;

/// <summary>MQTTnet hooks: connect (auth) and subscribe (ACL).</summary>
/// <remarks>
/// Every handler catches its own exceptions and fails closed. Logs never contain passwords or
/// message payloads; client-supplied strings are trimmed before logging.
/// </remarks>
public sealed class BrokerHooks
{
    readonly ILogger _log;
    readonly Authenticator _authenticator;
    readonly Dictionary<string, IReadOnlyCollection<string>> _subscribeAllow = new(StringComparer.Ordinal);

    public BrokerHooks(BrokerConfig config, ILogger log, int? maxConcurrentKdf = null)
    {
        _log = log;
        var users = config.Users ?? [];
        _authenticator = new Authenticator(users, maxConcurrentKdf);
        foreach (var user in users)
            _subscribeAllow[user.Username] = (user.SubscribeAllow ?? []).ToArray();
    }

    public void Attach(MqttServer server)
    {
        server.ValidatingConnectionAsync += ValidateConnectionAsync;
        server.InterceptingSubscriptionAsync += InterceptSubscriptionAsync;
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

            var allow = args.UserName is not null && _subscribeAllow.TryGetValue(args.UserName, out var list) ? list : [];
            if (!TopicFilter.IsAllowed(allow, filter))
            {
                Deny(args, MqttSubscribeReasonCode.NotAuthorized, "not in subscribe_allow");
                return Task.CompletedTask;
            }

            args.ProcessSubscription = true;
            _log.Information("Subscription {Filter} granted to {Username} (client {ClientId})",
                Trim(filter), args.UserName, Trim(args.ClientId));
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

    /// <summary>Bounds and de-controls client-supplied strings before they reach the log.</summary>
    internal static string Trim(string? value, int max = 128)
    {
        if (value is null)
            return "(none)";
        var clean = new string(value.Select(c => char.IsControl(c) ? '?' : c).Take(max).ToArray());
        return value.Length > max ? clean + "…" : clean;
    }
}
