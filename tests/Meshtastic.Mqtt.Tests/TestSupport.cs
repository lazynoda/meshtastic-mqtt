using System.Collections;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using MQTTnet;
using MQTTnet.Formatter;
using MQTTnet.Server;
using Serilog.Core;
using Serilog.Events;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

/// <summary>Shared plumbing for the tests that run a real broker on a loopback port.</summary>
static class TestSupport
{
    public const string AlicePassword = "correct-horse";

    /// <summary>
    /// The per-IP limits, turned off. The tests that open many connections at once (the password-queue
    /// tests, the claim-table tests) are not about these limits, and the default values would refuse
    /// connections they need.
    /// </summary>
    public const string PerIpLimitsOff = "limits:\n  max_connections_per_ip: 0\n  connect_rate_per_ip_per_minute: 0";

    /// <summary>
    /// The per-IP limits and the auth bans, turned off. The password-queue tests flood the broker with
    /// wrong logins from one address, and the ban of phase 4 would cut that flood short (and refuse the
    /// legitimate logins that follow it). Those tests are about the queue, not about the bans.
    /// </summary>
    public const string PerIpLimitsAndBansOff = "limits:\n  max_connections_per_ip: 0\n  connect_rate_per_ip_per_minute: 0\n  auth_fail_max_per_ip: 0";

    public static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    /// <summary>
    /// meshdev (firmware default password) and alice (downlink on the lower-case `test` channel and on `Test`).
    /// The phase-1 tests publish under msh/ES, so meshdev may publish there; the publish ACL itself is tested on the
    /// production root msh/EU_868 in PublishAclTests.
    /// </summary>
    public static BrokerConfig Config(int port, string extra = "") => ConfigLoader.Parse($"""
        listener:
          bind_address: 127.0.0.1
          port: {port}
        channels:
          Test: "Ag=="
          Valencia: "VA=="
        users:
          - username: meshdev
            password_hash: "{AuthTests.MeshdevHash}"
            publish_allow: [msh/ES/2/e/#]
          - username: alice
            password_hash: "{AuthTests.AliceHash}"
            subscribe_allow: [msh/ES/2/e/test/#, msh/ES/2/e/Test/#]
        {extra}
        """);

    public static MqttClientOptions ClientOptions(int port, string user, string password, string clientId,
        MqttProtocolVersion version = MqttProtocolVersion.V311, bool cleanSession = true, uint sessionExpiry = 0)
    {
        var builder = new MqttClientOptionsBuilder()
            .WithTcpServer("127.0.0.1", port)
            .WithClientId(clientId)
            .WithCredentials(user, password)
            .WithProtocolVersion(version)
            .WithCleanSession(cleanSession)
            .WithTimeout(TimeSpan.FromSeconds(10));
        if (sessionExpiry > 0)
            builder = builder.WithSessionExpiryInterval(sessionExpiry);
        return builder.Build();
    }

    public static async Task<bool> WaitUntil(Func<bool> condition, double seconds = 5)
    {
        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        while (!condition() && DateTime.UtcNow < deadline)
            await Task.Delay(50, TestContext.Current.CancellationToken);
        return condition();
    }

    /// <summary>
    /// Just enough of a publish to call the publish hook directly. The owner is the user bound to the session
    /// at connect time (the identity the ACLs use), and it is null when the session has no owner.
    /// </summary>
    public static InterceptingPublishEventArgs PublishArgs(string topic, byte[] payload, string userName, string? owner)
    {
        var items = new Hashtable();
        if (owner is not null)
            items[BrokerHooks.OwnerKey] = owner;
        var message = new MqttApplicationMessageBuilder().WithTopic(topic).WithPayload(payload).Build();
        return new InterceptingPublishEventArgs(message, "node-1", userName, items, CancellationToken.None);
    }

    public sealed class LogSink : ILogEventSink
    {
        public ConcurrentQueue<LogEvent> Events { get; } = new();
        public void Emit(LogEvent logEvent) => Events.Enqueue(logEvent);
    }
}

/// <summary>
/// A monotonic clock the tests drive by hand: the rate limits never sleep, they only read the clock.
/// </summary>
public sealed class FakeClock : TimeProvider
{
    long _ticks;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override long GetTimestamp() => _ticks;

    public override DateTimeOffset GetUtcNow() => new(_ticks, TimeSpan.Zero);

    /// <summary>Moves the clock forward.</summary>
    public void Advance(TimeSpan by) => _ticks += (long)(by.Ticks * TimestampFrequency / TimeSpan.TicksPerSecond);
}

/// <summary>Timing- and memory-sensitive tests run alone, after the parallel ones.</summary>
[CollectionDefinition("Isolated", DisableParallelization = true)]
public sealed class IsolatedCollection;
