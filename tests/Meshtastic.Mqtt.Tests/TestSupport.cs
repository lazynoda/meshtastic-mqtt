using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using MQTTnet;
using MQTTnet.Formatter;
using Serilog.Core;
using Serilog.Events;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

/// <summary>Shared plumbing for the tests that run a real broker on a loopback port.</summary>
static class TestSupport
{
    public const string AlicePassword = "correct-horse";

    public static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    /// <summary>meshdev (firmware default password) and alice (downlink on the lower-case `test` channel and on `Test`).</summary>
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

    public sealed class LogSink : ILogEventSink
    {
        public ConcurrentQueue<LogEvent> Events { get; } = new();
        public void Emit(LogEvent logEvent) => Events.Enqueue(logEvent);
    }
}

/// <summary>Timing- and memory-sensitive tests run alone, after the parallel ones.</summary>
[CollectionDefinition("Isolated", DisableParallelization = true)]
public sealed class IsolatedCollection;
