using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Meshtastic.Mqtt;
using MQTTnet;
using MQTTnet.Formatter;
using MQTTnet.Protocol;
using MQTTnet.Server;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The bans over the network: a banned address is closed at the accept, a connection accepted before the
/// ban is refused with "banned" (0x8A) without its password ever being checked, and the sessions that
/// were already connected are left alone.
/// </summary>
/// <remarks>
/// Isolated: the wrong logins pay a PBKDF2 each, so this suite must not compete with the other ones for
/// the CPU.
/// </remarks>
[Collection("Isolated")]
public sealed class AuthBanNetworkTests : IAsyncLifetime
{
    // A 100k-iteration hash of "large4cats" (the cheapest the broker accepts): the ten wrong logins of
    // these tests must not cost ten 600k-iteration hashes.
    const string FastMeshdevHash = "pbkdf2-sha256$100000$XyucR9HoOmBCt8nV4fA4Kg==$NOeVPAEswGliE8M1fvOj8e9fmJUP1+0Jz9VWbZSU6Po=";

    readonly int _port = FreePort();

    static CancellationToken Ct => TestContext.Current.CancellationToken;

    static BrokerConfig Config(int port, string limits = "") => ConfigLoader.Parse($"""
        listener:
          bind_address: 127.0.0.1
          port: {port}
        channels:
          Test: "Ag=="
        users:
          - username: meshdev
            password_hash: "{FastMeshdevHash}"
            publish_allow: [msh/ES/2/e/#]
          - username: alice
            password_hash: "{AuthTests.AliceHash}"
            subscribe_allow: [msh/ES/2/e/Test/#]
        {limits}
        """);

    /// <summary>
    /// The bans are on; the connect rate is off, so only the ban (and not the rate) can refuse a
    /// connection. The connection cap stays on: the tests look at its counter to prove that a banned
    /// connection takes no slot.
    /// </summary>
    const string BanLimits = """
        limits:
          max_connections_per_ip: 16
          connect_rate_per_ip_per_minute: 0
          auth_fail_max_per_ip: 10
          auth_fail_window_seconds: 600
          auth_ban_seconds: 3600
        """;

    /// <summary>
    /// How long the broker may take to close a connection it refuses at the accept: it refuses it
    /// before it reads a single byte, so the close must arrive at once (a second, not five).
    /// </summary>
    const double RefusedCloseTimeoutSeconds = 1;

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    /// <summary>Starts a broker with the given limits, runs the test and stops the broker again.</summary>
    async Task Run(string limits, Func<BrokerServer.Built, LogSink, Task> test)
    {
        var logs = new LogSink();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger();
        var built = TestBroker.CreateBuilt(Config(_port, limits), logger);
        await built.Server.StartAsync();
        try
        {
            await test(built, logs);
        }
        catch (Exception ex) when (ex is not Xunit.Sdk.XunitException)
        {
            var events = string.Join(" | ", logs.Events.TakeLast(15).Select(e => e.RenderMessage()));
            Assert.Fail($"unexpected {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}\nbroker log: {events}");
        }
        finally
        {
            await built.Server.StopAsync();
            built.Server.Dispose();
        }
    }

    async Task<MqttClientConnectResult> Connect(string user, string password, string clientId)
    {
        using var client = new MqttClientFactory().CreateMqttClient();
        return await client.ConnectAsync(ClientOptions(_port, user, password, clientId), Ct);
    }

    /// <summary>A client that stays connected until the caller disposes it.</summary>
    async Task<IMqttClient> ConnectAndKeep(string user, string password, string clientId)
    {
        var client = new MqttClientFactory().CreateMqttClient();
        var result = await client.ConnectAsync(ClientOptions(_port, user, password, clientId), Ct);
        Assert.Equal(MqttClientConnectResultCode.Success, result.ResultCode);
        return client;
    }

    /// <summary>True once the server closed the connection (end of stream or a reset).</summary>
    static async Task<bool> ClosedByServer(Socket socket, double seconds)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(seconds));
        var buffer = new byte[64];
        try
        {
            while (true)
            {
                if (await socket.ReceiveAsync(buffer, SocketFlags.None, timeout.Token) == 0)
                    return true;
            }
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (SocketException)
        {
            return true;
        }
    }

    /// <summary>
    /// Opens a connection the broker is expected to refuse at the accept. The connect itself may fail (the
    /// broker closes the socket before the handshake is over) or the socket may be closed right after.
    /// The close must arrive at once: the broker refuses the connection before it reads a single byte.
    /// </summary>
    async Task<bool> RefusedAtAccept(Socket socket)
    {
        try
        {
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, _port), Ct);
        }
        catch (SocketException)
        {
            return true;   // the broker refused it before the handshake was complete
        }
        return await ClosedByServer(socket, RefusedCloseTimeoutSeconds);
    }

    /// <summary>
    /// A raw CONNECT from a socket bound to <paramref name="localIp"/>; returns the reason code of the
    /// CONNACK (0 = accepted, 0x8A = banned).
    /// </summary>
    async Task<int> RawConnectFrom(string localIp, string clientId, string user, string password, bool v5 = false)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Parse(localIp), 0));
        await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, _port), Ct);
        await socket.SendAsync(ConnectPacket(clientId, user, password, v5), SocketFlags.None, Ct);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        var buffer = new byte[8];
        var read = 0;
        while (read < 4)
        {
            var n = await socket.ReceiveAsync(buffer.AsMemory(read), SocketFlags.None, timeout.Token);
            if (n == 0)
                break;
            read += n;
        }
        Assert.True(read >= 4, "the broker did not answer the CONNECT");
        Assert.Equal(0x20, buffer[0]);   // CONNACK
        return buffer[3];                // the reason code (the same place in MQTT 3.1.1 and MQTT 5)
    }

    /// <summary>A raw MQTT CONNECT packet (no will, keep-alive 60).</summary>
    static byte[] ConnectPacket(string clientId, string user, string password, bool v5)
    {
        var body = new List<byte>();
        void Str(string s)
        {
            var bytes = Encoding.UTF8.GetBytes(s);
            body.Add((byte)(bytes.Length >> 8));
            body.Add((byte)bytes.Length);
            body.AddRange(bytes);
        }
        Str("MQTT");
        body.Add(v5 ? (byte)5 : (byte)4);
        body.Add(0xC2);      // user name, password, clean session
        body.Add(0);
        body.Add(60);
        if (v5)
            body.Add(0x00);  // no properties
        Str(clientId);
        Str(user);
        Str(password);
        var packet = new List<byte> { 0x10 };
        var x = body.Count;
        do
        {
            var digit = (byte)(x % 128);
            x /= 128;
            packet.Add(x > 0 ? (byte)(digit | 0x80) : digit);
        } while (x > 0);
        packet.AddRange(body);
        return [.. packet];
    }

    // ---- The tests -----------------------------------------------------------------------------------------

    [Fact]
    public async Task TenWrongPasswords_CloseTheNextConnectionAtOnce_AndAnotherAddressLogsIn()
    {
        await Run(BanLimits, async (built, logs) =>
        {
            // Ten wrong passwords from 127.0.0.1: the tenth one bans the address.
            for (var i = 0; i < 10; i++)
            {
                var result = await Connect("meshdev", $"wrong-{i}", $"flood-{i}");
                Assert.NotEqual(MqttClientConnectResultCode.Success, result.ResultCode);
            }
            Assert.True(built.Bans.IsBanned("127.0.0.1"), "the address was not banned");
            Assert.Single(logs.Events, e => e.Level == LogEventLevel.Warning
                && e.MessageTemplate.Text.StartsWith("Banned")
                && e.Properties["RemoteIp"].ToString().Contains("127.0.0.1"));

            // The eleventh connection is closed at once, before a single MQTT byte is read.
            Assert.True(await WaitUntil(() => built.Listener.Guard.ConnectionsFor("127.0.0.1") == 0),
                "the connections of the flood leaked");
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Assert.True(await RefusedAtAccept(socket), "the banned connection was not closed");
            Assert.Equal(0, built.Listener.Guard.ConnectionsFor("127.0.0.1"));   // it took no slot and no token
            Assert.True(logs.Events.Any(e => e.RenderMessage().Contains(AuthBanManager.BannedIpReason)),
                "the refusal was not logged");
            Assert.True(built.Hooks.Drops.Snapshot().ContainsKey(AuthBanManager.BannedIpReason),
                "the refusal was not counted");

            // Another address is not affected: it logs in as meshdev.
            Assert.Equal(0, await RawConnectFrom("127.0.0.2", "!other001", "meshdev", "large4cats"));
        });
    }

    [Fact]
    public async Task AConnectionAcceptedBeforeTheBan_GetsBanned_AndItsPasswordIsNeverChecked()
    {
        await Run(BanLimits, async (built, _) =>
        {
            // A connection accepted before the ban: the accept check passed, the CONNECT comes later.
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, _port), Ct);
            Assert.True(await WaitUntil(() => built.Listener.Guard.ConnectionsFor("127.0.0.1") == 1),
                "the connection was not accepted");

            // The address is banned by ten wrong logins.
            for (var i = 0; i < 10; i++)
                await Connect("meshdev", $"wrong-{i}", $"flood-{i}");
            Assert.True(built.Bans.IsBanned("127.0.0.1"));
            var kdfRuns = built.Hooks.Authenticator.KdfRuns;

            // Now the held connection sends its CONNECT (MQTT 5): it is refused with "banned" (0x8A).
            await socket.SendAsync(ConnectPacket("held-1", "meshdev", "large4cats", v5: true), SocketFlags.None, Ct);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            var buffer = new byte[8];
            var read = 0;
            while (read < 4)
            {
                var n = await socket.ReceiveAsync(buffer.AsMemory(read), SocketFlags.None, timeout.Token);
                if (n == 0)
                    break;
                read += n;
            }
            Assert.True(read >= 4, "the broker did not answer the CONNECT");
            Assert.Equal(0x20, buffer[0]);   // CONNACK
            Assert.Equal(0x8A, buffer[3]);   // Banned
            Assert.Equal(kdfRuns, built.Hooks.Authenticator.KdfRuns);   // the password was never checked
        });
    }

    [Fact]
    public async Task ASessionConnectedBeforeTheBan_StaysConnectedAndCanPublish()
    {
        await Run(BanLimits, async (built, _) =>
        {
            var received = new ConcurrentQueue<string>();
            using var dashboard = new MqttClientFactory().CreateMqttClient();
            dashboard.ApplicationMessageReceivedAsync += e =>
            {
                received.Enqueue(e.ApplicationMessage.Topic);
                return Task.CompletedTask;
            };
            var dash = await dashboard.ConnectAsync(ClientOptions(_port, "alice", AlicePassword, "dash-1"), Ct);
            Assert.Equal(MqttClientConnectResultCode.Success, dash.ResultCode);
            var sub = await dashboard.SubscribeAsync(
                new MqttClientSubscribeOptionsBuilder().WithTopicFilter("msh/ES/2/e/Test/#").Build(), Ct);
            Assert.Equal(MqttClientSubscribeResultCode.GrantedQoS0, Assert.Single(sub.Items).ResultCode);

            using var node = new MqttClientFactory().CreateMqttClient();
            var nodeResult = await node.ConnectAsync(ClientOptions(_port, "meshdev", "large4cats", "!node0001"), Ct);
            Assert.Equal(MqttClientConnectResultCode.Success, nodeResult.ResultCode);

            // The address is banned: the sessions that were already connected are left alone.
            for (var i = 0; i < 10; i++)
                await Connect("meshdev", $"wrong-{i}", $"flood-{i}");
            Assert.True(built.Bans.IsBanned("127.0.0.1"));
            Assert.True(node.IsConnected, "the session was disconnected by the ban");

            // And it can still publish.
            var published = await node.PublishAsync(new MqttApplicationMessageBuilder()
                .WithTopic("msh/ES/2/e/Test/!1a2b3c4d")
                .WithPayload(PublishFilterTests.Fixture("test_ag.bin"))
                .WithQualityOfServiceLevel(MqttQualityOfServiceLevel.AtLeastOnce).Build(), Ct);
            Assert.Equal(MqttClientPublishReasonCode.Success, published.ReasonCode);
            Assert.True(await WaitUntil(() => received.Count == 1), "the publish did not arrive");
        });
    }

    [Fact]
    public async Task AConnectionRefusedAtTheAccept_IsNotCounted()
    {
        var limits = """
            limits:
              max_connections_per_ip: 1
              connect_rate_per_ip_per_minute: 0
              auth_fail_max_per_ip: 2
            """;
        await Run(limits, async (built, _) =>
        {
            using var client = await ConnectAndKeep("meshdev", "large4cats", "!first001");
            Assert.Equal(1, built.Listener.Guard.ConnectionsFor("127.0.0.1"));

            // The second connection is refused at the accept: it is not a password failure.
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Assert.True(await RefusedAtAccept(socket), "the refused connection was not closed");

            Assert.Equal(0, built.Bans.FailuresFor("127.0.0.1"));
            Assert.False(built.Bans.IsBanned("127.0.0.1"));
        });
    }
}
