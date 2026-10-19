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
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The limits over the network: a refused publish never reaches a subscriber and never disconnects the
/// publisher, the per-IP connection cap closes the socket at once, and a flood of logins from one address
/// cannot keep a cold login from another address out.
/// </summary>
/// <remarks>
/// Isolated: the auth-flood test measures how long a cold login takes, and the password hashing it has to
/// wait for is CPU-bound, so it must not compete with the other suites.
/// </remarks>
[Collection("Isolated")]
public sealed class LimitNetworkTests
{
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
            password_hash: "{AuthTests.MeshdevHash}"
            publish_allow: ["msh/EU_868/2/e/#", "msh/EU_868/2/map/"]
          - username: alice
            password_hash: "{AuthTests.AliceHash}"
            subscribe_allow: ["msh/#"]
        {limits}
        """);

    /// <summary>Starts a broker with the given limits, runs the test and stops the broker again.</summary>
    async Task Run(string limits, Func<MqttServer, ConnectionGuard, LogSink, Task> test)
    {
        var logs = new LogSink();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger();
        var built = TestBroker.CreateBuilt(Config(_port, limits), logger);
        await built.Server.StartAsync();
        try
        {
            await test(built.Server, built.Listener.Guard, logs);
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

    async Task<(IMqttClient Client, ConcurrentQueue<string> Received)> Connect(int port, string user, string password,
        string clientId, MqttProtocolVersion version = MqttProtocolVersion.V311)
    {
        var received = new ConcurrentQueue<string>();
        var client = new MqttClientFactory().CreateMqttClient();
        client.ApplicationMessageReceivedAsync += e =>
        {
            received.Enqueue(e.ApplicationMessage.Topic);
            return Task.CompletedTask;
        };
        var result = await client.ConnectAsync(ClientOptions(port, user, password, clientId, version), Ct);
        Assert.Equal(MqttClientConnectResultCode.Success, result.ResultCode);
        return (client, received);
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

    static Task<MqttClientPublishResult> Publish(IMqttClient client, string topic, byte[] payload) =>
        client.PublishAsync(new MqttApplicationMessageBuilder().WithTopic(topic).WithPayload(payload)
            .WithQualityOfServiceLevel(MqttQualityOfServiceLevel.AtLeastOnce).Build(), Ct);

    /// <summary>
    /// Opens a connection the broker is expected to refuse at the accept. The connect itself may fail (the
    /// broker closes the socket before the handshake is over) or the socket may be closed right after.
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
        return await ClosedByServer(socket, 5);
    }

    // ---- A refused publish ----------------------------------------------------------------------------------

    [Fact]
    public async Task ARefusedPublish_NeverReachesASubscriber_AndThePublisherStaysConnected()
    {
        await Run("limits:\n  max_connections_per_ip: 0\n  connect_rate_per_ip_per_minute: 0", async (server, _, _) =>
        {
            var (dashboard, received) = await Connect(_port, "alice", AlicePassword, "dash-1");
            var sub = await dashboard.SubscribeAsync(new MqttClientSubscribeOptionsBuilder().WithTopicFilter("msh/#").Build(), Ct);
            Assert.Equal(MqttClientSubscribeResultCode.GrantedQoS0, Assert.Single(sub.Items).ResultCode);

            var (publisher, _) = await Connect(_port, "meshdev", "large4cats", "!1a2b3c4d", MqttProtocolVersion.V500);

            // The first packet goes through.
            await Publish(publisher, "msh/EU_868/2/e/SFNarrow/!1a2b3c4d", PublishFilterTests.Fixture("sfnarrow_aq.bin"));
            Assert.True(await WaitUntil(() => received.Count == 1), "the first packet was not delivered");

            // The same packet again: the dedupe drops it and the subscriber sees nothing.
            await Publish(publisher, "msh/EU_868/2/e/SFNarrow/!1a2b3c4d", PublishFilterTests.Fixture("sfnarrow_aq.bin"));
            await Task.Delay(300, Ct);
            Assert.Single(received);
            Assert.True(publisher.IsConnected);

            // A payload over the cap is dropped too, and the publisher is still connected.
            var tooBig = await Publish(publisher, "msh/EU_868/2/e/SFNarrow/!1a2b3c4d", new byte[600]);
            await Task.Delay(300, Ct);
            Assert.Single(received);
            Assert.True(publisher.IsConnected);
            Assert.NotEqual(MqttClientPublishReasonCode.Success, tooBig.ReasonCode);
        });
    }

    [Fact]
    public async Task ARefusedPublish_OverThePerClientRate_AnswersQuotaExceeded_AndKeepsTheClient()
    {
        var limits = "limits:\n  max_connections_per_ip: 0\n  connect_rate_per_ip_per_minute: 0\n"
                   + "  publish_rate_per_client_per_minute: 60\n  publish_burst_per_client: 1";
        await Run(limits, async (server, _, _) =>
        {
            var (dashboard, received) = await Connect(_port, "alice", AlicePassword, "dash-2");
            await dashboard.SubscribeAsync(new MqttClientSubscribeOptionsBuilder().WithTopicFilter("msh/#").Build(), Ct);
            var (publisher, _) = await Connect(_port, "meshdev", "large4cats", "!1a2b3c4d", MqttProtocolVersion.V500);

            var first = await Publish(publisher, "msh/EU_868/2/e/SFNarrow/!1a2b3c4d", PublishFilterTests.Fixture("sfnarrow_aq.bin"));
            Assert.Equal(MqttClientPublishReasonCode.Success, first.ReasonCode);
            Assert.True(await WaitUntil(() => received.Count == 1));

            // The per-client rate of this broker is one publish, so the next one is refused.
            var refused = await Publish(publisher, "msh/EU_868/2/e/Test/!1a2b3c4d", PublishFilterTests.Fixture("test_ag.bin"));
            Assert.Equal(MqttClientPublishReasonCode.QuotaExceeded, refused.ReasonCode);
            await Task.Delay(300, Ct);
            Assert.Single(received);
            Assert.True(publisher.IsConnected);
            Assert.Single(await server.GetClientsAsync(), c => c.Id == "!1a2b3c4d");
        });
    }

    // ---- The per-IP limits ----------------------------------------------------------------------------------

    [Fact]
    public async Task OverTheConnectionCap_TheSocketIsClosedAtOnce()
    {
        var limits = "limits:\n  max_connections_per_ip: 2\n  connect_rate_per_ip_per_minute: 0";
        await Run(limits, async (_, guard, _) =>
        {
            var (first, _) = await Connect(_port, "meshdev", "large4cats", "!cap00001");
            var (second, _) = await Connect(_port, "meshdev", "large4cats", "!cap00002");
            Assert.Equal(2, guard.ConnectionsFor("127.0.0.1"));

            // The third connection never gets a CONNACK: the socket is closed on accept.
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Assert.True(await RefusedAtAccept(socket), "the refused connection was not closed");
            Assert.Equal(2, guard.ConnectionsFor("127.0.0.1"));
            await first.DisconnectAsync(cancellationToken: Ct);
            await second.DisconnectAsync(cancellationToken: Ct);

            // The slots are free again, so the same address may connect once more.
            Assert.True(await WaitUntil(() => guard.ConnectionsFor("127.0.0.1") == 0),
                $"the connection counter leaked: {guard.ConnectionsFor("127.0.0.1")}");
            var (third, _) = await Connect(_port, "meshdev", "large4cats", "!cap00003");
            Assert.Equal(1, guard.ConnectionsFor("127.0.0.1"));
            await third.DisconnectAsync(cancellationToken: Ct);
        });
    }

    [Fact]
    public async Task TheConnectionCounter_ReturnsToZero_WhenTheClientsClose()
    {
        var limits = "limits:\n  max_connections_per_ip: 4\n  connect_rate_per_ip_per_minute: 0";
        await Run(limits, async (_, guard, _) =>
        {
            var (first, _) = await Connect(_port, "meshdev", "large4cats", "!close0001");
            var (second, _) = await Connect(_port, "meshdev", "large4cats", "!close0002");
            Assert.Equal(2, guard.ConnectionsFor("127.0.0.1"));

            await first.DisconnectAsync(cancellationToken: Ct);
            await second.DisconnectAsync(cancellationToken: Ct);
            Assert.True(await WaitUntil(() => guard.ConnectionsFor("127.0.0.1") == 0),
                $"the connection counter leaked: {guard.ConnectionsFor("127.0.0.1")}");
        });
    }

    [Fact]
    public async Task TheConnectionCounter_ReturnsToZero_AfterAFailedLogin()
    {
        var limits = "limits:\n  max_connections_per_ip: 4\n  connect_rate_per_ip_per_minute: 0";
        await Run(limits, async (_, guard, _) =>
        {
            // The error path: the broker refuses the CONNECT and closes the connection.
            var client = new MqttClientFactory().CreateMqttClient();
            var result = await client.ConnectAsync(ClientOptions(_port, "meshdev", "not-the-password", "!fail0001"), Ct);
            Assert.NotEqual(MqttClientConnectResultCode.Success, result.ResultCode);

            Assert.True(await WaitUntil(() => guard.ConnectionsFor("127.0.0.1") == 0),
                $"the connection counter leaked: {guard.ConnectionsFor("127.0.0.1")}");
        });
    }

    [Fact]
    public async Task TheConnectionCounter_ReturnsToZero_AfterASocketIsReset()
    {
        // The error path: the client is reset abruptly (RST) after a successful CONNACK.
        var limits = "limits:\n  max_connections_per_ip: 4\n  connect_rate_per_ip_per_minute: 0";
        await Run(limits, async (_, guard, _) =>
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, _port), Ct);
            await socket.SendAsync(RawConnect("!rst00001", "meshdev", "large4cats"), SocketFlags.None, Ct);
            var buffer = new byte[4];
            var read = 0;
            while (read < buffer.Length)
            {
                var n = await socket.ReceiveAsync(buffer.AsMemory(read), SocketFlags.None, Ct);
                if (n == 0)
                    break;
                read += n;
            }
            Assert.Equal(4, read);
            Assert.Equal(0x20, buffer[0]);          // CONNACK
            Assert.Equal(1, guard.ConnectionsFor("127.0.0.1"));

            socket.LingerState = new LingerOption(true, 0);   // close() sends RST instead of FIN
            socket.Close();

            Assert.True(await WaitUntil(() => guard.ConnectionsFor("127.0.0.1") == 0),
                $"the connection counter leaked: {guard.ConnectionsFor("127.0.0.1")}");
        });
    }

    [Fact]
    public async Task TheConnectionCounter_ReturnsToZero_AfterTheSizeGuardClosesTheConnection()
    {
        // The error path: a packet that announces more than limits.max_packet_size, so the size guard
        // closes the connection.
        var limits = "limits:\n  max_connections_per_ip: 4\n  connect_rate_per_ip_per_minute: 0";
        await Run(limits, async (_, guard, logs) =>
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, _port), Ct);
            await socket.SendAsync(new byte[] { 0x10, 0xFF, 0xFF, 0xFF, 0x7F, 0x00 }, SocketFlags.None, Ct);

            // The log line proves that the connection was accepted and handled by the size guard.
            Assert.True(await WaitUntil(() => logs.Events.Any(e => e.RenderMessage().Contains("max_packet_size"))),
                "the size guard did not close the connection");
            Assert.True(await WaitUntil(() => guard.ConnectionsFor("127.0.0.1") == 0),
                $"the connection counter leaked: {guard.ConnectionsFor("127.0.0.1")}");
        });
    }

    [Fact]
    public async Task TheConnectionCounter_ReturnsToZero_AfterASocketThatSaysNothing()
    {
        // The error path: a socket that connects and goes away without sending a byte. The socket is kept
        // open until the broker has accepted it, so the test knows the slot was really taken.
        var limits = "limits:\n  max_connections_per_ip: 4\n  connect_rate_per_ip_per_minute: 0";
        await Run(limits, async (_, guard, _) =>
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, _port), Ct);
            Assert.True(await WaitUntil(() => guard.ConnectionsFor("127.0.0.1") == 1),
                "the connection was not accepted");
            socket.Close();

            Assert.True(await WaitUntil(() => guard.ConnectionsFor("127.0.0.1") == 0),
                $"the connection counter leaked: {guard.ConnectionsFor("127.0.0.1")}");
        });
    }

    [Fact]
    public async Task OverTheConnectRate_TheSocketIsClosedAtOnce()
    {
        var limits = "limits:\n  max_connections_per_ip: 0\n  connect_rate_per_ip_per_minute: 30\n  connect_burst_per_ip: 2";
        await Run(limits, async (_, _, logs) =>
        {
            var (first, _) = await Connect(_port, "meshdev", "large4cats", "!rate0001");
            var (second, _) = await Connect(_port, "meshdev", "large4cats", "!rate0002");

            // The third connection is over the burst: it is closed on accept.
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            Assert.True(await RefusedAtAccept(socket), "the refused connection was not closed");

            Assert.True(await WaitUntil(() => logs.Events.Any(e => e.RenderMessage().Contains(ConnectionGuard.ConnectRateReason))),
                "the refused connection was not logged");
            await first.DisconnectAsync(cancellationToken: Ct);
            await second.DisconnectAsync(cancellationToken: Ct);
        });
    }

    // ---- The single-IP auth flood ---------------------------------------------------------------------------

    [Fact]
    public async Task ASingleIpAuthFlood_DoesNotKeepAColdLoginFromAnotherAddressOut()
    {
        // The flood comes from 127.0.0.1 with the public credentials; the cold login comes from 127.0.0.2
        // (another loopback address). The per-IP connect rate cuts the flood at the accept, before it can
        // fill the password-hashing queue of the real meshdev user. The bans of phase 4 are off here: this
        // test is about the connect rate, and a ban would cut the flood for another reason.
        var limits = "limits:\n  max_connections_per_ip: 0\n  connect_rate_per_ip_per_minute: 30\n  connect_burst_per_ip: 10\n  auth_fail_max_per_ip: 0";
        await Run(limits, async (_, _, logs) =>
        {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            var attempts = 0;
            var sockets = new List<Socket>();
            var flood = Task.Run(async () =>
            {
                var n = 0;
                while (!stop.IsCancellationRequested)
                {
                    Interlocked.Increment(ref attempts);
                    await FloodAttempt(sockets, $"flood-{n++}");
                }
            });

            await Task.Delay(300, Ct);

            var watch = System.Diagnostics.Stopwatch.StartNew();
            var accepted = await ColdLoginFromAnotherAddress();
            var elapsed = watch.ElapsedMilliseconds;
            stop.Cancel();
            await flood;
            foreach (var s in sockets)
                s.Dispose();

            var refused = logs.Events.Count(e => e.RenderMessage().Contains(ConnectionGuard.ConnectRateReason));
            TestContext.Current.SendDiagnosticMessage(
                $"flood attempts={attempts} refused at accept={refused} cold login={elapsed} ms");
            Assert.True(accepted, "the cold login from the other address was refused");
            Assert.True(elapsed < 2000, $"the cold login took {elapsed} ms (bound 2000 ms)");

            // The flood was cut at the accept: most of its attempts never reached the broker.
            Assert.True(attempts > 20, $"the flood only made {attempts} attempts");
            Assert.True(refused > 0, "the flood was not cut at the accept");
        });
    }

    /// <summary>
    /// One guess: a TCP connection that sends a CONNECT with a wrong password. The socket is kept open (the
    /// broker reads the CONNECT and answers it), so the guess really reaches the password check.
    /// </summary>
    async Task FloodAttempt(List<Socket> sockets, string clientId)
    {
        try
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, _port), Ct);
            await socket.SendAsync(RawConnect(clientId, "meshdev", "guess-me-not"), SocketFlags.None, Ct);
            lock (sockets)
                sockets.Add(socket);
        }
        catch (Exception)
        {
            // The broker closes the refused connections; that is the point of the flood.
        }
    }

    /// <summary>A cold meshdev login from 127.0.0.2, over a raw socket bound to that address.</summary>
    async Task<bool> ColdLoginFromAnotherAddress()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Parse("127.0.0.2"), 0));
        await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, _port), Ct);
        await using var stream = new NetworkStream(socket);
        await stream.WriteAsync(RawConnect("!cold0001", "meshdev", "large4cats"), Ct);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        var buffer = new byte[4];
        try
        {
            await stream.ReadExactlyAsync(buffer, timeout.Token);
        }
        catch (Exception)
        {
            return false;
        }
        return buffer[0] == 0x20 && buffer[3] == 0x00;   // CONNACK, return code 0 (accepted)
    }

    /// <summary>A raw MQTT 3.1.1 CONNECT packet (no will, keep-alive 60).</summary>
    static byte[] RawConnect(string clientId, string user, string password)
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
        body.Add(4);
        body.Add(0xC2);      // user name, password, clean session
        body.Add(0);
        body.Add(60);
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
}
