using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using MQTTnet;
using MQTTnet.Protocol;
using MQTTnet.Server;
using Serilog;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// Review finding B2: an unauthenticated client must not make the broker allocate the Remaining Length it
/// announces. Packets above limits.max_packet_size (default 4096) are cut at the fixed header.
/// </summary>
[Collection("Isolated")]
public sealed class PacketSizeLimitTests : IAsyncLifetime
{
    readonly int _port = FreePort();
    readonly LogSink _logs = new();
    MqttServer _server = null!;

    public async ValueTask InitializeAsync()
    {
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(_logs).CreateLogger();
        _server = TestBroker.Create(Config(_port), logger);
        await _server.StartAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await _server.StopAsync();
        _server.Dispose();
    }

    static CancellationToken Ct => TestContext.Current.CancellationToken;

    static long CommittedBytes()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        return GC.GetGCMemoryInfo().TotalCommittedBytes;
    }

    async Task<Socket> Open()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, _port), Ct);
        return socket;
    }

    /// <summary>True once the server has closed the connection (read returns 0 or the socket errors).</summary>
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

    [Fact]
    public async Task HugeRemainingLength_BeforeAuth_DoesNotAllocate()
    {
        // The reviewer's repro: CONNECT announcing 268 435 455 bytes, then silence.
        var before = CommittedBytes();
        var sockets = new List<Socket>();
        for (var i = 0; i < 8; i++)
        {
            var s = await Open();
            await s.SendAsync(new byte[] { 0x10, 0xFF, 0xFF, 0xFF, 0x7F, 0x00 }, SocketFlags.None, Ct);
            sockets.Add(s);
        }
        await Task.Delay(1500, Ct);
        var after = CommittedBytes();
        var growthMb = (after - before) / (1024.0 * 1024);
        TestContext.Current.SendDiagnosticMessage($"B2 committed before={before / 1048576}MB after={after / 1048576}MB growth={growthMb:F1}MB (8 sockets)");
        try
        {
            Assert.True(growthMb < 64, $"committed memory grew by {growthMb:F1} MB for 8 hostile sockets");
            foreach (var s in sockets)
                Assert.True(await ClosedByServer(s, 5), "the oversized connection must be closed");
        }
        finally
        {
            foreach (var s in sockets)
                s.Dispose();
        }
    }

    [Fact]
    public async Task OversizedPacket_ClosesTheConnection_EvenAfterAuth()
    {
        var client = new MqttClientFactory().CreateMqttClient();
        await client.ConnectAsync(ClientOptions(_port, "meshdev", "large4cats", "!big00001"), Ct);
        Assert.True(client.IsConnected);

        try
        {
            await client.PublishAsync(new MqttApplicationMessageBuilder().WithTopic("msh/ES/2/e/Test/!big00001")
                .WithPayload(new byte[5000]).WithQualityOfServiceLevel(MqttQualityOfServiceLevel.AtLeastOnce).Build(), Ct);
        }
        catch (Exception)
        {
            // The broker closes the socket instead of acknowledging; either outcome below is fine.
        }
        Assert.True(await WaitUntil(() => !client.IsConnected), "a 5000-byte packet must close the connection");
        Assert.Contains(_logs.Events, e => e.RenderMessage().Contains("max_packet_size"));
    }

    [Fact]
    public async Task PacketJustUnderTheLimit_StillPasses()
    {
        // A PUBLISH whose Remaining Length is exactly 4096 (2 + topic + 2 packet id + payload) is accepted.
        const string topic = "msh/ES/2/e/Test/!1a2b3c4d";
        var payloadLength = 4096 - 2 - topic.Length - 2;
        var client = new MqttClientFactory().CreateMqttClient();
        await client.ConnectAsync(ClientOptions(_port, "meshdev", "large4cats", "!near0001"), Ct);
        var result = await client.PublishAsync(new MqttApplicationMessageBuilder().WithTopic(topic)
            .WithPayload(new byte[payloadLength]).WithQualityOfServiceLevel(MqttQualityOfServiceLevel.AtLeastOnce).Build(), Ct);
        Assert.True(result.IsSuccess);   // PUBACK received (the filter drops it as malformed, but the transport carried it)
        await Task.Delay(200, Ct);
        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task SilentSocket_IsClosedAfterTheCommunicationTimeout()
    {
        // limits.communication_timeout_seconds (default 10): a socket that never sends CONNECT is closed,
        // instead of MQTTnet's default 100 s.
        using var s = await Open();
        var watch = Stopwatch.StartNew();
        Assert.True(await ClosedByServer(s, 20), "a silent socket must be closed");
        TestContext.Current.SendDiagnosticMessage($"B2 silent socket closed after {watch.Elapsed.TotalSeconds:F1}s");
        Assert.InRange(watch.Elapsed.TotalSeconds, 5, 20);
    }
}
