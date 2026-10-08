using System.Collections;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Meshtastic.Mqtt;
using MQTTnet;
using MQTTnet.Adapter;
using MQTTnet.Formatter;
using MQTTnet.Packets;
using MQTTnet.Protocol;
using MQTTnet.Server;
using Serilog;
using Serilog.Events;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The hooks wired into a real MQTTnet server on a loopback port, driven by a real MQTT client.
/// </summary>
public sealed class BrokerIntegrationTests : IAsyncLifetime
{
    readonly int _port = FreePort();
    readonly LogSink _logs = new();
    BrokerConfig _config = null!;
    MqttServer _server = null!;
    Action _flushDrops = null!;

    public async ValueTask InitializeAsync()
    {
        _config = ConfigLoader.Parse($"""
            listener:
              bind_address: 127.0.0.1
              port: {_port}
            channels:
              Test: "Ag=="
              Valencia: "VA=="
            users:
              - username: meshdev
                password_hash: "{AuthTests.MeshdevHash}"
              - username: alice
                password_hash: "{AuthTests.AliceHash}"
                subscribe_allow: [msh/ES/2/e/test/#, msh/ES/2/e/Test/#]
            """);
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(_logs).CreateLogger();
        (_server, _flushDrops) = TestBroker.CreateWithHooks(_config, logger);
        await _server.StartAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await _server.StopAsync();
        _server.Dispose();
    }

    static CancellationToken Ct => TestContext.Current.CancellationToken;

    async Task<(IMqttClient Client, MqttClientConnectResult Result)> Connect(string user, string password, string clientId,
        MqttProtocolVersion version = MqttProtocolVersion.V311)
    {
        var client = new MqttClientFactory().CreateMqttClient();
        return (client, await client.ConnectAsync(ClientOptions(_port, user, password, clientId, version), Ct));
    }

    static async Task<MqttClientSubscribeResultCode> Subscribe(IMqttClient client, string filter)
    {
        var result = await client.SubscribeAsync(new MqttClientSubscribeOptionsBuilder().WithTopicFilter(filter).Build(), Ct);
        return Assert.Single(result.Items).ResultCode;
    }

    async Task<(IMqttClient Sub, ConcurrentQueue<string> Received)> Subscriber(params string[] filters)
    {
        var received = new ConcurrentQueue<string>();
        var (sub, _) = await Connect("alice", AlicePassword, "dash-1");
        sub.ApplicationMessageReceivedAsync += e =>
        {
            received.Enqueue(e.ApplicationMessage.Topic + " " + e.ApplicationMessage.Payload.Length + " retain=" + e.ApplicationMessage.Retain);
            return Task.CompletedTask;
        };
        foreach (var filter in filters)
            Assert.Equal(MqttClientSubscribeResultCode.GrantedQoS0, await Subscribe(sub, filter));
        return (sub, received);
    }

    async Task<Func<string, string, bool, Task>> Publisher()
    {
        var (pub, _) = await Connect("meshdev", "large4cats", "node-1");
        return async (topic, fixture, retain) =>
            await pub.PublishAsync(new MqttApplicationMessageBuilder().WithTopic(topic)
                    .WithPayload(PublishFilterTests.Fixture(fixture)).WithRetainFlag(retain)
                    .WithQualityOfServiceLevel(MqttQualityOfServiceLevel.AtLeastOnce).Build(), Ct);
    }

    static async Task Settle(ConcurrentQueue<string> received)
    {
        await WaitUntil(() => !received.IsEmpty);
        await Task.Delay(300, Ct);
    }

    [Fact]
    public async Task WrongPassword_IsRefused_AndLoggedWithoutThePassword()
    {
        var (_, result) = await Connect("meshdev", "not-the-password-xyz", "node-1");
        Assert.Equal(MqttClientConnectResultCode.BadUserNameOrPassword, result.ResultCode);

        var (_, unknown) = await Connect("mallory", "large4cats", "node-2");
        Assert.Equal(MqttClientConnectResultCode.BadUserNameOrPassword, unknown.ResultCode);

        // fail2ban (phase 4) reads these: Warning, one line per attempt, with username and IP.
        var failure = Assert.Single(_logs.Events, e => e.MessageTemplate.Text.StartsWith("Authentication failed")
                                                       && e.Properties["Username"].ToString().Contains("meshdev"));
        Assert.Equal(LogEventLevel.Warning, failure.Level);
        Assert.Contains("127.0.0.1", failure.Properties["RemoteIp"].ToString());
        Assert.Single(_logs.Events, e => e.MessageTemplate.Text.StartsWith("Authentication failed")
                                         && e.Properties["Username"].ToString().Contains("mallory"));
        Assert.DoesNotContain(_logs.Events, e => e.RenderMessage().Contains("not-the-password-xyz"));
    }

    [Fact]
    public async Task Meshdev_ConnectsButCannotSubscribe()
    {
        var (client, result) = await Connect("meshdev", "large4cats", "node-1");
        Assert.Equal(MqttClientConnectResultCode.Success, result.ResultCode);
        Assert.Equal(MqttClientSubscribeResultCode.UnspecifiedError, await Subscribe(client, "msh/#"));
        Assert.True(client.IsConnected);
    }

    [Fact]
    public async Task Meshdev_SubscribeRefusal_IsNotAuthorizedOnMqtt5()
    {
        var (client, _) = await Connect("meshdev", "large4cats", "node-1", MqttProtocolVersion.V500);
        Assert.Equal(MqttClientSubscribeResultCode.NotAuthorized, await Subscribe(client, "msh/#"));
        Assert.Equal(MqttClientSubscribeResultCode.NotAuthorized, await Subscribe(client, "msh/ES/2/e/test/#"));
        Assert.Equal(MqttClientSubscribeResultCode.NotAuthorized, await Subscribe(client, "$SYS/#"));
    }

    [Fact]
    public async Task AllowedUser_GetsOnlyItsFilters()
    {
        var (client, result) = await Connect("alice", AlicePassword, "dash-1", MqttProtocolVersion.V500);
        Assert.Equal(MqttClientConnectResultCode.Success, result.ResultCode);
        Assert.Equal(MqttClientSubscribeResultCode.GrantedQoS0, await Subscribe(client, "msh/ES/2/e/test/#"));
        Assert.Equal(MqttClientSubscribeResultCode.NotAuthorized, await Subscribe(client, "msh/#"));
        Assert.Equal(MqttClientSubscribeResultCode.NotAuthorized, await Subscribe(client, "msh/ES/2/e/+/#"));
        Assert.Equal(MqttClientSubscribeResultCode.NotAuthorized, await Subscribe(client, "#"));
    }

    [Fact]
    public async Task ValidPacketReachesSubscriber_GarbageAndChannelIdMismatchDoNot()
    {
        var (_, received) = await Subscriber("msh/ES/2/e/test/#");
        var publish = await Publisher();

        await publish("msh/ES/2/e/test/!1a2b3c4d", "garbage.bin", false);
        await publish("msh/ES/2/e/test/!1a2b3c4d", "test_wrong_key_aq.bin", false);   // channel_id Test != topic test
        await publish("msh/ES/2/e/test/!1a2b3c4d", "test_lower_aq.bin", true);
        await Settle(received);

        var only = Assert.Single(received);
        Assert.StartsWith("msh/ES/2/e/test/!1a2b3c4d 75 retain=False", only);
        Assert.Contains(_logs.Events, e => e.RenderMessage().Contains("channel_id does not match the topic"));
        Assert.DoesNotContain(_logs.Events, e => e.RenderMessage().Contains("fixture-payload"));
    }

    [Fact]
    public async Task WrongKey_WithMatchingChannelAndTopic_IsDroppedAsUndecryptable()
    {
        // channel_id `Test` on topic .../Test/..., but encrypted with AQ== while the broker has Test: Ag==.
        var (_, received) = await Subscriber("msh/ES/2/e/Test/#");
        var publish = await Publisher();

        await publish("msh/ES/2/e/Test/!1a2b3c4d", "test_wrong_key_aq.bin", false);
        await publish("msh/ES/2/e/Test/!1a2b3c4d", "test_ag.bin", false);   // the right key still passes
        await Settle(received);

        var only = Assert.Single(received);
        Assert.StartsWith("msh/ES/2/e/Test/!1a2b3c4d 66 ", only);
        Assert.Contains(_logs.Events, e => e.RenderMessage().Contains("undecryptable with the key configured for this channel"));
    }

    [Fact]
    public async Task AcceptedRetainedPublish_IsNotStored()
    {
        // Live delivery never shows retain (MQTTnet clears it without RetainAsPublished); the retained store is
        // what the retain-clearing line protects.
        var (_, received) = await Subscriber("msh/ES/2/e/Test/#");
        var publish = await Publisher();
        await publish("msh/ES/2/e/Test/!1a2b3c4d", "test_ag.bin", true);
        await Settle(received);

        Assert.Single(received);
        Assert.Empty(await _server.GetRetainedMessagesAsync());
    }

    [Fact]
    public async Task DroppedPublishes_AreDebugPerPacket_AndSummarisedPerReason()
    {
        var publish = await Publisher();
        await publish("msh/ES/2/e/test/!1a2b3c4d", "garbage.bin", false);
        await publish("msh/ES/2/e/test/!1a2b3c4d", "garbage.bin", false);
        await publish("msh/ES/2/e/Test/!1a2b3c4d", "test_wrong_key_aq.bin", false);
        await WaitUntil(() => _logs.Events.Count(e => e.MessageTemplate.Text.StartsWith("Dropped publish")) >= 3);

        var perPacket = _logs.Events.Where(e => e.MessageTemplate.Text.StartsWith("Dropped publish")).ToList();
        Assert.Equal(3, perPacket.Count);
        Assert.All(perPacket, e => Assert.Equal(LogEventLevel.Debug, e.Level));

        _flushDrops();
        var summary = Assert.Single(_logs.Events, e => e.Level == LogEventLevel.Information && e.MessageTemplate.Text.StartsWith("Dropped {Total}"));
        Assert.Equal("3", summary.Properties["Total"].ToString());
        var rendered = summary.RenderMessage();
        Assert.Contains("malformed protobuf", rendered);
        Assert.Contains("undecryptable", rendered);

        // Nothing dropped since: the next summary is silent.
        _flushDrops();
        Assert.Single(_logs.Events, e => e.MessageTemplate.Text.StartsWith("Dropped {Total}"));
    }

    [Fact]
    public async Task RefusedSubscribe_IsOneWarningPerPacket()
    {
        var (client, _) = await Connect("meshdev", "large4cats", "node-1", MqttProtocolVersion.V500);
        var builder = new MqttClientSubscribeOptionsBuilder();
        for (var i = 0; i < 50; i++)
            builder = builder.WithTopicFilter($"msh/ES/2/e/ch{i}/#");
        var result = await client.SubscribeAsync(builder.Build(), Ct);
        Assert.Equal(50, result.Items.Count);
        Assert.All(result.Items, r => Assert.Equal(MqttClientSubscribeResultCode.NotAuthorized, r.ResultCode));

        var warnings = _logs.Events.Where(e => e.Level >= LogEventLevel.Warning && e.RenderMessage().Contains("refused")).ToList();
        var warning = Assert.Single(warnings);
        Assert.Equal("50", warning.Properties["Refused"].ToString());
        Assert.Contains("meshdev", warning.Properties["Username"].ToString());
    }

    [Fact]
    public async Task AuthenticationMethodRefusal_LogsUsernameAndIp()
    {
        var hooks = new BrokerHooks(_config, LoggerFor(_logs));
        var args = Args(new MqttConnectPacket { ClientId = "x", Username = "meshdev", AuthenticationMethod = "SCRAM-SHA-1" }, new FakeAdapter());
        await hooks.ValidateConnectionAsync(args);

        Assert.Equal(MqttConnectReasonCode.BadAuthenticationMethod, args.ReasonCode);
        var line = Assert.Single(_logs.Events, e => e.RenderMessage().Contains("SCRAM-SHA-1"));
        Assert.Contains("meshdev", line.Properties["Username"].ToString());
        Assert.Contains("203.0.113.7", line.Properties["RemoteIp"].ToString());
    }

    [Fact]
    public async Task ConnectCheckException_LogsUsernameAndIp()
    {
        // The adapter throws when the hook asks for the protocol version (empty client id), forcing the catch branch.
        var hooks = new BrokerHooks(_config, LoggerFor(_logs));
        var args = Args(new MqttConnectPacket { ClientId = "", Username = "meshdev" }, new FakeAdapter(throwOnFormatter: true));
        await hooks.ValidateConnectionAsync(args);

        Assert.Equal(MqttConnectReasonCode.UnspecifiedError, args.ReasonCode);
        var line = Assert.Single(_logs.Events, e => e.Level == LogEventLevel.Error);
        Assert.Contains("meshdev", line.Properties["Username"].ToString());
        Assert.Contains("203.0.113.7", line.Properties["RemoteIp"].ToString());
    }

    static ILogger LoggerFor(LogSink sink) => new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(sink).CreateLogger();

    static ValidatingConnectionEventArgs Args(MqttConnectPacket packet, IMqttChannelAdapter adapter) =>
        new(packet, adapter, new Hashtable(), CancellationToken.None);

    [Fact]
    public async Task EmptyClientId_GetsAnAssignedIdOnMqtt5()
    {
        var (client, result) = await Connect("meshdev", "large4cats", "", MqttProtocolVersion.V500);
        Assert.Equal(MqttClientConnectResultCode.Success, result.ResultCode);
        Assert.StartsWith("auto-", result.AssignedClientIdentifier);
        Assert.True(client.IsConnected);

        var (_, bad) = await Connect("meshdev", "wrong", "", MqttProtocolVersion.V500);
        Assert.Equal(MqttClientConnectResultCode.BadUserNameOrPassword, bad.ResultCode);
    }

    [Fact]
    public async Task ReconnectWithSameClientId_TakesOverTheSession()
    {
        var (first, r1) = await Connect("meshdev", "large4cats", "!1a2b3c4d");
        Assert.Equal(MqttClientConnectResultCode.Success, r1.ResultCode);

        var (second, r2) = await Connect("meshdev", "large4cats", "!1a2b3c4d");
        Assert.Equal(MqttClientConnectResultCode.Success, r2.ResultCode);
        Assert.True(second.IsConnected);

        Assert.True(await WaitUntil(() => !first.IsConnected));

        var clients = await _server.GetClientsAsync();
        Assert.Single(clients, c => c.Id == "!1a2b3c4d");
    }

    /// <summary>Just enough of a connection for calling the connect hook directly.</summary>
    sealed class FakeAdapter(bool throwOnFormatter = false) : IMqttChannelAdapter
    {
        readonly MqttPacketFormatterAdapter _formatter = new(MqttProtocolVersion.V311, new MqttBufferWriter(4096, 65535));

        public long BytesReceived => 0;
        public long BytesSent => 0;
        public X509Certificate2 ClientCertificate => null!;
        public EndPoint RemoteEndPoint { get; } = new IPEndPoint(IPAddress.Parse("203.0.113.7"), 40000);
        public EndPoint LocalEndPoint { get; } = new IPEndPoint(IPAddress.Loopback, 1883);
        public bool IsSecureConnection => false;
        public MqttPacketFormatterAdapter PacketFormatterAdapter => throwOnFormatter ? throw new InvalidOperationException("boom") : _formatter;
        public Task ConnectAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DisconnectAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<MqttPacket> ReceivePacketAsync(CancellationToken cancellationToken) => Task.FromResult<MqttPacket>(null!);
        public void ResetStatistics() { }
        public Task SendPacketAsync(MqttPacket packet, CancellationToken cancellationToken) => Task.CompletedTask;
        public void Dispose() { }
    }
}
