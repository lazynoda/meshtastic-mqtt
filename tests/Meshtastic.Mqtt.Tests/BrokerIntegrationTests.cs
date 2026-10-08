using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Meshtastic.Mqtt;
using MQTTnet;
using MQTTnet.Formatter;
using MQTTnet.Protocol;
using MQTTnet.Server;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The hooks wired into a real MQTTnet server on a loopback port, driven by a real MQTT client.
/// </summary>
public sealed class BrokerIntegrationTests : IAsyncLifetime
{
    const string AlicePassword = "correct-horse";
    readonly int _port = FreePort();
    readonly LogSink _logs = new();
    MqttServer _server = null!;

    public async ValueTask InitializeAsync()
    {
        var config = ConfigLoader.Parse($"""
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
        var options = new MqttServerOptionsBuilder().WithDefaultEndpoint().WithDefaultEndpointPort(_port).Build();
        options.DefaultEndpointOptions.BoundInterNetworkAddress = IPAddress.Loopback;
        options.DefaultEndpointOptions.BoundInterNetworkV6Address = IPAddress.None;
        _server = new MqttServerFactory().CreateMqttServer(options);
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(_logs).CreateLogger();
        new BrokerHooks(config, logger).Attach(_server);
        await _server.StartAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await _server.StopAsync();
        _server.Dispose();
    }

    static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    async Task<(IMqttClient Client, MqttClientConnectResult Result)> Connect(string user, string password, string clientId,
        MqttProtocolVersion version = MqttProtocolVersion.V311)
    {
        var client = new MqttClientFactory().CreateMqttClient();
        var options = new MqttClientOptionsBuilder()
            .WithTcpServer("127.0.0.1", _port)
            .WithClientId(clientId)
            .WithCredentials(user, password)
            .WithProtocolVersion(version)
            .WithTimeout(TimeSpan.FromSeconds(10))
            .Build();
        return (client, await client.ConnectAsync(options, TestContext.Current.CancellationToken));
    }

    async Task<MqttClientSubscribeResultCode> Subscribe(IMqttClient client, string filter)
    {
        var result = await client.SubscribeAsync(new MqttClientSubscribeOptionsBuilder().WithTopicFilter(filter).Build(),
            TestContext.Current.CancellationToken);
        return Assert.Single(result.Items).ResultCode;
    }

    [Fact]
    public async Task WrongPassword_IsRefused_AndLoggedWithoutThePassword()
    {
        var (_, result) = await Connect("meshdev", "not-the-password-xyz", "node-1");
        Assert.Equal(MqttClientConnectResultCode.BadUserNameOrPassword, result.ResultCode);

        var (_, unknown) = await Connect("mallory", "large4cats", "node-2");
        Assert.Equal(MqttClientConnectResultCode.BadUserNameOrPassword, unknown.ResultCode);

        var failure = Assert.Single(_logs.Events, e => e.MessageTemplate.Text.StartsWith("Authentication failed")
                                                       && e.Properties["Username"].ToString().Contains("meshdev"));
        Assert.Contains("127.0.0.1", failure.Properties["RemoteIp"].ToString());
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
        var received = new ConcurrentQueue<string>();
        var (sub, _) = await Connect("alice", AlicePassword, "dash-1");
        sub.ApplicationMessageReceivedAsync += e =>
        {
            received.Enqueue(e.ApplicationMessage.Topic + " " + e.ApplicationMessage.Payload.Length + " retain=" + e.ApplicationMessage.Retain);
            return Task.CompletedTask;
        };
        Assert.Equal(MqttClientSubscribeResultCode.GrantedQoS0, await Subscribe(sub, "msh/ES/2/e/test/#"));

        var (pub, _) = await Connect("meshdev", "large4cats", "node-1");
        async Task Publish(string topic, string fixture, bool retain = false) =>
            await pub.PublishAsync(new MqttApplicationMessageBuilder().WithTopic(topic)
                    .WithPayload(PublishFilterTests.Fixture(fixture)).WithRetainFlag(retain)
                    .WithQualityOfServiceLevel(MqttQualityOfServiceLevel.AtLeastOnce).Build(),
                TestContext.Current.CancellationToken);

        await Publish("msh/ES/2/e/test/!1a2b3c4d", "garbage.bin");
        await Publish("msh/ES/2/e/test/!1a2b3c4d", "test_wrong_key_aq.bin");   // channel_id Test != topic test
        await Publish("msh/ES/2/e/test/!1a2b3c4d", "test_lower_aq.bin", retain: true);

        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (received.IsEmpty && DateTime.UtcNow < deadline)
            await Task.Delay(50, TestContext.Current.CancellationToken);
        await Task.Delay(300, TestContext.Current.CancellationToken);

        var only = Assert.Single(received);
        Assert.StartsWith("msh/ES/2/e/test/!1a2b3c4d 75 retain=False", only);
        Assert.Contains(_logs.Events, e => e.RenderMessage().Contains("channel_id does not match the topic"));
        Assert.DoesNotContain(_logs.Events, e => e.RenderMessage().Contains("fixture-payload"));
    }

    async Task<ConcurrentQueue<string>> SubscribeAlice(string filter)
    {
        var received = new ConcurrentQueue<string>();
        var (sub, _) = await Connect("alice", AlicePassword, "dash-2");
        sub.ApplicationMessageReceivedAsync += e =>
        {
            received.Enqueue(e.ApplicationMessage.Topic + " " + e.ApplicationMessage.Payload.Length);
            return Task.CompletedTask;
        };
        Assert.Equal(MqttClientSubscribeResultCode.GrantedQoS0, await Subscribe(sub, filter));
        return received;
    }

    async Task PublishAsMeshdev(string topic, string fixture, bool retain = false)
    {
        var (pub, _) = await Connect("meshdev", "large4cats", "node-2");
        await pub.PublishAsync(new MqttApplicationMessageBuilder().WithTopic(topic)
                .WithPayload(PublishFilterTests.Fixture(fixture)).WithRetainFlag(retain)
                .WithQualityOfServiceLevel(MqttQualityOfServiceLevel.AtLeastOnce).Build(),
            TestContext.Current.CancellationToken);
    }

    static async Task Settle(ConcurrentQueue<string> received)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (received.IsEmpty && DateTime.UtcNow < deadline)
            await Task.Delay(50, TestContext.Current.CancellationToken);
        await Task.Delay(300, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task WrongKey_WithMatchingChannelAndTopic_IsDroppedAsUndecryptable()
    {
        // channel_id `Test` on topic .../Test/..., but encrypted with AQ== while the broker has Test: Ag==.
        var received = await SubscribeAlice("msh/ES/2/e/Test/#");
        await PublishAsMeshdev("msh/ES/2/e/Test/!1a2b3c4d", "test_wrong_key_aq.bin");
        await PublishAsMeshdev("msh/ES/2/e/Test/!1a2b3c4d", "test_ag.bin");   // the right key still passes
        await Settle(received);

        var only = Assert.Single(received);
        Assert.Equal("msh/ES/2/e/Test/!1a2b3c4d 66", only);
        Assert.Contains(_logs.Events, e => e.RenderMessage().Contains("undecryptable with the key configured for this channel"));
    }

    [Fact]
    public async Task AcceptedRetainedPublish_IsNotStored()
    {
        // Live delivery never shows retain (MQTTnet clears it without RetainAsPublished); the retained store is
        // what the retain-clearing line protects.
        var received = await SubscribeAlice("msh/ES/2/e/Test/#");
        await PublishAsMeshdev("msh/ES/2/e/Test/!1a2b3c4d", "test_ag.bin", retain: true);
        await Settle(received);

        Assert.Single(received);
        Assert.Empty(await _server.GetRetainedMessagesAsync());
    }

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

        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (first.IsConnected && DateTime.UtcNow < deadline)
            await Task.Delay(50, TestContext.Current.CancellationToken);
        Assert.False(first.IsConnected);

        var clients = await _server.GetClientsAsync();
        Assert.Single(clients, c => c.Id == "!1a2b3c4d");
    }

    sealed class LogSink : ILogEventSink
    {
        public ConcurrentBag<LogEvent> Events { get; } = new();
        public void Emit(LogEvent logEvent) => Events.Add(logEvent);
    }
}
