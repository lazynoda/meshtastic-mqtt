using System.Collections;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text;
using Meshtastic.Mqtt;
using MQTTnet;
using MQTTnet.Formatter;
using MQTTnet.Protocol;
using MQTTnet.Server;
using Serilog;
using Serilog.Events;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The per-user publish ACL (<c>publish_allow</c>) on the production root msh/EU_868, map reports end to end, and
/// what a refused publish does (and does not do) to the publisher and to subscribers.
/// </summary>
public sealed class PublishAclTests : IAsyncLifetime
{
    const string Sfnarrow = "msh/EU_868/2/e/SFNarrow/!1a2b3c4d";
    const string MapTopic = "msh/EU_868/2/map/";

    readonly int _port = FreePort();
    readonly LogSink _logs = new();
    BrokerConfig _config = null!;
    MqttServer _server = null!;
    Action _flushDrops = null!;

    /// <summary>
    /// meshdev as in config.example.yaml; alice reads everything under msh/ (so she would see any leak) and has no
    /// publish_allow; bob may publish only on the Test channel.
    /// </summary>
    internal static BrokerConfig AclConfig(int port) => ConfigLoader.Parse($"""
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
          - username: bob
            password_hash: "{AuthTests.AliceHash}"
            publish_allow: ["msh/EU_868/2/e/Test/#"]
          - username: root
            password_hash: "{AuthTests.AliceHash}"
            publish_allow: ["#", "+/EU_868/2/map/"]
        """);

    public async ValueTask InitializeAsync()
    {
        _config = AclConfig(_port);
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

    BrokerHooks Hooks() => new(_config, new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(_logs).CreateLogger());

    // ---- The ACL decision, per topic -------------------------------------------------------------------------

    [Theory]
    [InlineData("msh/EU_868/2/e/SFNarrow/!abcd1234")]
    [InlineData("msh/EU_868/2/e/Test/!abcd1234")]
    [InlineData("msh/EU_868/2/e/PKI/!abcd1234")]
    [InlineData("msh/EU_868/2/map/")]
    public void Meshdev_MayPublish_OnlyUnderItsFilters(string topic) =>
        Assert.Null(Hooks().EvaluatePublish("meshdev", topic).Code);

    [Theory]
    [InlineData("msh/ES/2/e/SFNarrow/!abcd1234")]          // wrong root (the old msh/ES notes)
    [InlineData("msh/EU_868/2/json/SFNarrow/!abcd1234")]   // JSON uplink carries plaintext
    [InlineData("msh/EU_868_X/2/e/SFNarrow/!abcd1234")]    // a level is matched whole, not as a prefix
    [InlineData("msh/eu_868/2/e/SFNarrow/!abcd1234")]      // topics are case-sensitive
    [InlineData("$SYS/broker/clients")]
    [InlineData("msh/EU_868/2/map")]                       // the firmware's map topic has a trailing slash
    [InlineData("msh/EU_868/2/map/extra")]
    [InlineData("msh/EU_868/2")]
    [InlineData("msh")]
    public void Meshdev_IsRefused_OutsideItsFilters(string topic)
    {
        var (code, reason) = Hooks().EvaluatePublish("meshdev", topic);
        Assert.Equal(MqttPubAckReasonCode.NotAuthorized, code);
        Assert.Equal(BrokerHooks.NotInPublishAllowReason, reason);
    }

    [Fact]
    public void ParentOfAHashFilter_PassesTheAcl_ButNotThePacketFilter()
    {
        // Standard MQTT matching: "msh/EU_868/2/e/#" also matches "msh/EU_868/2/e" (spec 4.7.1.2), so the ACL lets
        // it through; the packet filter then drops it, because it is not <root>/2/e/<channel>/<gateway>.
        Assert.Null(Hooks().EvaluatePublish("meshdev", "msh/EU_868/2/e").Code);
        var r = new PacketInspector(_config).Inspect("msh/EU_868/2/e", PublishFilterTests.Fixture("sfnarrow_aq.bin"));
        Assert.False(r.Accepted);
        Assert.StartsWith("unsupported topic", r.Reason);
    }

    [Theory]
    [InlineData("alice", "msh/EU_868/2/e/SFNarrow/!abcd1234")]   // no publish_allow at all
    [InlineData("alice", "msh/EU_868/2/map/")]
    [InlineData("bob", "msh/EU_868/2/e/SFNarrow/!abcd1234")]     // bob only has the Test channel
    [InlineData("nobody", "msh/EU_868/2/e/SFNarrow/!abcd1234")]  // owner not in the config
    public void UsersWithoutAMatchingFilter_CannotPublish(string owner, string topic) =>
        Assert.Equal(MqttPubAckReasonCode.NotAuthorized, Hooks().EvaluatePublish(owner, topic).Code);

    [Fact]
    public void NoSessionOwner_IsRefused()
    {
        var (code, reason) = Hooks().EvaluatePublish(null, Sfnarrow);
        Assert.Equal(MqttPubAckReasonCode.NotAuthorized, code);
        Assert.Equal(BrokerHooks.NoOwnerReason, reason);
    }

    [Theory]
    [InlineData("$SYS/broker/clients")]
    [InlineData("$share/x/msh/EU_868/2/map/")]
    public void LeadingWildcard_NeverMatchesDollarTopics(string topic)
    {
        // "#" and "+/EU_868/2/map/" start with a wildcard, so they never match a topic starting with '$'.
        Assert.Equal(MqttPubAckReasonCode.NotAuthorized, Hooks().EvaluatePublish("root", topic).Code);
        Assert.Null(Hooks().EvaluatePublish("root", "anything/at/all").Code);
        Assert.Null(Hooks().EvaluatePublish("root", "xyz/EU_868/2/map/").Code);
    }

    [Theory]
    [InlineData("msh/EU_868/2/e/+/!abcd1234")]
    [InlineData("msh/EU_868/2/e/#")]
    [InlineData("msh/EU_868/2/e/SF#/!abcd1234")]
    [InlineData("")]
    public void WildcardsInATopicName_AreAProtocolError_EvenForAnAllowAllUser(string topic)
    {
        var (code, reason) = Hooks().EvaluatePublish("root", topic);
        Assert.Equal(MqttPubAckReasonCode.TopicNameInvalid, code);
        Assert.Equal(BrokerHooks.InvalidTopicNameReason, reason);
    }

    // ---- The hook: whose list, order, logging ---------------------------------------------------------------

    static InterceptingPublishEventArgs PublishArgs(string topic, byte[] payload, string userName, string? owner)
    {
        var items = new Hashtable();
        if (owner is not null)
            items[BrokerHooks.OwnerKey] = owner;
        var message = new MqttApplicationMessageBuilder().WithTopic(topic).WithPayload(payload).Build();
        return new InterceptingPublishEventArgs(message, "node-1", userName, items, CancellationToken.None);
    }

    [Theory]
    [InlineData("meshdev", "bob", false)]    // connection says meshdev, session belongs to bob: bob's list applies
    [InlineData("bob", "meshdev", true)]     // and the other way round
    [InlineData("meshdev", null, false)]     // no owner bound to the session: denied
    [InlineData("meshdev", "meshdev", true)]
    public async Task PublishHook_FollowsTheSessionOwner_NotTheUserName(string userName, string? owner, bool accepted)
    {
        var args = PublishArgs(Sfnarrow, PublishFilterTests.Fixture("sfnarrow_aq.bin"), userName, owner);
        await Hooks().InterceptPublishAsync(args);
        Assert.Equal(accepted, args.ProcessPublish);
        Assert.Equal(accepted ? MqttPubAckReasonCode.Success : MqttPubAckReasonCode.NotAuthorized, args.Response.ReasonCode);
        Assert.False(args.CloseConnection);
    }

    [Fact]
    public async Task RefusedPublish_IsDecidedBeforeThePayloadIsInspected()
    {
        // Garbage on a refused topic is counted as an ACL refusal, not as a malformed protobuf: the ACL runs first.
        var hooks = Hooks();
        var args = PublishArgs("msh/ES/2/e/SFNarrow/!1a2b3c4d", PublishFilterTests.Fixture("garbage.bin"), "meshdev", "meshdev");
        await hooks.InterceptPublishAsync(args);
        Assert.False(args.ProcessPublish);
        Assert.Contains(_logs.Events, e => e.RenderMessage().Contains(BrokerHooks.NotInPublishAllowReason));
        Assert.DoesNotContain(_logs.Events, e => e.RenderMessage().Contains("malformed protobuf"));
    }

    // ---- Over the network -----------------------------------------------------------------------------------

    async Task<(IMqttClient Client, ConcurrentQueue<string> Received)> Connect(string user, string password, string clientId,
        MqttProtocolVersion version = MqttProtocolVersion.V311)
    {
        var received = new ConcurrentQueue<string>();
        var client = new MqttClientFactory().CreateMqttClient();
        client.ApplicationMessageReceivedAsync += e =>
        {
            received.Enqueue(e.ApplicationMessage.Topic + " " + e.ApplicationMessage.Payload.Length);
            return Task.CompletedTask;
        };
        var result = await client.ConnectAsync(ClientOptions(_port, user, password, clientId, version), Ct);
        Assert.Equal(MqttClientConnectResultCode.Success, result.ResultCode);
        return (client, received);
    }

    async Task<ConcurrentQueue<string>> Dashboard()
    {
        var (alice, received) = await Connect("alice", AlicePassword, "dash-1");
        var sub = await alice.SubscribeAsync(new MqttClientSubscribeOptionsBuilder().WithTopicFilter("msh/#").Build(), Ct);
        Assert.Equal(MqttClientSubscribeResultCode.GrantedQoS0, Assert.Single(sub.Items).ResultCode);
        return received;
    }

    static Task<MqttClientPublishResult> Publish(IMqttClient client, string topic, string fixture) =>
        client.PublishAsync(new MqttApplicationMessageBuilder().WithTopic(topic)
            .WithPayload(PublishFilterTests.Fixture(fixture))
            .WithQualityOfServiceLevel(MqttQualityOfServiceLevel.AtLeastOnce).Build(), Ct);

    /// <summary>Publishes a valid packet that must arrive, to know every earlier publish has been processed.</summary>
    static async Task Marker(IMqttClient meshdev, ConcurrentQueue<string> received, string expected)
    {
        await Publish(meshdev, Sfnarrow, "sfnarrow_aq.bin");
        Assert.True(await WaitUntil(() => received.Any(r => r.StartsWith(expected))), "marker packet not delivered");
        await Task.Delay(200, Ct);
    }

    [Fact]
    public async Task RefusedPublishes_NeverReachASubscriber_AndTheClientStaysConnected()
    {
        var received = await Dashboard();
        var (meshdev, _) = await Connect("meshdev", "large4cats", "!1a2b3c4d");

        // The same valid envelope on topics outside meshdev's list.
        await Publish(meshdev, "msh/ES/2/e/SFNarrow/!1a2b3c4d", "sfnarrow_aq.bin");
        await Publish(meshdev, "msh/EU_868/2/json/SFNarrow/!1a2b3c4d", "sfnarrow_aq.bin");
        await Publish(meshdev, "msh/EU_868_X/2/e/SFNarrow/!1a2b3c4d", "sfnarrow_aq.bin");
        await Publish(meshdev, "msh/EU_868/2/e", "sfnarrow_aq.bin");   // passes the ACL, dropped by the packet filter
        await Marker(meshdev, received, Sfnarrow);

        Assert.Equal([$"{Sfnarrow} {PublishFilterTests.Fixture("sfnarrow_aq.bin").Length}"], received.ToArray());
        Assert.True(meshdev.IsConnected);
        Assert.Single(await _server.GetClientsAsync(), c => c.Id == "!1a2b3c4d");
        // One connection line for meshdev: it was never disconnected and never had to reconnect.
        Assert.Single(_logs.Events, e => e.MessageTemplate.Text.StartsWith("Client {ClientId} connected")
                                         && e.Properties["ClientId"].ToString().Contains("!1a2b3c4d"));
    }

    [Fact]
    public async Task UserWithoutPublishAllow_CannotPublish_AndStaysConnected()
    {
        var received = await Dashboard();
        var (bob, _) = await Connect("bob", AlicePassword, "bob-1");
        var (alice2, _) = await Connect("alice", AlicePassword, "dash-2");
        await Publish(alice2, Sfnarrow, "sfnarrow_aq.bin");           // alice: no publish_allow
        await Publish(bob, Sfnarrow, "sfnarrow_aq.bin");              // bob: Test only
        await Publish(bob, "msh/EU_868/2/e/Test/!1a2b3c4d", "test_ag.bin");   // bob's own channel passes
        Assert.True(await WaitUntil(() => !received.IsEmpty));
        await Task.Delay(300, Ct);

        Assert.Equal(["msh/EU_868/2/e/Test/!1a2b3c4d " + PublishFilterTests.Fixture("test_ag.bin").Length], received.ToArray());
        Assert.True(alice2.IsConnected);
        Assert.True(bob.IsConnected);
    }

    [Fact]
    public async Task RefusedPublish_IsNotAuthorizedOnMqtt5_AndSuccessOnAllowedTopics()
    {
        var (meshdev, _) = await Connect("meshdev", "large4cats", "!1a2b3c4e", MqttProtocolVersion.V500);
        var refused = await Publish(meshdev, "msh/ES/2/e/SFNarrow/!1a2b3c4d", "sfnarrow_aq.bin");
        Assert.Equal(MqttClientPublishReasonCode.NotAuthorized, refused.ReasonCode);
        // An allowed topic with nobody subscribed: MQTTnet answers "no matching subscribers", not a refusal.
        var allowed = await Publish(meshdev, Sfnarrow, "sfnarrow_aq.bin");
        Assert.Equal(MqttClientPublishReasonCode.NoMatchingSubscribers, allowed.ReasonCode);
        Assert.True(meshdev.IsConnected);
    }

    [Fact]
    public async Task RefusedPublishes_AreDebugPerPacket_NeverWarning_AndSummarisedPerReason()
    {
        var (meshdev, _) = await Connect("meshdev", "large4cats", "!1a2b3c4d");
        for (var i = 0; i < 20; i++)
            await Publish(meshdev, "msh/ES/2/e/SFNarrow/!1a2b3c4d", "sfnarrow_aq.bin");
        Assert.True(await WaitUntil(() => _logs.Events.Count(e => e.RenderMessage().Contains(BrokerHooks.NotInPublishAllowReason)) >= 20));

        var perPacket = _logs.Events.Where(e => e.RenderMessage().Contains(BrokerHooks.NotInPublishAllowReason)).ToList();
        Assert.All(perPacket, e => Assert.Equal(LogEventLevel.Debug, e.Level));
        Assert.DoesNotContain(_logs.Events, e => e.Level >= LogEventLevel.Warning);

        _flushDrops();
        var summary = Assert.Single(_logs.Events, e => e.Level == LogEventLevel.Information && e.MessageTemplate.Text.StartsWith("Refused or evicted {Total}"));
        Assert.Equal("20", summary.Properties["Total"].ToString());
        Assert.Contains("not in publish_allow", summary.RenderMessage());
    }

    [Fact]
    public async Task MapReports_ValidOnesAreDelivered_InvalidOnesAreNot()
    {
        var received = await Dashboard();
        var (meshdev, _) = await Connect("meshdev", "large4cats", "!1a2b3c4d");

        await Publish(meshdev, MapTopic, "map_report_encrypted.bin");
        await Publish(meshdev, MapTopic, "map_report_wrong_portnum.bin");
        await Publish(meshdev, MapTopic, "map_report_garbage.bin");
        await Publish(meshdev, MapTopic, "map_report_wrong_gateway.bin");
        await Publish(meshdev, MapTopic, "sfnarrow_aq.bin");
        await Publish(meshdev, "msh/EU_868/2/map/!1a2b3c4d", "map_report.bin");   // not in meshdev's list
        await Publish(meshdev, MapTopic, "map_report.bin");
        Assert.True(await WaitUntil(() => !received.IsEmpty));
        await Task.Delay(300, Ct);

        Assert.Equal([$"{MapTopic} {PublishFilterTests.Fixture("map_report.bin").Length}"], received.ToArray());
        _flushDrops();
        var summary = Assert.Single(_logs.Events, e => e.MessageTemplate.Text.StartsWith("Refused or evicted {Total}")).RenderMessage();
        foreach (var reason in new[] { "map report: packet is not decoded", "map report: portnum is not MAP_REPORT_APP",
                     "map report: payload is not a MapReport", "map report: gateway_id is not the sender (from)", "not in publish_allow" })
            Assert.Contains(reason, summary);
    }

    [Fact]
    public async Task MapTopicWithAnExtraLevel_IsDropped_EvenWhenTheAclAllowsIt()
    {
        // root may publish anywhere, so only the packet filter stands between it and <root>/2/map/<anything>.
        var received = await Dashboard();
        var (root, _) = await Connect("root", AlicePassword, "root-1");
        await Publish(root, "msh/EU_868/2/map/!1a2b3c4d", "map_report.bin");
        await Publish(root, "msh/EU_868/2/map", "map_report.bin");
        await Publish(root, MapTopic, "map_report.bin");
        Assert.True(await WaitUntil(() => !received.IsEmpty));
        await Task.Delay(300, Ct);
        Assert.Equal([$"{MapTopic} {PublishFilterTests.Fixture("map_report.bin").Length}"], received.ToArray());
        Assert.Equal(2, _logs.Events.Count(e => e.RenderMessage().Contains("unsupported map topic")));
    }

    // ---- Wildcards in a PUBLISH topic name (MQTTnet's client refuses to send them, so raw bytes) ---------------

    [Fact]
    public async Task WildcardTopicName_IsDropped_WithoutDisconnecting()
    {
        var received = await Dashboard();
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync("127.0.0.1", _port, Ct);
        await using var stream = new NetworkStream(socket);

        await stream.WriteAsync(RawConnect("raw-1", "meshdev", "large4cats"), Ct);
        Assert.Equal(new byte[] { 0x20, 0x02, 0x00, 0x00 }, await ReadExactly(stream, 4));   // CONNACK accepted

        var payload = PublishFilterTests.Fixture("sfnarrow_aq.bin");
        await stream.WriteAsync(RawPublish("msh/EU_868/2/e/+/!1a2b3c4d", payload), Ct);
        await stream.WriteAsync(RawPublish("msh/EU_868/2/e/#", payload), Ct);
        await stream.WriteAsync(new byte[] { 0xC0, 0x00 }, Ct);                               // PINGREQ
        Assert.Equal(new byte[] { 0xD0, 0x00 }, await ReadExactly(stream, 2));                // PINGRESP: still connected

        Assert.True(await WaitUntil(() => _logs.Events.Count(e => e.RenderMessage().Contains(BrokerHooks.InvalidTopicNameReason)) >= 2));
        await Task.Delay(200, Ct);
        Assert.Empty(received);
        Assert.Contains(await _server.GetClientsAsync(), c => c.Id == "raw-1");
    }

    static byte[] RawConnect(string clientId, string user, string password)
    {
        var body = new List<byte> { 0x00, 0x04, (byte)'M', (byte)'Q', (byte)'T', (byte)'T', 0x04, 0xC2, 0x00, 0x3C };
        body.AddRange(Str(clientId));
        body.AddRange(Str(user));
        body.AddRange(Str(password));
        return Frame(0x10, body);
    }

    static byte[] RawPublish(string topic, byte[] payload) => Frame(0x30, [.. Str(topic), .. payload]);   // QoS 0

    static byte[] Str(string s)
    {
        var b = Encoding.UTF8.GetBytes(s);
        return [(byte)(b.Length >> 8), (byte)b.Length, .. b];
    }

    static byte[] Frame(byte type, List<byte> body)
    {
        var frame = new List<byte> { type };
        var x = body.Count;
        do
        {
            var digit = (byte)(x % 128);
            x /= 128;
            frame.Add(x > 0 ? (byte)(digit | 0x80) : digit);
        } while (x > 0);
        frame.AddRange(body);
        return [.. frame];
    }

    static async Task<byte[]> ReadExactly(NetworkStream stream, int count)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        var buffer = new byte[count];
        await stream.ReadExactlyAsync(buffer, timeout.Token);
        return buffer;
    }
}
