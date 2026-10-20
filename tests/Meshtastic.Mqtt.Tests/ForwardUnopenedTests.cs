using System.Buffers;
using System.Collections.Concurrent;
using Google.Protobuf;
using Meshtastic.Mqtt;
using Meshtastic.Protobufs;
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
/// The per-user key <c>users[].forward_unopened</c>: a channel packet the broker cannot open is forwarded
/// unchanged, unless the user that published it drops those packets.
/// </summary>
/// <remarks>
/// The three users of the config below publish the same packets on the same broker: <c>forwarder</c> has
/// no <c>forward_unopened</c> key (the default forwards them), <c>dropper</c> has
/// <c>forward_unopened: false</c>, and <c>watcher</c> only reads.
/// </remarks>
public sealed class ForwardUnopenedTests : IAsyncLifetime
{
    readonly LogSink _logs = new();
    readonly List<MqttServer> _servers = [];
    readonly List<IMqttClient> _clients = [];
    Action _flushDrops = null!;

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    public async ValueTask DisposeAsync()
    {
        foreach (var client in _clients)
            client.Dispose();
        foreach (var server in _servers)
        {
            await server.StopAsync();
            server.Dispose();
        }
    }

    static CancellationToken Ct => TestContext.Current.CancellationToken;

    // ---- The config and the helpers --------------------------------------------------------------------------

    /// <summary>
    /// The broker of the tests: three users on one broker, so the two policies can be compared on the same
    /// packet. The per-IP limits are off: the tests open a few connections from one address.
    /// </summary>
    static BrokerConfig Config(int port, params string[] limits)
    {
        var limitLines = string.Join("\n", new[] { "  max_connections_per_ip: 0", "  connect_rate_per_ip_per_minute: 0" }
            .Concat(limits.Select(l => "  " + l)));
        var yaml = "listener:\n"
            + "  bind_address: 127.0.0.1\n"
            + $"  port: {port}\n"
            + "channels:\n"
            + "  Test: \"Ag==\"\n"
            + "limits:\n"
            + limitLines + "\n"
            + "users:\n"
            + $"  - username: forwarder\n    password_hash: \"{AuthTests.AliceHash}\"\n    publish_allow: [\"msh/ES/2/e/#\"]\n"
            + $"  - username: dropper\n    password_hash: \"{AuthTests.AliceHash}\"\n    forward_unopened: false\n    publish_allow: [\"msh/ES/2/e/#\"]\n"
            + $"  - username: watcher\n    password_hash: \"{AuthTests.AliceHash}\"\n    subscribe_allow: [\"msh/#\"]\n";
        return ConfigLoader.Parse(yaml);
    }

    async Task<int> StartBroker(params string[] limits)
    {
        var port = FreePort();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(_logs).CreateLogger();
        var (server, flush) = TestBroker.CreateWithHooks(Config(port, limits), logger);
        await server.StartAsync();
        _servers.Add(server);
        _flushDrops = flush;
        return port;
    }

    async Task<IMqttClient> Connect(int port, string user, string clientId)
    {
        var client = new MqttClientFactory().CreateMqttClient();
        var result = await client.ConnectAsync(ClientOptions(port, user, AlicePassword, clientId), Ct);
        Assert.Equal(MqttClientConnectResultCode.Success, result.ResultCode);
        _clients.Add(client);
        return client;
    }

    /// <summary>The subscriber: it keeps the payloads it receives, byte for byte.</summary>
    async Task<ConcurrentQueue<byte[]>> Subscribe(int port, string clientId, string filter)
    {
        var received = new ConcurrentQueue<byte[]>();
        var client = await Connect(port, "watcher", clientId);
        client.ApplicationMessageReceivedAsync += e =>
        {
            received.Enqueue(e.ApplicationMessage.Payload.ToArray());
            return Task.CompletedTask;
        };
        var result = await client.SubscribeAsync(new MqttClientSubscribeOptionsBuilder().WithTopicFilter(filter).Build(), Ct);
        Assert.Equal(MqttClientSubscribeResultCode.GrantedQoS0, Assert.Single(result.Items).ResultCode);
        return received;
    }

    static async Task Publish(IMqttClient client, string topic, byte[] payload) =>
        await client.PublishAsync(new MqttApplicationMessageBuilder().WithTopic(topic)
            .WithPayload(payload).WithQualityOfServiceLevel(MqttQualityOfServiceLevel.AtLeastOnce).Build(), Ct);

    /// <summary>The summary of the refusals since the last flush (empty when there was none).</summary>
    string Summary()
    {
        _flushDrops();
        var summary = _logs.Events.LastOrDefault(e => e.Level == LogEventLevel.Information
                                                    && e.MessageTemplate.Text.StartsWith("Refused or evicted {Total}"));
        return summary?.RenderMessage() ?? string.Empty;
    }

    // ---- The packets -----------------------------------------------------------------------------------------

    /// <summary>
    /// A packet of a channel that is not listed under <c>channels</c>: the broker only has the default key
    /// for it, and it does not open the packet.
    /// </summary>
    static byte[] UnknownChannelPacket()
    {
        var envelope = ServiceEnvelope.Parser.ParseFrom(PublishFilterTests.Fixture("test_ag.bin"));
        envelope.ChannelId = "Private";
        return envelope.ToByteArray();
    }

    /// <summary>
    /// A packet of the channel <c>Test</c> (the config has <c>Test: Ag==</c>) encrypted with another key:
    /// the key of the channel does not open it.
    /// </summary>
    static byte[] WrongKeyPacket() => PublishFilterTests.Fixture("test_wrong_key_aq.bin");

    /// <summary>The same packet, with another id: another packet for the dedupe and for the node's budget.</summary>
    static byte[] WithPacketId(byte[] packet, uint id)
    {
        var envelope = ServiceEnvelope.Parser.ParseFrom(packet);
        envelope.Packet.Id = id;
        return envelope.ToByteArray();
    }

    // ---- T1: the packets the broker cannot open are forwarded unchanged ---------------------------------------

    [Fact]
    public async Task T1_AUserWithoutTheKey_ForwardsTheUnopenedPackets_Unchanged()
    {
        var port = await StartBroker();
        var received = await Subscribe(port, "watcher-1", "msh/#");
        var forwarder = await Connect(port, "forwarder", "forwarder-1");

        var unknown = UnknownChannelPacket();
        var wrongKey = WrongKeyPacket();
        await Publish(forwarder, "msh/ES/2/e/Private/!1a2b3c4d", unknown);
        await Publish(forwarder, "msh/ES/2/e/Test/!1a2b3c4d", wrongKey);

        Assert.True(await WaitUntil(() => received.Count >= 2), "the two packets did not arrive");
        await Task.Delay(300, Ct);

        // Byte for byte the bytes the client published.
        var payloads = received.ToArray();
        Assert.Equal(2, payloads.Length);
        Assert.True(payloads.Any(p => p.SequenceEqual(unknown)), "the packet of the unknown channel changed");
        Assert.True(payloads.Any(p => p.SequenceEqual(wrongKey)), "the packet with the wrong key changed");
    }

    [Fact]
    public async Task T1_ThePolicyOfTheSessionOwner_Applies_AndNotTheUserNameOfThePublish()
    {
        // The session belongs to the dropper and the PUBLISH says "forwarder": the policy of the owner of
        // the session applies, the same identity the publish ACL uses.
        var config = Config(FreePort());
        var hooks = new BrokerHooks(config, new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(_logs).CreateLogger());
        var dropped = PublishArgs("msh/ES/2/e/Private/!1a2b3c4d", UnknownChannelPacket(), "forwarder", "dropper");
        await hooks.InterceptPublishAsync(dropped);
        Assert.False(dropped.ProcessPublish);

        // The other way round: the session belongs to the forwarder.
        var other = new BrokerHooks(config, new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(_logs).CreateLogger());
        var forwarded = PublishArgs("msh/ES/2/e/Private/!1a2b3c4d", UnknownChannelPacket(), "dropper", "forwarder");
        await other.InterceptPublishAsync(forwarded);
        Assert.True(forwarded.ProcessPublish);
    }

    // ---- T2: a user that drops them ------------------------------------------------------------------------
    [Fact]
    public async Task T2_AUserWithForwardUnopenedFalse_DropsThem_WithTodaysReason()
    {
        var port = await StartBroker();
        var received = await Subscribe(port, "watcher-1", "msh/#");
        var dropper = await Connect(port, "dropper", "dropper-1");

        await Publish(dropper, "msh/ES/2/e/Private/!1a2b3c4d", UnknownChannelPacket());
        await Publish(dropper, "msh/ES/2/e/Test/!1a2b3c4d", WrongKeyPacket());
        await Task.Delay(500, Ct);

        Assert.Empty(received);
        // The reason of today, and the two packets are counted in the summary.
        var summary = Summary();
        Assert.Contains("undecryptable with the key configured for this channel: 2", summary);
        Assert.Contains(_logs.Events, e => e.RenderMessage().Contains("undecryptable with the key configured for this channel")
                                          && e.Level == LogEventLevel.Debug);
    }

    // ---- T3: two users, two verdicts ------------------------------------------------------------------------

    [Fact]
    public async Task T3_TwoUsers_GetDifferentVerdictsForTheSamePacket()
    {
        var port = await StartBroker();
        var received = await Subscribe(port, "watcher-1", "msh/#");
        var dropper = await Connect(port, "dropper", "dropper-1");
        var forwarder = await Connect(port, "forwarder", "forwarder-1");

        var packet = UnknownChannelPacket();
        await Publish(dropper, "msh/ES/2/e/Private/!1a2b3c4d", packet);
        await Publish(forwarder, "msh/ES/2/e/Private/!1a2b3c4d", packet);

        Assert.True(await WaitUntil(() => received.Count >= 1), "the forwarded packet did not arrive");
        await Task.Delay(300, Ct);

        // The forwarder's copy is forwarded, the dropper's copy is dropped: one message at the subscriber.
        Assert.Single(received);
        Assert.Contains("undecryptable with the key configured for this channel: 1", Summary());
    }

    // ---- T4: every other check still applies ----------------------------------------------------------------

    [Fact]
    public async Task T4_AForwardedPacket_IsStillRefusedByThePublishAcl()
    {
        var port = await StartBroker();
        var received = await Subscribe(port, "watcher-1", "msh/#");
        var forwarder = await Connect(port, "forwarder", "forwarder-1");

        // The JSON topic is not in the publish_allow of the user: the ACL runs before the packet filter.
        await Publish(forwarder, "msh/ES/2/json/Private/!1a2b3c4d", UnknownChannelPacket());
        await Task.Delay(500, Ct);

        Assert.Empty(received);
        Assert.Contains("not in publish_allow: 1", Summary());
    }

    [Fact]
    public async Task T4_AForwardedPacket_IsStillRefusedByTheGatewayBinding()
    {
        var port = await StartBroker();
        var received = await Subscribe(port, "watcher-1", "msh/#");
        var forwarder = await Connect(port, "forwarder", "forwarder-1");

        // The gateway of the topic is not the gateway of the envelope.
        await Publish(forwarder, "msh/ES/2/e/Private/!deadbeef", UnknownChannelPacket());
        await Task.Delay(500, Ct);

        Assert.Empty(received);
        Assert.Contains("gateway in topic does not match gateway_id: 1", Summary());
    }

    [Fact]
    public async Task T4_AForwardedPacket_IsStillRefusedByTheChannelOfTheTopic()
    {
        var port = await StartBroker();
        var received = await Subscribe(port, "watcher-1", "msh/#");
        var forwarder = await Connect(port, "forwarder", "forwarder-1");

        // The channel of the topic is not the channel_id of the envelope.
        await Publish(forwarder, "msh/ES/2/e/Other/!1a2b3c4d", UnknownChannelPacket());
        await Task.Delay(500, Ct);

        Assert.Empty(received);
        Assert.Contains("channel_id does not match the topic: 1", Summary());
    }

    [Fact]
    public async Task T4_AForwardedPacket_IsStillRefusedByThePayloadCap()
    {
        var port = await StartBroker("max_payload_size: 64");
        var received = await Subscribe(port, "watcher-1", "msh/#");
        var forwarder = await Connect(port, "forwarder", "forwarder-1");

        var packet = UnknownChannelPacket();
        Assert.True(packet.Length > 64, "the fixture is not larger than the cap of this test");
        await Publish(forwarder, "msh/ES/2/e/Private/!1a2b3c4d", packet);
        await Task.Delay(500, Ct);

        Assert.Empty(received);
        Assert.Contains("payload larger than max_payload_size: 1", Summary());
    }

    [Fact]
    public async Task T4_AForwardedPacket_IsStillRefusedByTheRateOfTheNode()
    {
        var port = await StartBroker("packet_rate_per_from_per_minute: 1", "packet_burst_per_from: 1");
        var received = await Subscribe(port, "watcher-1", "msh/#");
        var forwarder = await Connect(port, "forwarder", "forwarder-1");

        // Two packets of the same node (the same `from`), so the second one exhausts its budget.
        await Publish(forwarder, "msh/ES/2/e/Private/!1a2b3c4d", WithPacketId(UnknownChannelPacket(), 0x20000001));
        await Publish(forwarder, "msh/ES/2/e/Private/!1a2b3c4d", WithPacketId(UnknownChannelPacket(), 0x20000002));
        await Task.Delay(500, Ct);

        Assert.Single(received);
        Assert.Contains("packet rate exceeded for the node: 1", Summary());
    }

    [Fact]
    public async Task T4_AForwardedPacket_IsStillDeduped()
    {
        var port = await StartBroker();
        var received = await Subscribe(port, "watcher-1", "msh/#");
        var forwarder = await Connect(port, "forwarder", "forwarder-1");

        // The same packet (the same from and id) from the same gateway, twice.
        var packet = UnknownChannelPacket();
        await Publish(forwarder, "msh/ES/2/e/Private/!1a2b3c4d", packet);
        await Publish(forwarder, "msh/ES/2/e/Private/!1a2b3c4d", packet);
        await Task.Delay(500, Ct);

        Assert.Single(received);
        Assert.Contains("duplicate from the same gateway: 1", Summary());
    }

    // ---- T6: the logs ---------------------------------------------------------------------------------------

    [Fact]
    public async Task T6_AForwardedPacket_IsOnlyDebug_AndIsNotInTheSummary()
    {
        var port = await StartBroker();
        var received = await Subscribe(port, "watcher-1", "msh/#");
        var forwarder = await Connect(port, "forwarder", "forwarder-1");

        // The Information lines of the connection and of the subscription are already in the sink: the
        // forwarded packet must not add one.
        var information = _logs.Events.Count(e => e.Level >= LogEventLevel.Information);

        await Publish(forwarder, "msh/ES/2/e/Private/!1a2b3c4d", UnknownChannelPacket());
        Assert.True(await WaitUntil(() => received.Count >= 1), "the packet did not arrive");
        await Task.Delay(300, Ct);

        // Not one Information line more (and no Warning): a forwarded packet is not a refusal.
        Assert.Equal(information, _logs.Events.Count(e => e.Level >= LogEventLevel.Information));

        // One Debug line per packet: the channel, the from, the id and why it was not opened.
        var line = Assert.Single(_logs.Events, e => e.RenderMessage().Contains("Forwarded an unopened packet"));
        Assert.Equal(LogEventLevel.Debug, line.Level);
        Assert.Contains("Private", line.RenderMessage());
        Assert.Contains("!1a2b3c4d", line.RenderMessage());
        Assert.Contains(PacketInspector.UnopenedNoKeyReason, line.RenderMessage());
        Assert.DoesNotContain(line.RenderMessage(), "fixture-payload");

        // No Warning, and the summary has nothing to count: a forwarded packet is not a refusal.
        Assert.DoesNotContain(_logs.Events, e => e.Level >= LogEventLevel.Warning);
        Assert.Equal(string.Empty, Summary());
    }

    // ---- P1: the line of a forwarded packet says whether the hash of the channel matches --------------

    [Fact]
    public async Task T6_TheForwardedLine_SaysWhetherTheChannelHashMatches()
    {
        // The hash of the channel is computed for every packet; the line of a forwarded packet says if
        // it matches the key the broker has, instead of throwing the information away.
        var config = Config(FreePort());
        var hooks = new BrokerHooks(config, new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(_logs).CreateLogger());
        var args = PublishArgs("msh/ES/2/e/Test/!1a2b3c4d", WrongKeyPacket(), "forwarder", "forwarder");
        await hooks.InterceptPublishAsync(args);
        Assert.True(args.ProcessPublish);

        var line = Assert.Single(_logs.Events, e => e.RenderMessage().Contains("Forwarded an unopened packet"));
        Assert.Equal(LogEventLevel.Debug, line.Level);
        // The packet was encrypted with another key: the hash of the channel does not match.
        Assert.Contains("channel hash matches: False", line.RenderMessage());
    }
}
