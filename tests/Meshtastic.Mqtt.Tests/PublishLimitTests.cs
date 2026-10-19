using System.Collections;
using Google.Protobuf;
using Meshtastic.Mqtt;
using Meshtastic.Protobufs;
using MQTTnet;
using MQTTnet.Protocol;
using MQTTnet.Server;
using Serilog;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The publish-side limits: the payload cap, the per-client publish rate, the gateway binding, the
/// cross-gateway dedupe and the per-node packet rate.
/// </summary>
/// <remarks>
/// The clock is a fake one (see <see cref="FakeClock"/>), so no test sleeps and every refill is exact.
/// The packets are the real-format fixtures; only the gateway id of the envelope is changed when a test
/// needs another gateway (the gateway is outside the encrypted part).
/// </remarks>
public sealed class PublishLimitTests
{
    const string Sfnarrow = "msh/EU_868/2/e/SFNarrow/!1a2b3c4d";
    const string TestChannel = "msh/EU_868/2/e/Test/!1a2b3c4d";
    const string Valencia = "msh/EU_868/2/e/Valencia/!1a2b3c4d";
    const string LowerTest = "msh/EU_868/2/e/test/!1a2b3c4d";
    const string LongFast = "msh/EU_868/2/e/LongFast/!fa8165a4";
    const string MapTopic = "msh/EU_868/2/map/";

    /// <summary>Five different packets (different ids) of the same node.</summary>
    static readonly (string Topic, string Fixture)[] DistinctPackets =
    [
        (Sfnarrow, "sfnarrow_aq.bin"),
        (TestChannel, "test_ag.bin"),
        (Valencia, "valencia_va.bin"),
        (LowerTest, "test_lower_aq.bin"),
        (LongFast, "longfast_real.bin"),
    ];

    static BrokerConfig Config(string limits = "") => ConfigLoader.Parse($"""
        channels:
          Test: "Ag=="
          Valencia: "VA=="
        users:
          - username: meshdev
            password_hash: "{AuthTests.MeshdevHash}"
            publish_allow: ["msh/EU_868/2/e/#", "msh/EU_868/2/map/"]
        {limits}
        """);

    static byte[] Fixture(string name) => PublishFilterTests.Fixture(name);

    /// <summary>The fixture envelope with another gateway id (the gateway is not part of the encryption).</summary>
    static byte[] WithGateway(string name, string gateway)
    {
        var env = ServiceEnvelope.Parser.ParseFrom(Fixture(name));
        env.GatewayId = gateway;
        return env.ToByteArray();
    }

    /// <summary>The broker's hooks, a fake clock and the drop counters, all in one place.</summary>
    sealed class Harness
    {
        public LogSink Logs { get; } = new();
        public FakeClock Clock { get; } = new();
        public DropCounters Drops { get; }
        public BrokerHooks Hooks { get; }

        public Harness(BrokerConfig config)
        {
            var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(Logs).CreateLogger();
            Drops = new DropCounters(logger, start: false);
            Hooks = new BrokerHooks(config, logger, drops: Drops, time: Clock);
        }

        public sealed record Outcome(bool Accepted, MqttPubAckReasonCode Code, bool Closed);

        /// <summary>
        /// Runs one publish through the hook. The hook answers synchronously, so this never blocks.
        /// </summary>
        public Outcome PublishNow(string topic, byte[] payload, string owner = "meshdev", string clientId = "node-1")
        {
            var items = new Hashtable { [BrokerHooks.OwnerKey] = owner };
            var message = new MqttApplicationMessageBuilder().WithTopic(topic).WithPayload(payload).Build();
            var args = new InterceptingPublishEventArgs(message, clientId, owner, items, CancellationToken.None);
            Hooks.InterceptPublishAsync(args).GetAwaiter().GetResult();
            return new Outcome(args.ProcessPublish, args.Response.ReasonCode, args.CloseConnection);
        }

        public Task<Outcome> Publish(string topic, byte[] payload, string owner = "meshdev", string clientId = "node-1") =>
            Task.FromResult(PublishNow(topic, payload, owner, clientId));

        /// <summary>How many publishes were dropped under this reason so far.</summary>
        public long Dropped(string reason) => Drops.Snapshot().TryGetValue(reason, out var n) ? n : 0;
    }

    // ---- The payload cap ------------------------------------------------------------------------------------

    [Fact]
    public async Task PayloadCap_AcceptsARealPacketAtTheLimit_AndDropsOneByteMore()
    {
        // The fixture is a real envelope: at the limit it is forwarded, one byte over it is dropped.
        var payload = Fixture("sfnarrow_aq.bin");
        Assert.Equal(74, payload.Length);

        var atLimit = new Harness(Config($"limits:\n  max_payload_size: {payload.Length}"));
        Assert.True((await atLimit.Publish(Sfnarrow, payload)).Accepted);
        Assert.Equal(0, atLimit.Dropped(BrokerHooks.PayloadTooLargeReason));

        var overLimit = new Harness(Config($"limits:\n  max_payload_size: {payload.Length - 1}"));
        var refused = await overLimit.Publish(Sfnarrow, payload);
        Assert.False(refused.Accepted);
        Assert.False(refused.Closed);        // the client stays connected
        Assert.Equal(1, overLimit.Dropped(BrokerHooks.PayloadTooLargeReason));
    }

    [Fact]
    public async Task PayloadCap_DropsAPayloadOverTheLimit_BeforeThePacketIsParsed()
    {
        var harness = new Harness(Config("limits:\n  max_payload_size: 64"));
        var atLimit = await harness.Publish(Sfnarrow, new byte[64]);
        Assert.False(atLimit.Accepted);                                   // not an envelope: dropped later
        Assert.False(atLimit.Closed);                                      // the client stays connected
        Assert.Equal(0, harness.Dropped(BrokerHooks.PayloadTooLargeReason));

        var overLimit = await harness.Publish(Sfnarrow, new byte[65]);
        Assert.False(overLimit.Accepted);
        Assert.False(overLimit.Closed);                                    // the client stays connected
        Assert.Equal(1, harness.Dropped(BrokerHooks.PayloadTooLargeReason));
    }

    [Fact]
    public async Task PayloadCap_IsCheckedAfterTheAcl_AndBeforeThePacketIsParsed()
    {
        // A topic outside publish_allow is refused by the ACL even with an oversized payload, and an
        // oversized payload never reaches the packet filter.
        var harness = new Harness(Config("limits:\n  max_payload_size: 64"));
        var refused = await harness.Publish("msh/ES/2/e/SFNarrow/!1a2b3c4d", new byte[200]);
        Assert.False(refused.Accepted);
        Assert.False(refused.Closed);                                      // the client stays connected
        Assert.Equal(1, harness.Dropped(BrokerHooks.NotInPublishAllowReason));
        Assert.Equal(0, harness.Dropped(BrokerHooks.PayloadTooLargeReason));

        var tooBig = await harness.Publish(Sfnarrow, new byte[200]);
        Assert.False(tooBig.Accepted);
        Assert.False(tooBig.Closed);                                       // the client stays connected
        Assert.Equal(1, harness.Dropped(BrokerHooks.PayloadTooLargeReason));
        Assert.DoesNotContain(harness.Logs.Events, e => e.RenderMessage().Contains("malformed protobuf"));
    }

    // ---- The per-client publish rate -------------------------------------------------------------------------

    [Fact]
    public async Task PerClientRate_AllowsTheBurst_ThenRefusesWithQuotaExceeded()
    {
        var harness = new Harness(Config("limits:\n  publish_rate_per_client_per_minute: 60\n  publish_burst_per_client: 3"));
        Assert.True((await harness.Publish(Sfnarrow, Fixture("sfnarrow_aq.bin"))).Accepted);
        Assert.True((await harness.Publish(TestChannel, Fixture("test_ag.bin"))).Accepted);
        Assert.True((await harness.Publish(Valencia, Fixture("valencia_va.bin"))).Accepted);

        var refused = await harness.Publish(LowerTest, Fixture("test_lower_aq.bin"));
        Assert.False(refused.Accepted);
        Assert.Equal(MqttPubAckReasonCode.QuotaExceeded, refused.Code);
        Assert.False(refused.Closed);        // the client stays connected
        Assert.Equal(1, harness.Dropped(BrokerHooks.PublishRateReason));
    }

    [Fact]
    public async Task PerClientRate_RefillsWithTheClock()
    {
        var harness = new Harness(Config("limits:\n  publish_rate_per_client_per_minute: 60\n  publish_burst_per_client: 2"));
        Assert.True((await harness.Publish(Sfnarrow, Fixture("sfnarrow_aq.bin"))).Accepted);
        Assert.True((await harness.Publish(TestChannel, Fixture("test_ag.bin"))).Accepted);
        var refused = await harness.Publish(Valencia, Fixture("valencia_va.bin"));
        Assert.False(refused.Accepted);
        Assert.False(refused.Closed);        // the client stays connected

        harness.Clock.Advance(TimeSpan.FromSeconds(1));   // 60 per minute is one per second
        Assert.True((await harness.Publish(Valencia, Fixture("valencia_va.bin"))).Accepted);
    }

    [Fact]
    public async Task PerClientRate_IsCountedPerClient()
    {
        // The budget belongs to the (owner, client id) pair: another client has its own.
        var harness = new Harness(Config("limits:\n  publish_rate_per_client_per_minute: 60\n  publish_burst_per_client: 1"));
        Assert.True((await harness.Publish(Sfnarrow, Fixture("sfnarrow_aq.bin"), clientId: "a")).Accepted);
        var refused = await harness.Publish(TestChannel, Fixture("test_ag.bin"), clientId: "a");
        Assert.False(refused.Accepted);
        Assert.False(refused.Closed);        // the client stays connected
        Assert.True((await harness.Publish(TestChannel, Fixture("test_ag.bin"), clientId: "b")).Accepted);
    }

    [Fact]
    public async Task PerClientRate_StateDiesWithTheSession()
    {
        var harness = new Harness(Config("limits:\n  publish_rate_per_client_per_minute: 60\n  publish_burst_per_client: 1"));
        Assert.True((await harness.Publish(Sfnarrow, Fixture("sfnarrow_aq.bin"), clientId: "node-a")).Accepted);
        var refused = await harness.Publish(TestChannel, Fixture("test_ag.bin"), clientId: "node-a");
        Assert.False(refused.Accepted);
        Assert.False(refused.Closed);        // the client stays connected
        Assert.Equal(1, harness.Hooks.PublishRate.Count);

        await harness.Hooks.OnSessionDeletedAsync(new SessionDeletedEventArgs("node-a", "meshdev", new Hashtable()));
        Assert.Equal(0, harness.Hooks.PublishRate.Count);

        // A client id taken over later starts with a full budget.
        Assert.True((await harness.Publish(Valencia, Fixture("valencia_va.bin"), clientId: "node-a")).Accepted);
    }

    [Fact]
    public async Task PerClientRate_IsOffWhenTheRateIsZero()
    {
        var harness = new Harness(Config("limits:\n  publish_rate_per_client_per_minute: 0\n  packet_rate_per_from_per_minute: 0"));
        var flood = SplitFlood(Fixture("flood_packets.bin"));
        for (var i = 0; i < 20; i++)
            Assert.True((await harness.Publish(Sfnarrow, flood[i], clientId: "flood")).Accepted);
    }

    // ---- The gateway binding --------------------------------------------------------------------------------

    [Theory]
    [InlineData("!1a2b3c4d", true)]        // the gateway the envelope claims
    [InlineData("!deadbeef", true)]       // another gateway: a relay is not the sender, but it must be a node id
    [InlineData("!1A2B3C4D", false)]       // upper case: not what the firmware writes
    [InlineData("1a2b3c4d", false)]        // no '!'
    [InlineData("!1a2b3c4", false)]        // not 8 digits
    [InlineData("!1a2b3c4dd", false)]      // too long
    [InlineData("!1a2b3c4d\u200b", false)] // a zero-width space glued to it
    [InlineData("!1a2b3c4\u200b", false)]
    public void GatewayBinding_TheTopicMustCarryTheEnvelopesGateway(string gateway, bool accepted)
    {
        var env = ServiceEnvelope.Parser.ParseFrom(Fixture("sfnarrow_aq.bin"));
        env.GatewayId = gateway;
        var r = new PacketInspector(Config()).Inspect($"msh/EU_868/2/e/SFNarrow/{gateway}", env.ToByteArray());
        Assert.Equal(accepted, r.Accepted);
        if (!accepted)
            Assert.Equal(PacketInspector.GatewayMismatchReason, r.Reason);
    }

    [Fact]
    public void GatewayBinding_TopicAndEnvelopeMustAgree()
    {
        var env = ServiceEnvelope.Parser.ParseFrom(Fixture("sfnarrow_aq.bin"));
        env.GatewayId = "!deadbeef";
        var r = new PacketInspector(Config()).Inspect(Sfnarrow, env.ToByteArray());
        Assert.False(r.Accepted);
        Assert.Equal(PacketInspector.GatewayMismatchReason, r.Reason);
    }

    [Fact]
    public void GatewayBinding_AcceptsTheGatewayTheFirmwareWrites()
    {
        // NodeDB::getNodeId() is snprintf("!%08x", node_num): '!' and 8 lowercase hex digits.
        Assert.True(PacketInspector.IsGatewayId("!1a2b3c4d"));
        Assert.True(PacketInspector.IsGatewayId("!00000000"));
        Assert.False(PacketInspector.IsGatewayId("!1A2B3C4D"));
        Assert.False(PacketInspector.IsGatewayId("1a2b3c4d"));
        Assert.False(PacketInspector.IsGatewayId("!1a2b3c4"));
        Assert.False(PacketInspector.IsGatewayId("!1a2b3c4dd"));
        Assert.False(PacketInspector.IsGatewayId("!1a2b3c4d\u200b"));
        Assert.False(PacketInspector.IsGatewayId(null));
        Assert.False(PacketInspector.IsGatewayId(""));
    }

    [Fact]
    public async Task GatewayBinding_DropsThePublish_AndCountsIt()
    {
        var harness = new Harness(Config());
        var env = ServiceEnvelope.Parser.ParseFrom(Fixture("sfnarrow_aq.bin"));
        env.GatewayId = "!deadbeef";
        var refused = await harness.Publish(Sfnarrow, env.ToByteArray());
        Assert.False(refused.Accepted);
        Assert.False(refused.Closed);                                      // the client stays connected
        Assert.Equal(1, harness.Dropped(PacketInspector.GatewayMismatchReason));
    }

    // ---- The cross-gateway dedupe ---------------------------------------------------------------------------

    [Fact]
    public async Task Dedupe_AReplayFromTheSameGateway_IsDropped()
    {
        var harness = new Harness(Config());
        Assert.True((await harness.Publish(Sfnarrow, Fixture("sfnarrow_aq.bin"))).Accepted);

        var replay = await harness.Publish(Sfnarrow, Fixture("sfnarrow_aq.bin"));
        Assert.False(replay.Accepted);
        Assert.False(replay.Closed);                                      // the client stays connected
        Assert.Equal(1, harness.Dropped(BrokerHooks.DuplicateGatewayReason));
    }

    [Fact]
    public async Task Dedupe_KeepsOneCopyPerGateway_AndCapsTheNumberOfGateways()
    {
        var harness = new Harness(Config());
        for (var i = 0; i < 32; i++)
        {
            var gateway = $"!{i + 1:x8}";
            var outcome = await harness.Publish($"msh/EU_868/2/e/SFNarrow/{gateway}",
                WithGateway("sfnarrow_aq.bin", gateway), clientId: $"gw-{i}");
            Assert.True(outcome.Accepted, $"the copy of gateway {gateway} must be kept");
        }

        var extra = await harness.Publish("msh/EU_868/2/e/SFNarrow/!00000021",
            WithGateway("sfnarrow_aq.bin", "!00000021"), clientId: "gw-32");
        Assert.False(extra.Accepted);
        Assert.False(extra.Closed);                                       // the client stays connected
        Assert.Equal(1, harness.Dropped(BrokerHooks.TooManyGatewaysReason));
    }

    [Fact]
    public async Task Dedupe_EntryExpiresAfterTheWindow()
    {
        var harness = new Harness(Config("limits:\n  dedupe_window_seconds: 10\n  packet_rate_per_from_per_minute: 0"));
        Assert.True((await harness.Publish(Sfnarrow, Fixture("sfnarrow_aq.bin"))).Accepted);
        var replay = await harness.Publish(Sfnarrow, Fixture("sfnarrow_aq.bin"));
        Assert.False(replay.Accepted);
        Assert.False(replay.Closed);                                      // the client stays connected

        harness.Clock.Advance(TimeSpan.FromSeconds(11));
        Assert.True((await harness.Publish(Sfnarrow, Fixture("sfnarrow_aq.bin"))).Accepted);
    }

    [Fact]
    public async Task Dedupe_EvictsTheOldestEntriesAtTheCap()
    {
        var harness = new Harness(Config("limits:\n  dedupe_max_entries: 4\n  packet_rate_per_from_per_minute: 0"));
        foreach (var (topic, fixture) in DistinctPackets)
            Assert.True((await harness.Publish(topic, Fixture(fixture))).Accepted);

        Assert.Equal(4, harness.Hooks.Gate.DedupeCount);
        Assert.Equal(1, harness.Hooks.Gate.DedupeEvictions);

        // The oldest entry is gone: the same packet may be published again.
        Assert.True((await harness.Publish(Sfnarrow, Fixture("sfnarrow_aq.bin"))).Accepted);
        Assert.Equal(4, harness.Hooks.Gate.DedupeCount);
        Assert.Equal(2, harness.Hooks.Gate.DedupeEvictions);
    }

    [Fact]
    public async Task FillingTheDedupeTable_CountsTheEvictions_ForTheOperator()
    {
        // The eviction is counted, so it shows in the periodic summary: an operator sees that a cap was hit.
        var harness = new Harness(Config("limits:\n  dedupe_max_entries: 4\n  packet_rate_per_from_per_minute: 0"));
        foreach (var (topic, fixture) in DistinctPackets)
            Assert.True((await harness.Publish(topic, Fixture(fixture))).Accepted);

        Assert.Equal(1, harness.Dropped(PacketGate.DedupeEvictionReason));
    }

    [Fact]
    public async Task MapReports_AreNotDeduplicated()
    {
        // A map report carries no packet id, so it is never a replay of another one.
        var harness = new Harness(Config());
        Assert.True((await harness.Publish(MapTopic, Fixture("map_report.bin"))).Accepted);
        Assert.True((await harness.Publish(MapTopic, Fixture("map_report.bin"))).Accepted);
        Assert.Equal(0, harness.Hooks.Gate.DedupeCount);
    }

    // ---- The per-node packet rate ---------------------------------------------------------------------------

    [Fact]
    public async Task PerFromRate_IsChargedOncePerPacket_NotPerCopy()
    {
        var harness = new Harness(Config("limits:\n  packet_rate_per_from_per_minute: 60\n  packet_burst_per_from: 1"));
        // Five copies of the same packet, from five gateways: one packet, one token.
        for (var i = 0; i < 5; i++)
        {
            var gateway = $"!{i + 1:x8}";
            Assert.True((await harness.Publish($"msh/EU_868/2/e/SFNarrow/{gateway}",
                WithGateway("sfnarrow_aq.bin", gateway), clientId: $"gw-{i}")).Accepted);
        }

        // The next packet of the same node has no budget left.
        var refused = await harness.Publish(TestChannel, Fixture("test_ag.bin"), clientId: "next");
        Assert.False(refused.Accepted);
        Assert.False(refused.Closed);        // the client stays connected
        Assert.Equal(1, harness.Dropped(BrokerHooks.PacketRateReason));

        // The clock refills the budget (a packet that was refused keeps its verdict, so this one is new).
        harness.Clock.Advance(TimeSpan.FromSeconds(1));
        Assert.True((await harness.Publish(Valencia, Fixture("valencia_va.bin"), clientId: "next")).Accepted);
    }

    [Fact]
    public async Task PerFromRate_VerdictIsSticky_ForTheWholePacket()
    {
        var harness = new Harness(Config("limits:\n  packet_rate_per_from_per_minute: 1\n  packet_burst_per_from: 1"));
        // The first packet of the node takes the only token of its budget.
        Assert.True((await harness.Publish(Sfnarrow, Fixture("sfnarrow_aq.bin"), clientId: "a")).Accepted);

        // The next packet of the same node has no budget left: it is refused.
        var refused = await harness.Publish(TestChannel, Fixture("test_ag.bin"), clientId: "b");
        Assert.False(refused.Accepted);
        Assert.False(refused.Closed);        // the client stays connected

        // The verdict is sticky: a later copy of that packet, from another gateway, is refused too.
        var later = await harness.Publish("msh/EU_868/2/e/Test/!00000002",
            WithGateway("test_ag.bin", "!00000002"), clientId: "c");
        Assert.False(later.Accepted);
        Assert.False(later.Closed);          // the client stays connected
        Assert.Equal(2, harness.Dropped(BrokerHooks.PacketRateReason));

        // A copy of the first packet is not charged again: it is still accepted.
        var copy = await harness.Publish("msh/EU_868/2/e/SFNarrow/!00000002",
            WithGateway("sfnarrow_aq.bin", "!00000002"), clientId: "d");
        Assert.True(copy.Accepted);
    }

    [Fact]
    public async Task MapReports_AreChargedAsOnePacketOfTheirNode()
    {
        var harness = new Harness(Config("limits:\n  packet_rate_per_from_per_minute: 60\n  packet_burst_per_from: 1"));
        Assert.True((await harness.Publish(MapTopic, Fixture("map_report.bin"))).Accepted);

        // The node's budget is spent: its next packet is refused.
        var refused = await harness.Publish(Sfnarrow, Fixture("sfnarrow_aq.bin"));
        Assert.False(refused.Accepted);
        Assert.False(refused.Closed);        // the client stays connected
        Assert.Equal(1, harness.Dropped(BrokerHooks.PacketRateReason));
    }

    // ---- Bounded memory -------------------------------------------------------------------------------------

    [Fact]
    public async Task AFloodOfForgedPackets_StaysUnderTheEntryCap()
    {
        var harness = new Harness(Config("limits:\n  dedupe_max_entries: 100\n  packet_rate_per_from_per_minute: 0"));
        var flood = SplitFlood(Fixture("flood_packets.bin"));
        Assert.Equal(200, flood.Count);

        for (var i = 0; i < flood.Count; i++)
            await harness.Publish(Sfnarrow, flood[i], clientId: $"flood-{i}");

        Assert.True(harness.Hooks.Gate.DedupeCount <= 100, $"{harness.Hooks.Gate.DedupeCount} entries left");
        Assert.Equal(100, harness.Hooks.Gate.DedupeEvictions);
        Assert.Equal(100, harness.Dropped(PacketGate.DedupeEvictionReason));
    }

    [Fact]
    public void AFloodOfForgedNodeNumbers_StaysUnderTheNodeCap()
    {
        // The per-node rate table is bounded too: a client that forges the `from` of its packets cannot
        // grow it without limit.
        var clock = new FakeClock();
        var gate = new PacketGate(Config("limits:\n  packet_rate_per_from_per_minute: 60\n  packet_burst_per_from: 1").Limits!, clock, 50);
        for (uint i = 1; i <= 500; i++)
            gate.EvaluatePacket(i, i, "!00000001");

        Assert.True(gate.RateCount <= 50, $"{gate.RateCount} nodes left");
        Assert.True(gate.RateEvictions >= 450, $"{gate.RateEvictions} evictions");
    }

    // ---- Concurrency ----------------------------------------------------------------------------------------

    /// <summary>
    /// Runs <paramref name="body"/> for 0..count-1, each on its own thread and all released at the same
    /// moment, so the calls really race. The publish hook answers synchronously, so without the barrier
    /// the calls would run one after another.
    /// </summary>
    static Harness.Outcome[] RunInParallel(int count, Func<int, Harness.Outcome> body)
    {
        var results = new Harness.Outcome[count];
        var errors = new Exception?[count];
        var barrier = new Barrier(count);
        var inside = new CountdownEvent(count);
        var threads = new Thread[count];
        for (var i = 0; i < count; i++)
        {
            var index = i;
            threads[i] = new Thread(() =>
            {
                try
                {
                    // All the threads are released at the same moment...
                    if (!barrier.SignalAndWait(TimeSpan.FromSeconds(30)))
                        throw new TimeoutException("the parallel publishes did not start together");
                    // ...and all of them are inside the call at the same time: the countdown only reaches
                    // zero when the calls really overlap, so the test cannot pass by accident.
                    inside.Signal();
                    if (!inside.Wait(TimeSpan.FromSeconds(30)))
                        throw new TimeoutException("the parallel publishes did not overlap");
                    results[index] = body(index);
                }
                catch (Exception ex)
                {
                    errors[index] = ex;
                }
            })
            { IsBackground = true };
        }
        foreach (var t in threads)
            t.Start();
        foreach (var t in threads)
            t.Join();
        foreach (var error in errors)
            if (error is not null)
                throw error;
        return results;
    }

    [Fact]
    public void ParallelCopiesOfOnePacket_KeepExactlyTheGatewayCap()
    {
        // 64 gateways send the same packet at the same time: the cap (32 by default) decides, and no copy
        // is lost or counted twice. Repeated, so a race would show up.
        for (var round = 0; round < 20; round++)
        {
            var harness = new Harness(Config());
            var outcomes = RunInParallel(64, i => harness.PublishNow($"msh/EU_868/2/e/SFNarrow/!{i + 1:x8}",
                WithGateway("sfnarrow_aq.bin", $"!{i + 1:x8}"), clientId: $"gw-{i}"));

            Assert.Equal(32, outcomes.Count(o => o.Accepted));
            Assert.Equal(32, harness.Dropped(BrokerHooks.TooManyGatewaysReason));
            Assert.Equal(0, harness.Dropped(BrokerHooks.DuplicateGatewayReason));
            Assert.DoesNotContain(outcomes, o => o.Closed);   // no refusal disconnects the client
        }
    }

    [Fact]
    public void ParallelReplaysOfOnePacket_FromOneGateway_AreCountedExactly()
    {
        // The same packet, from the same gateway, 64 times at once: one copy is kept.
        for (var round = 0; round < 20; round++)
        {
            var harness = new Harness(Config(
                "limits:\n  publish_rate_per_client_per_minute: 0\n  packet_rate_per_from_per_minute: 0"));
            var outcomes = RunInParallel(64, _ => harness.PublishNow(Sfnarrow, Fixture("sfnarrow_aq.bin"),
                clientId: "one-gateway"));

            Assert.Equal(1, outcomes.Count(o => o.Accepted));
            Assert.Equal(63, harness.Dropped(BrokerHooks.DuplicateGatewayReason));
            Assert.DoesNotContain(outcomes, o => o.Closed);   // no refusal disconnects the client
        }
    }

    [Fact]
    public void ParallelPacketsOfOneNode_ShareTheNodeBudget()
    {
        // 20 different packets of one node, the node's budget is 5 packets: exactly 5 get through.
        for (var round = 0; round < 20; round++)
        {
            var harness = new Harness(Config(
                "limits:\n  packet_rate_per_from_per_minute: 1\n  packet_burst_per_from: 5"));
            var flood = SplitFlood(Fixture("flood_packets.bin"));
            var outcomes = RunInParallel(20, i => harness.PublishNow(Sfnarrow, flood[i], clientId: $"gw-{i}"));

            Assert.Equal(5, outcomes.Count(o => o.Accepted));
            Assert.Equal(15, harness.Dropped(BrokerHooks.PacketRateReason));
            Assert.DoesNotContain(outcomes, o => o.Closed);   // no refusal disconnects the client
        }
    }

    [Fact]
    public void ParallelPublishesOfOneClient_ShareTheClientBudget()
    {
        // 20 publishes of one client, the client's budget is 5: exactly 5 get through, the rest are told
        // that the quota is exceeded.
        for (var round = 0; round < 20; round++)
        {
            var harness = new Harness(Config(
                "limits:\n  publish_rate_per_client_per_minute: 1\n  publish_burst_per_client: 5\n  packet_rate_per_from_per_minute: 0"));
            var flood = SplitFlood(Fixture("flood_packets.bin"));
            var outcomes = RunInParallel(20, i => harness.PublishNow(Sfnarrow, flood[i], clientId: "one-client"));

            Assert.Equal(5, outcomes.Count(o => o.Accepted));
            Assert.Equal(15, outcomes.Count(o => o.Code == MqttPubAckReasonCode.QuotaExceeded));
            Assert.Equal(15, harness.Dropped(BrokerHooks.PublishRateReason));
            Assert.DoesNotContain(outcomes, o => o.Closed);   // no refusal disconnects the client
        }
    }

    /// <summary>Splits the flood fixture: every envelope is preceded by its length as two big-endian bytes.</summary>
    static List<byte[]> SplitFlood(byte[] blob)
    {
        var envelopes = new List<byte[]>();
        for (var i = 0; i + 2 <= blob.Length;)
        {
            var length = (blob[i] << 8) | blob[i + 1];
            i += 2;
            envelopes.Add(blob[i..(i + length)]);
            i += length;
        }
        return envelopes;
    }
}
