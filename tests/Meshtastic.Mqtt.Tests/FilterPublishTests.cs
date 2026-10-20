using Meshtastic.Mqtt;
using Meshtastic.Protobufs;
using Serilog;
using Serilog.Events;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The filters in the publish path: where they run (R7) and what they write in the log (R8).
/// </summary>
public sealed class FilterPublishTests
{
    /// <summary>The text of the packets of these tests: it must never reach the log.</summary>
    const string Secret = "secreto-de-prueba";

    static BrokerHooks Hooks(BrokerConfig config, PacketFilter filter, LogSink logs)
    {
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger();
        return new BrokerHooks(config, logger, filter: filter);
    }

    [Fact]
    public async Task R7_AFilteredCopySpendsNoDedupeEntryAndNoBudgetOfTheNode()
    {
        var file = FilterFixtures.WriteFile("""
            gateways:
              "!a1b2c3d4":
                - name: only-iberia
                  channels:
                    allow: [Iberia]
            """);
        try
        {
            var config = FilterFixtures.Config(file,
                extra: "limits:\n  packet_rate_per_from_per_minute: 1\n  packet_burst_per_from: 1\n");
            var (logger, logs) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);
            var hooks = Hooks(config, filter, logs);

            // The same packet (the same from and id) from two gateways.
            var fromA = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 0x20000001, 0xa1b2c3d4,
                PortNum.TextMessageApp, System.Text.Encoding.UTF8.GetBytes(Secret));
            var fromB = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 0x20000001, 0xb2c3d4e5,
                PortNum.TextMessageApp, System.Text.Encoding.UTF8.GetBytes(Secret));

            // The copy of the gateway A is filtered: it is dropped before the packet gate.
            var refused = PublishArgs(FilterFixtures.Topic("Test", 0xa1b2c3d4), fromA, "meshdev", "meshdev");
            await hooks.InterceptPublishAsync(refused);
            Assert.False(refused.ProcessPublish);
            Assert.Equal(0, hooks.Gate.DedupeCount);
            Assert.Equal(0, hooks.Gate.RateCount);

            // The copy of the gateway B is allowed: it reaches the subscribers and it is the first copy
            // the dedupe and the node's budget see.
            var allowed = PublishArgs(FilterFixtures.Topic("Test", 0xb2c3d4e5), fromB, "meshdev", "meshdev");
            await hooks.InterceptPublishAsync(allowed);
            Assert.True(allowed.ProcessPublish);
            Assert.Equal(1, hooks.Gate.DedupeCount);
            Assert.Equal(1, hooks.Gate.RateCount);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public async Task R8_AFilteredPacketIsCountedInTheSummaryUnderItsRule()
    {
        var file = FilterFixtures.WriteFile("""
            gateways:
              "!a1b2c3d4":
                - name: block-node-1
                  channels:
                    allow: [Iberia]
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, logs) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);
            var hooks = Hooks(config, filter, logs);

            var packet = FilterFixtures.TextPacket(config, "Test", FilterFixtures.Node, 1, 0xa1b2c3d4, Secret);
            var args = PublishArgs(FilterFixtures.Topic("Test", 0xa1b2c3d4), packet, "meshdev", "meshdev");
            await hooks.InterceptPublishAsync(args);
            Assert.False(args.ProcessPublish);

            // The reason of the summary is the name of the rule, whole: the digits are not collapsed.
            var counts = hooks.Drops.Snapshot();
            Assert.Contains("filtered: block-node-1", counts.Keys);
            Assert.Equal(1, counts["filtered: block-node-1"]);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public async Task R8_AFilteredPacketIsOnlyADebugLineAndItNeverCarriesThePayload()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: no-secret
                  drop_if:
                    - field: payload.text
                      op: contains
                      value: secreto
                      portnum: TEXT_MESSAGE_APP
                  unopened: allow
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, logs) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);
            var hooks = Hooks(config, filter, logs);

            var before = logs.Events.Count(e => e.Level >= LogEventLevel.Information);
            var packet = FilterFixtures.TextPacket(config, "Test", FilterFixtures.Node, 0x20000002, 0xa1b2c3d4, Secret);
            var args = PublishArgs(FilterFixtures.Topic("Test", 0xa1b2c3d4), packet, "meshdev", "meshdev");
            await hooks.InterceptPublishAsync(args);
            Assert.False(args.ProcessPublish);

            // One Debug line per packet: the scope, the rule, the channel, the from, the id and the gateway.
            var line = Assert.Single(logs.Events, e => e.MessageTemplate.Text.StartsWith("Dropped publish"));
            Assert.Equal(LogEventLevel.Debug, line.Level);
            var message = line.RenderMessage();

            // The line, exactly as it is written.
            Assert.Equal("Dropped publish on \"msh/ES/2/e/Test/!a1b2c3d4\" from \"node-1\": filtered: no-secret "
                + "(scope user, key *, channel Test, from \"!deadbeef\", id 536870914, gateway !a1b2c3d4)", message);
            Assert.Contains("filtered: no-secret", message);
            Assert.Contains("user", message);
            Assert.Contains("Test", message);
            Assert.Contains("!deadbeef", message);
            Assert.Contains("!a1b2c3d4", message);
            Assert.Contains("536870914", message);   // the id of the packet

            // Nothing above Debug for this packet, and no line carries the text of the message.
            Assert.Equal(before, logs.Events.Count(e => e.Level >= LogEventLevel.Information));
            Assert.DoesNotContain(logs.Events, e => e.Level >= LogEventLevel.Warning);
            Assert.DoesNotContain(logs.Events, e => e.RenderMessage().Contains(Secret));
            Assert.DoesNotContain(logs.Events, e => e.RenderMessage().Contains("secreto"));
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }
}
