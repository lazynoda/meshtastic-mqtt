using System.Globalization;
using System.Text;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using Meshtastic.Mqtt;
using Meshtastic.Protobufs;
using Serilog;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The packets and the files the tests of the filters need: an envelope built with the protobuf
/// classes and encrypted with the key of its channel, and a rules file in a temporary directory.
/// </summary>
static class FilterFixtures
{
    /// <summary>The gateway of the packets of the tests.</summary>
    public const uint Gateway = 0xa1b2c3d4;

    /// <summary>The node that sends the packets of the tests.</summary>
    public const uint Node = 0xdeadbeef;

    /// <summary>Writes a rules file and remembers it, so that it is deleted at the end.</summary>
    public static string WriteFile(string yaml)
    {
        var path = Path.Combine(Path.GetTempPath(), $"mmqtt-filters-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, yaml);
        return path;
    }

    /// <summary>Deletes the files that were written.</summary>
    public static void Delete(params string[] paths)
    {
        foreach (var path in paths)
        {
            try
            {
                File.Delete(path);
            }
            catch (IOException)
            {
            }
        }
    }

    /// <summary>
    /// A file with ten thousand rules that share one name: nine thousand nine hundred and ninety-nine
    /// problems, so the report of the file has to count them.
    /// </summary>
    public static string FileWithDuplicateNames()
    {
        var builder = new StringBuilder("gateways:\n");
        for (var scope = 1; scope <= 10; scope++)
        {
            builder.Append($"  \"!{scope:x8}\":\n");
            for (var i = 0; i < 1000; i++)
                builder.Append("    - name: the-same\n      channels:\n        allow: [Iberia]\n");
        }
        return builder.ToString();
    }

    /// <summary>A file with a number of distinct patterns of regular expressions.</summary>
    public static string FileWithPatterns(int count) =>
        FileWithPatterns(count, index => $"buy[ ]+now-{index}");

    /// <summary>A file with a number of distinct patterns of regular expressions.</summary>
    /// <param name="count">How many distinct patterns the file holds.</param>
    /// <param name="pattern">The pattern of each rule, by its number.</param>
    public static string FileWithPatterns(int count, Func<int, string> pattern)
    {
        var builder = new StringBuilder("gateways:\n");
        var index = 0;
        for (var scope = 1; scope <= 10 && index < count; scope++)
        {
            builder.Append($"  \"!{scope:x8}\":\n");
            for (var i = 0; i < 1000 && index < count; i++, index++)
            {
                builder.Append($"    - name: rule-{index}\n");
                builder.Append("      drop_if:\n");
                builder.Append("        - field: payload.text\n");
                builder.Append("          op: regex\n");
                builder.Append($"          value: \"{pattern(index)}\"\n");
                builder.Append("          portnum: TEXT_MESSAGE_APP\n");
                builder.Append("      unopened: allow\n");
            }
        }
        return builder.ToString();
    }

    /// <summary>The config of the tests: two users, two channels and, maybe, a rules file.</summary>
    public static BrokerConfig Config(string? filtersFile = null, bool dropPki = true, string extra = "") =>
        ConfigLoader.Parse("listener:\n  bind_address: 127.0.0.1\n  port: 1883\n"
            + $"drop_pki: {dropPki.ToString().ToLowerInvariant()}\n"
            + "channels:\n  Test: \"Ag==\"\n  Iberia: \"AQ==\"\n"
            + extra
            + "users:\n"
            + $"  - username: meshdev\n    password_hash: \"{AuthTests.AliceHash}\"\n    publish_allow: [\"msh/ES/2/e/#\", \"msh/ES/2/map/\"]\n"
            + $"  - username: alice\n    password_hash: \"{AuthTests.AliceHash}\"\n    publish_allow: [\"msh/ES/2/e/#\"]\n"
            + (filtersFile is null ? "" : $"filters:\n  file: \"{filtersFile}\"\n"));

    /// <summary>A logger that keeps the events, so that the tests can read them.</summary>
    public static (ILogger Logger, LogSink Logs) Logger()
    {
        var logs = new LogSink();
        return (new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger(), logs);
    }

    /// <summary>The topic of a channel packet.</summary>
    public static string Topic(string channel, uint gateway) => $"msh/ES/2/e/{channel}/!{gateway:x8}";

    /// <summary>
    /// A channel packet: a <c>Data</c> of the portnum, encrypted with the key of the channel (or with
    /// <paramref name="key"/>, to build a packet the broker cannot open).
    /// </summary>
    public static byte[] ChannelPacket(BrokerConfig config, string channel, uint from, uint id, uint gateway,
        PortNum portnum, byte[]? payload = null, byte[]? key = null)
    {
        var data = new Protobufs.Data { Portnum = portnum, Payload = ByteString.CopyFrom(payload ?? []) };
        var plain = data.ToByteArray();
        var channelKey = key ?? (config.ChannelKeyMap.TryGetValue(channel, out var found) ? found : config.DefaultKey);
        var encrypted = PacketCrypto.Transform(channelKey, from, id, plain);
        var packet = new MeshPacket
        {
            From = from,
            Id = id,
            To = uint.MaxValue,
            Channel = ChannelKeys.ChannelHash(channel, channelKey),
            Encrypted = ByteString.CopyFrom(encrypted),
        };
        var envelope = new ServiceEnvelope { ChannelId = channel, GatewayId = $"!{gateway:x8}", Packet = packet };
        return envelope.ToByteArray();
    }

    /// <summary>A text message packet.</summary>
    public static byte[] TextPacket(BrokerConfig config, string channel, uint from, uint id, uint gateway,
        string text) =>
        ChannelPacket(config, channel, from, id, gateway, PortNum.TextMessageApp,
            System.Text.Encoding.UTF8.GetBytes(text));

    /// <summary>A map report: a decoded packet with a MapReport as its payload.</summary>
    public static byte[] MapReport(uint from, string longName)
    {
        var report = new MapReport { LongName = longName, ShortName = "SN", PositionPrecision = 14 };
        var data = new Protobufs.Data { Portnum = PortNum.MapReportApp, Payload = report.ToByteString() };
        var packet = new MeshPacket { From = from, Id = 0, To = uint.MaxValue, Decoded = data };
        var envelope = new ServiceEnvelope
        {
            ChannelId = "SFNarrow",
            GatewayId = $"!{from:x8}",
            Packet = packet,
        };
        return envelope.ToByteArray();
    }

    /// <summary>
    /// The payload of a telemetry message with a battery level. The message is built through the
    /// descriptor of the protobuf, so the test does not depend on the name the generator gives the
    /// nested messages.
    /// </summary>
    public static byte[] TelemetryWithBattery(uint batteryLevel)
    {
        var telemetry = FilterSchema.PayloadMessages[FilterSchema.TelemetryApp];
        var metricsField = telemetry.FindFieldByName("device_metrics")!;
        var message = (IMessage)Activator.CreateInstance(telemetry.ClrType)!;
        var metrics = (IMessage)Activator.CreateInstance(metricsField.MessageType!.ClrType)!;
        var battery = metricsField.MessageType!.FindFieldByName("battery_level")!;
        var value = Convert.ChangeType(batteryLevel, battery.Accessor.GetValue(metrics).GetType());
        battery.Accessor.SetValue(metrics, value);
        metricsField.Accessor.SetValue(message, metrics);
        return message.ToByteArray();
    }

    /// <summary>
    /// The payload of a telemetry message with the free memory of the host. The message is built
    /// through the descriptor of the protobuf, so the test does not depend on the name the generator
    /// gives the nested messages.
    /// </summary>
    public static byte[] TelemetryWithFreeMem(ulong freeMemBytes)
    {
        var telemetry = FilterSchema.PayloadMessages[FilterSchema.TelemetryApp];
        var metricsField = telemetry.FindFieldByName("host_metrics")!;
        var message = (IMessage)Activator.CreateInstance(telemetry.ClrType)!;
        var metrics = (IMessage)Activator.CreateInstance(metricsField.MessageType!.ClrType)!;
        var freeMem = metricsField.MessageType!.FindFieldByName("freemem_bytes")!;
        freeMem.Accessor.SetValue(metrics, freeMemBytes);
        metricsField.Accessor.SetValue(message, metrics);
        return message.ToByteArray();
    }

    /// <summary>What the filter sees of a published packet (the same the publish hook builds).</summary>
    public static FilterInput Input(BrokerConfig config, string topic, byte[] payload, string user = "meshdev")
    {
        var inspection = new PacketInspector(config).Inspect(topic, payload);
        return new FilterInput(user, inspection.Gateway, inspection.GatewayNode, inspection.From, inspection.Channel,
            topic, inspection.Packet, inspection.Data, inspection.Portnum);
    }
}

/// <summary>
/// The packet filters: the scopes, the way the rules combine, the constraints, the operators and the
/// packets the broker could not open.
/// </summary>
public sealed class FilterTests
{
    // ---- R2: the scopes ------------------------------------------------------------------------------------

    [Fact]
    public void R2_GatewayScope_AllowsOnlyItsChannels()
    {
        // Noda's first example: the gateway !a1b2c3d4 may only send Iberia and SFNarrow.
        var file = FilterFixtures.WriteFile("""
            gateways:
              "!a1b2c3d4":
                - name: only-iberia-and-sfnarrow
                  channels:
                    allow: [Iberia, SFNarrow]
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            // The two channels of the rule pass.
            foreach (var channel in new[] { "Iberia", "SFNarrow" })
            {
                var allowed = FilterFixtures.ChannelPacket(config, channel, FilterFixtures.Node, 1,
                    FilterFixtures.Gateway, PortNum.TextMessageApp, "hola"u8.ToArray());
                var verdict = filter.Evaluate(FilterFixtures.Input(config,
                    FilterFixtures.Topic(channel, FilterFixtures.Gateway), allowed));
                Assert.True(verdict.Passed, channel);
            }

            // Another channel of the same gateway is refused, and the rule is named.
            var onTest = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 2, FilterFixtures.Gateway,
                PortNum.TextMessageApp, "hola"u8.ToArray());
            var refused = filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), onTest));
            Assert.False(refused.Passed);
            Assert.Equal("only-iberia-and-sfnarrow", refused.RuleName);
            Assert.Equal("gateway", refused.Scope);
            Assert.Equal("!a1b2c3d4", refused.ScopeKey);

            // The same packet from another gateway passes: the rule is about that gateway.
            var fromAnother = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 3, 0xb2c3d4e5,
                PortNum.TextMessageApp, "hola"u8.ToArray());
            Assert.True(filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", 0xb2c3d4e5), fromAnother)).Passed);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R2_NodeScope_AllowsOnlyItsPortnums_WhateverTheGateway()
    {
        // Noda's second example: the node !deadbeef, whatever gateway uploads it, may only send
        // POSITION_APP and TEXT_MESSAGE_APP.
        var file = FilterFixtures.WriteFile("""
            nodes:
              "!deadbeef":
                - name: only-position-and-text
                  portnums:
                    allow: [POSITION_APP, TEXT_MESSAGE_APP]
                  unopened: drop
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            // Three gateways upload the same node.
            foreach (var gateway in new[] { 0x11111111u, 0x22222222u, 0x33333333u })
            {
                var telemetry = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 7, gateway,
                    PortNum.TelemetryApp, new Telemetry().ToByteArray());
                var verdict = filter.Evaluate(FilterFixtures.Input(config, FilterFixtures.Topic("Test", gateway), telemetry));
                Assert.False(verdict.Passed, $"gateway !{gateway:x8}");
                Assert.Equal("only-position-and-text", verdict.RuleName);
                Assert.Equal("node", verdict.Scope);
                Assert.Equal("!deadbeef", verdict.ScopeKey);
            }

            // The portnums of the list pass, from any gateway.
            foreach (var gateway in new[] { 0x11111111u, 0x22222222u, 0x33333333u })
            {
                var text = FilterFixtures.TextPacket(config, "Test", FilterFixtures.Node, 8, gateway, "hola");
                Assert.True(filter.Evaluate(FilterFixtures.Input(config, FilterFixtures.Topic("Test", gateway), text)).Passed);
            }

            // Another node is not affected by the rule of this one.
            var other = FilterFixtures.ChannelPacket(config, "Test", 0x11112222u, 9, 0x11111111u,
                PortNum.TelemetryApp, new Telemetry().ToByteArray());
            Assert.True(filter.Evaluate(FilterFixtures.Input(config, FilterFixtures.Topic("Test", 0x11111111u), other)).Passed);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R2_UserScope_AppliesToTheSessionOwner()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              meshdev:
                - name: no-text
                  portnums:
                    deny: [TEXT_MESSAGE_APP]
                  unopened: drop
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var text = FilterFixtures.TextPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway, "hola");
            var topic = FilterFixtures.Topic("Test", FilterFixtures.Gateway);

            var refused = filter.Evaluate(FilterFixtures.Input(config, topic, text, "meshdev"));
            Assert.False(refused.Passed);
            Assert.Equal("user", refused.Scope);
            Assert.Equal("meshdev", refused.ScopeKey);

            // Another user is not affected.
            Assert.True(filter.Evaluate(FilterFixtures.Input(config, topic, text, "alice")).Passed);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R2_TheThreeStarScopes_ApplyToEveryUserGatewayAndNode()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: star-user
                  channels:
                    allow: [Iberia]
            gateways:
              "*":
                - name: star-gateway
                  channels:
                    allow: [Iberia]
            nodes:
              "*":
                - name: star-node
                  channels:
                    allow: [Iberia]
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var onTest = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                PortNum.TextMessageApp, "hola"u8.ToArray());
            var verdict = filter.Evaluate(FilterFixtures.Input(config, FilterFixtures.Topic("Test", FilterFixtures.Gateway), onTest));
            Assert.False(verdict.Passed);
            Assert.Equal("star-user", verdict.RuleName);   // the user scope is judged first

            var onIberia = FilterFixtures.ChannelPacket(config, "Iberia", FilterFixtures.Node, 2, FilterFixtures.Gateway,
                PortNum.TextMessageApp, "hola"u8.ToArray());
            Assert.True(filter.Evaluate(FilterFixtures.Input(config, FilterFixtures.Topic("Iberia", FilterFixtures.Gateway), onIberia)).Passed);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    // ---- R3: the rules combine --------------------------------------------------------------------------------

    [Fact]
    public void R3_UserAllows_GatewayDenies_ThePacketIsDropped()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              meshdev:
                - name: user-allows
                  channels:
                    allow: [Iberia]
            gateways:
              "!a1b2c3d4":
                - name: gateway-denies
                  channels:
                    deny: [Iberia]
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var packet = FilterFixtures.ChannelPacket(config, "Iberia", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                PortNum.TextMessageApp, "hola"u8.ToArray());
            var verdict = filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Iberia", FilterFixtures.Gateway), packet));
            Assert.False(verdict.Passed);
            Assert.Equal("gateway-denies", verdict.RuleName);
            Assert.Equal("gateway", verdict.Scope);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R3_AllThreeScopesAllow_ThePacketIsDelivered()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              meshdev:
                - name: user-allows
                  channels:
                    allow: [Iberia]
            gateways:
              "!a1b2c3d4":
                - name: gateway-allows
                  channels:
                    allow: [Iberia]
            nodes:
              "!deadbeef":
                - name: node-allows
                  channels:
                    allow: [Iberia]
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var packet = FilterFixtures.ChannelPacket(config, "Iberia", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                PortNum.TextMessageApp, "hola"u8.ToArray());
            Assert.True(filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Iberia", FilterFixtures.Gateway), packet)).Passed);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    // ---- R4: the constraints -----------------------------------------------------------------------------------

    [Fact]
    public void R4_TopicsAllowAndDeny_WithTheWildcards()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: only-the-test-channel-topic
                  topics:
                    allow: ["msh/ES/2/e/Test/+"]
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var packet = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                PortNum.TextMessageApp, "hola"u8.ToArray());
            Assert.True(filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), packet)).Passed);

            var other = FilterFixtures.ChannelPacket(config, "Iberia", FilterFixtures.Node, 2, FilterFixtures.Gateway,
                PortNum.TextMessageApp, "hola"u8.ToArray());
            Assert.False(filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Iberia", FilterFixtures.Gateway), other)).Passed);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R4_TopicsDeny_WithTheHashWildcard()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: no-private-channel
                  topics:
                    deny: ["msh/ES/2/e/Private/#"]
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var packet = FilterFixtures.ChannelPacket(config, "Private", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                PortNum.TextMessageApp, "hola"u8.ToArray());
            var verdict = filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Private", FilterFixtures.Gateway), packet));
            Assert.False(verdict.Passed);
            Assert.Equal("no-private-channel", verdict.RuleName);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R4_TheChannelPki_IsAChannelName()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: no-pki
                  channels:
                    deny: [PKI]
            """);
        try
        {
            var config = FilterFixtures.Config(file, dropPki: false);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var pki = PublishFilterTests.Fixture("pki_dm.bin");
            var verdict = filter.Evaluate(FilterFixtures.Input(config, "msh/ES/2/e/PKI/!1a2b3c4d", pki));
            Assert.False(verdict.Passed);
            Assert.Equal("no-pki", verdict.RuleName);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R5_AMapReportIsFilteredByAPayloadCondition()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: no-map-report-of-madrid
                  drop_if:
                    - field: payload.long_name
                      op: contains
                      value: Madrid
                      portnum: MAP_REPORT_APP
                  unopened: allow
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var madrid = FilterFixtures.MapReport(0x1a2b3c4d, "Nodo Mapa Madrid");
            var verdict = filter.Evaluate(FilterFixtures.Input(config, "msh/ES/2/map/", madrid));
            Assert.False(verdict.Passed);
            Assert.Equal("no-map-report-of-madrid", verdict.RuleName);

            var other = FilterFixtures.MapReport(0x1a2b3c4d, "Nodo Mapa Sevilla");
            Assert.True(filter.Evaluate(FilterFixtures.Input(config, "msh/ES/2/map/", other)).Passed);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R6_APkiDirectMessageIsAlwaysUnopened()
    {
        // The broker never opens a direct message: a rule that needs an opened packet drops it.
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: only-text
                  portnums:
                    allow: [TEXT_MESSAGE_APP]
                  unopened: drop
            """);
        try
        {
            var config = FilterFixtures.Config(file, dropPki: false);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var pki = PublishFilterTests.Fixture("pki_dm.bin");
            var verdict = filter.Evaluate(FilterFixtures.Input(config, "msh/ES/2/e/PKI/!1a2b3c4d", pki));
            Assert.False(verdict.Passed);
            Assert.Equal("only-text", verdict.RuleName);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R4_AMapReportHasNoChannel_SoAnAllowListRefusesItAndADenyListAcceptsIt()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: needs-a-channel
                  channels:
                    allow: [Iberia]
                - name: no-map-report
                  channels:
                    deny: [Iberia]
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var report = FilterFixtures.MapReport(0x1a2b3c4d, "Nodo");
            // The first rule refuses it: a map report has no channel, so an allow-list is not satisfied.
            var verdict = filter.Evaluate(FilterFixtures.Input(config, "msh/ES/2/map/", report));
            Assert.False(verdict.Passed);
            Assert.Equal("needs-a-channel", verdict.RuleName);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R4_AMapReportHasNoChannel_SoADenyListAcceptsIt()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: no-map-report
                  channels:
                    deny: [Iberia]
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var report = FilterFixtures.MapReport(0x1a2b3c4d, "Nodo");
            Assert.True(filter.Evaluate(FilterFixtures.Input(config, "msh/ES/2/map/", report)).Passed);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    // ---- R5: the conditions and the operators ------------------------------------------------------------------

    [Theory]
    [InlineData("payload.text", "eq", "hola", true)]          // a text
    [InlineData("payload.text", "eq", "adios", false)]
    [InlineData("payload.text", "ne", "adios", true)]
    [InlineData("payload.text", "contains", "ol", true)]       // a text
    [InlineData("payload.text", "contains", "xyz", false)]
    [InlineData("payload.text", "regex", "^ho.*$", true)]       // a text
    [InlineData("payload.text", "regex", "^ad.*$", false)]
    [InlineData("packet.id", "eq", "42", true)]                // a number
    [InlineData("packet.id", "eq", "43", false)]
    [InlineData("packet.id", "ne", "43", true)]
    [InlineData("packet.id", "lt", "43", true)]                 // a number
    [InlineData("packet.id", "le", "42", true)]
    [InlineData("packet.id", "gt", "43", false)]
    [InlineData("packet.id", "ge", "42", true)]
    [InlineData("packet.id", "in", "[41, 42]", true)]          // a list
    [InlineData("packet.id", "in", "[41, 43]", false)]
    [InlineData("data.portnum", "eq", "TEXT_MESSAGE_APP", true)]   // an enum, by its name
    [InlineData("data.portnum", "eq", "1", true)]                  // an enum, by its number
    [InlineData("data.portnum", "ne", "POSITION_APP", true)]
    [InlineData("data.portnum", "in", "[POSITION_APP, TEXT_MESSAGE_APP]", true)]
    [InlineData("packet.want_ack", "eq", "false", true)]        // a boolean
    [InlineData("packet.want_ack", "ne", "true", true)]
    // A uint64 with the high bit put (N8): the number is compared as it is, without an overflow.
    [InlineData("payload.host_metrics.freemem_bytes", "eq", "18446744073709551615", true,
        "TELEMETRY_APP", "telemetry")]
    [InlineData("payload.host_metrics.freemem_bytes", "ne", "18446744073709551615", false,
        "TELEMETRY_APP", "telemetry")]
    [InlineData("payload.host_metrics.freemem_bytes", "lt", "100", false,
        "TELEMETRY_APP", "telemetry")]
    [InlineData("payload.host_metrics.freemem_bytes", "gt", "9223372036854775807", true,
        "TELEMETRY_APP", "telemetry")]
    [InlineData("payload.host_metrics.freemem_bytes", "in", "[18446744073709551615]", true,
        "TELEMETRY_APP", "telemetry")]
    public void R5_EveryOperator_OnAFieldOfItsType(string field, string op, string value, bool dropped,
        string portnum = "TEXT_MESSAGE_APP", string packet = "text")
    {
        var file = FilterFixtures.WriteFile($$"""
            users:
              "*":
                - name: the-rule
                  drop_if:
                    - field: {{field}}
                      op: {{op}}
                      value: {{value}}
                      portnum: {{portnum}}
                  unopened: allow
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var bytes = packet == "telemetry"
                ? FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 42, FilterFixtures.Gateway,
                    PortNum.TelemetryApp, FilterFixtures.TelemetryWithFreeMem(ulong.MaxValue))
                : FilterFixtures.TextPacket(config, "Test", FilterFixtures.Node, 42, FilterFixtures.Gateway, "hola");
            var verdict = filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), bytes));
            Assert.True(dropped == !verdict.Passed, $"{field} {op} {value}");
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R5_NeOnAnAbsentField_IsTrue()
    {
        // The packet is encrypted: the decoded variant of the header is not there.
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: no-decoded
                  drop_if:
                    - field: packet.decoded.portnum
                      op: ne
                      value: TEXT_MESSAGE_APP
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var packet = FilterFixtures.TextPacket(config, "Test", FilterFixtures.Node, 42, FilterFixtures.Gateway, "hola");
            var verdict = filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), packet));
            Assert.False(verdict.Passed);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R5_ANestedPath_ReadsTheFieldOfTheMessage()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: low-battery
                  drop_if:
                    - field: payload.device_metrics.battery_level
                      op: lt
                      value: 20
                      portnum: TELEMETRY_APP
                  unopened: allow
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var telemetry = FilterFixtures.TelemetryWithBattery(10);
            var packet = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                PortNum.TelemetryApp, telemetry);
            var verdict = filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), packet));
            Assert.False(verdict.Passed);
            Assert.Equal("low-battery", verdict.RuleName);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R5_AConditionWithAPortnum_DoesNotApplyToAnotherPortnum()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: no-text
                  drop_if:
                    - field: payload.text
                      op: contains
                      value: hola
                      portnum: TEXT_MESSAGE_APP
                  unopened: allow
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var telemetry = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                PortNum.TelemetryApp, new Telemetry().ToByteArray());
            Assert.True(filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), telemetry)).Passed);

            var text = FilterFixtures.TextPacket(config, "Test", FilterFixtures.Node, 2, FilterFixtures.Gateway, "hola");
            Assert.False(filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), text)).Passed);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    // ---- R6: the packets the broker could not open -----------------------------------------------------------

    [Fact]
    public void R6_UnopenedDrop_ThePacketIsDropped()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: only-text
                  portnums:
                    allow: [TEXT_MESSAGE_APP]
                  unopened: drop
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            // The packet is encrypted with another key: the broker cannot open it.
            var unopened = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                PortNum.TextMessageApp, "hola"u8.ToArray(), config.DefaultKey);
            var verdict = filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), unopened));
            Assert.False(verdict.Passed);
            Assert.Equal("only-text", verdict.RuleName);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R6_UnopenedAllow_ThePacketIsJudgedOnTheRestOfTheRule()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: only-text
                  portnums:
                    allow: [TEXT_MESSAGE_APP]
                  channels:
                    allow: [Test]
                  unopened: allow
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            // The packet is encrypted with another key: the broker cannot open it. The part of the rule
            // that needs an opened packet is skipped, so the rule is judged on the channel alone.
            var unopened = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                PortNum.TextMessageApp, "hola"u8.ToArray(), config.DefaultKey);
            Assert.True(filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), unopened)).Passed);

            // The channel is not in the list: the rule fails on the part that does not need an open packet.
            var onIberia = FilterFixtures.ChannelPacket(config, "Iberia", FilterFixtures.Node, 2, FilterFixtures.Gateway,
                PortNum.TextMessageApp, "hola"u8.ToArray());
            Assert.False(filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Iberia", FilterFixtures.Gateway), onIberia)).Passed);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R6_APacketConditionWorksOnAnUnopenedPacket()
    {
        // The header of a packet the broker cannot open is in clear: the packet. conditions still work.
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: not-this-node
                  drop_if:
                    - field: packet.from
                      op: eq
                      value: 3735928559
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var unopened = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                PortNum.TextMessageApp, "hola"u8.ToArray(), config.DefaultKey);
            var verdict = filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), unopened));
            Assert.False(verdict.Passed);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R6_ARuleThatDoesNotNeedAnOpenedPacket_CanStillDropTheUnopenedOnes()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: no-unopened
                  channels:
                    allow: [Test]
                  unopened: drop
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            // The packet is encrypted with another key: the broker cannot open it, and the rule says
            // that an unopened packet fails it.
            var unopened = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                PortNum.TextMessageApp, "hola"u8.ToArray(), config.DefaultKey);
            var verdict = filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), unopened));
            Assert.False(verdict.Passed);
            Assert.Equal("no-unopened", verdict.RuleName);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    // ---- R10: the bounds ---------------------------------------------------------------------------------------

    [Fact]
    public void R10_APacketWithNoApplicableRule_DoesNotDecodeThePayload()
    {
        // The rule is of another node: nothing of this packet has to be read.
        var file = FilterFixtures.WriteFile("""
            nodes:
              "!11111111":
                - name: other-node
                  drop_if:
                    - field: payload.text
                      op: contains
                      value: hola
                      portnum: TEXT_MESSAGE_APP
                  unopened: allow
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var packet = FilterFixtures.TextPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway, "hola");
            Assert.True(filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), packet)).Passed);
            Assert.Equal(0, filter.Metrics.PayloadDecodes);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R10_ThePayloadIsDecodedOnceForOnePacket()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: one
                  drop_if:
                    - field: payload.text
                      op: contains
                      value: adios
                      portnum: TEXT_MESSAGE_APP
                  unopened: allow
                - name: two
                  drop_if:
                    - field: payload.text
                      op: regex
                      value: "h.*"
                      portnum: TEXT_MESSAGE_APP
                  unopened: allow
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var packet = FilterFixtures.TextPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway, "hola");
            var verdict = filter.Evaluate(FilterFixtures.Input(config, FilterFixtures.Topic("Test", FilterFixtures.Gateway), packet));
            Assert.Equal("two", verdict.RuleName);
            // Both rules read the text of the message, and it is decoded once.
            Assert.Equal(1, filter.Metrics.PayloadDecodes);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    // ---- M1: the numbers of 64 bits ------------------------------------------------------------------------

    [Fact]
    public void M1_AUint64FieldWithTheHighBitSet_NeverThrows()
    {
        // The repro of the review: a uint64 with the high bit put (the free memory of the host of a
        // node) must not throw an OverflowException when the rule is evaluated.
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: too-little-memory
                  drop_if:
                    - field: payload.host_metrics.freemem_bytes
                      op: lt
                      value: 100
                      portnum: TELEMETRY_APP
                  unopened: allow
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var packet = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                PortNum.TelemetryApp, FilterFixtures.TelemetryWithFreeMem(ulong.MaxValue));
            var verdict = filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), packet));

            // The rule is not failed by the condition: the packet passes.
            Assert.True(verdict.Passed);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void M1_AUint64FieldWithTheHighBitSet_IsComparedExactly()
    {
        var file = FilterFixtures.WriteFile("""
            users:
              "*":
                - name: no-memory
                  drop_if:
                    - field: payload.host_metrics.freemem_bytes
                      op: eq
                      value: 18446744073709551615
                      portnum: TELEMETRY_APP
                    - field: payload.host_metrics.freemem_bytes
                      op: gt
                      value: 9223372036854775807
                      portnum: TELEMETRY_APP
                  unopened: allow
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var packet = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                PortNum.TelemetryApp, FilterFixtures.TelemetryWithFreeMem(ulong.MaxValue));
            var verdict = filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), packet));

            // The two conditions are true: the rule fails and the packet is dropped.
            Assert.False(verdict.Passed);
            Assert.Equal("no-memory", verdict.RuleName);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void M1_NoNumericFieldOfTheDecodedMessages_ThrowsInTheEvaluation()
    {
        // Every numeric field of the messages the filter decodes (the payload of every portnum it
        // knows) is read with the extreme values of its type and with every operator: the evaluation
        // never throws, so the catch of the publish hook never turns a packet into an internal error.
        var fields = NumericFields().ToArray();
        Assert.NotEmpty(fields);
        var checkedFields = 0;
        foreach (var (portnum, path, descriptor, chain) in fields)
            checkedFields += CheckField("payload.", path, descriptor, chain, portnum);
        Assert.True(checkedFields > 50, checkedFields.ToString(CultureInfo.InvariantCulture));
    }

    [Fact]
    public void M1_NoNumericFieldOfThePacketOrTheData_ThrowsInTheEvaluation()
    {
        // The same for the cleartext header of the packet and for the decoded data: every numeric
        // field the loader accepts under `packet.` and under `data.`.
        var packetFields = NumericLeaves(MeshPacket.Descriptor, "", []).ToArray();
        var dataFields = NumericLeaves(Protobufs.Data.Descriptor, "", []).ToArray();
        Assert.NotEmpty(packetFields);
        Assert.NotEmpty(dataFields);
        var checkedFields = 0;
        foreach (var (path, chain) in packetFields)
            checkedFields += CheckField("packet.", path, MeshPacket.Descriptor, chain, null);
        foreach (var (path, chain) in dataFields)
            checkedFields += CheckField("data.", path, Protobufs.Data.Descriptor, chain, null);
        Assert.True(checkedFields > 20, checkedFields.ToString(CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// Reads one field with every extreme value of its type and with every operator: the evaluation
    /// never throws. It returns how many values it read.
    /// </summary>
    /// <param name="prefix">The prefix of the path: <c>packet.</c>, <c>data.</c> or <c>payload.</c>.</param>
    /// <param name="path">The path of the field, without the prefix.</param>
    /// <param name="descriptor">The message that holds the field.</param>
    /// <param name="chain">The fields to walk, from the root of the message to the leaf.</param>
    /// <param name="portnum">The portnum of the payload, when the field is in a payload.</param>
    static int CheckField(string prefix, string path, MessageDescriptor descriptor, FieldDescriptor[] chain,
        int? portnum)
    {
        var values = ExtremeValues(chain[^1]).ToArray();
        foreach (var value in values)
        {
            var literal = LiteralOf(chain[^1], value);
            var file = FilterFixtures.WriteFile(Rule(prefix, path, literal, portnum));
            try
            {
                var config = FilterFixtures.Config(file);
                var (logger, _) = FilterFixtures.Logger();
                using var filter = new PacketFilter(config, logger, startWatcher: false);

                try
                {
                    filter.Evaluate(InputWith(prefix, descriptor, chain, value, portnum));
                }
                catch (Exception ex)
                {
                    Assert.Fail($"the evaluation of '{prefix}{path}' with {literal} threw "
                        + $"{ex.GetType().Name}: {ex.Message}");
                }
            }
            finally
            {
                FilterFixtures.Delete(file);
            }
        }
        return values.Length;
    }

    /// <summary>The rule that reads the field with every operator.</summary>
    static string Rule(string prefix, string path, string literal, int? portnum)
    {
        var field = prefix + path;
        var builder = new StringBuilder();
        builder.AppendLine("users:");
        builder.AppendLine("  \"*\":");
        builder.AppendLine("    - name: the-rule");
        builder.AppendLine("      drop_if:");
        foreach (var op in new[] { "eq", "ne", "in", "lt", "le", "gt", "ge" })
        {
            builder.AppendLine($"        - field: {field}");
            builder.AppendLine($"          op: {op}");
            builder.AppendLine(op == "in" ? $"          value: [{literal}]" : $"          value: {literal}");
            if (portnum is not null)
                builder.AppendLine($"          portnum: {FilterSchema.PortNumName(portnum.Value)}");
        }
        builder.AppendLine("      unopened: allow");
        return builder.ToString();
    }

    /// <summary>The input of a packet that holds the value in the field.</summary>
    static FilterInput InputWith(string prefix, MessageDescriptor descriptor, FieldDescriptor[] chain, object value,
        int? portnum)
    {
        var message = Build(descriptor, chain, value);
        var packet = new MeshPacket { From = FilterFixtures.Node, Id = 1, To = uint.MaxValue };
        Protobufs.Data? data = null;
        if (prefix == "packet.")
        {
            packet = (MeshPacket)message;
        }
        else if (prefix == "data.")
        {
            data = (Protobufs.Data)message;
            packet.Decoded = data;
        }
        else
        {
            data = new Protobufs.Data { Portnum = (PortNum)portnum!.Value, Payload = message.ToByteString() };
            packet.Decoded = data;
        }
        return new FilterInput("meshdev", "!a1b2c3d4", 0xa1b2c3d4, FilterFixtures.Node, "Test",
            FilterFixtures.Topic("Test", FilterFixtures.Gateway), packet, data,
            portnum is null ? PortNum.TextMessageApp : (PortNum)portnum.Value);
    }

    /// <summary>Every numeric field of the messages the filter decodes, with the chain to reach it.</summary>
    static IEnumerable<(int Portnum, string Path, MessageDescriptor Descriptor, FieldDescriptor[] Chain)>
        NumericFields()
    {
        foreach (var (portnum, descriptor) in FilterSchema.PayloadMessages)
        {
            foreach (var (path, chain) in NumericLeaves(descriptor, "", []))
                yield return (portnum, path, descriptor, chain);
        }
    }

    /// <summary>The numeric fields of a message, and of the messages it holds.</summary>
    static IEnumerable<(string Path, FieldDescriptor[] Chain)> NumericLeaves(MessageDescriptor descriptor,
        string prefix, FieldDescriptor[] chain)
    {
        foreach (var field in descriptor.Fields.InFieldNumberOrder())
        {
            if (field.IsRepeated || field.FieldType == FieldType.Bytes)
                continue;   // a list and a text are not numbers
            var path = chain.Append(field).ToArray();
            if (field.FieldType is FieldType.Message or FieldType.Group)
            {
                foreach (var nested in NumericLeaves(field.MessageType!, $"{prefix}{field.Name}.", path))
                    yield return nested;
                continue;
            }
            if (!IsNumeric(field.FieldType) && field.FieldType != FieldType.Enum)
                continue;
            yield return ($"{prefix}{field.Name}", path);
        }
    }

    /// <summary>Whether the type of the field is a number.</summary>
    static bool IsNumeric(FieldType type) => type is FieldType.Int32 or FieldType.Int64 or FieldType.UInt32
        or FieldType.UInt64 or FieldType.SInt32 or FieldType.SInt64 or FieldType.Fixed32 or FieldType.Fixed64
        or FieldType.SFixed32 or FieldType.SFixed64 or FieldType.Float or FieldType.Double;

    /// <summary>The message with the value in the field.</summary>
    static IMessage Build(MessageDescriptor descriptor, FieldDescriptor[] chain, object value)
    {
        var message = (IMessage)Activator.CreateInstance(descriptor.ClrType)!;
        var current = message;
        for (var i = 0; i < chain.Length - 1; i++)
        {
            var child = (IMessage)Activator.CreateInstance(chain[i].MessageType!.ClrType)!;
            chain[i].Accessor.SetValue(current, child);
            current = child;
        }
        chain[^1].Accessor.SetValue(current, value);
        return message;
    }

    /// <summary>
    /// The extreme values of a numeric field: both ends of its type, and the numbers that are not
    /// numbers for the fields of floating point.
    /// </summary>
    static IEnumerable<object> ExtremeValues(FieldDescriptor field) => field.FieldType switch
    {
        FieldType.UInt64 => new object[] { ulong.MaxValue },
        FieldType.Fixed64 => new object[] { ulong.MaxValue },
        FieldType.Int64 => new object[] { long.MinValue, long.MaxValue },
        FieldType.SInt64 => new object[] { long.MinValue, long.MaxValue },
        FieldType.SFixed64 => new object[] { long.MinValue, long.MaxValue },
        FieldType.UInt32 => new object[] { uint.MaxValue },
        FieldType.Fixed32 => new object[] { uint.MaxValue },
        FieldType.Int32 => new object[] { int.MinValue, int.MaxValue },
        FieldType.SInt32 => new object[] { int.MinValue, int.MaxValue },
        FieldType.SFixed32 => new object[] { int.MinValue, int.MaxValue },
        FieldType.Float => new object[] { float.MaxValue, float.MinValue, float.NaN },
        FieldType.Double => new object[] { double.MaxValue, double.MinValue, double.NaN },
        // An enum holds a number: a value that has no name is a number like any other.
        FieldType.Enum => new object[]
        {
            Enum.ToObject(field.EnumType!.ClrType, int.MaxValue),
            Enum.ToObject(field.EnumType!.ClrType, int.MinValue),
        },
        _ => Array.Empty<object>(),
    };

    /// <summary>The value of the rule, as the file writes it.</summary>
    static string LiteralOf(FieldDescriptor field, object value)
    {
        // The numbers of an enum are compared by their number: the value of the rule is a number the
        // portnum range accepts (the field of the portnum is the only one that has a range).
        if (field.FieldType == FieldType.Enum)
            return "1";
        return value switch
        {
            ulong number => number.ToString(CultureInfo.InvariantCulture),
            long number => number.ToString(CultureInfo.InvariantCulture),
            uint number => number.ToString(CultureInfo.InvariantCulture),
            int number => number.ToString(CultureInfo.InvariantCulture),
            float number => number.ToString(CultureInfo.InvariantCulture),
            double number => number.ToString(CultureInfo.InvariantCulture),
            _ => "1",
        };
    }
}
