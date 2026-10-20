using Google.Protobuf;
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
    public void R5_EveryOperator_OnAFieldOfItsType(string field, string op, string value, bool dropped)
    {
        var file = FilterFixtures.WriteFile($$"""
            users:
              "*":
                - name: the-rule
                  drop_if:
                    - field: {{field}}
                      op: {{op}}
                      value: {{value}}
                      portnum: TEXT_MESSAGE_APP
                  unopened: allow
            """);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var packet = FilterFixtures.TextPacket(config, "Test", FilterFixtures.Node, 42, FilterFixtures.Gateway, "hola");
            var verdict = filter.Evaluate(FilterFixtures.Input(config,
                FilterFixtures.Topic("Test", FilterFixtures.Gateway), packet));
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
}
