using Google.Protobuf;
using Meshtastic.Mqtt;
using Meshtastic.Protobufs;
using Xunit;
using static Meshtastic.Mqtt.Tests.PublishFilterTests;
using PbConfig = Meshtastic.Protobufs.Config;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// Map reports (<c>&lt;root&gt;/2/map/</c>) in the packet filter. The map_report*.bin fixtures are built by
/// Fixtures/make_fixtures.py with hand-written protobuf, mirroring firmware <c>MQTT::perhapsReportToMap()</c>.
/// </summary>
public class MapReportTests
{
    const string MapTopic = "msh/EU_868/2/map/";

    static Inspection Inspect(string topic, byte[] payload) => new PacketInspector(PublishFilterTests.Config()).Inspect(topic, payload);

    [Fact]
    public void ValidMapReport_IsAccepted()
    {
        var r = Inspect(MapTopic, Fixture("map_report.bin"));
        Assert.True(r.Accepted, r.Reason);
        Assert.Equal("map report", r.Reason);
        Assert.Equal(0x1A2B3C4Du, r.From);
        Assert.Equal(0u, r.PacketId);             // the firmware never assigns an id to a map report
        Assert.Equal(PortNum.MapReportApp, r.Portnum);
        Assert.Null(r.Channel);
    }

    [Fact]
    public void Fixture_IsTheFirmwareShape()
    {
        // Cross-check the independent fixture against the protobuf library: a decoded broadcast packet from the
        // reporting node, MAP_REPORT_APP, and a MapReport carrying what perhapsReportToMap() fills in.
        var env = ServiceEnvelope.Parser.ParseFrom(Fixture("map_report.bin"));
        Assert.Equal("SFNarrow", env.ChannelId);
        Assert.Equal("!1a2b3c4d", env.GatewayId);
        Assert.Equal(MeshPacket.PayloadVariantOneofCase.Decoded, env.Packet.PayloadVariantCase);
        Assert.Equal(uint.MaxValue, env.Packet.To);
        Assert.Equal(PortNum.MapReportApp, env.Packet.Decoded.Portnum);
        var report = MapReport.Parser.ParseFrom(env.Packet.Decoded.Payload);
        Assert.Equal("Nodo Mapa Madrid", report.LongName);
        Assert.Equal("MAPA", report.ShortName);
        Assert.Equal(PbConfig.Types.DeviceConfig.Types.Role.Router, report.Role);
        Assert.Equal(HardwareModel.Rak4631, report.HwModel);
        Assert.Equal(PbConfig.Types.LoRaConfig.Types.RegionCode.Eu868, report.Region);
        Assert.Equal(PbConfig.Types.LoRaConfig.Types.ModemPreset.ShortFast, report.ModemPreset);
        Assert.Equal(14u, report.PositionPrecision);
        Assert.True(report.HasOptedReportLocation);
        // Truncated to 14 bits plus half a step, as the firmware does: about 40.4 N, 3.7 W.
        Assert.InRange(report.LatitudeI / 1e7, 40.3, 40.5);
        Assert.InRange(report.LongitudeI / 1e7, -3.8, -3.6);
    }

    [Theory]
    [InlineData("map_report_encrypted.bin", "map report: packet is not decoded")]
    [InlineData("sfnarrow_aq.bin", "map report: packet is not decoded")]
    [InlineData("map_report_wrong_portnum.bin", "map report: portnum is not MAP_REPORT_APP")]
    [InlineData("plaintext_decoded.bin", "map report: portnum is not MAP_REPORT_APP")]
    [InlineData("map_report_garbage.bin", "map report: payload is not a MapReport")]
    [InlineData("map_report_wrong_gateway.bin", "map report: gateway_id is not the sender (from)")]
    [InlineData("garbage.bin", "map report: malformed protobuf")]
    public void InvalidMapReports_AreDropped_EachWithItsOwnReason(string fixture, string reason)
    {
        var r = Inspect(MapTopic, Fixture(fixture));
        Assert.False(r.Accepted);
        Assert.Equal(reason, r.Reason);
    }

    public static TheoryData<string, Action<ServiceEnvelope>, string> Mutations => new()
    {
        { "no packet", e => e.Packet = null, "map report: envelope without packet" },
        { "from 0", e => e.Packet.From = 0, "map report: packet without from" },
        { "empty MapReport", e => e.Packet.Decoded.Payload = ByteString.Empty, "map report: payload is not a MapReport" },
        { "gateway upper case", e => e.GatewayId = "!1A2B3C4D", "map report: gateway_id is not the sender (from)" },
        { "gateway without !", e => e.GatewayId = "1a2b3c4d", "map report: gateway_id is not the sender (from)" },
        { "gateway not padded", e => { e.Packet.From = 0xABCD; e.GatewayId = "!abcd"; }, "map report: gateway_id is not the sender (from)" },
        { "no gateway", e => e.GatewayId = "", "map report: gateway_id is not the sender (from)" },
    };

    [Theory]
    [MemberData(nameof(Mutations))]
    public void MutatedMapReports_AreDropped(string name, Action<ServiceEnvelope> mutate, string reason)
    {
        var env = ServiceEnvelope.Parser.ParseFrom(Fixture("map_report.bin"));
        mutate(env);
        var r = Inspect(MapTopic, env.ToByteArray());
        Assert.False(r.Accepted, name);
        Assert.Equal(reason, r.Reason);
    }

    [Fact]
    public void ZeroPaddedGatewayId_IsAccepted()
    {
        var env = ServiceEnvelope.Parser.ParseFrom(Fixture("map_report.bin"));
        env.Packet.From = 0xABCD;
        env.GatewayId = "!0000abcd";
        Assert.True(Inspect(MapTopic, env.ToByteArray()).Accepted);
    }

    [Theory]
    [InlineData("msh/EU_868/2/map/!1a2b3c4d")]    // extra level
    [InlineData("msh/EU_868/2/map/SFNarrow/!1a2b3c4d")]
    [InlineData("msh/EU_868/2/map")]              // no trailing slash
    [InlineData("msh/EU_868/2/map//")]
    [InlineData("2/map/")]                        // no root
    [InlineData("msh//2/map/")]                   // empty root level
    public void OtherMapTopics_AreDropped(string topic)
    {
        var r = Inspect(topic, Fixture("map_report.bin"));
        Assert.False(r.Accepted, topic);
        Assert.Contains("unsupported", r.Reason);
    }

    [Theory]
    [InlineData("msh/EU_868/2/map/")]
    [InlineData("msh/2/map/")]
    [InlineData("msh/EU_868/ES/2/map/")]    // root of any depth, like the /2/e/ topics
    public void MapTopic_FollowsTheFirmware(string topic) =>
        Assert.True(PacketInspector.IsMapReportTopic(topic));

    [Fact]
    public void MapReportOnAChannelTopic_IsNotAccepted()
    {
        // A plaintext map report is not a channel packet: on /2/e/ it is dropped as not encrypted.
        var r = Inspect("msh/EU_868/2/e/SFNarrow/!1a2b3c4d", Fixture("map_report.bin"));
        Assert.False(r.Accepted);
    }
}
