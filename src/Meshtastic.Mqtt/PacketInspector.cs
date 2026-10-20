using Google.Protobuf;
using Meshtastic.Protobufs;

namespace Meshtastic.Mqtt;

/// <summary>Outcome of inspecting one published message. Never carries the payload.</summary>
public sealed record Inspection(
    bool Accepted,
    string Reason,
    string? Channel = null,
    uint From = 0,
    uint PacketId = 0,
    PortNum? Portnum = null,
    bool? ChannelHashMatches = null,
    string? Gateway = null,
    uint GatewayNode = 0,
    /// <summary>
    /// The broker could not open the packet. It is not a refusal of the packet: the policy of the user that
    /// published it decides (<c>users[].forward_unopened</c>), and the publish hook applies it.
    /// </summary>
    bool Unopened = false,
    /// <summary>Why the packet was not opened: no key for its channel, or a key that does not open it.</summary>
    string? UnopenedWhy = null,
    /// <summary>
    /// The cleartext header of the packet (the fields the filters read). It is there even for a packet
    /// the broker could not open: only the payload of the packet is encrypted.
    /// </summary>
    MeshPacket? Packet = null,
    /// <summary>
    /// The decoded data of the packet, or null when the broker could not open it (a channel packet it
    /// does not have the key of, a PKI direct message).
    /// </summary>
    Protobufs.Data? Data = null);

/// <summary>
/// Decides whether a published message may reach subscribers. Pure logic on (topic, payload):
/// no MQTTnet types, no logging, never throws.
/// </summary>
public sealed class PacketInspector(BrokerConfig config)
{
    /// <summary>channel_id the firmware uses for PKI-encrypted DMs (src/mqtt/MQTT.cpp onSend()).</summary>
    public const string PkiChannel = "PKI";

    /// <summary>8-byte AES-CCM tag + 4-byte extra nonce appended to every PKI packet.</summary>
    const int PkiOverhead = 12;

    /// <summary>
    /// The reason of a packet the broker could not open. It is the drop reason when the user that published
    /// it drops those packets (<c>users[].forward_unopened: false</c>), and it is the key of the summary.
    /// </summary>
    public const string UndecryptableReason = "undecryptable with the key configured for this channel";

    /// <summary>Why a packet was not opened: its channel is not listed under <c>channels</c>.</summary>
    public const string UnopenedNoKeyReason = "no key is configured for this channel";

    /// <summary>Why a packet was not opened: the key of its channel does not open it.</summary>
    public const string UnopenedByKeyReason = "the key configured for this channel does not open it";

    public Inspection Inspect(string? topic, ReadOnlySpan<byte> payload)
    {
        try
        {
            return InspectCore(topic, payload);
        }
        catch (Exception ex)
        {
            return Drop($"internal error ({ex.GetType().Name})");
        }
    }

    Inspection InspectCore(string? topic, ReadOnlySpan<byte> payload)
    {
        if (payload.IsEmpty)
            return Drop("empty payload");
        if (IsMapReportTopic(topic))
            return InspectMapReport(payload);
        if (!TryParseTopic(topic, out var topicChannel, out var topicGateway))
        {
            return HasMapLevels(topic)
                ? Drop("unsupported map topic (expected <root>/2/map/)")
                : Drop("unsupported topic (expected <root>/2/e/<channel>/<gateway>)");
        }

        ServiceEnvelope envelope;
        try
        {
            envelope = ServiceEnvelope.Parser.ParseFrom(payload);
        }
        catch (InvalidProtocolBufferException)
        {
            return Drop("malformed protobuf");
        }

        var packet = envelope.Packet;
        if (packet is null)
            return Drop("envelope without packet");
        if (string.IsNullOrWhiteSpace(envelope.ChannelId) || string.IsNullOrWhiteSpace(envelope.GatewayId))
            return Drop("envelope without channel_id or gateway_id");

        var channel = envelope.ChannelId;
        if (packet.From == 0 || packet.Id == 0)
            return Drop("packet without from or id", channel, packet);
        if (packet.PayloadVariantCase != MeshPacket.PayloadVariantOneofCase.Encrypted)
            return Drop("packet is not encrypted", channel, packet);
        if (packet.Encrypted.Length == 0 || packet.Encrypted.Length > PacketCrypto.MaxEncryptedBytes)
            return Drop($"encrypted payload size {packet.Encrypted.Length} outside 1-{PacketCrypto.MaxEncryptedBytes}", channel, packet);
        if (!string.Equals(channel, topicChannel, StringComparison.Ordinal))
            return Drop("channel_id does not match the topic", channel, packet);
        if (!GatewayMatchesTopic(topicGateway, envelope.GatewayId))
            return Drop(GatewayMismatchReason, channel, packet);

        if (channel == PkiChannel)
            return InspectPki(packet, topicGateway);

        var gatewayNode = GatewayNode(topicGateway);
        // The key of the channel: the one of its name, or the default key for a channel that is not listed.
        byte[] key;
        bool listed;
        if (config.ChannelKeyMap.TryGetValue(channel, out var channelKey))
        {
            key = channelKey;
            listed = true;
        }
        else
        {
            key = config.DefaultKey;
            listed = false;
        }
        var hashMatches = ChannelKeys.ChannelHash(channel, key) == packet.Channel;
        var data = TryDecrypt(packet, key);
        if (data is null)
        {
            // The broker could not open the packet. It does not drop it here: the policy of the user that
            // published it decides (users[].forward_unopened), and the reason is the same either way.
            var why = listed ? UnopenedByKeyReason : UnopenedNoKeyReason;
            return new Inspection(false, UndecryptableReason, channel, packet.From, packet.Id, null, hashMatches,
                topicGateway, gatewayNode, Unopened: true, UnopenedWhy: why, Packet: packet);
        }
        return new Inspection(true, "decrypted", channel, packet.From, packet.Id, data.Portnum, hashMatches,
            topicGateway, gatewayNode, Packet: packet, Data: data);
    }

    Inspection InspectPki(MeshPacket packet, string gateway)
    {
        // Firmware only produces PKI packets as unicast, with channel hash 0 and the CCM overhead appended.
        if (packet.To == 0 || packet.To == uint.MaxValue || packet.Channel != 0 || packet.Encrypted.Length <= PkiOverhead)
            return Drop("malformed PKI packet", PkiChannel, packet);
        return config.DropPki
            ? Drop("PKI DM (drop_pki: true)", PkiChannel, packet)
            : new Inspection(true, "PKI DM passed through opaquely (drop_pki: false)", PkiChannel, packet.From, packet.Id,
                null, null, gateway, GatewayNode(gateway), Packet: packet);
    }

    /// <summary>
    /// A map report as the firmware publishes it (<c>src/mqtt/MQTT.cpp</c> <c>perhapsReportToMap()</c>): a
    /// ServiceEnvelope around a <b>decoded</b> MeshPacket with portnum MAP_REPORT_APP whose payload is a
    /// <c>MapReport</c>, sent by the reporting node itself, so <c>gateway_id</c> is <c>!%08x</c> of <c>from</c>.
    /// The packet id is left 0 by the firmware (zeroed packet, never assigned), so it is not required. No channel key
    /// applies: the topic names no channel and the packet is plaintext.
    /// </summary>
    static Inspection InspectMapReport(ReadOnlySpan<byte> payload)
    {
        ServiceEnvelope envelope;
        try
        {
            envelope = ServiceEnvelope.Parser.ParseFrom(payload);
        }
        catch (InvalidProtocolBufferException)
        {
            return Drop("map report: malformed protobuf");
        }

        var packet = envelope.Packet;
        if (packet is null)
            return Drop("map report: envelope without packet");
        if (packet.From == 0)
            return Drop("map report: packet without from", packet: packet);
        if (packet.PayloadVariantCase != MeshPacket.PayloadVariantOneofCase.Decoded)
            return Drop("map report: packet is not decoded", packet: packet);
        var data = packet.Decoded;
        if (data.Portnum != PortNum.MapReportApp)
            return Drop("map report: portnum is not MAP_REPORT_APP", packet: packet);
        // The firmware always sets has_opted_report_location, so a real report is never the empty message.
        if (data.Payload.IsEmpty)
            return Drop("map report: payload is not a MapReport", packet: packet);
        try
        {
            MapReport.Parser.ParseFrom(data.Payload);
        }
        catch (InvalidProtocolBufferException)
        {
            return Drop("map report: payload is not a MapReport", packet: packet);
        }
        if (!string.Equals(envelope.GatewayId, $"!{packet.From:x8}", StringComparison.Ordinal))
            return Drop("map report: gateway_id is not the sender (from)", packet: packet);

        return new Inspection(true, "map report", null, packet.From, packet.Id, PortNum.MapReportApp, null,
            envelope.GatewayId, packet.From, Packet: packet, Data: data);
    }

    /// <summary>
    /// The map-report topic exactly as the firmware builds it: <c>&lt;root&gt;/2/map/</c> (<c>MQTT::reinitTopics()</c>,
    /// <c>mapTopic = root + "/2/map/"</c>), with the trailing slash, so the last level is empty and there is no
    /// channel or gateway level. Root is one or more non-empty levels.
    /// </summary>
    public static bool IsMapReportTopic(string? topic)
    {
        if (string.IsNullOrEmpty(topic))
            return false;
        var levels = topic.Split('/');
        var n = levels.Length;
        return n >= 4 && levels[n - 1].Length == 0 && levels[n - 2] == "map" && levels[n - 3] == "2"
            && !levels.Take(n - 3).Any(string.IsNullOrEmpty);
    }

    /// <summary>Any other topic with a <c>2/map</c> pair of levels (extra levels, no trailing slash): never published by the firmware.</summary>
    static bool HasMapLevels(string? topic)
    {
        if (string.IsNullOrEmpty(topic))
            return false;
        var levels = topic.Split('/');
        for (var i = 1; i < levels.Length; i++)
        {
            if (levels[i - 1] == "2" && levels[i] == "map")
                return true;
        }
        return false;
    }

    /// <summary>Same success test as firmware <c>perhapsDecode()</c>: Data parses and portnum is not UNKNOWN_APP.</summary>
    static Protobufs.Data? TryDecrypt(MeshPacket packet, byte[] key)
    {
        var plain = PacketCrypto.Transform(key, packet.From, packet.Id, packet.Encrypted.Span);
        try
        {
            var data = Protobufs.Data.Parser.ParseFrom(plain);
            return data.Portnum == PortNum.UnknownApp ? null : data;
        }
        catch (InvalidProtocolBufferException)
        {
            return null;
        }
    }

    /// <summary>Accepts <c>&lt;root&gt;/2/e/&lt;channel&gt;/&lt;gateway&gt;</c>, root being one or more levels.</summary>
    public static bool TryParseTopic(string? topic, out string channel) => TryParseTopic(topic, out channel, out _);

    /// <summary>
    /// Accepts <c>&lt;root&gt;/2/e/&lt;channel&gt;/&lt;gateway&gt;</c>, root being one or more levels, and reports
    /// the channel and the gateway level of the topic.
    /// </summary>
    public static bool TryParseTopic(string? topic, out string channel, out string gateway)
    {
        channel = string.Empty;
        gateway = string.Empty;
        if (string.IsNullOrEmpty(topic))
            return false;
        var levels = topic.Split('/');
        var n = levels.Length;
        if (n < 5 || levels[n - 4] != "2" || levels[n - 3] != "e")
            return false;
        if (levels.Take(n - 4).Any(string.IsNullOrEmpty) || levels[n - 2].Length == 0 || levels[n - 1].Length == 0)
            return false;
        channel = levels[n - 2];
        gateway = levels[n - 1];
        return true;
    }

    /// <summary>
    /// Drop reason of a topic whose gateway level does not match the envelope's gateway id.
    /// </summary>
    public const string GatewayMismatchReason = "gateway in topic does not match gateway_id";

    /// <summary>
    /// Whether the gateway level of the topic is the gateway the envelope claims.
    /// </summary>
    /// <remarks>
    /// The firmware builds the topic from the same string it puts in the envelope
    /// (<c>src/mqtt/MQTT.cpp</c> <c>onSend()</c>: <c>nodeId</c> is both the topic's last level and
    /// <c>gateway_id</c>), and <c>NodeDB::getNodeId()</c> writes it as <c>"!"</c> + 8 lowercase hex digits.
    /// A topic whose gateway is anything else (a different id, upper case, no <c>!</c>, or a zero-width
    /// character glued to it) is not a gateway the firmware would have published.
    /// </remarks>
    public static bool GatewayMatchesTopic(string? topicGateway, string? envelopeGateway)
    {
        if (string.IsNullOrEmpty(topicGateway) || !string.Equals(topicGateway, envelopeGateway, StringComparison.Ordinal))
            return false;
        return IsGatewayId(topicGateway);
    }

    /// <summary>
    /// Whether the string is a node id as the firmware writes it: <c>!</c> followed by 8 lowercase hex digits.
    /// </summary>
    public static bool IsGatewayId(string? gateway)
    {
        if (gateway is null || gateway.Length != 9 || gateway[0] != '!')
            return false;
        for (var i = 1; i < gateway.Length; i++)
        {
            var c = gateway[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return false;
        }
        return true;
    }

    /// <summary>
    /// The node number of a gateway id ("!" + 8 lowercase hex digits), as the firmware writes it. The
    /// dedupe keeps the gateways as these numbers, so the id is parsed once and not kept as a string.
    /// </summary>
    public static bool TryParseGatewayId(string? gateway, out uint node)
    {
        node = 0;
        if (gateway is null || !IsGatewayId(gateway))
            return false;
        uint value = 0;
        for (var i = 1; i < gateway.Length; i++)
        {
            var c = gateway[i];
            value = (value << 4) | (c <= '9' ? (uint)(c - '0') : (uint)(c - 'a' + 10));
        }
        node = value;
        return true;
    }

    /// <summary>The node number of a gateway id (0 when the id is not one).</summary>
    static uint GatewayNode(string? gateway) => TryParseGatewayId(gateway, out var node) ? node : 0;

    static Inspection Drop(string reason, string? channel = null, MeshPacket? packet = null, bool? hashMatches = null) =>
        new(false, reason, channel, packet?.From ?? 0, packet?.Id ?? 0, null, hashMatches, Packet: packet);
}
