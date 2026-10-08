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
    bool? ChannelHashMatches = null);

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
        if (!TryParseTopic(topic, out var topicChannel))
            return Drop("unsupported topic (expected <root>/2/e/<channel>/<gateway>)");

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

        if (channel == PkiChannel)
            return InspectPki(packet);

        var key = config.ChannelKeyMap.TryGetValue(channel, out var configured) ? configured : config.DefaultKey;
        var hashMatches = ChannelKeys.ChannelHash(channel, key) == packet.Channel;
        var data = TryDecrypt(packet, key);
        if (data is null)
        {
            return config.DropUndecryptable
                ? Drop("undecryptable with the key configured for this channel", channel, packet, hashMatches)
                : new Inspection(true, "undecryptable, passed (drop_undecryptable: false)", channel, packet.From, packet.Id, null, hashMatches);
        }
        return new Inspection(true, "decrypted", channel, packet.From, packet.Id, data.Portnum, hashMatches);
    }

    Inspection InspectPki(MeshPacket packet)
    {
        // Firmware only produces PKI packets as unicast, with channel hash 0 and the CCM overhead appended.
        if (packet.To == 0 || packet.To == uint.MaxValue || packet.Channel != 0 || packet.Encrypted.Length <= PkiOverhead)
            return Drop("malformed PKI packet", PkiChannel, packet);
        return config.DropPki
            ? Drop("PKI DM (drop_pki: true)", PkiChannel, packet)
            : new Inspection(true, "PKI DM passed through opaquely (drop_pki: false)", PkiChannel, packet.From, packet.Id);
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
    public static bool TryParseTopic(string? topic, out string channel)
    {
        channel = string.Empty;
        if (string.IsNullOrEmpty(topic))
            return false;
        var levels = topic.Split('/');
        var n = levels.Length;
        if (n < 5 || levels[n - 4] != "2" || levels[n - 3] != "e")
            return false;
        if (levels.Take(n - 4).Any(string.IsNullOrEmpty) || levels[n - 2].Length == 0 || levels[n - 1].Length == 0)
            return false;
        channel = levels[n - 2];
        return true;
    }

    static Inspection Drop(string reason, string? channel = null, MeshPacket? packet = null, bool? hashMatches = null) =>
        new(false, reason, channel, packet?.From ?? 0, packet?.Id ?? 0, null, hashMatches);
}
