using System.Text;

namespace Meshtastic.Mqtt;

/// <summary>
/// Channel key handling, mirroring meshtastic/firmware <c>src/mesh/Channels.cpp</c>.
/// </summary>
public static class ChannelKeys
{
    /// <summary><c>defaultpsk</c> from firmware <c>src/mesh/Channels.h</c>.</summary>
    public static ReadOnlySpan<byte> DefaultPsk =>
    [
        0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
        0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
    ];

    /// <summary>Decodes a base64 PSK as written in a channel URL or the CLI and expands it.</summary>
    public static bool TryExpand(string? base64, out byte[] key, out string? error)
    {
        key = [];
        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(base64 ?? string.Empty);
        }
        catch (FormatException)
        {
            error = $"'{base64}' is not valid base64";
            return false;
        }
        return TryExpand(raw, out key, out error);
    }

    /// <summary>
    /// Same rules as firmware <c>Channels::getKey()</c>: 0 bytes = no encryption; 1 byte = index into the
    /// default key family (0 = no encryption, N = <c>defaultpsk</c> with its last byte increased by N-1);
    /// 2-15 bytes are zero-padded to AES-128, 17-31 to AES-256; 16 and 32 are used as is.
    /// </summary>
    public static bool TryExpand(ReadOnlySpan<byte> raw, out byte[] key, out string? error)
    {
        error = null;
        switch (raw.Length)
        {
            case 0:
                key = [];
                return true;
            case 1:
                if (raw[0] == 0)
                {
                    key = [];
                    return true;
                }
                key = DefaultPsk.ToArray();
                key[^1] = unchecked((byte)(key[^1] + raw[0] - 1));
                return true;
            case 16:
            case 32:
                key = raw.ToArray();
                return true;
            case < 16:
                key = new byte[16];
                raw.CopyTo(key);
                return true;
            case < 32:
                key = new byte[32];
                raw.CopyTo(key);
                return true;
            default:
                key = [];
                error = $"a PSK is at most 32 bytes, got {raw.Length}";
                return false;
        }
    }

    /// <summary>
    /// Firmware <c>Channels::generateHash()</c> for a non-AEAD channel: XOR of the channel name bytes
    /// XOR the XOR of the expanded key bytes. Travels in clear in <c>MeshPacket.channel</c>.
    /// </summary>
    public static byte ChannelHash(string channelName, ReadOnlySpan<byte> expandedKey)
    {
        byte h = 0;
        foreach (var b in Encoding.UTF8.GetBytes(channelName))
            h ^= b;
        foreach (var b in expandedKey)
            h ^= b;
        return h;
    }
}
