using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Meshtastic.Mqtt;

/// <summary>
/// AES-CTR channel encryption as done by firmware <c>CryptoEngine::encryptPacket()</c>.
/// </summary>
/// <remarks>
/// Implemented on <see cref="Aes"/> instead of <c>Meshtastic.Crypto.PacketEncryption</c>: that helper
/// keeps one static BouncyCastle cipher for the whole process, and MQTTnet runs publish handlers
/// concurrently, so two packets decrypting at the same time could corrupt each other.
/// </remarks>
public static class PacketCrypto
{
    /// <summary>Firmware refuses to decrypt anything larger (<c>MAX_BLOCKSIZE</c> / Router scratch buffer).</summary>
    public const int MaxEncryptedBytes = 256;

    /// <summary>
    /// Nonce from <c>CryptoEngine::initNonce()</c>: packet id as uint64 LE, sender node number as
    /// uint32 LE, then 4 zero bytes. The last 4 bytes are the big-endian block counter (CTR counter size 4).
    /// </summary>
    public static byte[] Nonce(uint from, uint packetId)
    {
        var nonce = new byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(nonce, packetId);
        BinaryPrimitives.WriteUInt32LittleEndian(nonce.AsSpan(8), from);
        return nonce;
    }

    /// <summary>Encrypts or decrypts (CTR is symmetric). An empty key means the channel has no encryption.</summary>
    public static byte[] Transform(ReadOnlySpan<byte> key, uint from, uint packetId, ReadOnlySpan<byte> input)
    {
        if (key.Length == 0)
            return input.ToArray();
        if (key.Length is not (16 or 32))
            throw new ArgumentException("AES key must be 16 or 32 bytes", nameof(key));

        using var aes = Aes.Create();
        aes.Key = key.ToArray();

        var counter = Nonce(from, packetId);
        Span<byte> keystream = stackalloc byte[16];
        var output = new byte[input.Length];
        for (var offset = 0; offset < input.Length; offset += 16)
        {
            aes.EncryptEcb(counter, keystream, PaddingMode.None);
            var n = Math.Min(16, input.Length - offset);
            for (var i = 0; i < n; i++)
                output[offset + i] = (byte)(input[offset + i] ^ keystream[i]);
            var block = BinaryPrimitives.ReadUInt32BigEndian(counter.AsSpan(12));
            BinaryPrimitives.WriteUInt32BigEndian(counter.AsSpan(12), unchecked(block + 1));
        }
        return output;
    }
}
