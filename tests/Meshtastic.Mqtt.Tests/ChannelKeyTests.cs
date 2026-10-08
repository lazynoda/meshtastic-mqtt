using System.Text;
using Meshtastic.Mqtt;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

public class ChannelKeyTests
{
    // defaultpsk from meshtastic/firmware src/mesh/Channels.h, written out independently of the code under test.
    static readonly byte[] FirmwareDefaultPsk =
        [0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01];

    static byte[] DefaultWithLastByte(byte last)
    {
        var k = (byte[])FirmwareDefaultPsk.Clone();
        k[^1] = last;
        return k;
    }

    [Fact]
    public void AQ_IsTheDefaultKey()
    {
        Assert.True(ChannelKeys.TryExpand("AQ==", out var key, out _));
        Assert.Equal(FirmwareDefaultPsk, key);
    }

    [Fact]
    public void Ag_IsDefaultKeyPlusOne()
    {
        Assert.True(ChannelKeys.TryExpand("Ag==", out var key, out _));
        Assert.Equal(DefaultWithLastByte(0x02), key);
    }

    [Fact]
    public void VA_IsIndex84()
    {
        Assert.Equal(new byte[] { 84 }, Convert.FromBase64String("VA=="));
        Assert.True(ChannelKeys.TryExpand("VA==", out var key, out _));
        Assert.Equal(DefaultWithLastByte(0x01 + 84 - 1), key);   // 0x54
    }

    [Fact]
    public void Va_IsADifferentKey()
    {
        // Base64 is case sensitive: "Va==" decodes to byte 85, so it would select a different key than "VA==" (84).
        Assert.Equal(new byte[] { 85 }, Convert.FromBase64String("Va=="));
        Assert.True(ChannelKeys.TryExpand("Va==", out var key, out _));
        Assert.NotEqual(DefaultWithLastByte(0x54), key);
    }

    [Fact]
    public void Index255_WrapsLikeUint8()
    {
        Assert.True(ChannelKeys.TryExpand([255], out var key, out _));
        Assert.Equal(DefaultWithLastByte(unchecked((byte)(0x01 + 255 - 1))), key);
    }

    [Theory]
    [InlineData("AA==")]   // index 0
    [InlineData("")]       // empty
    public void NoEncryption_IsAnEmptyKey(string psk)
    {
        Assert.True(ChannelKeys.TryExpand(psk, out var key, out _));
        Assert.Empty(key);
    }

    [Theory]
    [InlineData(2, 16)]
    [InlineData(15, 16)]
    [InlineData(16, 16)]
    [InlineData(17, 32)]
    [InlineData(31, 32)]
    [InlineData(32, 32)]
    public void ShortKeys_AreZeroPadded(int length, int expected)
    {
        var raw = Enumerable.Range(1, length).Select(i => (byte)i).ToArray();
        Assert.True(ChannelKeys.TryExpand(raw, out var key, out _));
        Assert.Equal(expected, key.Length);
        Assert.Equal(raw, key[..length]);
        Assert.All(key[length..], b => Assert.Equal(0, b));
    }

    [Fact]
    public void TooLong_IsRejected()
    {
        Assert.False(ChannelKeys.TryExpand(new byte[33], out _, out var error));
        Assert.Contains("32", error);
    }

    [Fact]
    public void NotBase64_IsRejected() =>
        Assert.False(ChannelKeys.TryExpand("not base64!", out _, out _));

    [Fact]
    public void ChannelHash_MatchesARealPacket()
    {
        // The captured LongFast packet (see Fixtures/make_fixtures.py) carries channel hash 8.
        Assert.True(ChannelKeys.TryExpand("AQ==", out var key, out _));
        Assert.Equal(8, ChannelKeys.ChannelHash("LongFast", key));
    }

    [Fact]
    public void ChannelHash_IsXorOfNameAndKey()
    {
        byte expected = 0;
        foreach (var b in Encoding.ASCII.GetBytes("Valencia")) expected ^= b;
        foreach (var b in DefaultWithLastByte(0x54)) expected ^= b;
        Assert.True(ChannelKeys.TryExpand("VA==", out var key, out _));
        Assert.Equal(expected, ChannelKeys.ChannelHash("Valencia", key));
    }
}

public class PacketCryptoTests
{
    [Fact]
    public void Nonce_MatchesFirmwareLayout()
    {
        var nonce = PacketCrypto.Nonce(0xfa8165a4, 1777428186);
        Assert.Equal(Convert.FromHexString("da66f16900000000a46581fa00000000"), nonce);
    }

    [Fact]
    public void DecryptsARealPacket()
    {
        // Real LongFast NODEINFO packet from meshtastic/c-sharp's crypto test vector.
        var encrypted = Convert.FromBase64String("kiDV39nDDsi8AON+Czei6zUpy+F/7E+lyIpicxJR40KXBFmPkqFUEnobI5voQadha+s=");
        ChannelKeys.TryExpand("AQ==", out var key, out _);
        var plain = PacketCrypto.Transform(key, 4202784164, 1777428186, encrypted);
        var data = Protobufs.Data.Parser.ParseFrom(plain);
        Assert.Equal(Protobufs.PortNum.NodeinfoApp, data.Portnum);
        Assert.Equal("Meshtastic 65a4", Protobufs.User.Parser.ParseFrom(data.Payload).LongName);
    }

    [Fact]
    public void AgreesWithTheMeshtasticLibraryOnMultiBlockInput()
    {
        // Upstream used Meshtastic.Crypto.PacketEncryption; ours must produce the same bytes (incl. counter carry).
        var input = Enumerable.Range(0, 200).Select(i => (byte)i).ToArray();
        ChannelKeys.TryExpand("Ag==", out var key, out _);
        var ours = PacketCrypto.Transform(key, 0x12345678, 0xfffffff0, input);
        var theirs = Meshtastic.Crypto.PacketEncryption.TransformPacket(input, new Meshtastic.Crypto.NonceGenerator(0x12345678, 0xfffffff0).Create(), key);
        Assert.Equal(theirs, ours);
    }

    [Fact]
    public void Aes256_Works()
    {
        var key = Enumerable.Range(0, 32).Select(i => (byte)(i * 7)).ToArray();
        var input = Encoding.ASCII.GetBytes("aes-256 round trip, longer than one block");
        var cipher = PacketCrypto.Transform(key, 1, 2, input);
        Assert.NotEqual(input, cipher);
        Assert.Equal(input, PacketCrypto.Transform(key, 1, 2, cipher));
    }

    [Fact]
    public void EmptyKey_IsPlaintext()
    {
        var input = new byte[] { 1, 2, 3 };
        Assert.Equal(input, PacketCrypto.Transform([], 1, 2, input));
    }
}
