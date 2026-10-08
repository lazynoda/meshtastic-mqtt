using System.Buffers;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Meshtastic.Mqtt;
using MQTTnet.Channel;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

/// <summary>The MQTT framing tracker behind limits.max_packet_size, fed byte streams directly.</summary>
public class PacketSizeGuardTests
{
    static PacketSizeGuardChannel Guard(int max = 4096) => new(new NullChannel(), max);

    /// <summary>Fixed header (type byte + Remaining Length) only; never allocates the body.</summary>
    static byte[] Header(byte type, int bodyLength)
    {
        var header = new List<byte> { type };
        var x = bodyLength;
        do
        {
            var b = (byte)(x % 128);
            x /= 128;
            header.Add(x > 0 ? (byte)(b | 0x80) : b);
        } while (x > 0);
        return [.. header];
    }

    static byte[] Packet(byte type, int bodyLength) => [.. Header(type, bodyLength), .. new byte[bodyLength]];

    [Theory]
    [InlineData(0)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(4095)]
    [InlineData(4096)]
    public void PacketsUpToTheLimit_Pass(int body) => Assert.True(Guard().Accept(Packet(0x30, body)));

    [Theory]
    [InlineData(4097)]
    [InlineData(16384)]
    [InlineData(268_435_455)]
    public void PacketsOverTheLimit_Trip(int body) => Assert.False(Guard().Accept(Header(0x30, body)));

    [Fact]
    public void HostileConnect_TripsOnTheLengthBytes()
    {
        Assert.False(Guard().Accept(new byte[] { 0x10, 0xFF, 0xFF, 0xFF, 0x7F, 0x00 }));
        // Rejected as soon as the partial length passes the limit, before the last length byte arrives.
        Assert.False(Guard().Accept(new byte[] { 0x10, 0xFF, 0xFF }));
    }

    [Fact]
    public void FiveLengthBytes_AreMalformed() =>
        Assert.False(Guard(int.MaxValue).Accept(new byte[] { 0x10, 0x80, 0x80, 0x80, 0x80, 0x01 }));

    [Fact]
    public void Framing_SurvivesArbitraryReadSplits()
    {
        // Several valid packets followed by an oversized one, fed one byte at a time and in odd chunks.
        byte[] stream = [.. Packet(0x10, 40), .. Packet(0x30, 4096), .. Packet(0xC0, 0), .. Packet(0x30, 1000), .. Packet(0x30, 5000)];
        var oversizedAt = stream.Length - (5000 + 3);

        foreach (var chunk in new[] { 1, 2, 3, 7, 1000, 4099 })
        {
            var guard = Guard();
            var tripped = -1;
            for (var i = 0; i < stream.Length; i += chunk)
            {
                if (!guard.Accept(stream.AsSpan(i, Math.Min(chunk, stream.Length - i))))
                {
                    tripped = i;
                    break;
                }
            }
            Assert.True(tripped >= 0, $"chunk {chunk}: oversized packet not detected");
            Assert.True(tripped <= oversizedAt + 3, $"chunk {chunk}: detected late at {tripped}");
            Assert.True(tripped + chunk > oversizedAt, $"chunk {chunk}: tripped early at {tripped} on valid packets");
        }
    }

    [Fact]
    public async Task ReadAsync_ReportsEndOfStream_OnceTripped()
    {
        // MQTTnet reads 2 bytes (type + first length byte), then the length one byte at a time.
        var inner = new NullChannel(new byte[] { 0x10, 0xFF, 0xFF, 0xFF, 0x7F });
        long? reported = null;
        var guard = new PacketSizeGuardChannel(inner, 4096, n => reported = n);
        var buffer = new byte[2];
        var ct = TestContext.Current.CancellationToken;
        Assert.Equal(2, await guard.ReadAsync(buffer, 0, 2, ct));   // 0x10 0xFF: 127 so far, under the limit
        Assert.Equal(0, await guard.ReadAsync(buffer, 0, 1, ct));   // 0xFF: 16383 > 4096 -> end of stream
        Assert.Equal(0, await guard.ReadAsync(buffer, 0, 1, ct));   // stays closed
        Assert.Equal(16383, reported);
    }

    /// <summary>A channel that serves a fixed byte sequence.</summary>
    sealed class NullChannel(byte[]? data = null) : IMqttChannel
    {
        int _offset;
        public X509Certificate2 ClientCertificate => null!;
        public EndPoint RemoteEndPoint => new IPEndPoint(IPAddress.Loopback, 1);
        public EndPoint LocalEndPoint => new IPEndPoint(IPAddress.Loopback, 2);
        public bool IsSecureConnection => false;
        public Task ConnectAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DisconnectAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task WriteAsync(ReadOnlySequence<byte> buffer, bool isEndOfPacket, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            var source = data ?? [];
            var n = Math.Min(count, source.Length - _offset);
            Array.Copy(source, _offset, buffer, offset, n);
            _offset += n;
            return Task.FromResult(n);
        }

        public void Dispose() { }
    }
}
