using Google.Protobuf;
using Meshtastic.Mqtt;
using Meshtastic.Protobufs;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// Publish filtering on real-format envelopes. The *.bin fixtures are produced by
/// Fixtures/make_fixtures.py with hand-written protobuf and OpenSSL AES-CTR, independent of the broker.
/// </summary>
public class PublishFilterTests
{
    internal static byte[] Fixture(string name) => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    internal static BrokerConfig Config(bool dropUndecryptable = true, bool dropPki = true) => ConfigLoader.Parse($"""
        drop_undecryptable: {dropUndecryptable.ToString().ToLowerInvariant()}
        drop_pki: {dropPki.ToString().ToLowerInvariant()}
        channels:
          Test: "Ag=="
          Bots: "Ag=="
          Valencia: "VA=="
        users:
          - username: meshdev
            password_hash: "{AuthTests.AliceHash}"
        """);

    static Inspection Inspect(string topic, byte[] payload, BrokerConfig? config = null) =>
        new PacketInspector(config ?? Config()).Inspect(topic, payload);

    [Theory]
    [InlineData("msh/ES/2/e/SFNarrow/!1a2b3c4d", "sfnarrow_aq.bin", "SFNarrow")]
    [InlineData("msh/ES/2/e/Test/!1a2b3c4d", "test_ag.bin", "Test")]
    [InlineData("msh/ES/2/e/Valencia/!1a2b3c4d", "valencia_va.bin", "Valencia")]
    [InlineData("msh/ES/2/e/test/!1a2b3c4d", "test_lower_aq.bin", "test")]
    [InlineData("msh/EU_868/2/e/LongFast/!fa8165a4", "longfast_real.bin", "LongFast")]
    public void ValidPackets_PassWithTheirChannelKey(string topic, string fixture, string channel)
    {
        var r = Inspect(topic, Fixture(fixture));
        Assert.True(r.Accepted, r.Reason);
        Assert.Equal(channel, r.Channel);
        Assert.NotNull(r.Portnum);
        Assert.True(r.ChannelHashMatches);
    }

    [Fact]
    public void ChannelKeyLookup_IsCaseSensitive()
    {
        // `test` is not `Test` (the firmware hashes the exact name): with only `Test: Ag==` configured, a `test`
        // channel uses default_psk. Its default-key traffic passes; Ag==-keyed traffic on it is undecryptable.
        var lowerDefault = Inspect("msh/ES/2/e/test/!1a2b3c4d", Fixture("test_lower_aq.bin"));
        Assert.True(lowerDefault.Accepted, lowerDefault.Reason);
        var lowerAg = Inspect("msh/ES/2/e/test/!1a2b3c4d", Fixture("test_lower_ag.bin"));
        Assert.False(lowerAg.Accepted);
        Assert.Contains("undecryptable", lowerAg.Reason);
    }

    [Fact]
    public void RealPacket_ReportsHeaderFieldsForLogging()
    {
        var r = Inspect("msh/EU_868/2/e/LongFast/!fa8165a4", Fixture("longfast_real.bin"));
        Assert.Equal(4202784164u, r.From);
        Assert.Equal(1777428186u, r.PacketId);
        Assert.Equal(PortNum.NodeinfoApp, r.Portnum);
    }

    [Fact]
    public void TestPacketWithDefaultKey_IsUndecryptable()
    {
        var r = Inspect("msh/ES/2/e/Test/!1a2b3c4d", Fixture("test_wrong_key_aq.bin"));
        Assert.False(r.Accepted);
        Assert.Contains("undecryptable", r.Reason);
        Assert.False(r.ChannelHashMatches);
    }

    [Fact]
    public void Undecryptable_PassesWhenConfigured()
    {
        var r = Inspect("msh/ES/2/e/Test/!1a2b3c4d", Fixture("test_wrong_key_aq.bin"), Config(dropUndecryptable: false));
        Assert.True(r.Accepted);
        Assert.Null(r.Portnum);
    }

    [Fact]
    public void KeysAreChosenByChannel_NotBruteForced()
    {
        // A valid SFNarrow (AQ==) packet relabelled as Valencia must not be rescued by trying the other keys.
        var env = ServiceEnvelope.Parser.ParseFrom(Fixture("sfnarrow_aq.bin"));
        env.ChannelId = "Valencia";
        var r = Inspect("msh/ES/2/e/Valencia/!1a2b3c4d", env.ToByteArray());
        Assert.False(r.Accepted);
        Assert.Contains("undecryptable", r.Reason);
    }

    [Fact]
    public void UnlistedChannel_UsesDefaultPsk()
    {
        var env = ServiceEnvelope.Parser.ParseFrom(Fixture("longfast_real.bin"));
        Assert.True(Inspect("msh/ES/2/e/LongFast/!fa8165a4", env.ToByteArray()).Accepted);

        var other = ConfigLoader.Parse($"default_psk: Ag==\nusers:\n  - username: a\n    password_hash: \"{AuthTests.AliceHash}\"\n");
        Assert.False(Inspect("msh/ES/2/e/LongFast/!fa8165a4", env.ToByteArray(), other).Accepted);
    }

    [Theory]
    [InlineData("msh/ES/2/e/Test/!1a2b3c4d", "sfnarrow_aq.bin")]       // envelope says SFNarrow
    [InlineData("msh/ES/2/e/sfnarrow/!1a2b3c4d", "sfnarrow_aq.bin")]   // topic match is exact
    public void ChannelIdMustMatchTopic(string topic, string fixture)
    {
        var r = Inspect(topic, Fixture(fixture));
        Assert.False(r.Accepted);
        Assert.Contains("does not match the topic", r.Reason);
    }

    [Theory]
    [InlineData("msh/ES/2/json/SFNarrow/!1a2b3c4d")]
    [InlineData("msh/ES/2/map/")]
    [InlineData("msh/ES/2/e/SFNarrow")]
    [InlineData("msh/ES/2/e/SFNarrow/!1a2b3c4d/extra")]
    [InlineData("2/e/SFNarrow/!1a2b3c4d")]
    [InlineData("msh//2/e/SFNarrow/!1a2b3c4d")]
    [InlineData("msh/ES/2/e//!1a2b3c4d")]
    [InlineData("")]
    [InlineData(null)]
    public void UnsupportedTopics_AreDropped(string? topic) =>
        Assert.False(Inspect(topic!, Fixture("sfnarrow_aq.bin")).Accepted);

    [Fact]
    public void LongerRoot_IsAccepted() =>
        Assert.True(Inspect("msh/EU_868/ES/2/e/SFNarrow/!1a2b3c4d", Fixture("sfnarrow_aq.bin")).Accepted);

    [Fact]
    public void Garbage_IsDropped()
    {
        var r = Inspect("msh/ES/2/e/SFNarrow/!1a2b3c4d", Fixture("garbage.bin"));
        Assert.False(r.Accepted);
    }

    [Fact]
    public void EmptyPayload_IsDropped() =>
        Assert.Equal("empty payload", Inspect("msh/ES/2/e/SFNarrow/!1a2b3c4d", []).Reason);

    [Fact]
    public void PlaintextPacket_IsDropped()
    {
        var r = Inspect("msh/ES/2/e/SFNarrow/!1a2b3c4d", Fixture("plaintext_decoded.bin"));
        Assert.False(r.Accepted);
        Assert.Contains("not encrypted", r.Reason);
    }

    [Fact]
    public void PkiDm_IsDroppedByDefault()
    {
        var r = Inspect("msh/ES/2/e/PKI/!1a2b3c4d", Fixture("pki_dm.bin"));
        Assert.False(r.Accepted);
        Assert.Contains("drop_pki", r.Reason);
    }

    [Fact]
    public void PkiDm_PassesOpaquelyWhenConfigured()
    {
        var config = Config(dropPki: false);
        Assert.True(Inspect("msh/ES/2/e/PKI/!1a2b3c4d", Fixture("pki_dm.bin"), config).Accepted);

        // ...but only if it is shaped like a PKI packet.
        var env = ServiceEnvelope.Parser.ParseFrom(Fixture("pki_dm.bin"));
        env.Packet.To = uint.MaxValue;
        Assert.False(Inspect("msh/ES/2/e/PKI/!1a2b3c4d", env.ToByteArray(), config).Accepted);
    }

    [Fact]
    public void PkiFlag_DoesNotOpenUndecryptableChannelPackets()
    {
        var r = Inspect("msh/ES/2/e/Test/!1a2b3c4d", Fixture("test_wrong_key_aq.bin"), Config(dropPki: false));
        Assert.False(r.Accepted);
    }

    public static TheoryData<string, Action<ServiceEnvelope>> Mutations => new()
    {
        { "no packet", e => e.Packet = null },
        { "no channel_id", e => e.ChannelId = "" },
        { "no gateway_id", e => e.GatewayId = " " },
        { "from 0", e => e.Packet.From = 0 },
        { "id 0", e => e.Packet.Id = 0 },
        { "empty encrypted", e => e.Packet.Encrypted = ByteString.Empty },
        { "oversized encrypted", e => e.Packet.Encrypted = ByteString.CopyFrom(new byte[PacketCrypto.MaxEncryptedBytes + 1]) },
        { "decoded instead of encrypted", e => e.Packet.Decoded = new Protobufs.Data { Portnum = PortNum.TextMessageApp } },
        { "flipped ciphertext", e => e.Packet.Encrypted = ByteString.CopyFrom(e.Packet.Encrypted.Select(b => (byte)~b).ToArray()) },
    };

    [Theory]
    [MemberData(nameof(Mutations))]
    public void InvalidEnvelopes_AreDropped(string name, Action<ServiceEnvelope> mutate)
    {
        var env = ServiceEnvelope.Parser.ParseFrom(Fixture("sfnarrow_aq.bin"));
        mutate(env);
        var r = Inspect("msh/ES/2/e/SFNarrow/!1a2b3c4d", env.ToByteArray());
        Assert.False(r.Accepted, name);
    }

    [Fact]
    public void RandomBytes_NeverThrow()
    {
        var inspector = new PacketInspector(Config(dropUndecryptable: false, dropPki: false));
        var valid = Fixture("sfnarrow_aq.bin");
        var rng = new Random(1234);
        for (var i = 0; i < 20_000; i++)
        {
            byte[] payload;
            if (i % 2 == 0)
            {
                payload = new byte[rng.Next(1, 600)];
                rng.NextBytes(payload);
            }
            else
            {
                payload = (byte[])valid.Clone();
                for (var j = 0; j < 1 + rng.Next(4); j++)
                    payload[rng.Next(payload.Length)] = (byte)rng.Next(256);
                payload = payload[..rng.Next(1, payload.Length + 1)];
            }
            var r = inspector.Inspect("msh/ES/2/e/SFNarrow/!1a2b3c4d", payload);
            Assert.DoesNotContain("internal error", r.Reason);
        }
    }
}
