using System.Net;
using Meshtastic.Mqtt;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

public class ConfigTests
{
    const string Hash = AuthTests.AliceHash;

    static string Minimal(string extra = "") => $"""
        users:
          - username: meshdev
            password_hash: "{Hash}"
        {extra}
        """;

    [Fact]
    public void Minimal_UsesSafeDefaults()
    {
        var c = ConfigLoader.Parse(Minimal());
        Assert.Equal(1883, c.Listener.Port);
        Assert.Equal(IPAddress.Any, c.BindAddress);
        Assert.True(c.DropUndecryptable);
        Assert.True(c.DropPki);
        Assert.Equal("AQ==", c.DefaultPsk);
        Assert.Empty(c.Users![0].SubscribeAllow!);
        Assert.Equal(Serilog.Events.LogEventLevel.Information, c.MinimumLevel);
    }

    [Fact]
    public void ExampleConfig_IsValidAndMatchesTheSpanishMesh()
    {
        var c = ConfigLoader.LoadFile(Path.Combine(AppContext.BaseDirectory, "config.example.yaml"));
        var meshdev = Assert.Single(c.Users!);
        Assert.Equal("meshdev", meshdev.Username);
        Assert.Empty(meshdev.SubscribeAllow!);
        Assert.True(meshdev.ParsedHash!.Verify("large4cats"u8));
        Assert.True(c.DropUndecryptable);
        Assert.True(c.DropPki);

        ChannelKeys.TryExpand("AQ==", out var aq, out _);
        ChannelKeys.TryExpand("Ag==", out var ag, out _);
        ChannelKeys.TryExpand("VA==", out var va, out _);
        Assert.Equal(aq, c.DefaultKey);
        Assert.Equal(ag, c.ChannelKeyMap["Test"]);
        Assert.Equal(ag, c.ChannelKeyMap["Bots"]);
        Assert.Equal(va, c.ChannelKeyMap["Valencia"]);
        Assert.False(c.ChannelKeyMap.ContainsKey("Zaragoza"));   // stays on default_psk
        Assert.Equal(4096, c.Limits!.MaxPacketSize);
        Assert.Equal(10, c.Limits.CommunicationTimeoutSeconds);
    }

    [Fact]
    public void ChannelLookup_IsCaseSensitive()
    {
        // The firmware hashes the exact channel name (Channels::generateHash), so `Test` and `test` are
        // different channels on the mesh and may carry different keys.
        var c = ConfigLoader.Parse(Minimal("channels:\n  Test: Ag==\n  test: AQ=="));
        ChannelKeys.TryExpand("Ag==", out var ag, out _);
        ChannelKeys.TryExpand("AQ==", out var aq, out _);
        Assert.Equal(ag, c.ChannelKeyMap["Test"]);
        Assert.Equal(aq, c.ChannelKeyMap["test"]);
        Assert.False(ConfigLoader.Parse(Minimal("channels:\n  Test: Ag==")).ChannelKeyMap.ContainsKey("test"));
    }

    [Theory]
    [InlineData("drop_undecryptable:", "drop_undecryptable")]
    [InlineData("drop_undecryptable: ~", "drop_undecryptable")]
    [InlineData("drop_pki:", "drop_pki")]
    [InlineData("drop_pki: null", "drop_pki")]
    public void NullBoolean_IsRejected(string extra, string mentions)
    {
        // An empty value must not silently turn a security filter off.
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse(Minimal(extra)));
        Assert.Contains(mentions, ex.Message);
        Assert.Contains("true or false", ex.Message);
    }

    [Fact]
    public void AbsentBooleans_KeepTheirDefaults()
    {
        var c = ConfigLoader.Parse(Minimal());
        Assert.True(c.DropUndecryptable);
        Assert.True(c.DropPki);
        var off = ConfigLoader.Parse(Minimal("drop_undecryptable: false\ndrop_pki: false"));
        Assert.False(off.DropUndecryptable);
        Assert.False(off.DropPki);
    }

    [Theory]
    [InlineData("channels:\n  Valencia: VA==\n  Valencia: AQ==", "Valencia")]                 // same channel twice
    [InlineData("log_level: debug\nlog_level: information", "log_level")]
    [InlineData("listener:\n  port: 1883\n  port: 1884", "port")]
    public void DuplicateKeys_AreRejected(string extra, string mentions)
    {
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse(Minimal(extra)));
        Assert.Contains("Duplicate key", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(mentions, ex.Message);
    }

    [Fact]
    public void DuplicateUsersBlock_IsRejected()
    {
        // Two `users:` blocks used to keep only the second one, silently dropping users.
        var yaml = $"users:\n  - username: a\n    password_hash: \"{Hash}\"\nusers:\n  - username: b\n    password_hash: \"{Hash}\"\n";
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse(yaml));
        Assert.Contains("users", ex.Message);
    }

    [Theory]
    [InlineData("default_psk:", "default_psk")]
    [InlineData("default_psk: ''", "default_psk")]
    [InlineData("default_psk: ~", "default_psk")]
    [InlineData("channels:\n  Test:", "channels.Test")]
    [InlineData("channels:\n  Test: ''", "channels.Test")]
    public void EmptyPsk_IsRejected_AndPointsAtAA(string extra, string mentions)
    {
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse(Minimal(extra)));
        Assert.Contains(mentions, ex.Message);
        Assert.Contains("\"AA==\" means no encryption", ex.Message);
    }

    [Fact]
    public void ExplicitNoEncryptionPsk_IsAccepted()
    {
        var c = ConfigLoader.Parse(Minimal("channels:\n  Open: AA=="));
        Assert.Empty(c.ChannelKeyMap["Open"]);
    }

    [Fact]
    public void Limits_HaveSafeDefaults_AndCanBeSet()
    {
        var d = ConfigLoader.Parse(Minimal()).Limits!;
        Assert.Equal(4096, d.MaxPacketSize);
        Assert.Equal(10, d.CommunicationTimeoutSeconds);

        var c = ConfigLoader.Parse(Minimal("limits:\n  max_packet_size: 2048\n  communication_timeout_seconds: 5")).Limits!;
        Assert.Equal(2048, c.MaxPacketSize);
        Assert.Equal(5, c.CommunicationTimeoutSeconds);
    }

    [Theory]
    [InlineData("limits:\n  max_packet_size: 100", "limits.max_packet_size")]
    [InlineData("limits:\n  max_packet_size: 268435455", "limits.max_packet_size")]
    [InlineData("limits:\n  max_packet_size:", "limits.max_packet_size")]
    [InlineData("limits:\n  communication_timeout_seconds: 0", "limits.communication_timeout_seconds")]
    [InlineData("limits:", "limits")]
    [InlineData("limits:\n  max_packet: 4096", "max_packet")]
    public void InvalidLimits_AreRejected(string extra, string mentions)
    {
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse(Minimal(extra)));
        Assert.Contains(mentions, ex.Message);
    }

    [Theory]
    [InlineData("listener:\n  port: 0", "listener.port")]
    [InlineData("listener:\n  port: 70000", "listener.port")]
    [InlineData("listener:\n  bind_address: localhost", "listener.bind_address")]
    [InlineData("log_level: chatty", "log_level")]
    [InlineData("default_psk: '***'", "default_psk")]
    [InlineData("channels:\n  Test: '***'", "channels.Test")]
    [InlineData("channels:\n  'a/b': AQ==", "channel name")]
    [InlineData("listener:\n  prot: 1883", "prot")]                         // unknown key = typo, not ignored
    [InlineData("drop_undecryptable: maybe", "maybe")]
    public void InvalidValues_FailWithAClearMessage(string extra, string mentions)
    {
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse(Minimal(extra)));
        Assert.Contains(mentions, ex.Message);
    }

    [Fact]
    public void PlaintextPassword_IsRejected()
    {
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse("users:\n  - username: meshdev\n    password_hash: large4cats\n"));
        Assert.Contains("password_hash", ex.Message);
    }

    [Fact]
    public void InvalidSubscribeFilter_IsRejected()
    {
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse(
            $"users:\n  - username: a\n    password_hash: \"{Hash}\"\n    subscribe_allow: ['msh/#/x']\n"));
        Assert.Contains("subscribe_allow", ex.Message);
    }

    [Fact]
    public void DuplicateUser_IsRejected()
    {
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse(
            $"users:\n  - username: a\n    password_hash: \"{Hash}\"\n  - username: a\n    password_hash: \"{Hash}\"\n"));
        Assert.Contains("defined twice", ex.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData("users: []")]
    [InlineData("log_level: debug")]
    public void NoUsers_IsRejected(string yaml) =>
        Assert.Throws<ConfigException>(() => ConfigLoader.Parse(yaml));

    [Fact]
    public void BrokenYaml_ReportsTheLine()
    {
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse("users:\n  - username: [unclosed\n"));
        Assert.Contains("line", ex.Message);
    }

    [Fact]
    public void ErrorMessages_NeverEchoAPasswordHash()
    {
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse(
            $"log_level: nope\nusers:\n  - username: a\n    password_hash: \"{Hash}\"\n"));
        Assert.DoesNotContain(Hash, ex.Message);
    }

    [Fact]
    public void MissingFile_IsAConfigError() =>
        Assert.Throws<ConfigException>(() => ConfigLoader.LoadFile("/nonexistent/config.yaml"));
}
