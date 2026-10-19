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
        Assert.Empty(c.Users![0].PublishAllow!);
        Assert.Equal(Serilog.Events.LogEventLevel.Information, c.MinimumLevel);
    }

    [Theory]
    [InlineData("")]                        // key left out
    [InlineData("    publish_allow:\n")]    // empty value
    [InlineData("    publish_allow: []\n")]
    public void MissingOrEmptyPublishAllow_IsAnEmptyList(string line)
    {
        // Empty = no publish at all (enforced in the publish hook; see PublishAclTests).
        var c = ConfigLoader.Parse($"users:\n  - username: a\n    password_hash: \"{Hash}\"\n{line}");
        Assert.NotNull(c.Users![0].PublishAllow);
        Assert.Empty(c.Users![0].PublishAllow!);
    }

    [Fact]
    public void PublishAllow_IsParsedPerUser()
    {
        var c = ConfigLoader.Parse(
            $"users:\n  - username: a\n    password_hash: \"{Hash}\"\n    publish_allow: ['msh/EU_868/2/e/#', 'msh/EU_868/2/map/', 'msh/+/2/e/Test/+']\n"
            + $"  - username: b\n    password_hash: \"{Hash}\"\n");
        Assert.Equal(["msh/EU_868/2/e/#", "msh/EU_868/2/map/", "msh/+/2/e/Test/+"], c.Users![0].PublishAllow!);
        Assert.Empty(c.Users![1].PublishAllow!);
    }

    [Theory]
    [InlineData("msh/#/x", "'#' must be a whole level and the last one")]
    [InlineData("msh/EU_868/2/e#", "'#' must be a whole level and the last one")]
    [InlineData("msh/EU+/2/e/#", "'+' must be a whole level")]
    [InlineData("", "topic filter is empty")]
    public void InvalidPublishFilter_FailsStartup_NamingUserKeyAndProblem(string filter, string problem)
    {
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse(
            $"users:\n  - username: a\n    password_hash: \"{Hash}\"\n    publish_allow: ['msh/EU_868/2/e/#', '{filter}']\n"));
        Assert.Contains("users[a].publish_allow: ", ex.Message);
        Assert.Contains(problem, ex.Message);
    }

    [Fact]
    public void InvalidPublishFilter_InAConfigFile_GivesOneClearStartupLine()
    {
        // Program prints this message under "Invalid config '<path>':" and exits with code 1.
        var path = Path.Combine(AppContext.BaseDirectory, $"bad-publish-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, $"users:\n  - username: meshdev\n    password_hash: \"{Hash}\"\n    publish_allow: ['msh/#/e']\n");
        try
        {
            var ex = Assert.Throws<ConfigException>(() => ConfigLoader.LoadFile(path));
            Assert.Equal("- users[meshdev].publish_allow: '#' must be a whole level and the last one: 'msh/#/e'", ex.Message);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ExampleConfig_IsValidAndMatchesTheSpanishMesh()
    {
        var c = ConfigLoader.LoadFile(Path.Combine(AppContext.BaseDirectory, "config.example.yaml"));
        var meshdev = Assert.Single(c.Users!);
        Assert.Equal("meshdev", meshdev.Username);
        Assert.Empty(meshdev.SubscribeAllow!);
        Assert.Equal(["msh/EU_868/2/e/#", "msh/EU_868/2/map/"], meshdev.PublishAllow!);
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
        Assert.Equal(3, c.Limits.AuthQueueTimeoutSeconds);
        Assert.Equal(64, c.Limits.AuthMaxPending);
        Assert.Equal(4, c.Limits.AuthMaxPendingPerUser);
        Assert.Equal(16, c.Limits.MaxConnectionsPerIp);
        Assert.Equal(30, c.Limits.ConnectRatePerIpPerMinute);
        Assert.Equal(10, c.Limits.ConnectBurstPerIp);
        Assert.Equal(512, c.Limits.MaxPayloadSize);
        Assert.Equal(120, c.Limits.PublishRatePerClientPerMinute);
        Assert.Equal(60, c.Limits.PublishBurstPerClient);
        Assert.Equal(120, c.Limits.DedupeWindowSeconds);
        Assert.Equal(32, c.Limits.DedupeMaxGatewaysPerPacket);
        Assert.Equal(200_000, c.Limits.DedupeMaxEntries);
        Assert.Equal(30, c.Limits.PacketRatePerFromPerMinute);
        Assert.Equal(15, c.Limits.PacketBurstPerFrom);
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
        Assert.Equal(3, d.AuthQueueTimeoutSeconds);
        Assert.Equal(64, d.AuthMaxPending);
        Assert.Equal(4, d.AuthMaxPendingPerUser);
        Assert.Equal(16, d.MaxConnectionsPerIp);
        Assert.Equal(30, d.ConnectRatePerIpPerMinute);
        Assert.Equal(10, d.ConnectBurstPerIp);
        Assert.Equal(512, d.MaxPayloadSize);
        Assert.Equal(120, d.PublishRatePerClientPerMinute);
        Assert.Equal(60, d.PublishBurstPerClient);
        Assert.Equal(120, d.DedupeWindowSeconds);
        Assert.Equal(32, d.DedupeMaxGatewaysPerPacket);
        Assert.Equal(200_000, d.DedupeMaxEntries);
        Assert.Equal(30, d.PacketRatePerFromPerMinute);
        Assert.Equal(15, d.PacketBurstPerFrom);

        var c = ConfigLoader.Parse(Minimal("limits:\n  max_packet_size: 2048\n  communication_timeout_seconds: 5\n  auth_queue_timeout_seconds: 2\n  auth_max_pending: 8\n  auth_max_pending_per_user: 2")).Limits!;
        Assert.Equal(2048, c.MaxPacketSize);
        Assert.Equal(5, c.CommunicationTimeoutSeconds);
        Assert.Equal(2, c.AuthQueueTimeoutSeconds);
        Assert.Equal(8, c.AuthMaxPending);
        Assert.Equal(2, c.AuthMaxPendingPerUser);
    }

    [Fact]
    public void TheNewLimits_CanBeSet()
    {
        var c = ConfigLoader.Parse(Minimal("""
            limits:
              max_connections_per_ip: 4
              connect_rate_per_ip_per_minute: 6
              connect_burst_per_ip: 2
              max_payload_size: 128
              publish_rate_per_client_per_minute: 60
              publish_burst_per_client: 10
              dedupe_window_seconds: 30
              dedupe_max_gateways_per_packet: 4
              dedupe_max_entries: 1000
              packet_rate_per_from_per_minute: 6
              packet_burst_per_from: 2
            """)).Limits!;
        Assert.Equal(4, c.MaxConnectionsPerIp);
        Assert.Equal(6, c.ConnectRatePerIpPerMinute);
        Assert.Equal(2, c.ConnectBurstPerIp);
        Assert.Equal(128, c.MaxPayloadSize);
        Assert.Equal(60, c.PublishRatePerClientPerMinute);
        Assert.Equal(10, c.PublishBurstPerClient);
        Assert.Equal(30, c.DedupeWindowSeconds);
        Assert.Equal(4, c.DedupeMaxGatewaysPerPacket);
        Assert.Equal(1000, c.DedupeMaxEntries);
        Assert.Equal(6, c.PacketRatePerFromPerMinute);
        Assert.Equal(2, c.PacketBurstPerFrom);
    }

    [Fact]
    public void TheNewLimits_CanBeTurnedOff()
    {
        // 0 means "off" wherever the section says so: the per-IP cap, the connect rate, the per-client
        // publish rate, the dedupe window and the per-node packet rate.
        var c = ConfigLoader.Parse(Minimal("""
            limits:
              max_connections_per_ip: 0
              connect_rate_per_ip_per_minute: 0
              connect_burst_per_ip: 0
              publish_rate_per_client_per_minute: 0
              publish_burst_per_client: 0
              dedupe_window_seconds: 0
              packet_rate_per_from_per_minute: 0
              packet_burst_per_from: 0
            """)).Limits!;
        Assert.Equal(0, c.MaxConnectionsPerIp);
        Assert.Equal(0, c.ConnectRatePerIpPerMinute);
        Assert.Equal(0, c.ConnectBurstPerIp);
        Assert.Equal(0, c.PublishRatePerClientPerMinute);
        Assert.Equal(0, c.PublishBurstPerClient);
        Assert.Equal(0, c.DedupeWindowSeconds);
        Assert.Equal(0, c.PacketRatePerFromPerMinute);
        Assert.Equal(0, c.PacketBurstPerFrom);
        // The payload cap and the entry caps have no "off" value: they are never 0.
        Assert.Equal(512, c.MaxPayloadSize);
        Assert.Equal(32, c.DedupeMaxGatewaysPerPacket);
        Assert.Equal(200_000, c.DedupeMaxEntries);
    }

    [Theory]
    [InlineData("limits:\n  max_packet_size: 100", "limits.max_packet_size")]
    [InlineData("limits:\n  max_packet_size: 268435455", "limits.max_packet_size")]
    [InlineData("limits:\n  max_packet_size:", "limits.max_packet_size")]
    [InlineData("limits:\n  communication_timeout_seconds: 0", "limits.communication_timeout_seconds")]
    [InlineData("limits:\n  auth_queue_timeout_seconds: 0", "limits.auth_queue_timeout_seconds")]
    [InlineData("limits:\n  auth_max_pending: 0", "limits.auth_max_pending")]
    [InlineData("limits:\n  auth_max_pending_per_user: 0", "limits.auth_max_pending_per_user")]
    [InlineData("limits:", "limits")]
    [InlineData("limits:\n  max_packet: 4096", "max_packet")]
    [InlineData("limits:\n  max_connections_per_ip: -1", "limits.max_connections_per_ip")]
    [InlineData("limits:\n  max_connections_per_ip: 100001", "limits.max_connections_per_ip")]
    [InlineData("limits:\n  max_connections_per_ip:", "limits.max_connections_per_ip")]
    [InlineData("limits:\n  connect_rate_per_ip_per_minute: -1", "limits.connect_rate_per_ip_per_minute")]
    [InlineData("limits:\n  connect_rate_per_ip_per_minute: 1000001", "limits.connect_rate_per_ip_per_minute")]
    [InlineData("limits:\n  connect_burst_per_ip: -1", "limits.connect_burst_per_ip")]
    [InlineData("limits:\n  connect_burst_per_ip: 1000001", "limits.connect_burst_per_ip")]
    [InlineData("limits:\n  max_payload_size: 63", "limits.max_payload_size")]
    [InlineData("limits:\n  max_payload_size: 4097", "limits.max_payload_size")]
    [InlineData("limits:\n  max_payload_size: 0", "limits.max_payload_size")]
    [InlineData("limits:\n  max_payload_size:", "limits.max_payload_size")]
    [InlineData("limits:\n  publish_rate_per_client_per_minute: -1", "limits.publish_rate_per_client_per_minute")]
    [InlineData("limits:\n  publish_rate_per_client_per_minute: 1000001", "limits.publish_rate_per_client_per_minute")]
    [InlineData("limits:\n  publish_burst_per_client: -1", "limits.publish_burst_per_client")]
    [InlineData("limits:\n  publish_burst_per_client: 1000001", "limits.publish_burst_per_client")]
    [InlineData("limits:\n  dedupe_window_seconds: -1", "limits.dedupe_window_seconds")]
    [InlineData("limits:\n  dedupe_window_seconds: 86401", "limits.dedupe_window_seconds")]
    [InlineData("limits:\n  dedupe_max_gateways_per_packet: 0", "limits.dedupe_max_gateways_per_packet")]
    [InlineData("limits:\n  dedupe_max_gateways_per_packet: 100001", "limits.dedupe_max_gateways_per_packet")]
    [InlineData("limits:\n  dedupe_max_entries: 0", "limits.dedupe_max_entries")]
    [InlineData("limits:\n  dedupe_max_entries: 10000001", "limits.dedupe_max_entries")]
    [InlineData("limits:\n  packet_rate_per_from_per_minute: -1", "limits.packet_rate_per_from_per_minute")]
    [InlineData("limits:\n  packet_rate_per_from_per_minute: 1000001", "limits.packet_rate_per_from_per_minute")]
    [InlineData("limits:\n  packet_burst_per_from: -1", "limits.packet_burst_per_from")]
    [InlineData("limits:\n  packet_burst_per_from: 1000001", "limits.packet_burst_per_from")]
    public void InvalidLimits_AreRejected(string extra, string mentions)
    {
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse(Minimal(extra)));
        Assert.Contains(mentions, ex.Message);
    }

    [Fact]
    public void ThePayloadCap_CannotBeLargerThanThePacketSize()
    {
        // The broker never reads a packet larger than max_packet_size, so a bigger payload cap is a typo.
        var ex = Assert.Throws<ConfigException>(() => ConfigLoader.Parse(
            Minimal("limits:\n  max_packet_size: 1024\n  max_payload_size: 2048")));
        Assert.Contains("limits.max_payload_size", ex.Message);
        Assert.Contains("1024", ex.Message);
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
