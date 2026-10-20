using System.Globalization;
using System.Text.Json;
using Meshtastic.Mqtt;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Formatting.Compact;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The limits of the startup line: the dictionary the log attaches and the text of the line are built
/// from the same values, so they can never disagree.
/// </summary>
public sealed class LimitsValuesTests
{
    /// <summary>The value of a limit as an integer.</summary>
    static int Int(IReadOnlyDictionary<string, object> values, string key) =>
        Convert.ToInt32(values[key], CultureInfo.InvariantCulture);

    [Fact]
    public void TheEffectiveLimits_HaveTheirDefaults()
    {
        var values = new LimitsConfig().EffectiveValues();

        Assert.Equal(22, values.Count);
        Assert.Equal(LimitsConfig.DefaultMaxPacketSize, Int(values, "max_packet_size"));
        Assert.Equal(LimitsConfig.DefaultCommunicationTimeoutSeconds, Int(values, "communication_timeout_seconds"));
        Assert.Equal(LimitsConfig.DefaultAuthQueueTimeoutSeconds, Int(values, "auth_queue_timeout_seconds"));
        Assert.Equal(LimitsConfig.DefaultAuthMaxPending, Int(values, "auth_max_pending"));
        Assert.Equal(LimitsConfig.DefaultAuthMaxPendingPerUser, Int(values, "auth_max_pending_per_user"));
        Assert.Equal(LimitsConfig.DefaultMaxConnectionsPerIp, Int(values, "max_connections_per_ip"));
        Assert.Equal(LimitsConfig.DefaultConnectRatePerIpPerMinute, Int(values, "connect_rate_per_ip_per_minute"));
        Assert.Equal(LimitsConfig.DefaultConnectBurstPerIp, Int(values, "connect_burst_per_ip"));
        Assert.Equal(LimitsConfig.DefaultMaxPayloadSize, Int(values, "max_payload_size"));
        Assert.Equal(LimitsConfig.DefaultPublishRatePerClientPerMinute, Int(values, "publish_rate_per_client_per_minute"));
        Assert.Equal(LimitsConfig.DefaultPublishBurstPerClient, Int(values, "publish_burst_per_client"));
        Assert.Equal(LimitsConfig.DefaultDedupeWindowSeconds, Int(values, "dedupe_window_seconds"));
        Assert.Equal(LimitsConfig.DefaultDedupeMaxGatewaysPerPacket, Int(values, "dedupe_max_gateways_per_packet"));
        Assert.Equal(LimitsConfig.DefaultDedupeMaxEntries, Int(values, "dedupe_max_entries"));
        Assert.Equal(LimitsConfig.DefaultPacketRatePerFromPerMinute, Int(values, "packet_rate_per_from_per_minute"));
        Assert.Equal(LimitsConfig.DefaultPacketBurstPerFrom, Int(values, "packet_burst_per_from"));
        Assert.Equal(LimitsConfig.DefaultAuthFailMaxPerIp, Int(values, "auth_fail_max_per_ip"));
        Assert.Equal(LimitsConfig.DefaultAuthFailWindowSeconds, Int(values, "auth_fail_window_seconds"));
        Assert.Equal(LimitsConfig.DefaultAuthBanSeconds, Int(values, "auth_ban_seconds"));
        Assert.Equal(LimitsConfig.DefaultMaxTrackedEntries, Int(values, "max_tracked_entries"));
        Assert.Equal(LimitsConfig.DefaultRateIdleExpirySeconds, Int(values, "rate_idle_expiry_seconds"));

        // The exempt ranges are a list of strings.
        Assert.Empty(Assert.IsType<List<string>>(values["auth_ban_exempt"]));
    }

    [Fact]
    public void TheEffectiveLimits_HaveTheValuesThatAreSet()
    {
        var limits = new LimitsConfig
        {
            MaxPacketSize = 8192,
            DedupeMaxEntries = 1000,
            RateIdleExpirySeconds = 120,
            AuthBanExempt = ["10.0.0.0/8", "2001:db8::/32"],
        };
        var values = limits.EffectiveValues();

        Assert.Equal(22, values.Count);
        Assert.Equal(8192, Int(values, "max_packet_size"));
        Assert.Equal(1000, Int(values, "dedupe_max_entries"));
        Assert.Equal(120, Int(values, "rate_idle_expiry_seconds"));
        Assert.Equal(["10.0.0.0/8", "2001:db8::/32"], Assert.IsType<List<string>>(values["auth_ban_exempt"]));

        // The keys that are not set keep their default.
        Assert.Equal(LimitsConfig.DefaultMaxConnectionsPerIp, Int(values, "max_connections_per_ip"));
    }

    [Fact]
    public void TheEffectiveLimits_FallBackToTheDefaultWhenAKeyIsEmpty()
    {
        // A key that is not in the config (or is empty) must not change the value the broker uses.
        var limits = new LimitsConfig { MaxPacketSize = null, DedupeMaxEntries = null, AuthBanExempt = null };
        var values = limits.EffectiveValues();

        Assert.Equal(LimitsConfig.DefaultMaxPacketSize, Int(values, "max_packet_size"));
        Assert.Equal(LimitsConfig.DefaultDedupeMaxEntries, Int(values, "dedupe_max_entries"));
        Assert.Empty(Assert.IsType<List<string>>(values["auth_ban_exempt"]));
    }

    [Fact]
    public void TheEffectiveLimits_KeepTheOrderOfTheStartupLine()
    {
        // The dictionary is ordered: the keys come in the order of the startup line.
        var values = new LimitsConfig().EffectiveValues();

        Assert.Equal(new[]
        {
            "max_packet_size", "communication_timeout_seconds", "auth_queue_timeout_seconds",
            "auth_max_pending", "auth_max_pending_per_user", "max_connections_per_ip",
            "connect_rate_per_ip_per_minute", "connect_burst_per_ip", "max_payload_size",
            "publish_rate_per_client_per_minute", "publish_burst_per_client", "dedupe_window_seconds",
            "dedupe_max_gateways_per_packet", "dedupe_max_entries", "packet_rate_per_from_per_minute",
            "packet_burst_per_from", "auth_fail_max_per_ip", "auth_fail_window_seconds",
            "auth_ban_seconds", "auth_ban_exempt", "max_tracked_entries", "rate_idle_expiry_seconds",
        }, values.Keys);
    }

    [Fact]
    public void TheStartupLine_HasEveryEffectiveLimit()
    {
        // The text of the line and the dictionary of the log are built from the same values: the line
        // shows every entry of the dictionary as "key=value".
        var limits = new LimitsConfig();
        var values = limits.EffectiveValues();
        var described = limits.Describe();

        Assert.Equal(22, values.Count);
        foreach (var (key, rendered) in new[]
        {
            ("max_packet_size", "4096"),
            ("communication_timeout_seconds", "10"),
            ("auth_queue_timeout_seconds", "3"),
            ("auth_max_pending", "64"),
            ("auth_max_pending_per_user", "4"),
            ("max_connections_per_ip", "16"),
            ("connect_rate_per_ip_per_minute", "30"),
            ("connect_burst_per_ip", "10"),
            ("max_payload_size", "512"),
            ("publish_rate_per_client_per_minute", "120"),
            ("publish_burst_per_client", "60"),
            ("dedupe_window_seconds", "120"),
            ("dedupe_max_gateways_per_packet", "32"),
            ("dedupe_max_entries", "200000"),
            ("packet_rate_per_from_per_minute", "30"),
            ("packet_burst_per_from", "15"),
            ("auth_fail_max_per_ip", "10"),
            ("auth_fail_window_seconds", "600"),
            ("auth_ban_seconds", "3600"),
            ("auth_ban_exempt", "[]"),
            ("max_tracked_entries", "100000"),
            ("rate_idle_expiry_seconds", "600"),
        })
        {
            Assert.True(values.ContainsKey(key), $"the dictionary has no {key}");
            Assert.Contains($"{key}={rendered}", described);
        }
    }

    [Fact]
    public void TheStartupLine_ShowsTheLimitsThatAreSet()
    {
        // The same, with every limit set: the line shows the values the broker will use.
        var limits = new LimitsConfig
        {
            MaxPacketSize = 8192,
            CommunicationTimeoutSeconds = 20,
            AuthQueueTimeoutSeconds = 5,
            AuthMaxPending = 16,
            AuthMaxPendingPerUser = 2,
            MaxConnectionsPerIp = 8,
            ConnectRatePerIpPerMinute = 60,
            ConnectBurstPerIp = 20,
            MaxPayloadSize = 1024,
            PublishRatePerClientPerMinute = 240,
            PublishBurstPerClient = 120,
            DedupeWindowSeconds = 60,
            DedupeMaxGatewaysPerPacket = 16,
            DedupeMaxEntries = 100000,
            PacketRatePerFromPerMinute = 60,
            PacketBurstPerFrom = 30,
            AuthFailMaxPerIp = 5,
            AuthFailWindowSeconds = 300,
            AuthBanSeconds = 120,
            AuthBanExempt = ["10.0.0.0/8", "2001:db8::/32"],
            MaxTrackedEntries = 50000,
            RateIdleExpirySeconds = 900,
        };
        var values = limits.EffectiveValues();
        var described = limits.Describe();

        Assert.Equal(22, values.Count);
        foreach (var (key, rendered) in new[]
        {
            ("max_packet_size", "8192"),
            ("communication_timeout_seconds", "20"),
            ("auth_queue_timeout_seconds", "5"),
            ("auth_max_pending", "16"),
            ("auth_max_pending_per_user", "2"),
            ("max_connections_per_ip", "8"),
            ("connect_rate_per_ip_per_minute", "60"),
            ("connect_burst_per_ip", "20"),
            ("max_payload_size", "1024"),
            ("publish_rate_per_client_per_minute", "240"),
            ("publish_burst_per_client", "120"),
            ("dedupe_window_seconds", "60"),
            ("dedupe_max_gateways_per_packet", "16"),
            ("dedupe_max_entries", "100000"),
            ("packet_rate_per_from_per_minute", "60"),
            ("packet_burst_per_from", "30"),
            ("auth_fail_max_per_ip", "5"),
            ("auth_fail_window_seconds", "300"),
            ("auth_ban_seconds", "120"),
            ("auth_ban_exempt", "[10.0.0.0/8, 2001:db8::/32]"),
            ("max_tracked_entries", "50000"),
            ("rate_idle_expiry_seconds", "900"),
        })
        {
            Assert.True(values.ContainsKey(key), $"the dictionary has no {key}");
            Assert.Contains($"{key}={rendered}", described);
        }
    }

    [Fact]
    public void TheStartupLine_AttachesTheLimitsAsAStructuredDictionary()
    {
        // The startup line shows the limits as text and attaches them as data: the JSON log holds an
        // object keyed by the name of the limit, not a list of pairs.
        var config = TestSupport.Config(1883,
            "limits:\n  auth_ban_exempt: ['10.0.0.0/8', '2001:db8::/32']");
        var logs = new TestSupport.LogSink();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger();

        StartupLine.Write(logger, config);

        var startup = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Information);
        using var writer = new StringWriter();
        new RenderedCompactJsonFormatter().Format(startup, writer);
        using var document = JsonDocument.Parse(writer.ToString());

        // The limits are an object with the 22 keys.
        var limits = document.RootElement.GetProperty("LimitValues");
        Assert.Equal(JsonValueKind.Object, limits.ValueKind);
        Assert.Equal(22, limits.EnumerateObject().Count());
        Assert.Equal(4096, limits.GetProperty("max_packet_size").GetInt32());
        Assert.Equal(new[] { "10.0.0.0/8", "2001:db8::/32" },
            limits.GetProperty("auth_ban_exempt").EnumerateArray().Select(range => range.GetString()));

        // And the text of the limits is on the line as it is: not wrapped in quotes.
        var message = document.RootElement.GetProperty("@m").GetString()!;
        Assert.Contains($"limits: {config.Limits!.Describe()}", message);
        var limitsStart = message.IndexOf("limits: ", StringComparison.Ordinal) + "limits: ".Length;
        Assert.NotEqual('"', message[limitsStart]);
    }
}
