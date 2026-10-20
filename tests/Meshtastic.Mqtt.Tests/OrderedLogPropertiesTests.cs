using System.Text.Json;
using Meshtastic.Mqtt;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Formatting.Compact;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The structured properties of the log: the JSON objects they are written as keep the order of their
/// keys (the order of the enumeration of a plain dictionary is not guaranteed), the values keep their
/// types, and the objects have no type tag.
/// </summary>
public sealed class OrderedLogPropertiesTests
{
    /// <summary>The limits of the startup line, in the order they are written.</summary>
    static readonly string[] ExpectedLimitKeys = new[]
    {
        "max_packet_size", "communication_timeout_seconds", "auth_queue_timeout_seconds",
        "auth_max_pending", "auth_max_pending_per_user", "max_connections_per_ip",
        "connect_rate_per_ip_per_minute", "connect_burst_per_ip", "max_payload_size",
        "publish_rate_per_client_per_minute", "publish_burst_per_client", "dedupe_window_seconds",
        "dedupe_max_gateways_per_packet", "dedupe_max_entries", "packet_rate_per_from_per_minute",
        "packet_burst_per_from", "auth_fail_max_per_ip", "auth_fail_window_seconds",
        "auth_ban_seconds", "auth_ban_exempt", "max_tracked_entries", "rate_idle_expiry_seconds",
    };

    [Fact]
    public void TheStartupLine_AttachesTheLimitsInAGuaranteedOrder()
    {
        // The limits are attached as a JSON object whose keys keep the order of the startup line. The
        // object is built explicitly, because the order of a plain dictionary is not guaranteed.
        var config = TestSupport.Config(1883,
            "limits:\n  auth_ban_exempt: ['10.0.0.0/8', '2001:db8::/32']");
        var logs = new LogSink();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger();

        StartupLine.Write(logger, config);

        var startup = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Information);
        Assert.IsType<StructureValue>(startup.Properties["LimitValues"]);

        var json = Render(startup);
        using var document = JsonDocument.Parse(json);
        var limits = document.RootElement.GetProperty("LimitValues");

        Assert.Equal(JsonValueKind.Object, limits.ValueKind);
        Assert.Equal(ExpectedLimitKeys, limits.EnumerateObject().Select(property => property.Name));

        // The values keep their types: the numbers are numbers and the exempt ranges a list of strings.
        Assert.Equal(JsonValueKind.Number, limits.GetProperty("max_packet_size").ValueKind);
        Assert.Equal(4096, limits.GetProperty("max_packet_size").GetInt32());
        Assert.Equal(JsonValueKind.Array, limits.GetProperty("auth_ban_exempt").ValueKind);
        Assert.Equal(new[] { "10.0.0.0/8", "2001:db8::/32" },
            limits.GetProperty("auth_ban_exempt").EnumerateArray().Select(range => range.GetString()));

        // And the object has no type tag.
        Assert.DoesNotContain("$type", json);
    }

    [Fact]
    public void TheSummary_AttachesTheCountsInTheOrderOfTheText()
    {
        // The counts per reason are attached as a JSON object whose keys keep the order of the text of
        // the line (the ordinal order of the reasons).
        var logs = new LogSink();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger();
        var drops = new DropCounters(logger, start: false);
        drops.Increment("not in publish_allow");
        drops.Increment("banned IP");
        drops.Increment("evicted: dedupe table full");
        drops.Increment("banned IP");

        drops.Flush();

        var summary = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Information);
        Assert.IsType<StructureValue>(summary.Properties["Drops"]);

        var json = Render(summary);
        using var document = JsonDocument.Parse(json);
        var breakdown = document.RootElement.GetProperty("Drops");

        Assert.Equal(JsonValueKind.Object, breakdown.ValueKind);
        Assert.Equal(new[] { "banned IP", "evicted: dedupe table full", "not in publish_allow" },
            breakdown.EnumerateObject().Select(property => property.Name));

        // The counts are numbers.
        Assert.Equal(JsonValueKind.Number, breakdown.GetProperty("banned IP").ValueKind);
        Assert.Equal(2, breakdown.GetProperty("banned IP").GetInt64());
        Assert.Equal(1, breakdown.GetProperty("evicted: dedupe table full").GetInt64());
        Assert.Equal(1, breakdown.GetProperty("not in publish_allow").GetInt64());

        // And the object has no type tag.
        Assert.DoesNotContain("$type", json);
    }

    /// <summary>The event as the JSON log writes it (the format of the production log).</summary>
    static string Render(LogEvent logEvent)
    {
        using var writer = new StringWriter();
        new RenderedCompactJsonFormatter().Format(logEvent, writer);
        return writer.ToString();
    }
}
