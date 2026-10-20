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
/// The periodic summary of the drop counters: it counts the refused publishes, the refused connections
/// and the evictions, so it must not call them all publishes.
/// </summary>
public sealed class DropSummaryTests
{
    static (DropCounters Drops, LogSink Logs) Counters()
    {
        var logs = new LogSink();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger();
        return (new DropCounters(logger, start: false), logs);
    }

    [Fact]
    public void TheSummary_CountsWhatWasRefusedOrEvicted()
    {
        var (drops, logs) = Counters();
        drops.Increment("not in publish_allow");
        drops.Increment("not in publish_allow");
        drops.Increment("banned IP");
        drops.Increment("evicted: dedupe table full");

        drops.Flush();

        var summary = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Information);
        var message = summary.RenderMessage();
        Assert.StartsWith("Refused or evicted 4 in the last 60 s: ", message);
        Assert.Contains("not in publish_allow: 2", message);
        Assert.Contains("banned IP: 1", message);
        Assert.Contains("evicted: dedupe table full: 1", message);
    }

    [Fact]
    public void TheSummary_IsSilentWhenNothingWasRefused()
    {
        var (drops, logs) = Counters();
        drops.Flush();
        Assert.Empty(logs.Events);

        // And the counters are reset by the summary: the next one has nothing to say.
        drops.Increment("banned IP");
        drops.Flush();
        Assert.Single(logs.Events);
        drops.Flush();
        Assert.Single(logs.Events);
    }

    [Fact]
    public void TheSummary_ShowsTheBreakdownWithoutQuotes_AndKeepsItStructured()
    {
        // The line the operator reads must not wrap the breakdown in quotes, and the counts per reason
        // must stay structured in the log (the JSON), so a log store can filter by them.
        var (drops, logs) = Counters();
        drops.Increment("not in publish_allow");
        drops.Increment("not in publish_allow");
        drops.Increment("banned IP");

        drops.Flush();

        var summary = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Information);
        var message = summary.RenderMessage();
        Assert.Equal("Refused or evicted 3 in the last 60 s: banned IP: 1, not in publish_allow: 2", message);
        Assert.DoesNotContain('"', message);

        // The counts per reason are a structured property of the event.
        using var writer = new StringWriter();
        new RenderedCompactJsonFormatter().Format(summary, writer);
        using var document = JsonDocument.Parse(writer.ToString());
        var breakdown = document.RootElement.GetProperty("Drops");
        Assert.Equal(JsonValueKind.Object, breakdown.ValueKind);
        Assert.Equal(1, breakdown.GetProperty("banned IP").GetInt64());
        Assert.Equal(2, breakdown.GetProperty("not in publish_allow").GetInt64());
    }

    // DF6: the numbers of a reason are collapsed, except the ones between two slashes: the fixed "/2/" of
    // the topic format is part of the shape of the reason, not a value.

    [Fact]
    public void DF6_TheTopicReasons_KeepTheirSlashTwo_AndTheSizeReasonIsCollapsed()
    {
        var (drops, logs) = Counters();
        drops.Increment("unsupported topic (expected <root>/2/e/<channel>/<gateway>)");
        drops.Increment("unsupported map topic (expected <root>/2/map/)");
        drops.Increment("encrypted payload size 300 outside 1-256");

        drops.Flush();

        var message = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Information).RenderMessage();
        Assert.Contains("unsupported topic (expected <root>/2/e/<channel>/<gateway>): 1", message);
        Assert.Contains("unsupported map topic (expected <root>/2/map/): 1", message);
        Assert.Contains("encrypted payload size N outside N-N: 1", message);
        Assert.DoesNotContain("/N/", message);
    }

    [Fact]
    public void DF6_AMultiDigitNumberBetweenTwoSlashes_IsKeptWhole()
    {
        // The whole run of digits is kept, not one digit at a time.
        var (drops, logs) = Counters();
        drops.Increment("a reason with /12/ in it");
        drops.Increment("a reason with 12 in it");

        drops.Flush();

        var message = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Information).RenderMessage();
        Assert.Contains("a reason with /12/ in it: 1", message);
        Assert.Contains("a reason with N in it: 1", message);
    }
}
