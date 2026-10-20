using Meshtastic.Mqtt;
using Serilog;
using Serilog.Core;
using Serilog.Events;
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
}
