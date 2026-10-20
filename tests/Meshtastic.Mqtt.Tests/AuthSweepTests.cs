using Meshtastic.Mqtt;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The sweep of the auth tables: it costs what it expires, not what the tables hold, and the outcome
/// is the same as the one of the old full scan.
/// </summary>
/// <remarks>
/// The clock is a fake one, so the windows and the bans are tested without a single sleep.
/// </remarks>
public sealed class AuthSweepTests
{
    /// <summary>A ban manager, a fake clock and the log it writes to.</summary>
    static (AuthBanManager Bans, FakeClock Clock, LogSink Logs) Manager(LimitsConfig limits)
    {
        var clock = new FakeClock();
        var logs = new LogSink();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger();
        return (new AuthBanManager(limits, clock, logger), clock, logs);
    }

    /// <summary>The limits of the tests: a window of 10 minutes and a ban of one minute.</summary>
    static LimitsConfig Limits(int maxFailures = 100) => new()
    {
        AuthFailMaxPerIp = maxFailures,
        AuthFailWindowSeconds = 600,
        AuthBanSeconds = 60,
    };

    [Fact]
    public void TheFailureSweep_VisitsOnlyTheOldestEntry()
    {
        // 100 live failures and none expired: the sweep visits the oldest one and stops there.
        var (bans, clock, _) = Manager(Limits());
        for (var i = 0; i < 100; i++)
            bans.RecordFailure($"10.0.0.{i}");
        Assert.Equal(100, bans.TrackedFailures);

        // A quarter of the window passes: the next failure sweeps, and no window has passed.
        clock.Advance(TimeSpan.FromSeconds(200));
        var before = bans.FailureSweepVisits;
        bans.RecordFailure("10.1.0.1");

        Assert.Equal(1, bans.FailureSweepVisits - before);   // it visited the oldest entry and stopped
        Assert.Equal(101, bans.TrackedFailures);              // nothing was expired
    }

    [Fact]
    public void TheFailureSweep_KeepsAFailureWhoseWindowRestarted()
    {
        // The window of 1.2.3.4 restarts, so its entry goes to the tail of the order: the sweep forgets
        // the older window of 5.6.7.8 and keeps the new one of 1.2.3.4.
        var (bans, clock, _) = Manager(Limits());
        bans.RecordFailure("1.2.3.4");              // the window starts
        clock.Advance(TimeSpan.FromSeconds(590));
        bans.RecordFailure("5.6.7.8");              // a sweep runs here: the window of 1.2.3.4 is still open
        clock.Advance(TimeSpan.FromSeconds(11));    // 601 s: the window of 1.2.3.4 has passed
        bans.RecordFailure("1.2.3.4");              // the sweep is not due: a new window starts
        Assert.Equal(1, bans.FailuresFor("1.2.3.4"));

        clock.Advance(TimeSpan.FromSeconds(600));   // the window of 5.6.7.8 has passed, the new one has not
        bans.RecordFailure("9.9.9.9");              // the sweep runs here

        Assert.Equal(1, bans.FailuresFor("1.2.3.4"));   // the new window is open: the entry is kept
        Assert.Equal(0, bans.FailuresFor("5.6.7.8"));   // its window has passed: the entry is forgotten
        Assert.Equal(2, bans.TrackedFailures);
    }

    [Fact]
    public void TheBanSweep_SkipsTheStaleEntryOfABanThatWasBannedAgain()
    {
        // The first ban of 1.2.3.4 ends and is forgotten by the lazy path, but the queue still holds its
        // entry. The address is banned again, and the sweep must not end that second ban.
        var (bans, clock, logs) = Manager(Limits(maxFailures: 1));
        Assert.True(bans.RecordFailure("1.2.3.4"));        // banned until t=60
        clock.Advance(TimeSpan.FromSeconds(50));
        Assert.True(bans.RecordFailure("5.6.7.8"));        // a sweep runs here: the first ban has not ended
        clock.Advance(TimeSpan.FromSeconds(10));           // t=60: the first ban has ended
        Assert.False(bans.IsBanned("1.2.3.4"));           // the lazy path forgets it

        // The address is banned again, for another minute.
        Assert.True(bans.RecordFailure("1.2.3.4"));

        // The clock passes the expiry of the first ban, but not the one of the second.
        clock.Advance(TimeSpan.FromSeconds(30));           // t=90
        bans.RecordFailure("9.9.9.9");                    // the sweep runs here

        Assert.True(bans.IsBanned("1.2.3.4"));             // the second ban is alive
        var ended = logs.Events.Count(e => e.Level == LogEventLevel.Debug
            && e.RenderMessage().Contains("ended"));
        Assert.Equal(1, ended);                            // only the first ban was logged as ended
    }
}
