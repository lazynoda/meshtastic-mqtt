using Meshtastic.Mqtt;
using Serilog;
using Serilog.Core;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The caps of the bounded tables are configuration (<c>limits.max_tracked_entries</c>), not constants:
/// every table of the broker honours the configured cap.
/// </summary>
public sealed class TrackedEntriesTests
{
    /// <summary>The smallest cap that may be configured.</summary>
    const int SmallCap = 1000;

    static ILogger LoggerFor(LogSink sink) =>
        new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(sink).CreateLogger();

    [Fact]
    public void ThePerIpTables_HonourTheConfiguredCap()
    {
        // The table of the connections of one address and the table of the connect rates.
        var clock = new FakeClock();
        var guard = new ConnectionGuard(new LimitsConfig { MaxTrackedEntries = SmallCap }, clock);

        for (var i = 0; i <= SmallCap; i++)
            Assert.True(guard.TryAcquire($"10.0.{i / 256}.{i % 256}", out _));

        Assert.Equal(SmallCap, guard.TrackedIps);
        Assert.Equal(1, guard.Evictions);
    }

    [Fact]
    public void TheAuthTables_HonourTheConfiguredCap()
    {
        var clock = new FakeClock();
        var logger = LoggerFor(new LogSink());

        // The table of the failed logins.
        var failures = new AuthBanManager(
            new LimitsConfig { MaxTrackedEntries = SmallCap, AuthFailMaxPerIp = 100 }, clock, logger);
        for (var i = 0; i <= SmallCap; i++)
            Assert.False(failures.RecordFailure($"10.0.{i / 256}.{i % 256}"));
        Assert.Equal(SmallCap, failures.TrackedFailures);
        Assert.Equal(1, failures.FailureEvictions);

        // The table of the bans.
        var bans = new AuthBanManager(
            new LimitsConfig { MaxTrackedEntries = SmallCap, AuthFailMaxPerIp = 1 }, clock, logger);
        for (var i = 0; i <= SmallCap; i++)
            Assert.True(bans.RecordFailure($"10.0.{i / 256}.{i % 256}"));
        Assert.Equal(SmallCap, bans.TrackedBans);
        Assert.Equal(1, bans.BanEvictions);
    }

    [Fact]
    public void TheRateTables_HonourTheConfiguredCap()
    {
        var clock = new FakeClock();

        // The per-node rate table.
        var gate = new PacketGate(new LimitsConfig
        {
            MaxTrackedEntries = SmallCap,
            PacketRatePerFromPerMinute = 1_000_000,
            PacketBurstPerFrom = 1_000_000,
        }, clock);
        for (uint i = 1; i <= SmallCap + 1; i++)
            gate.EvaluatePacket(i, i, 1);
        Assert.Equal(SmallCap, gate.RateCount);
        Assert.Equal(1, gate.RateEvictions);

        // The per-client rate table.
        var config = ConfigLoader.Parse($"""
            users:
              - username: meshdev
                password_hash: "{AuthTests.MeshdevHash}"
            limits:
              max_tracked_entries: {SmallCap}
            """);
        var hooks = new BrokerHooks(config, LoggerFor(new LogSink()), time: clock);
        for (var i = 0; i <= SmallCap; i++)
            Assert.True(hooks.PublishRate.TryTake("meshdev", $"client-{i}"));
        Assert.Equal(SmallCap, hooks.PublishRate.Count);
        Assert.Equal(1, hooks.PublishRate.Evictions);
    }
}
