using Meshtastic.Mqtt;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The rate tables themselves: the token bucket, the per-client budget and their bounds (a hard entry cap,
/// an idle expiry, counted evictions). The clock is a fake one, so no test sleeps.
/// </summary>
public sealed class RateTableTests
{
    [Fact]
    public void TheTokenBucket_AllowsTheBurst_RefillsAndRefuses()
    {
        var clock = new FakeClock();
        var table = new TokenBucketTable(capacity: 3, refillPerSecond: 0.5, maxEntries: 100,
            idleExpiry: TimeSpan.FromMinutes(10), time: clock);

        Assert.True(table.TryTake("a"));
        Assert.True(table.TryTake("a"));
        Assert.True(table.TryTake("a"));
        Assert.False(table.TryTake("a"));

        // Another key has its own bucket.
        Assert.True(table.TryTake("b"));

        // 0.5 tokens per second: one token after two seconds.
        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.True(table.TryTake("a"));
        Assert.False(table.TryTake("a"));
    }

    [Fact]
    public void TheTokenBucket_NeverGrowsOverItsCapacity()
    {
        var clock = new FakeClock();
        var table = new TokenBucketTable(capacity: 2, refillPerSecond: 10, maxEntries: 100,
            idleExpiry: TimeSpan.FromMinutes(10), time: clock);
        clock.Advance(TimeSpan.FromHours(1));
        Assert.True(table.TryTake("a"));
        Assert.True(table.TryTake("a"));
        Assert.False(table.TryTake("a"));
    }

    [Fact]
    public void TheTokenBucket_EvictsTheOldestKeyAtItsCap()
    {
        var clock = new FakeClock();
        var table = new TokenBucketTable(capacity: 1, refillPerSecond: 0, maxEntries: 4,
            idleExpiry: TimeSpan.FromMinutes(10), time: clock);
        foreach (var key in new[] { "a", "b", "c", "d" })
            Assert.True(table.TryTake(key));

        Assert.Equal(4, table.Count);
        table.TryTake("e");   // "a" is the oldest and is evicted
        Assert.Equal(4, table.Count);
        Assert.Equal(1, table.Evictions);
    }

    [Fact]
    public void TheTokenBucket_ForgetsAnIdleKey()
    {
        var clock = new FakeClock();
        var table = new TokenBucketTable(capacity: 1, refillPerSecond: 0, maxEntries: 100,
            idleExpiry: TimeSpan.FromMinutes(10), time: clock);
        Assert.True(table.TryTake("a"));
        Assert.False(table.TryTake("a"));

        clock.Advance(TimeSpan.FromMinutes(11));
        Assert.True(table.TryTake("a"));   // the idle key was swept away
        Assert.Equal(1, table.Count);
    }

    [Fact]
    public void TheClientTable_IsKeyedByOwnerAndClientId()
    {
        var clock = new FakeClock();
        var table = new ClientRateTable(capacity: 1, refillPerSecond: 0, maxEntries: 100,
            idleExpiry: TimeSpan.FromMinutes(10), time: clock);

        Assert.True(table.TryTake("meshdev", "node-1"));
        Assert.False(table.TryTake("meshdev", "node-1"));

        // The same client id under another user is another key: a full budget.
        Assert.True(table.TryTake("alice", "node-1"));

        // And another client id of the same user has its own budget.
        Assert.True(table.TryTake("meshdev", "node-2"));
    }

    [Fact]
    public void TheClientTable_ForgetsTheSessionAndTheIdleClients()
    {
        var clock = new FakeClock();
        var table = new ClientRateTable(capacity: 1, refillPerSecond: 0, maxEntries: 100,
            idleExpiry: TimeSpan.FromMinutes(10), time: clock);

        Assert.True(table.TryTake("meshdev", "node-1"));
        Assert.False(table.TryTake("meshdev", "node-1"));

        // The session is gone: the client id is free again.
        table.Remove("node-1");
        Assert.Equal(0, table.Count);
        Assert.True(table.TryTake("meshdev", "node-1"));

        // An idle client is forgotten too.
        clock.Advance(TimeSpan.FromMinutes(11));
        Assert.True(table.TryTake("meshdev", "node-1"));
        Assert.Equal(1, table.Count);
    }

    [Fact]
    public void TheTables_ReportTheirEvictions()
    {
        // Every eviction is reported, so the operator sees in the periodic summary that a cap was hit.
        var evicted = 0;
        var table = new TokenBucketTable(capacity: 1, refillPerSecond: 0, maxEntries: 2,
            idleExpiry: TimeSpan.FromMinutes(10), time: new FakeClock(), onEvicted: () => evicted++);
        table.TryTake("a");
        table.TryTake("b");
        table.TryTake("c");   // "a" is the oldest and is evicted
        Assert.Equal(1, evicted);
        Assert.Equal(1, table.Evictions);
        Assert.Equal(2, table.Count);
    }

    [Fact]
    public void TheClientTable_ReportsItsEvictions()
    {
        var evicted = 0;
        var table = new ClientRateTable(capacity: 1, refillPerSecond: 0, maxEntries: 2,
            idleExpiry: TimeSpan.FromMinutes(10), time: new FakeClock(), onEvicted: () => evicted++);
        table.TryTake("meshdev", "a");
        table.TryTake("meshdev", "b");
        table.TryTake("meshdev", "c");
        Assert.Equal(1, evicted);
        Assert.Equal(1, table.Evictions);
    }
}
