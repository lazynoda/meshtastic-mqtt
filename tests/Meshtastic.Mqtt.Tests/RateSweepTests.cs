using Meshtastic.Mqtt;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The sweeps of the rate tables: they cost what they expire, not what the table holds, and the table
/// keeps its entries in the order of their last use (so the entry that is evicted when the table is full
/// is the least recently used one).
/// </summary>
/// <remarks>
/// The clock is a fake one, so no test sleeps.
/// </remarks>
public sealed class RateSweepTests
{
    /// <summary>An idle expiry long enough for the timelines of the tests below.</summary>
    static readonly TimeSpan IdleExpiry = TimeSpan.FromMinutes(60);

    [Fact]
    public void TheTokenBucketSweep_VisitsOnlyTheOldestEntry()
    {
        // 100 live keys and none idle: the sweep visits the oldest one and stops there.
        var clock = new FakeClock();
        var table = new TokenBucketTable(capacity: 1, refillPerSecond: 0, maxEntries: 1000,
            idleExpiry: IdleExpiry, time: clock);
        for (var i = 0; i < 100; i++)
            table.TryTake($"key-{i}");

        // A quarter of the idle expiry passes: the next take sweeps, and nothing has expired.
        clock.Advance(TimeSpan.FromMinutes(20));
        var before = table.SweepVisits;
        table.TryTake("another");

        Assert.Equal(1, table.SweepVisits - before);   // it visited the oldest entry and stopped
        Assert.Equal(101, table.Count);                // nothing was expired
    }

    [Fact]
    public void TheTokenBucketSweep_KeepsAKeyThatWasUsedRecently()
    {
        // The key inserted first but used recently survives the sweep that forgets the idle ones.
        var clock = new FakeClock();
        var table = new TokenBucketTable(capacity: 1, refillPerSecond: 0, maxEntries: 1000,
            idleExpiry: IdleExpiry, time: clock);

        table.TryTake("a");                          // inserted first
        clock.Advance(TimeSpan.FromMinutes(10));
        table.TryTake("b");                          // inserted later
        clock.Advance(TimeSpan.FromMinutes(40));
        table.TryTake("a");                          // used again: it is the most recently used key
        clock.Advance(TimeSpan.FromMinutes(25));
        table.TryTake("c");                          // the sweep runs here: "b" is idle, "a" is not

        Assert.Equal(2, table.Count);                // "b" was forgotten, "a" and "c" are there
        Assert.False(table.TryTake("a"));            // "a" survived: its budget was already spent
    }

    [Fact]
    public void TheTokenBucket_EvictsTheLeastRecentlyUsedKeyAtItsCap()
    {
        // The table is full: the key that goes is the least recently used one, not the first inserted.
        var clock = new FakeClock();
        var table = new TokenBucketTable(capacity: 1, refillPerSecond: 0, maxEntries: 4,
            idleExpiry: IdleExpiry, time: clock);
        table.TryTake("a");
        table.TryTake("b");
        table.TryTake("c");
        table.TryTake("d");

        clock.Advance(TimeSpan.FromSeconds(1));
        table.TryTake("a");                          // "a" is used again: it is the most recently used key

        table.TryTake("e");                          // the table is full: the least recently used key goes

        Assert.Equal(1, table.Evictions);
        Assert.True(table.TryTake("b"));             // "b" was evicted: it starts again with a full budget
        Assert.False(table.TryTake("a"));            // "a" survived: its budget was already spent
    }

    [Fact]
    public void TheClientTableSweep_VisitsOnlyTheOldestEntry()
    {
        var clock = new FakeClock();
        var table = new ClientRateTable(capacity: 1, refillPerSecond: 0, maxEntries: 1000,
            idleExpiry: IdleExpiry, time: clock);
        for (var i = 0; i < 100; i++)
            table.TryTake("meshdev", $"client-{i}");

        clock.Advance(TimeSpan.FromMinutes(20));
        var before = table.SweepVisits;
        table.TryTake("meshdev", "another");

        Assert.Equal(1, table.SweepVisits - before);   // it visited the oldest entry and stopped
        Assert.Equal(101, table.Count);                // nothing was expired
    }

    [Fact]
    public void TheClientTableSweep_KeepsAClientThatWasUsedRecently()
    {
        var clock = new FakeClock();
        var table = new ClientRateTable(capacity: 1, refillPerSecond: 0, maxEntries: 1000,
            idleExpiry: IdleExpiry, time: clock);

        table.TryTake("meshdev", "a");
        clock.Advance(TimeSpan.FromMinutes(10));
        table.TryTake("meshdev", "b");
        clock.Advance(TimeSpan.FromMinutes(40));
        table.TryTake("meshdev", "a");
        clock.Advance(TimeSpan.FromMinutes(25));
        table.TryTake("meshdev", "c");                   // the sweep runs here: "b" is idle, "a" is not

        Assert.Equal(2, table.Count);
        Assert.False(table.TryTake("meshdev", "a"));     // "a" survived: its budget was already spent
    }

    [Fact]
    public void TheClientTable_EvictsTheLeastRecentlyUsedClientAtItsCap()
    {
        // The client id taken over by another user ends at the tail of the order too, so it is not the
        // one that is evicted.
        var clock = new FakeClock();
        var table = new ClientRateTable(capacity: 1, refillPerSecond: 0, maxEntries: 3,
            idleExpiry: IdleExpiry, time: clock);
        table.TryTake("alice", "a");
        table.TryTake("alice", "b");
        table.TryTake("alice", "c");

        Assert.True(table.TryTake("bob", "a"));           // the id is taken over: a full budget again

        table.TryTake("bob", "d");                         // the table is full: the least recently used goes

        Assert.Equal(1, table.Evictions);
        Assert.True(table.TryTake("bob", "b"));           // "b" was evicted: it starts again with a full budget
        Assert.False(table.TryTake("bob", "a"));          // "a" survived: its budget was already spent
    }

    [Fact]
    public void TheTokenBucketTable_TouchesOnlyTheEntriesThatWereAlreadyThere()
    {
        // A new key is added at the tail of the order, so it is already the most recently used one: it
        // does not have to be touched. The key that was already there goes to the tail.
        var clock = new FakeClock();
        var table = new TokenBucketTable(capacity: 1, refillPerSecond: 0, maxEntries: 1000,
            idleExpiry: IdleExpiry, time: clock);

        table.TryTake("a");                          // a new key
        Assert.Equal(0, table.TouchMoves);
        table.TryTake("b");                          // another new key
        Assert.Equal(0, table.TouchMoves);
        table.TryTake("a");                          // "a" was already there: it goes to the tail
        Assert.Equal(1, table.TouchMoves);
    }

    [Fact]
    public void TheClientTable_TakesOverAClientId_AndItIsNotEvictedAtTheCap()
    {
        // The client id taken over by another user ends at the tail of the order, so it is the most
        // recently used one: it is not the client that is evicted when the table is full.
        //
        // The taken-over id is the first one that was inserted, so it is the one that would be
        // evicted if it did not end at the tail of the order.
        var clock = new FakeClock();
        var table = new ClientRateTable(capacity: 1, refillPerSecond: 0, maxEntries: 3,
            idleExpiry: IdleExpiry, time: clock);

        table.TryTake("alice", "x");                  // the first client: the one taken over later
        table.TryTake("alice", "a");
        table.TryTake("alice", "b");
        Assert.Equal(0, table.TouchMoves);           // a new client is added at the tail: it is not touched

        Assert.True(table.TryTake("bob", "x"));      // the id is taken over: a full budget again
        var moves = table.TouchMoves;                // the take over moved it to the tail of the order

        table.TryTake("bob", "c");                    // a new client: the table is full, so one is evicted
        Assert.Equal(1, table.Evictions);

        // "x" survived the eviction with the budget it spent on the take over, and "a" is the one
        // that was evicted: it starts again with a full budget. "x" is checked first: the check of a
        // client that is not there would evict another one.
        Assert.False(table.TryTake("bob", "x"));
        Assert.True(table.TryTake("alice", "a"));

        // The take over is the touch that moved the entry to the tail of the order; the check of "x"
        // touched it once more, because it was not the last one of the order any more.
        Assert.Equal(moves + 1, table.TouchMoves);
    }

    [Fact]
    public void TheClientTable_TakesOverAClientId_AndItSurvivesTheSweep()
    {
        // The client id taken over by another user ends at the tail of the order, so the sweep that
        // forgets the clients that were idle for a long time forgets the older ones and keeps it.
        //
        // The taken-over id is the first one that was inserted, so it is the one that would stop the
        // sweep if it did not end at the tail of the order.
        var clock = new FakeClock();
        var table = new ClientRateTable(capacity: 1, refillPerSecond: 0, maxEntries: 10,
            idleExpiry: IdleExpiry, time: clock);

        table.TryTake("alice", "x");                  // the first client: the one taken over later
        table.TryTake("alice", "a");
        Assert.Equal(0, table.TouchMoves);           // a new client is added at the tail: it is not touched

        clock.Advance(TimeSpan.FromMinutes(50));
        Assert.True(table.TryTake("bob", "x"));      // the id is taken over: a full budget again
        var moves = table.TouchMoves;                // the take over moved it to the tail of the order

        clock.Advance(TimeSpan.FromMinutes(20));
        table.TryTake("bob", "z");                    // a new client: the sweep runs here
        Assert.Equal(2, table.Count);                // "a" was forgotten, "x" was kept

        // "a" was forgotten by the sweep, so it starts again with a full budget, and "x" was kept
        // with the budget it spent on the take over.
        Assert.True(table.TryTake("alice", "a"));
        Assert.False(table.TryTake("bob", "x"));

        // The take over is the touch that moved the entry to the tail of the order; the check of "x"
        // touched it once more, because it was not the last one of the order any more.
        Assert.Equal(moves + 1, table.TouchMoves);
    }
}
