using Meshtastic.Mqtt;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The bounded map the rate tables are built on: its order is the order of the last use, and an entry
/// that is already the last one of the order does not have to be moved.
/// </summary>
public sealed class BoundedMapTests
{
    [Fact]
    public void TouchingTheLastEntry_LeavesTheOrderUnchanged()
    {
        var map = NewMap();
        var moves = map.TouchMoves;

        map.Touch("c");                        // "c" is already the last one of the order
        Assert.Equal(moves, map.TouchMoves);   // so the order does not change
        Assert.Equal(new[] { "a", "b", "c" }, Order(map));

        // An entry that is not the last one does go to the tail of the order.
        map = NewMap();
        map.Touch("a");
        Assert.Equal(moves + 1, map.TouchMoves);
        Assert.Equal(new[] { "b", "c", "a" }, Order(map));
    }

    /// <summary>A map with three entries, in the order they were added.</summary>
    static BoundedMap<string, int> NewMap()
    {
        var map = new BoundedMap<string, int>(10);
        map.Set("a", 1);
        map.Set("b", 2);
        map.Set("c", 3);
        return map;
    }

    /// <summary>The keys of the map, oldest first (the sweep walks the order from its head).</summary>
    static List<string> Order(BoundedMap<string, int> map)
    {
        var keys = new List<string>();
        map.RemoveOldestWhile((key, _) =>
        {
            keys.Add(key);
            return true;
        });
        return keys;
    }
}
