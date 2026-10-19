using Meshtastic.Mqtt;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The per-IP limits: how many connections one address may hold at once, and how often it may open one.
/// The clock is a fake one, so the refill is exact and no test sleeps.
/// </summary>
public sealed class ConnectionLimitTests
{
    static BrokerConfig Config(string limits) => ConfigLoader.Parse($"""
        users:
          - username: meshdev
            password_hash: "{AuthTests.MeshdevHash}"
        {limits}
        """);

    static LimitsConfig Limits(string limits) => Config(limits).Limits!;

    [Fact]
    public void ConnectionCap_RefusesOverTheCap_AndGivesTheSlotBack()
    {
        var guard = new ConnectionGuard(Limits("limits:\n  max_connections_per_ip: 2"), new FakeClock());
        Assert.True(guard.TryAcquire("1.2.3.4", out var reason));
        Assert.Null(reason);
        Assert.True(guard.TryAcquire("1.2.3.4", out reason));
        Assert.Null(reason);

        Assert.False(guard.TryAcquire("1.2.3.4", out reason));
        Assert.Equal(ConnectionGuard.ConnectionCapReason, reason);
        Assert.Equal(2, guard.ConnectionsFor("1.2.3.4"));

        // Another address has its own budget.
        Assert.True(guard.TryAcquire("5.6.7.8", out reason));

        // The slot comes back when the connection closes.
        guard.Release("1.2.3.4");
        Assert.Equal(1, guard.ConnectionsFor("1.2.3.4"));
        Assert.True(guard.TryAcquire("1.2.3.4", out reason));
        Assert.Equal(2, guard.ConnectionsFor("1.2.3.4"));

        // Releasing more than was taken never makes the counter negative.
        guard.Release("1.2.3.4");
        guard.Release("1.2.3.4");
        guard.Release("1.2.3.4");
        Assert.Equal(0, guard.ConnectionsFor("1.2.3.4"));
    }

    [Fact]
    public void ConnectionCap_IsOffWhenItIsZero()
    {
        var guard = new ConnectionGuard(Limits("limits:\n  max_connections_per_ip: 0\n  connect_rate_per_ip_per_minute: 0"), new FakeClock());
        for (var i = 0; i < 100; i++)
            Assert.True(guard.TryAcquire("1.2.3.4", out _));
        Assert.Equal(0, guard.ConnectionsFor("1.2.3.4"));
    }

    [Fact]
    public void ConnectRate_AllowsTheBurst_RefillsAndRefuses()
    {
        var clock = new FakeClock();
        var guard = new ConnectionGuard(Limits("limits:\n  connect_rate_per_ip_per_minute: 60\n  connect_burst_per_ip: 3"), clock);
        for (var i = 0; i < 3; i++)
            Assert.True(guard.TryAcquire("1.2.3.4", out _));

        Assert.False(guard.TryAcquire("1.2.3.4", out var reason));
        Assert.Equal(ConnectionGuard.ConnectRateReason, reason);

        // 60 per minute is one per second.
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.True(guard.TryAcquire("1.2.3.4", out _));
        Assert.False(guard.TryAcquire("1.2.3.4", out _));

        // Another address has its own bucket.
        Assert.True(guard.TryAcquire("5.6.7.8", out _));
    }

    [Fact]
    public void ConnectRate_IsOffWhenTheRateOrTheBurstIsZero()
    {
        var clock = new FakeClock();
        var noRate = new ConnectionGuard(Limits("limits:\n  max_connections_per_ip: 0\n  connect_rate_per_ip_per_minute: 0"), clock);
        var noBurst = new ConnectionGuard(Limits("limits:\n  max_connections_per_ip: 0\n  connect_burst_per_ip: 0"), clock);
        for (var i = 0; i < 100; i++)
        {
            Assert.True(noRate.TryAcquire("1.2.3.4", out _));
            Assert.True(noBurst.TryAcquire("1.2.3.4", out _));
        }
    }

    [Fact]
    public void TheConnectionCapIsCheckedBeforeTheRate()
    {
        // An address at its cap is refused for the cap, and the refusal does not burn a token of its rate
        // bucket: with the slot free again, the same address is refused for the rate instead.
        var clock = new FakeClock();
        var guard = new ConnectionGuard(Limits(
            "limits:\n  max_connections_per_ip: 1\n  connect_rate_per_ip_per_minute: 60\n  connect_burst_per_ip: 1"), clock);
        Assert.True(guard.TryAcquire("1.2.3.4", out _));

        Assert.False(guard.TryAcquire("1.2.3.4", out var reason));
        Assert.Equal(ConnectionGuard.ConnectionCapReason, reason);

        // The slot is free again, and now it is the rate that refuses (the refused attempt took no token).
        guard.Release("1.2.3.4");
        Assert.False(guard.TryAcquire("1.2.3.4", out reason));
        Assert.Equal(ConnectionGuard.ConnectRateReason, reason);
    }
}
