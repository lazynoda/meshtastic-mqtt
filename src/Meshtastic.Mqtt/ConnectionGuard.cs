namespace Meshtastic.Mqtt;

/// <summary>
/// The per-IP limits applied when a TCP connection is accepted, before a single MQTT byte is read.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><c>max_connections_per_ip</c> caps how many connections one address may hold at once. The socket
/// is closed at once when the cap is reached, and the counter is given back on every close path.</item>
/// <item><c>connect_rate_per_ip_per_minute</c> (with the burst <c>connect_burst_per_ip</c>) is a token
/// bucket: it bounds how often one address may open a connection, and with it a flood of CONNECTs or
/// password guesses. The token is taken when the connection is accepted, so an address that only opens
/// sockets and never speaks MQTT is bounded too.</item>
/// </list>
/// Both are off when their value is 0. Everything happens under one lock, so the counters cannot leak
/// between concurrent accepts.
/// </remarks>
public sealed class ConnectionGuard
{
    /// <summary>Drop reason of a connection refused because the address is at its connection cap.</summary>
    public const string ConnectionCapReason = "too many connections from one IP";

    /// <summary>Drop reason of a connection refused because the address is over its connect rate.</summary>
    public const string ConnectRateReason = "too many connection attempts from one IP";

    /// <summary>Drop reason of an eviction: the table of tracked addresses is full.</summary>
    public const string ConnectionTableEvictionReason = "evicted: per-IP connection table full";

    /// <summary>Drop reason of an eviction: the table of per-address connect rates is full.</summary>
    public const string RateTableEvictionReason = "evicted: per-IP rate table full";

    readonly int _maxPerIp;
    readonly TokenBucketTable? _connectRate;
    readonly BoundedMap<string, int> _connections;
    readonly object _lock = new();

    public ConnectionGuard(LimitsConfig limits, TimeProvider time, Action? onConnectionEvicted = null,
        Action? onRateEvicted = null)
    {
        _maxPerIp = limits.MaxConnectionsPerIp ?? LimitsConfig.DefaultMaxConnectionsPerIp;
        // The caps of the tables are configuration, not constants (see limits.max_tracked_entries).
        var maxTracked = limits.MaxTrackedEntries ?? LimitsConfig.DefaultMaxTrackedEntries;
        var idleExpiry = TimeSpan.FromSeconds(limits.RateIdleExpirySeconds ?? LimitsConfig.DefaultRateIdleExpirySeconds);
        _connections = new BoundedMap<string, int>(maxTracked, onConnectionEvicted);
        var rate = limits.ConnectRatePerIpPerMinute ?? LimitsConfig.DefaultConnectRatePerIpPerMinute;
        var burst = limits.ConnectBurstPerIp ?? LimitsConfig.DefaultConnectBurstPerIp;
        if (rate > 0 && burst > 0)
            _connectRate = new TokenBucketTable(burst, rate / 60.0, maxTracked, idleExpiry, time, onRateEvicted);
    }

    /// <summary>The connection cap per address (0 = off).</summary>
    public int MaxConnectionsPerIp => _maxPerIp;

    /// <summary>Whether the connect rate is on.</summary>
    public bool ConnectRateOn => _connectRate is not null;

    /// <summary>
    /// Takes a slot for <paramref name="ip"/>. False (with a reason) when the connection must be refused.
    /// </summary>
    public bool TryAcquire(string ip, out string? reason)
    {
        lock (_lock)
        {
            _connections.TryGet(ip, out var count);
            if (_maxPerIp > 0 && count >= _maxPerIp)
            {
                reason = ConnectionCapReason;
                return false;
            }
            if (_connectRate is not null && !_connectRate.TryTake(ip))
            {
                reason = ConnectRateReason;
                return false;
            }
            if (_maxPerIp > 0)
                _connections.Set(ip, count + 1);
            reason = null;
            return true;
        }
    }

    /// <summary>Gives the slot back. Called on every close path, so the counter never leaks.</summary>
    public void Release(string ip)
    {
        lock (_lock)
        {
            if (!_connections.TryGet(ip, out var count))
                return;
            if (count <= 1)
                _connections.Remove(ip);
            else
                _connections.Set(ip, count - 1);
        }
    }

    /// <summary>Connections currently open for <paramref name="ip"/> (for tests).</summary>
    public int ConnectionsFor(string ip)
    {
        lock (_lock)
            return _connections.TryGet(ip, out var count) ? count : 0;
    }

    /// <summary>Addresses currently tracked (for tests).</summary>
    public int TrackedIps
    {
        get
        {
            lock (_lock)
                return _connections.Count;
        }
    }

    /// <summary>Addresses evicted from the tables to stay under the cap (for tests).</summary>
    public long Evictions => _connections.Evictions;
}
