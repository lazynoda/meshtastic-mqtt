namespace Meshtastic.Mqtt;

/// <summary>
/// A token bucket: it holds at most <c>capacity</c> tokens and refills them at a fixed rate.
/// </summary>
/// <remarks>
/// The clock is a <see cref="TimeProvider"/>, so the tests can drive it with a fake clock and never sleep.
/// The refill is computed from the monotonic timestamp, so a wall-clock step (NTP) neither extends nor cuts it.
/// </remarks>
public struct TokenBucket
{
    double _tokens;
    long _lastTicks;

    public TokenBucket(double capacity, long now)
    {
        _tokens = capacity;
        _lastTicks = now;
    }

    /// <summary>Tokens currently available (for tests and diagnostics).</summary>
    public double Tokens => _tokens;

    /// <summary>
    /// Refills the bucket for the time passed and takes one token. False when the bucket is empty.
    /// </summary>
    /// <param name="now">Current monotonic timestamp.</param>
    /// <param name="frequency">Ticks per second of the clock.</param>
    /// <param name="refillPerSecond">Tokens added per second.</param>
    /// <param name="capacity">Maximum number of tokens.</param>
    public bool TryTake(long now, long frequency, double refillPerSecond, double capacity)
    {
        var elapsed = (now - _lastTicks) / (double)frequency;
        if (elapsed > 0)
        {
            _tokens = Math.Min(capacity, _tokens + elapsed * refillPerSecond);
            _lastTicks = now;
        }
        if (_tokens < 1)
            return false;
        _tokens -= 1;
        return true;
    }
}

/// <summary>
/// A map with a hard entry cap: when it is full, the oldest entry is evicted. Evictions are counted and
/// reported to <see cref="_onEvicted"/>, so the operator sees them in the periodic summary.
/// </summary>
/// <remarks>
/// Used for every table the broker keeps about clients, so a flood of forged keys cannot grow the memory
/// without bound. The order is the insertion order (first seen first evicted); an entry that is replaced
/// keeps its place.
/// </remarks>
internal sealed class BoundedMap<TKey, TValue> where TKey : notnull
{
    sealed class Node
    {
        public TKey Key = default!;
        public TValue Value = default!;
        public LinkedListNode<Node>? Order;
    }

    readonly Dictionary<TKey, Node> _map = new();
    readonly LinkedList<Node> _order = new();
    readonly int _maxEntries;
    readonly Action? _onEvicted;
    long _evictions;

    public BoundedMap(int maxEntries, Action? onEvicted = null)
    {
        _maxEntries = Math.Max(1, maxEntries);
        _onEvicted = onEvicted;
    }

    public int Count => _map.Count;

    /// <summary>Entries evicted to stay under the cap.</summary>
    public long Evictions => Interlocked.Read(ref _evictions);

    public bool TryGet(TKey key, out TValue value)
    {
        if (_map.TryGetValue(key, out var node))
        {
            value = node.Value;
            return true;
        }
        value = default!;
        return false;
    }

    /// <summary>Adds or replaces an entry, evicting the oldest one when the map is full.</summary>
    public void Set(TKey key, TValue value)
    {
        if (_map.TryGetValue(key, out var existing))
        {
            existing.Value = value;
            return;
        }
        while (_map.Count >= _maxEntries)
        {
            var oldest = _order.First;
            if (oldest is null)
                break;
            _order.RemoveFirst();
            _map.Remove(oldest.Value.Key);
            Interlocked.Increment(ref _evictions);
            // The eviction is counted, so an operator sees that a cap was hit.
            _onEvicted?.Invoke();
        }
        var node = new Node { Key = key, Value = value };
        node.Order = _order.AddLast(node);
        _map[key] = node;
    }

    public bool Remove(TKey key)
    {
        if (!_map.TryGetValue(key, out var node))
            return false;
        _map.Remove(key);
        if (node.Order is not null)
            _order.Remove(node.Order);
        return true;
    }

    /// <summary>A snapshot of the keys (for sweeps); the caller must not hold the table's lock.</summary>
    public List<TKey> Keys()
    {
        var keys = new List<TKey>(_map.Count);
        foreach (var node in _map.Values)
            keys.Add(node.Key);
        return keys;
    }
}

/// <summary>
/// A bounded table of token buckets, one per key.
/// </summary>
/// <remarks>
/// Idle buckets are swept away and the table never grows past its cap, so a flood of forged keys (a client
/// id, a node number, an IP) cannot grow the memory without bound. Every update happens under one lock, so
/// MQTTnet's concurrent handlers cannot take a token twice or lose one.
/// </remarks>
public sealed class TokenBucketTable
{
    sealed class Entry
    {
        public TokenBucket Bucket;
        public long LastUsed;
    }

    readonly double _capacity;
    readonly double _refillPerSecond;
    readonly TimeProvider _time;
    readonly TimeSpan _idleExpiry;
    readonly BoundedMap<string, Entry> _buckets;
    readonly object _lock = new();
    long _lastSweepTicks;

    /// <param name="capacity">Burst: the number of tokens a fresh key starts with.</param>
    /// <param name="refillPerSecond">Tokens added per second.</param>
    /// <param name="maxEntries">Hard cap on the number of keys tracked.</param>
    /// <param name="idleExpiry">How long a key survives without being used.</param>
    /// <param name="time">The monotonic clock.</param>
    /// <param name="onEvicted">Called on every eviction, so the operator sees that the cap was hit.</param>
    public TokenBucketTable(double capacity, double refillPerSecond, int maxEntries, TimeSpan idleExpiry,
        TimeProvider time, Action? onEvicted = null)
    {
        _capacity = capacity;
        _refillPerSecond = refillPerSecond;
        _time = time;
        _idleExpiry = idleExpiry;
        _buckets = new BoundedMap<string, Entry>(maxEntries, onEvicted);
        _lastSweepTicks = time.GetTimestamp();
    }

    /// <summary>Number of keys currently tracked.</summary>
    public int Count
    {
        get
        {
            lock (_lock)
                return _buckets.Count;
        }
    }

    /// <summary>Entries evicted to stay under the cap.</summary>
    public long Evictions => _buckets.Evictions;

    /// <summary>Takes one token for <paramref name="key"/>; false when the bucket is empty.</summary>
    public bool TryTake(string key)
    {
        lock (_lock)
        {
            var now = _time.GetTimestamp();
            // The idle buckets are swept first: a key that was forgotten starts with a full bucket again.
            Sweep(now);
            if (!_buckets.TryGet(key, out var entry))
            {
                entry = new Entry { Bucket = new TokenBucket(_capacity, now), LastUsed = now };
                _buckets.Set(key, entry);
            }
            else
            {
                entry.LastUsed = now;
            }
            return entry.Bucket.TryTake(now, _time.TimestampFrequency, _refillPerSecond, _capacity);
        }
    }

    /// <summary>Forgets a key (the session that owned it is gone).</summary>
    public void Remove(string key)
    {
        lock (_lock)
            _buckets.Remove(key);
    }

    void Sweep(long now)
    {
        var expiry = (long)(_idleExpiry.TotalSeconds * _time.TimestampFrequency);
        if (expiry <= 0)
            return;
        if (now - _lastSweepTicks < expiry / 4)
            return;
        _lastSweepTicks = now;
        foreach (var key in _buckets.Keys())
        {
            if (_buckets.TryGet(key, out var entry) && now - entry.LastUsed > expiry)
                _buckets.Remove(key);
        }
    }
}

/// <summary>
/// A token bucket per client, keyed by the user that owns the session and the client id.
/// </summary>
/// <remarks>
/// A client id taken over by another user starts with a fresh budget (the key is the pair, not the id
/// alone). The state dies with the session (see <see cref="Remove"/>) and with the idle expiry.
/// </remarks>
public sealed class ClientRateTable
{
    /// <summary>Drop reason of an eviction: the per-client table is full.</summary>
    public const string EvictionReason = "evicted: per-client rate table full";

    sealed class Entry
    {
        public string Owner = string.Empty;
        public TokenBucket Bucket;
        public long LastUsed;
    }

    readonly double _capacity;
    readonly double _refillPerSecond;
    readonly TimeProvider _time;
    readonly TimeSpan _idleExpiry;
    readonly BoundedMap<string, Entry> _entries;
    readonly object _lock = new();
    long _lastSweepTicks;

    public ClientRateTable(double capacity, double refillPerSecond, int maxEntries, TimeSpan idleExpiry,
        TimeProvider time, Action? onEvicted = null)
    {
        _capacity = capacity;
        _refillPerSecond = refillPerSecond;
        _time = time;
        _idleExpiry = idleExpiry;
        _entries = new BoundedMap<string, Entry>(maxEntries, onEvicted);
        _lastSweepTicks = time.GetTimestamp();
    }

    /// <summary>Number of clients currently tracked.</summary>
    public int Count
    {
        get
        {
            lock (_lock)
                return _entries.Count;
        }
    }

    /// <summary>Entries evicted to stay under the cap.</summary>
    public long Evictions => _entries.Evictions;

    /// <summary>Takes one token for the (owner, client id) pair; false when the bucket is empty.</summary>
    public bool TryTake(string owner, string clientId)
    {
        lock (_lock)
        {
            var now = _time.GetTimestamp();
            // The idle clients are swept first: a client that was forgotten starts with a full budget again.
            Sweep(now);
            if (!_entries.TryGet(clientId, out var entry) || entry.Owner != owner)
            {
                // A new client (or the same id taken over by another user) starts with a full bucket.
                entry = new Entry { Owner = owner, Bucket = new TokenBucket(_capacity, now), LastUsed = now };
                _entries.Set(clientId, entry);
            }
            else
            {
                entry.LastUsed = now;
            }
            return entry.Bucket.TryTake(now, _time.TimestampFrequency, _refillPerSecond, _capacity);
        }
    }

    /// <summary>Forgets a client (its session was deleted).</summary>
    public void Remove(string clientId)
    {
        lock (_lock)
            _entries.Remove(clientId);
    }

    void Sweep(long now)
    {
        var expiry = (long)(_idleExpiry.TotalSeconds * _time.TimestampFrequency);
        if (expiry <= 0)
            return;
        if (now - _lastSweepTicks < expiry / 4)
            return;
        _lastSweepTicks = now;
        foreach (var key in _entries.Keys())
        {
            if (_entries.TryGet(key, out var entry) && now - entry.LastUsed > expiry)
                _entries.Remove(key);
        }
    }
}
