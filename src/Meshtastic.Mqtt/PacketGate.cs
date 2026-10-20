namespace Meshtastic.Mqtt;

/// <summary>
/// The cross-gateway dedupe and the per-node packet rate.
/// </summary>
/// <remarks>
/// <para>
/// The dedupe is keyed by (from, packet id): the pair a real node uses for a packet, so every copy of the
/// same packet sent by different gateways is one packet of the mesh. One copy per gateway is kept (the
/// dashboards use each gateway's copy to show who heard a packet and at what SNR), so a copy from a
/// gateway that already sent this packet is dropped, and a copy from a new gateway is dropped once
/// <c>dedupe_max_gateways_per_packet</c> gateways have sent it. The gateways of a packet are kept as their
/// node numbers, not as strings: the gateway binding already guarantees the format (<c>!</c> and 8
/// lowercase hex digits), so the id is parsed once and the table holds 4 bytes per gateway.
/// </para>
/// <para>
/// The per-node rate (<c>packet_rate_per_from_per_minute</c>) is charged once per packet, on its first
/// copy, and never for the later copies of the same packet. The verdict is sticky: a packet whose first
/// copy was refused is refused for every later copy too, so a node that is over its budget does not get
/// a second chance by waiting for another gateway to relay it.
/// </para>
/// <para>
/// Map reports (packet id 0) are not deduplicated: they carry no id, and each one is charged as one
/// packet of its node.
/// </para>
/// </remarks>
public sealed class PacketGate
{
    /// <summary>What the gate decided about a copy.</summary>
    public enum Verdict
    {
        /// <summary>The copy may be forwarded.</summary>
        Accept,

        /// <summary>This gateway already sent this packet.</summary>
        DuplicateFromSameGateway,

        /// <summary>Too many gateways have already sent this packet.</summary>
        TooManyGateways,

        /// <summary>The node is over its packet budget.</summary>
        RateExceeded,
    }

    sealed class Entry
    {
        public readonly HashSet<uint> Gateways = new();
        public long FirstSeen;
        public bool RateRefused;
    }

    /// <summary>Drop reason of an eviction: the dedupe table is full.</summary>
    public const string DedupeEvictionReason = "evicted: dedupe table full";

    /// <summary>Drop reason of an eviction: the per-node rate table is full.</summary>
    public const string RateEvictionReason = "evicted: per-node rate table full";

    readonly bool _dedupeOn;
    readonly int _maxGateways;
    readonly TimeSpan _window;
    readonly TimeProvider _time;
    readonly BoundedMap<(uint From, uint Id), Entry> _entries;
    readonly TokenBucketTable? _rate;
    readonly object _lock = new();
    long _lastSweepTicks;

    public PacketGate(LimitsConfig limits, TimeProvider time, Action? onDedupeEvicted = null,
        Action? onRateEvicted = null)
    {
        _time = time;
        var window = limits.DedupeWindowSeconds ?? LimitsConfig.DefaultDedupeWindowSeconds;
        _dedupeOn = window > 0;
        _window = TimeSpan.FromSeconds(window);
        _maxGateways = limits.DedupeMaxGatewaysPerPacket ?? LimitsConfig.DefaultDedupeMaxGatewaysPerPacket;
        _entries = new BoundedMap<(uint, uint), Entry>(limits.DedupeMaxEntries ?? LimitsConfig.DefaultDedupeMaxEntries,
            onDedupeEvicted);
        _lastSweepTicks = time.GetTimestamp();

        var rate = limits.PacketRatePerFromPerMinute ?? LimitsConfig.DefaultPacketRatePerFromPerMinute;
        var burst = limits.PacketBurstPerFrom ?? LimitsConfig.DefaultPacketBurstPerFrom;
        if (rate > 0 && burst > 0)
        {
            // The caps of the tables are configuration, not constants (see limits.max_tracked_entries).
            var maxTracked = limits.MaxTrackedEntries ?? LimitsConfig.DefaultMaxTrackedEntries;
            var idleExpiry = TimeSpan.FromSeconds(limits.RateIdleExpirySeconds ?? LimitsConfig.DefaultRateIdleExpirySeconds);
            _rate = new TokenBucketTable(burst, rate / 60.0, maxTracked, idleExpiry, time, onRateEvicted);
        }
    }

    /// <summary>Whether the cross-gateway dedupe is on.</summary>
    public bool DedupeOn => _dedupeOn;

    /// <summary>Whether the per-node packet rate is on.</summary>
    public bool RateOn => _rate is not null;

    /// <summary>Packets currently remembered for the dedupe (for tests).</summary>
    public int DedupeCount
    {
        get
        {
            lock (_lock)
                return _entries.Count;
        }
    }

    /// <summary>Dedupe entries evicted to stay under the cap (for tests).</summary>
    public long DedupeEvictions => _entries.Evictions;

    /// <summary>Nodes currently tracked by the rate table (for tests).</summary>
    public int RateCount => _rate?.Count ?? 0;

    /// <summary>Nodes evicted from the rate table to stay under the cap (for tests).</summary>
    public long RateEvictions => _rate?.Evictions ?? 0;

    /// <summary>The entries the dedupe sweeps have visited so far (for tests).</summary>
    internal long SweepVisits => _entries.Visits;

    /// <summary>
    /// The gateways that sent this packet, as node numbers (for tests). The set holds the parsed
    /// numbers, not the strings of the gateway ids.
    /// </summary>
    internal uint[] GatewaysOf(uint from, uint id)
    {
        lock (_lock)
            return _entries.TryGet((from, id), out var entry) ? [.. entry.Gateways.OrderBy(g => g)] : [];
    }

    /// <summary>
    /// Decides about one copy of a channel packet: the dedupe first, then the node's packet budget.
    /// </summary>
    /// <param name="from">The node that sent the packet.</param>
    /// <param name="id">The packet id.</param>
    /// <param name="gateway">The gateway that sent this copy, as its node number.</param>
    public Verdict EvaluatePacket(uint from, uint id, uint gateway)
    {
        if (!_dedupeOn)
        {
            // Without the dedupe there is no way to tell the copies of one packet apart: every copy is
            // charged to the node's budget on its own.
            return _rate is not null && !_rate.TryTake(NodeKey(from)) ? Verdict.RateExceeded : Verdict.Accept;
        }

        lock (_lock)
        {
            var now = _time.GetTimestamp();
            var key = (from, id);
            if (_entries.TryGet(key, out var entry))
            {
                if (IsExpired(entry, now))
                {
                    _entries.Remove(key);
                }
                else
                {
                    if (entry.Gateways.Contains(gateway))
                        return Verdict.DuplicateFromSameGateway;
                    if (entry.Gateways.Count >= _maxGateways)
                        return Verdict.TooManyGateways;
                    entry.Gateways.Add(gateway);
                    // The packet was already charged (or already refused): the verdict is sticky.
                    return entry.RateRefused ? Verdict.RateExceeded : Verdict.Accept;
                }
            }

            // The first copy of this packet: it is charged to the node's budget, once.
            var allowed = _rate is null || _rate.TryTake(NodeKey(from));
            var fresh = new Entry { FirstSeen = now, RateRefused = !allowed };
            fresh.Gateways.Add(gateway);
            _entries.Set(key, fresh);
            Sweep(now);
            return allowed ? Verdict.Accept : Verdict.RateExceeded;
        }
    }

    /// <summary>
    /// Decides about one map report: no dedupe (a map report carries no id), but it is charged as one
    /// packet of its node.
    /// </summary>
    public Verdict EvaluateMapReport(uint from) =>
        _rate is not null && !_rate.TryTake(NodeKey(from)) ? Verdict.RateExceeded : Verdict.Accept;

    bool IsExpired(Entry entry, long now) => now - entry.FirstSeen >= (long)_window.TotalSeconds * _time.TimestampFrequency;

    /// <summary>
    /// Removes the entries that are past the window, so a quiet broker forgets them. The entries expire
    /// from the oldest end of the order and the sweep stops at the first entry that has not expired: a
    /// sweep costs what it expires, not what the table holds.
    /// </summary>
    void Sweep(long now)
    {
        var expiry = (long)_window.TotalSeconds * _time.TimestampFrequency;
        if (expiry <= 0 || now - _lastSweepTicks < expiry / 4)
            return;
        _lastSweepTicks = now;
        _entries.RemoveOldestWhile((_, entry) => IsExpired(entry, now));
    }

    /// <summary>The key of a node in the rate table.</summary>
    static string NodeKey(uint from) => from.ToString("x8", System.Globalization.CultureInfo.InvariantCulture);
}
