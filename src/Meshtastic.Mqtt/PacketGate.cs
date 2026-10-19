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
/// <c>dedupe_max_gateways_per_packet</c> gateways have sent it.
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
        public readonly HashSet<string> Gateways = new(StringComparer.Ordinal);
        public long FirstSeen;
        public bool RateRefused;
    }

    /// <summary>How many node numbers the rate table may track at once.</summary>
    internal const int MaxTrackedNodes = 100_000;

    /// <summary>How long a node survives in the rate table without sending a packet.</summary>
    internal static readonly TimeSpan IdleExpiry = TimeSpan.FromMinutes(10);

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

    public PacketGate(LimitsConfig limits, TimeProvider time, int maxTrackedNodes = MaxTrackedNodes,
        Action? onDedupeEvicted = null, Action? onRateEvicted = null)
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
            _rate = new TokenBucketTable(burst, rate / 60.0, maxTrackedNodes, IdleExpiry, time, onRateEvicted);
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

    /// <summary>
    /// Decides about one copy of a channel packet: the dedupe first, then the node's packet budget.
    /// </summary>
    /// <param name="from">The node that sent the packet.</param>
    /// <param name="id">The packet id.</param>
    /// <param name="gateway">The gateway that sent this copy (the envelope's gateway id).</param>
    public Verdict EvaluatePacket(uint from, uint id, string gateway)
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

    /// <summary>Removes the entries that are past the window, so a quiet broker forgets them.</summary>
    void Sweep(long now)
    {
        var expiry = (long)_window.TotalSeconds * _time.TimestampFrequency;
        if (expiry <= 0 || now - _lastSweepTicks < expiry / 4)
            return;
        _lastSweepTicks = now;
        foreach (var key in _entries.Keys())
        {
            if (_entries.TryGet(key, out var entry) && IsExpired(entry, now))
                _entries.Remove(key);
        }
    }

    /// <summary>The key of a node in the rate table.</summary>
    static string NodeKey(uint from) => from.ToString("x8", System.Globalization.CultureInfo.InvariantCulture);
}
