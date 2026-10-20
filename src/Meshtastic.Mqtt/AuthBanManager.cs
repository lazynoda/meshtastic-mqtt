using MQTTnet.Protocol;
using Serilog;

namespace Meshtastic.Mqtt;

/// <summary>
/// The failed logins per IP address and the bans they cause.
/// </summary>
/// <remarks>
/// <para>
/// Only a failed password check counts (see <see cref="CountsAsFailure"/>): a wrong password, an
/// unknown user or an unsupported authentication method. A full password queue ("server busy"), a
/// client-id conflict, a connection refused at the accept and a connection refused because the address
/// is already banned are not password failures and are not counted.
/// </para>
/// <para>
/// The failures of one address are counted in a window: <c>auth_fail_max_per_ip</c> failures within
/// <c>auth_fail_window_seconds</c> since the first failure of the window ban the address for
/// <c>auth_ban_seconds</c>. When the window has passed, the next failure starts a new one. A successful
/// login does <b>not</b> reset the counter: with the public <c>meshdev</c> credentials an attacker
/// could interleave a correct login between the guesses, and the honest nodes behind the same address
/// (CGNAT, VPN) would keep the guesses alive.
/// </para>
/// <para>
/// Both tables are bounded (<c>limits.max_tracked_entries</c>): the failures are evicted oldest first, the
/// bans evict the one that ends soonest. They also expire by themselves: an amortized sweep forgets the
/// failures whose window has passed and the bans that have ended, so a flood of failures from many
/// rotating addresses leaves nothing behind. The state is in memory only: a restart forgets every ban.
/// </para>
/// </remarks>
public sealed class AuthBanManager
{
    /// <summary>Drop reason of a connection refused because the address is banned.</summary>
    public const string BannedIpReason = "banned IP";

    /// <summary>Drop reason of an eviction: the table of failed logins is full.</summary>
    public const string FailureTableEvictionReason = "evicted: auth failure table full";

    /// <summary>Drop reason of an eviction: the table of bans is full.</summary>
    public const string BanTableEvictionReason = "evicted: auth ban table full";

    /// <summary>
    /// How many counted failures happen between two sweeps when the clock does not move. The sweep also
    /// runs when the clock has moved far enough (see <see cref="_sweepIntervalTicks"/>).
    /// </summary>
    internal const int SweepEveryInserts = 4096;

    /// <summary>The failed logins of one address inside the current window.</summary>
    sealed class Failure
    {
        public long WindowStart;
        public int Count;
    }

    /// <summary>A ban and the moment it ends.</summary>
    sealed class Ban
    {
        public long ExpiresAt;
    }

    readonly int _maxFailures;
    readonly int _banSeconds;
    readonly long _windowTicks;
    readonly long _banTicks;
    readonly long _sweepIntervalTicks;
    readonly IpCidr[] _exempt;
    readonly TimeProvider _time;
    readonly ILogger _log;
    readonly Action? _onBanEvicted;
    readonly BoundedMap<string, Failure> _failures;
    readonly Dictionary<string, Ban> _bans = new(StringComparer.Ordinal);
    /// <summary>
    /// The bans by the moment they end, so the one that ends soonest can be evicted first.
    /// <para>
    /// Its size is bounded: it never holds more entries than the ban table has bans (the cap of the
    /// ban table). It is rebuilt from the live bans when it grows past that, and the entries of the bans
    /// that have ended are dropped when they reach its head.
    /// </para>
    /// </summary>
    readonly PriorityQueue<string, long> _bansByExpiry = new();
    readonly object _lock = new();
    readonly int _maxTracked;
    long _banEvictions;
    long _lastSweepTicks;
    int _insertsSinceSweep;

    /// <param name="limits">The limits section (the four auth-ban keys).</param>
    /// <param name="time">The clock; the tests drive it with a fake one.</param>
    /// <param name="log">Where the ban is logged (one Warning per ban).</param>
    /// <param name="onFailureEvicted">Called when the failure table is full and evicts an entry.</param>
    /// <param name="onBanEvicted">Called when the ban table is full and evicts an entry.</param>
    public AuthBanManager(LimitsConfig limits, TimeProvider time, ILogger log,
        Action? onFailureEvicted = null, Action? onBanEvicted = null)
    {
        _time = time;
        _log = log;
        _maxFailures = limits.AuthFailMaxPerIp ?? LimitsConfig.DefaultAuthFailMaxPerIp;
        _banSeconds = limits.AuthBanSeconds ?? LimitsConfig.DefaultAuthBanSeconds;
        _windowTicks = ToTicks(limits.AuthFailWindowSeconds ?? LimitsConfig.DefaultAuthFailWindowSeconds, time);
        _banTicks = ToTicks(_banSeconds, time);
        // The tables are swept at least every quarter of the shortest life of an entry (the failure
        // window or the ban), and at least every SweepEveryInserts counted failures.
        _sweepIntervalTicks = Math.Max(1, Math.Min(_windowTicks, _banTicks) / 4);
        _exempt = ParseExempt(limits.AuthBanExempt ?? []);
        // The caps of the tables are configuration, not constants (see limits.max_tracked_entries).
        _maxTracked = limits.MaxTrackedEntries ?? LimitsConfig.DefaultMaxTrackedEntries;
        _failures = new BoundedMap<string, Failure>(_maxTracked, onFailureEvicted);
        _onBanEvicted = onBanEvicted;
        _lastSweepTicks = time.GetTimestamp();
    }

    /// <summary>
    /// The exempt ranges. A range that cannot be parsed is a typo the operator must see: it is an
    /// error, not a range that is silently dropped (the config validation reports it too).
    /// </summary>
    static IpCidr[] ParseExempt(List<string> ranges)
    {
        var exempt = new IpCidr[ranges.Count];
        for (var i = 0; i < ranges.Count; i++)
        {
            if (!IpCidr.TryParse(ranges[i], out var cidr, out var error))
                throw new ConfigException($"limits.auth_ban_exempt: {error}");
            exempt[i] = cidr!;
        }
        return exempt;
    }

    /// <summary>Whether the bans are on (the failure limit is not 0).</summary>
    public bool Enabled => _maxFailures > 0;

    /// <summary>The failed logins one address may make before it is banned (0 = off).</summary>
    public int MaxFailuresPerIp => _maxFailures;

    /// <summary>How long a banned address is refused, in seconds.</summary>
    public int BanSeconds => _banSeconds;

    /// <summary>The ranges whose failures are never counted and which are never banned.</summary>
    public int ExemptRanges => _exempt.Length;

    /// <summary>Whether the address is banned right now.</summary>
    public bool IsBanned(string ip)
    {
        lock (_lock)
        {
            var now = _time.GetTimestamp();
            // The tables are swept first: a broker without new failures must not keep the failures
            // whose window has passed and the bans that have ended.
            SweepIfDueLocked(now);
            return IsBannedLocked(ip, now);
        }
    }

    /// <summary>
    /// Counts one failed login of <paramref name="ip"/>. Bans the address when it reaches the limit.
    /// True when this failure started the ban.
    /// </summary>
    public bool RecordFailure(string ip)
    {
        if (_maxFailures <= 0)
            return false;   // the bans are off

        bool banned;
        int failures;
        lock (_lock)
        {
            var now = _time.GetTimestamp();
            // The tables are swept first: the entries that are over are forgotten, so a flood of
            // failures from many addresses does not fill them with entries that expired long ago.
            SweepIfDueLocked(now);
            if (IsExempt(ip))
                return false;
            if (IsBannedLocked(ip, now))
                return false;   // already banned: this is not a new failure

            _insertsSinceSweep++;
            if (!_failures.TryGet(ip, out var failure))
            {
                failure = new Failure { WindowStart = now, Count = 0 };
                // The table is bounded: the oldest address is evicted when it is full.
                _failures.Set(ip, failure);
            }
            else if (now - failure.WindowStart > _windowTicks)
            {
                // The window has passed: this failure starts a new one.
                failure.WindowStart = now;
                failure.Count = 0;
            }

            failure.Count++;
            if (failure.Count < _maxFailures)
                return false;

            // The limit is reached: the address is banned and its counter is cleared.
            _failures.Remove(ip);
            StartBanLocked(ip, now);
            banned = true;
            failures = failure.Count;
        }

        // The Warning is written outside the lock: the log must not be held up by the lock of the
        // tables, and a log call that blocks must not block the other logins.
        _log.Warning("Banned {RemoteIp} for {Seconds} s after {Failures} authentication failures",
            ip, _banSeconds, failures);
        return true;
    }

    /// <summary>
    /// Counts one failed login, but only if the reason code is a password failure. False when the reason
    /// is not counted, or when this failure did not start a ban.
    /// </summary>
    public bool RecordFailure(string ip, MqttConnectReasonCode reason)
    {
        if (!CountsAsFailure(reason))
            return false;
        return RecordFailure(ip);
    }

    /// <summary>
    /// Whether a refusal with this reason code is a failed password check, and so counts towards the ban
    /// of the address.
    /// </summary>
    public static bool CountsAsFailure(MqttConnectReasonCode reason) =>
        reason is MqttConnectReasonCode.BadUserNameOrPassword or MqttConnectReasonCode.BadAuthenticationMethod;

    /// <summary>The failed logins of the address inside the current window (for tests).</summary>
    public int FailuresFor(string ip)
    {
        lock (_lock)
        {
            if (!_failures.TryGet(ip, out var failure))
                return 0;
            if (_time.GetTimestamp() - failure.WindowStart > _windowTicks)
                return 0;   // the window has passed
            return failure.Count;
        }
    }

    /// <summary>Addresses with failed logins counted right now (for tests).</summary>
    public int TrackedFailures
    {
        get
        {
            lock (_lock)
                return _failures.Count;
        }
    }

    /// <summary>Addresses banned right now (for tests).</summary>
    public int TrackedBans
    {
        get
        {
            lock (_lock)
                return _bans.Count;
        }
    }

    /// <summary>Addresses evicted from the failure table to stay under the cap (for tests).</summary>
    public long FailureEvictions => _failures.Evictions;

    /// <summary>Bans evicted from the ban table to stay under the cap (for tests).</summary>
    public long BanEvictions => Interlocked.Read(ref _banEvictions);

    /// <summary>
    /// The entries of the queue that orders the bans by the moment they end (for tests). It never holds
    /// more entries than the ban table has bans.
    /// </summary>
    public int ExpiryQueueCount
    {
        get
        {
            lock (_lock)
                return _bansByExpiry.Count;
        }
    }

    bool IsBannedLocked(string ip, long now)
    {
        if (!_bans.TryGetValue(ip, out var ban))
            return false;
        if (now < ban.ExpiresAt)
            return true;
        // The ban is over: it is forgotten and the address may log in again.
        _bans.Remove(ip);
        _log.Debug("Ban for {RemoteIp} ended", ip);
        return false;
    }

    /// <summary>
    /// Forgets the entries that are over, when it is time to: the failures whose window has passed and
    /// the bans that have ended. The sweep is amortized: it runs when the clock has moved far enough or
    /// after enough counted failures, never on every one of them.
    /// </summary>
    void SweepIfDueLocked(long now)
    {
        if (_insertsSinceSweep < SweepEveryInserts && now - _lastSweepTicks < _sweepIntervalTicks)
            return;
        _lastSweepTicks = now;
        _insertsSinceSweep = 0;

        // The failures whose window has passed are forgotten: an address that fails again starts a new one.
        foreach (var ip in _failures.Keys())
        {
            if (_failures.TryGet(ip, out var failure) && now - failure.WindowStart > _windowTicks)
                _failures.Remove(ip);
        }

        // The bans that have ended are forgotten, and logged like the lazy path does. The queue is
        // ordered by the moment the bans end, so its head says whether any of them has ended.
        if (_bansByExpiry.TryPeek(out _, out var nextExpiry) && nextExpiry <= now)
        {
            List<string>? ended = null;
            foreach (var (ip, ban) in _bans)
            {
                if (now >= ban.ExpiresAt)
                    (ended ??= []).Add(ip);
            }
            if (ended is not null)
            {
                foreach (var ip in ended)
                {
                    _bans.Remove(ip);
                    _log.Debug("Ban for {RemoteIp} ended", ip);
                }
            }

            // The entries of the bans that have ended are the oldest ones (the queue is ordered by the
            // moment they end), so they are dropped from its head.
            while (_bansByExpiry.TryPeek(out _, out var expiry) && expiry <= now)
                _bansByExpiry.Dequeue();
        }
    }

    void StartBanLocked(string ip, long now)
    {
        var expiresAt = now + _banTicks;
        if (_bans.Count >= _maxTracked)
        {
            // The table is full: the ban that ends soonest is evicted (an expired one is simply dropped).
            while (_bans.Count >= _maxTracked && _bansByExpiry.TryDequeue(out var victim, out var expiry))
            {
                if (!_bans.TryGetValue(victim, out var ban) || ban.ExpiresAt != expiry)
                    continue;   // a stale entry: the ban was replaced or has already ended
                _bans.Remove(victim);
                if (expiry > now)
                {
                    Interlocked.Increment(ref _banEvictions);
                    _onBanEvicted?.Invoke();
                }
            }
        }

        // The queue is bounded: it never holds more entries than the ban table has bans. The entries of
        // the bans that have ended are dropped when it grows past the cap.
        if (_bansByExpiry.Count >= _maxTracked)
            RebuildExpiryQueueLocked();

        _bans[ip] = new Ban { ExpiresAt = expiresAt };
        _bansByExpiry.Enqueue(ip, expiresAt);
    }

    /// <summary>Rebuilds the queue of the bans from the live ones, dropping the stale entries.</summary>
    void RebuildExpiryQueueLocked()
    {
        _bansByExpiry.Clear();
        foreach (var (ip, ban) in _bans)
            _bansByExpiry.Enqueue(ip, ban.ExpiresAt);
    }

    bool IsExempt(string ip)
    {
        if (_exempt.Length == 0)
            return false;
        foreach (var range in _exempt)
        {
            if (range.Matches(ip))
                return true;
        }
        return false;
    }

    /// <summary>Seconds as the ticks of the clock (the frequency is the number of ticks per second).</summary>
    static long ToTicks(int seconds, TimeProvider time) => (long)seconds * time.TimestampFrequency;
}
