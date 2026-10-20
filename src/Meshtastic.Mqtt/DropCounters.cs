using System.Collections.Concurrent;
using Serilog;

namespace Meshtastic.Mqtt;

/// <summary>
/// Counts what the broker refused (the dropped publishes, the refused connections) and what it evicted,
/// per reason, and logs the totals at Information on a fixed period, only when something was counted.
/// Per-packet drop lines are Debug, so a public publisher cannot flood the log.
/// </summary>
public sealed class DropCounters : IAsyncDisposable
{
    public static readonly TimeSpan DefaultPeriod = TimeSpan.FromSeconds(60);

    // Reasons come from PacketInspector and the publish ACL, a small fixed set once numbers are collapsed, so the
    // dictionary stays small.
    readonly ConcurrentDictionary<string, long> _counts = new(StringComparer.Ordinal);
    readonly ILogger _log;
    readonly TimeSpan _period;
    readonly CancellationTokenSource _stop = new();
    readonly Task? _loop;

    public DropCounters(ILogger log, TimeSpan? period = null, bool start = true)
    {
        _log = log;
        _period = period ?? DefaultPeriod;
        if (start)
            _loop = RunAsync(_period, _stop.Token);
    }

    public void Increment(string reason)
    {
        // Collapse numbers ("size 300 outside 1-256" -> "size N outside N-N") so keys stay a small fixed set.
        var key = Digits.Replace(reason, "N");
        _counts.AddOrUpdate(key, 1, (_, n) => n + 1);
    }

    /// <summary>The counts as they are now, without flushing them (for tests).</summary>
    public IReadOnlyDictionary<string, long> Snapshot()
    {
        var copy = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var (reason, n) in _counts)
            copy[reason] = n;
        return copy;
    }

    static readonly System.Text.RegularExpressions.Regex Digits = new("[0-9]+", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>Logs and resets the counters; logs nothing when nothing was dropped.</summary>
    public void Flush()
    {
        var snapshot = new SortedDictionary<string, long>(StringComparer.Ordinal);
        foreach (var reason in _counts.Keys)
        {
            if (_counts.TryRemove(reason, out var n) && n > 0)
                snapshot[reason] = n;
        }
        if (snapshot.Count == 0)
            return;
        // The counters hold more than dropped publishes: refused connections and evictions too, so the
        // line does not call them all publishes.
        var breakdown = string.Join(", ", snapshot.Select(reason => $"{reason.Key}: {reason.Value}"));
        _log.Information("Refused or evicted {Total} in the last {Seconds} s: {Drops}",
            snapshot.Values.Sum(), (int)_period.TotalSeconds, breakdown);
    }

    async Task RunAsync(TimeSpan period, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(period);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
                Flush();
        }
        catch (OperationCanceledException)
        {
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        if (_loop is not null)
            await _loop.ConfigureAwait(false);
        Flush();
        _stop.Dispose();
    }
}
