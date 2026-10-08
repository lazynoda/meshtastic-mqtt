using System.Collections.Concurrent;
using Serilog;

namespace Meshtastic.Mqtt;

/// <summary>
/// Counts dropped publishes per reason and logs the totals at Information on a fixed period, only when
/// something was dropped. Per-packet drop lines are Debug, so a public publisher cannot flood the log.
/// </summary>
public sealed class DropCounters : IAsyncDisposable
{
    public static readonly TimeSpan DefaultPeriod = TimeSpan.FromSeconds(60);

    // Reasons come from PacketInspector, a small fixed set once numbers are collapsed, so the dictionary stays small.
    readonly ConcurrentDictionary<string, long> _counts = new(StringComparer.Ordinal);
    readonly ILogger _log;
    readonly CancellationTokenSource _stop = new();
    readonly Task? _loop;

    public DropCounters(ILogger log, TimeSpan? period = null, bool start = true)
    {
        _log = log;
        if (start)
            _loop = RunAsync(period ?? DefaultPeriod, _stop.Token);
    }

    public void Increment(string reason)
    {
        // Collapse numbers ("size 300 outside 1-256" -> "size N outside N-N") so keys stay a small fixed set.
        var key = Digits.Replace(reason, "N");
        _counts.AddOrUpdate(key, 1, (_, n) => n + 1);
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
        _log.Information("Dropped {Total} publish(es) in the last period by reason: {Drops}", snapshot.Values.Sum(), snapshot);
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
