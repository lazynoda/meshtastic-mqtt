using System.Security.Cryptography;
using Serilog;

namespace Meshtastic.Mqtt;

/// <summary>The size and the time of the rules file, without reading it.</summary>
internal readonly record struct FilterFileInfo(long Size, DateTimeOffset Mtime);

/// <summary>
/// How the filter reads the rules file. The broker reads the file of the disk; the tests replace it
/// with one they drive by hand.
/// </summary>
internal interface IFilterFile
{
    /// <summary>The size and the time of the file, or null when it cannot be read.</summary>
    FilterFileInfo? Stat(string path);

    /// <summary>The bytes of the file, or null when it cannot be read.</summary>
    byte[]? ReadAllBytes(string path);

    /// <summary>The text of the file, or null when it cannot be read.</summary>
    string? ReadAllText(string path);
}

/// <summary>The rules file of the disk.</summary>
sealed class FilterFile : IFilterFile
{
    public FilterFileInfo? Stat(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
                return null;
            return new FilterFileInfo(info.Length, info.LastWriteTimeUtc);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public byte[]? ReadAllBytes(string path)
    {
        try
        {
            return File.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public string? ReadAllText(string path)
    {
        try
        {
            return File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}

/// <summary>
/// The filters of the broker: the rules of the file, and the file is checked again and again so that
/// a change is applied without a restart.
/// </summary>
/// <remarks>
/// <para>
/// The ruleset is immutable and the filter holds one reference to it: a reload builds a new one and
/// swaps the reference, so a reader never sees half a ruleset and never locks.
/// </para>
/// <para>
/// A file that cannot be read or is not valid is not loaded: the rules the broker had stay in force
/// and one Warning is written, with every problem of the file. The Warning is not repeated until the
/// file changes again.
/// </para>
/// </remarks>
public sealed class PacketFilter : IDisposable
{
    /// <summary>How often the content of the file is read again when it did not change.</summary>
    static readonly TimeSpan HashEvery = TimeSpan.FromSeconds(60);

    readonly ILogger _log;
    readonly string? _path;
    readonly TimeSpan _period;
    readonly IReadOnlyCollection<string> _knownUsers;
    readonly TimeProvider _clock;
    readonly IFilterFile _file;
    readonly FilterMetrics _metrics = new();
    readonly CancellationTokenSource _stop = new();
    readonly Task? _loop;
    volatile FilterRuleset _ruleset = FilterRuleset.Empty;
    FileState? _loaded;
    FileState? _warned;
    int _checking;
    int _pending;
    int _forced;
    bool _disposed;

    /// <summary>
    /// Reads the rules file of the configuration and starts watching it.
    /// </summary>
    /// <param name="config">The configuration of the broker (the path and the period of the check).</param>
    /// <param name="log">Where the reload lines and the warnings are written.</param>
    /// <param name="startWatcher">Whether the background check runs (the tests drive it by hand).</param>
    /// <exception cref="FilterException">The file is missing or is not valid: the broker does not start.</exception>
    public PacketFilter(BrokerConfig config, ILogger log, bool startWatcher = true)
        : this(config, log, startWatcher, TimeProvider.System, new FilterFile())
    {
    }

    /// <summary>
    /// Reads the rules file of the configuration, with the clock and the file the tests drive.
    /// </summary>
    /// <param name="config">The configuration of the broker (the path and the period of the check).</param>
    /// <param name="log">Where the reload lines and the warnings are written.</param>
    /// <param name="startWatcher">Whether the background check runs (the tests drive it by hand).</param>
    /// <param name="clock">The clock the filter reads the time with.</param>
    /// <param name="file">How the filter reads the file.</param>
    internal PacketFilter(BrokerConfig config, ILogger log, bool startWatcher, TimeProvider clock, IFilterFile file)
    {
        _log = log;
        _clock = clock;
        _file = file;
        _knownUsers = config.Users?.Select(user => user.Username).ToArray() ?? [];

        var filters = config.Filters;
        if (filters is null || string.IsNullOrWhiteSpace(filters.File))
            return;   // no filters: every packet that passes the other checks is forwarded

        _path = filters.File;
        _period = TimeSpan.FromSeconds(filters.EffectiveReloadCheckSeconds);
        _ruleset = LoadRules(_path);
        _loaded = ReadState(_path);

        if (startWatcher)
            _loop = RunAsync(_stop.Token);
    }

    /// <summary>Whether the broker has a rules file.</summary>
    public bool Enabled => _path is not null;

    /// <summary>The rules that are in force now.</summary>
    public FilterRuleset Ruleset => _ruleset;

    /// <summary>The number of rules that are in force now.</summary>
    public int RuleCount => _ruleset.RuleCount;

    /// <summary>How many payloads the filter decoded (for the tests).</summary>
    public FilterMetrics Metrics => _metrics;

    /// <summary>Judges one published packet.</summary>
    public FilterVerdict Evaluate(in FilterInput input) => _ruleset.Evaluate(input, _metrics);

    /// <summary>
    /// Reads the file again and swaps the rules, if it changed. A file that cannot be read or is not
    /// valid keeps the rules that are in force and is reported once.
    /// </summary>
    public void CheckForChange()
    {
        if (_path is null)
            return;

        // Only one check at a time: the timer and the SIGHUP of the operator may run at once, and two
        // checks of the same change would write the reload line twice. A call that finds a check
        // running returns without doing anything.
        if (Interlocked.CompareExchange(ref _checking, 1, 0) != 0)
            return;

        try
        {
            while (true)
            {
                // A reload asked by the operator reads the content of the file, whatever its size and
                // its time; the poll of the timer only reads it when they change.
                var forced = Interlocked.Exchange(ref _forced, 0) != 0;
                CheckOnce(forced);
                // A reload that was asked for while the check was running is done now.
                if (Interlocked.Exchange(ref _pending, 0) == 0)
                    break;
            }
        }
        finally
        {
            Interlocked.Exchange(ref _checking, 0);
            // A reload that arrived while the check was ending is not lost.
            if (Interlocked.Exchange(ref _pending, 0) != 0)
                CheckForChange();
        }
    }

    /// <summary>Reads the file again and swaps the rules (the SIGHUP of the operator).</summary>
    public void ReloadNow()
    {
        if (_path is null)
            return;

        // The SIGHUP of the operator reads the content of the file, whatever its size and its time: an
        // edit that keeps them is applied at once.
        Interlocked.Exchange(ref _forced, 1);
        // The check that is running re-checks at the end: the operator asked for it.
        Interlocked.Exchange(ref _pending, 1);
        CheckForChange();
    }

    /// <summary>One check of the file: it swaps the rules when the file changed.</summary>
    /// <param name="forceRead">Whether the content of the file is read even if its size and its time
    /// did not change (the SIGHUP of the operator).</param>
    void CheckOnce(bool forceRead)
    {
        var state = ReadState(_path!, forceRead);
        if (state is null)
            return;
        if (_loaded is not null && state.SameAs(_loaded))
        {
            // The file did not change: the hash that was just read is the one of the file in force, and
            // it is fresh until the next minute.
            _loaded.HashedAt = state.HashedAt;
            return;
        }
        if (_warned is not null && state.SameAs(_warned))
        {
            // The problem of this file was already reported: the hash that was just read is its one.
            _warned.HashedAt = state.HashedAt;
            return;
        }

        try
        {
            var ruleset = LoadRules(_path!);
            _ruleset = ruleset;
            _loaded = state;
            _warned = null;
            _log.Information("Filters reloaded: {Rules} {Rule:l} ({Users} user, {Gateways} gateway, {Nodes} node rules), sha256 {Sha:l}",
                ruleset.RuleCount, FilterSchema.RuleWord(ruleset.RuleCount), ruleset.UserRuleCount,
                ruleset.GatewayRuleCount, ruleset.NodeRuleCount, state.Sha8);
        }
        catch (FilterException ex)
        {
            // The rules that are in force stay in force: a broken file does not open the mesh.
            _warned = state;
            _log.Warning("The filters were not reloaded, the rules that are in force stay in force: {Errors:l}",
                string.Join("; ", ex.Errors));
        }
    }

    async Task RunAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(_period);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
                CheckForChange();
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>Reads the file and compiles its rules.</summary>
    FilterRuleset LoadRules(string path)
    {
        // A file that is over the budget of its size is not read: the size is the problem, and the
        // rules that are in force stay in force.
        var info = _file.Stat(path);
        if (info is not null && info.Value.Size > FilterLoader.MaxFileBytes)
            throw new FilterException([$"{path}: {FilterLoader.SizeMessage(info.Value.Size)}"]);
        var text = _file.ReadAllText(path);
        if (text is null)
            throw new FilterException([$"{path}: the file cannot be read"]);
        return FilterLoader.Parse(text, _knownUsers, path);
    }

    /// <summary>The state of the file: its size, its time and the hash of its content.</summary>
    sealed class FileState
    {
        public bool Readable;
        public long Size;
        public DateTimeOffset Mtime;
        public string Sha256 = string.Empty;
        public DateTimeOffset HashedAt;

        /// <summary>The first eight hex digits of the hash, as the reload line writes them.</summary>
        public string Sha8 => Sha256.Length >= 8 ? Sha256[..8] : Sha256;

        public bool SameAs(FileState? other) =>
            other is not null
            && Readable == other.Readable
            && Size == other.Size
            && Mtime == other.Mtime
            && Sha256 == other.Sha256;
    }

    /// <summary>
    /// The state of the file. The hash of the content is what makes the check work with a bind mount
    /// and with a file that is replaced atomically. The content is only read when the size or the time
    /// of the file changed, and at least once a minute, so a poll of a file that did not change does
    /// not read it.
    /// </summary>
    /// <param name="path">The path of the rules file.</param>
    /// <param name="forceRead">Whether the content is read even if the size and the time of the file
    /// did not change (the SIGHUP of the operator).</param>
    FileState? ReadState(string path, bool forceRead = false)
    {
        var info = _file.Stat(path);
        if (info is null)
            return new FileState { Readable = false, HashedAt = _clock.GetUtcNow() };

        var now = _clock.GetUtcNow();

        // A file that is over the budget of its size is not read and not hashed: the size is the
        // problem, and the state of the file is its size and its time.
        if (info.Value.Size > FilterLoader.MaxFileBytes)
        {
            return new FileState
            {
                Readable = true,
                Size = info.Value.Size,
                Mtime = info.Value.Mtime,
                HashedAt = now,
            };
        }

        var previous = _warned ?? _loaded;
        if (!forceRead && previous is not null && previous.Readable && previous.Size == info.Value.Size
            && previous.Mtime == info.Value.Mtime && now - previous.HashedAt < HashEvery)
        {
            // The file did not change and the hash is fresh: the file is not read.
            return new FileState
            {
                Readable = true,
                Size = previous.Size,
                Mtime = previous.Mtime,
                Sha256 = previous.Sha256,
                HashedAt = previous.HashedAt,
            };
        }

        var bytes = _file.ReadAllBytes(path);
        if (bytes is null)
            return new FileState { Readable = false, HashedAt = now };
        return new FileState
        {
            Readable = true,
            Size = bytes.LongLength,
            Mtime = info.Value.Mtime,
            Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            HashedAt = now,
        };
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _stop.Cancel();
        try
        {
            _loop?.GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
        }
        _stop.Dispose();
    }
}
