using System.Security.Cryptography;
using Serilog;

namespace Meshtastic.Mqtt;

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
    readonly ILogger _log;
    readonly string? _path;
    readonly TimeSpan _period;
    readonly IReadOnlyCollection<string> _knownUsers;
    readonly FilterMetrics _metrics = new();
    readonly CancellationTokenSource _stop = new();
    readonly Task? _loop;
    volatile FilterRuleset _ruleset = FilterRuleset.Empty;
    FileState? _loaded;
    FileState? _warned;
    bool _disposed;

    /// <summary>
    /// Reads the rules file of the configuration and starts watching it.
    /// </summary>
    /// <param name="config">The configuration of the broker (the path and the period of the check).</param>
    /// <param name="log">Where the reload lines and the warnings are written.</param>
    /// <param name="startWatcher">Whether the background check runs (the tests drive it by hand).</param>
    /// <exception cref="FilterException">The file is missing or is not valid: the broker does not start.</exception>
    public PacketFilter(BrokerConfig config, ILogger log, bool startWatcher = true)
    {
        _log = log;
        _knownUsers = config.Users?.Select(user => user.Username).ToArray() ?? [];

        var filters = config.Filters;
        if (filters is null || string.IsNullOrWhiteSpace(filters.File))
            return;   // no filters: every packet that passes the other checks is forwarded

        _path = filters.File;
        _period = TimeSpan.FromSeconds(filters.EffectiveReloadCheckSeconds);
        _ruleset = FilterLoader.LoadFile(_path, _knownUsers);
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

        var state = ReadState(_path);
        if (state is null)
            return;
        if (_loaded is not null && state.SameAs(_loaded))
            return;   // nothing changed
        if (_warned is not null && state.SameAs(_warned))
            return;   // the problem of this file was already reported

        try
        {
            var ruleset = FilterLoader.LoadFile(_path, _knownUsers);
            _ruleset = ruleset;
            _loaded = state;
            _warned = null;
            _log.Information("Filters reloaded: {Rules} rules ({Users} user, {Gateways} gateway, {Nodes} node scopes), sha256 {Sha:l}",
                ruleset.RuleCount, ruleset.UserRuleCount, ruleset.GatewayRuleCount, ruleset.NodeRuleCount, state.Sha8);
        }
        catch (FilterException ex)
        {
            // The rules that are in force stay in force: a broken file does not open the mesh.
            _warned = state;
            _log.Warning("The filters were not reloaded, the rules that are in force stay in force: {Errors:l}",
                string.Join("; ", ex.Errors));
        }
    }

    /// <summary>Reads the file again and swaps the rules (the SIGHUP of the operator).</summary>
    public void ReloadNow() => CheckForChange();

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

    /// <summary>The state of the file: its size, its time and the hash of its content.</summary>
    sealed class FileState
    {
        public bool Readable;
        public long Size;
        public DateTimeOffset Mtime;
        public string Sha256 = string.Empty;

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
    /// and with a file that is replaced atomically.
    /// </summary>
    static FileState? ReadState(string path)
    {
        try
        {
            var info = new FileInfo(path);
            var bytes = File.ReadAllBytes(path);
            return new FileState
            {
                Readable = true,
                Size = bytes.LongLength,
                Mtime = info.LastWriteTimeUtc,
                Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new FileState { Readable = false };
        }
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
