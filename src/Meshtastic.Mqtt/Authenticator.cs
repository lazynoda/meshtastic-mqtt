using System.Security.Cryptography;

namespace Meshtastic.Mqtt;

public enum AuthResult
{
    Success,
    Failed,

    /// <summary>The password-hashing queue is full or the wait timed out; the password was not checked.</summary>
    Busy,
}

/// <summary>Checks MQTT CONNECT credentials against the configured users.</summary>
/// <remarks>
/// PBKDF2 is deliberately slow, and thousands of nodes share the public meshdev credentials and reconnect
/// together after any broker restart. After a password verifies once, its SHA-256 digest is remembered
/// per user (one entry per configured user, so the cache is bounded by the config, not by clients);
/// later logins with the same password are a constant-time digest compare. Anything else, including
/// unknown usernames, pays the full PBKDF2 cost.
///
/// PBKDF2 runs in two bounded schedulers so that a flood of bad logins cannot hold good ones hostage:
/// <list type="bullet">
/// <item>Configured usernames get <c>maxConcurrentKdf</c> slots; unknown usernames get one slot of their own.
/// A flood of made-up usernames therefore never delays a configured user. The price is at most one more
/// core busy with PBKDF2 while both are saturated.</item>
/// <item>Logins with the same (username, password) share one check: a cold reconnect storm of meshdev nodes
/// pays PBKDF2 once. The success cache is checked again when a check starts.</item>
/// <item>Checks are grouped by username and the groups are served round-robin, so wrong passwords for one
/// username (the public <c>meshdev</c>) delay another username's cold login by at most one check per
/// username with work pending, whatever the attacker does. Each username may have at most
/// <c>maxPendingPerUser</c> distinct checks pending (joining an existing one is free); further ones are
/// answered <see cref="AuthResult.Busy"/> at once, so one username can neither fill the scheduler nor make
/// its own queue longer than that cap.</item>
/// <item>Within a username the check with the most logins waiting on it runs first (oldest first on ties): in
/// a restart storm the real meshdev password has many waiters and an attacker's guesses have few. Sending a
/// guess several times inflates its waiters, but that only reorders the few checks inside that username's cap
/// and never touches another username. A cold login for a username with guesses queued therefore waits for at
/// most <c>maxPendingPerUser</c> checks.</item>
/// <item>Each scheduler holds at most <c>maxPending</c> distinct checks in total; a check that has not started
/// within <c>queueTimeout</c> is answered <see cref="AuthResult.Busy"/> without running PBKDF2 (when a worker
/// next picks, so at most one PBKDF2 later). Memory and waiting time are bounded.</item>
/// </list>
/// What this does not do: a flood of wrong passwords for one username that is sustained from more connections
/// than the per-user cap keeps that username's own queue full, and a lone cold login for that username is told
/// Busy until it finds a free place (nothing distinguishes it from a guess before PBKDF2 runs). Other usernames
/// are unaffected; a reconnect storm needs only one of its nodes admitted, because the rest join that check for
/// free. Limiting such a flood is a per-IP job, outside this class.
/// Under saturation an unknown username may get Busy while a configured one is checked, which reveals that
/// the username exists; on this broker usernames are not secrets.
/// </remarks>
public sealed class Authenticator
{
    readonly Dictionary<string, PasswordHash> _users = new(StringComparer.Ordinal);
    readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte[]> _verified = new(StringComparer.Ordinal);
    readonly PasswordHash _unknownUser;
    readonly KdfScheduler _known;
    readonly KdfScheduler _unknown;
    long _kdfRuns;

    public Authenticator(IEnumerable<UserConfig> users, int? maxConcurrentKdf = null, TimeSpan? queueTimeout = null,
        int? maxPending = null, int? maxPendingPerUser = null)
    {
        foreach (var user in users)
            _users[user.Username] = user.ParsedHash ?? throw new ArgumentException($"user '{user.Username}' has no parsed hash");
        var iterations = _users.Count > 0 ? _users.Values.Max(h => h.Iterations) : PasswordHasher.DefaultIterations;
        _unknownUser = PasswordHash.Unmatchable(iterations);

        var slots = maxConcurrentKdf ?? Math.Max(1, Environment.ProcessorCount / 2);
        var timeout = queueTimeout ?? TimeSpan.FromSeconds(LimitsConfig.DefaultAuthQueueTimeoutSeconds);
        var pending = Math.Max(maxPending ?? LimitsConfig.DefaultAuthMaxPending, slots);
        var perUser = Math.Min(pending, Math.Max(1, maxPendingPerUser ?? LimitsConfig.DefaultAuthMaxPendingPerUser));
        _known = new KdfScheduler(slots, timeout, pending, perUser);
        // Unknown usernames are one group: there is no user to be fair to, and the lane exists only so that
        // they cannot delay configured users.
        _unknown = new KdfScheduler(1, timeout, pending, pending);
    }

    /// <summary>PBKDF2 computations actually run (for tests and diagnostics).</summary>
    internal long KdfRuns => Interlocked.Read(ref _kdfRuns);

    public Task<AuthResult> AuthenticateAsync(string? username, byte[]? password, CancellationToken cancellationToken = default)
    {
        password ??= [];
        var digest = SHA256.HashData(password);
        var key = Convert.ToHexString(digest);

        if (string.IsNullOrEmpty(username) || !_users.TryGetValue(username, out var hash))
        {
            // Same work as a real check, so a quiet broker does not reveal which usernames exist.
            return _unknown.RunAsync(string.Empty, (username ?? string.Empty) + "\n" + key, () =>
            {
                Interlocked.Increment(ref _kdfRuns);
                _unknownUser.Verify(password);
                return AuthResult.Failed;
            });
        }

        if (IsCached(username, digest))
            return Task.FromResult(AuthResult.Success);

        return _known.RunAsync(username, key, () =>
        {
            if (IsCached(username, digest))
                return AuthResult.Success;
            Interlocked.Increment(ref _kdfRuns);
            if (!hash.Verify(password))
                return AuthResult.Failed;
            _verified[username] = digest;
            return AuthResult.Success;
        });
    }

    bool IsCached(string username, byte[] digest) =>
        _verified.TryGetValue(username, out var known) && CryptographicOperations.FixedTimeEquals(known, digest);

    /// <summary>
    /// A bounded set of pending checks served by a few workers. Checks are grouped (by username); groups are
    /// served round-robin and each holds at most <paramref name="maxPendingPerGroup"/> distinct checks. Inside a
    /// group the most-awaited check runs first. Callers with the same (group, key) share one check and one result.
    /// </summary>
    sealed class KdfScheduler(int slots, TimeSpan queueTimeout, int maxPending, int maxPendingPerGroup)
    {
        sealed class Job(Func<AuthResult> work, long deadlineTicks)
        {
            public readonly Func<AuthResult> Work = work;
            // Environment.TickCount64 is monotonic: a wall-clock step (NTP) neither extends nor cuts the wait.
            public readonly long DeadlineTicks = deadlineTicks;
            public readonly TaskCompletionSource<AuthResult> Result = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public readonly long Sequence = Interlocked.Increment(ref _sequence);
            public int Waiters = 1;
            public bool Started;
        }

        sealed class Group
        {
            public readonly Dictionary<string, Job> Jobs = new(StringComparer.Ordinal);
            public bool Queued;   // present in _rotation
        }

        static long _sequence;
        readonly object _lock = new();
        readonly Dictionary<string, Group> _groups = new(StringComparer.Ordinal);
        // Round-robin order of groups with work pending. A group is appended when its first job is added and
        // re-appended after a worker takes a job from it while it still has unstarted jobs.
        readonly Queue<string> _rotation = new();
        int _pending;   // jobs in all groups, started ones included
        int _workers;

        public Task<AuthResult> RunAsync(string group, string key, Func<AuthResult> work)
        {
            Job job;
            lock (_lock)
            {
                if (!_groups.TryGetValue(group, out var g))
                    g = _groups[group] = new Group();
                if (g.Jobs.TryGetValue(key, out var existing))
                {
                    existing.Waiters++;
                    return existing.Result.Task;
                }
                if (g.Jobs.Count >= maxPendingPerGroup || _pending >= maxPending)
                {
                    if (g.Jobs.Count == 0 && !g.Queued)
                        _groups.Remove(group);
                    return Task.FromResult(AuthResult.Busy);
                }
                job = new Job(work, Environment.TickCount64 + (long)queueTimeout.TotalMilliseconds);
                g.Jobs[key] = job;
                _pending++;
                if (!g.Queued)
                {
                    g.Queued = true;
                    _rotation.Enqueue(group);
                }
                if (_workers >= slots)
                    return job.Result.Task;
                _workers++;
            }
            _ = Task.Run(WorkerLoop);
            return job.Result.Task;
        }

        void WorkerLoop()
        {
            while (true)
            {
                string? group = null;
                string? key = null;
                Job? next = null;
                lock (_lock)
                {
                    ExpireAll(Environment.TickCount64);
                    // Take the first group in the rotation that still has an unstarted job.
                    var rounds = _rotation.Count;
                    while (rounds-- > 0 && next is null)
                    {
                        var candidate = _rotation.Dequeue();
                        if (!_groups.TryGetValue(candidate, out var g))
                            continue;
                        g.Queued = false;
                        next = MostAwaited(g, out key);
                        if (next is not null)
                        {
                            group = candidate;
                            next.Started = true;
                            if (g.Jobs.Values.Any(j => !j.Started))
                            {
                                g.Queued = true;
                                _rotation.Enqueue(candidate);
                            }
                        }
                        else if (g.Jobs.Count == 0)
                        {
                            _groups.Remove(candidate);
                        }
                    }
                    if (next is null)
                    {
                        _workers--;
                        return;
                    }
                }

                AuthResult result;
                try
                {
                    result = next.Work();
                }
                catch (Exception)
                {
                    result = AuthResult.Failed;   // fail closed
                }
                lock (_lock)
                    Remove(group!, key!);
                next.Result.TrySetResult(result);
            }
        }

        /// <summary>Answers every unstarted job past its deadline with Busy, in all groups.</summary>
        void ExpireAll(long now)
        {
            List<(string Group, string Key, Job Job)>? expired = null;
            foreach (var (name, g) in _groups)
            {
                foreach (var (k, j) in g.Jobs)
                {
                    if (!j.Started && now > j.DeadlineTicks)
                        (expired ??= []).Add((name, k, j));
                }
            }
            foreach (var (name, k, j) in expired ?? [])
            {
                Remove(name, k);
                j.Result.TrySetResult(AuthResult.Busy);
            }
        }

        /// <summary>The group's unstarted job with the most waiters (oldest on ties), if any.</summary>
        static Job? MostAwaited(Group g, out string? key)
        {
            key = null;
            Job? next = null;
            foreach (var (k, j) in g.Jobs)
            {
                if (j.Started)
                    continue;
                if (next is null || j.Waiters > next.Waiters || (j.Waiters == next.Waiters && j.Sequence < next.Sequence))
                {
                    next = j;
                    key = k;
                }
            }
            return next;
        }

        void Remove(string group, string key)
        {
            if (!_groups.TryGetValue(group, out var g) || !g.Jobs.Remove(key))
                return;
            _pending--;
            if (g.Jobs.Count == 0 && !g.Queued)
                _groups.Remove(group);
        }
    }
}
