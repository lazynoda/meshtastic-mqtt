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
/// <item>The check with the most logins waiting on it runs first (oldest first on ties). In a restart storm
/// the real meshdev password has many waiters and an attacker's guesses have one each, so the legitimate
/// check jumps the queue.</item>
/// <item>Each scheduler holds at most <c>maxPending</c> distinct checks (joining an existing one is free);
/// a check that has not started within <c>queueTimeout</c> is answered <see cref="AuthResult.Busy"/> without
/// running PBKDF2 (when a worker next picks, so at most one PBKDF2 later). Memory and waiting time are bounded.</item>
/// </list>
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

    public Authenticator(IEnumerable<UserConfig> users, int? maxConcurrentKdf = null, TimeSpan? queueTimeout = null, int? maxPending = null)
    {
        foreach (var user in users)
            _users[user.Username] = user.ParsedHash ?? throw new ArgumentException($"user '{user.Username}' has no parsed hash");
        var iterations = _users.Count > 0 ? _users.Values.Max(h => h.Iterations) : PasswordHasher.DefaultIterations;
        _unknownUser = PasswordHash.Unmatchable(iterations);

        var slots = maxConcurrentKdf ?? Math.Max(1, Environment.ProcessorCount / 2);
        var timeout = queueTimeout ?? TimeSpan.FromSeconds(LimitsConfig.DefaultAuthQueueTimeoutSeconds);
        var pending = Math.Max(maxPending ?? LimitsConfig.DefaultAuthMaxPending, slots);
        _known = new KdfScheduler(slots, timeout, pending);
        _unknown = new KdfScheduler(1, timeout, pending);
    }

    /// <summary>PBKDF2 computations actually run (for tests and diagnostics).</summary>
    internal long KdfRuns => Interlocked.Read(ref _kdfRuns);

    public Task<AuthResult> AuthenticateAsync(string? username, byte[]? password, CancellationToken cancellationToken = default)
    {
        password ??= [];
        var digest = SHA256.HashData(password);
        var key = (username ?? string.Empty) + "\n" + Convert.ToHexString(digest);

        if (string.IsNullOrEmpty(username) || !_users.TryGetValue(username, out var hash))
        {
            // Same work as a real check, so a quiet broker does not reveal which usernames exist.
            return _unknown.RunAsync(key, () =>
            {
                Interlocked.Increment(ref _kdfRuns);
                _unknownUser.Verify(password);
                return AuthResult.Failed;
            });
        }

        if (IsCached(username, digest))
            return Task.FromResult(AuthResult.Success);

        return _known.RunAsync(key, () =>
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
    /// A bounded set of pending checks served by a few workers, most-awaited first. Callers with the same key
    /// share one check and one result.
    /// </summary>
    sealed class KdfScheduler(int slots, TimeSpan queueTimeout, int maxPending)
    {
        sealed class Job(Func<AuthResult> work, DateTime deadlineUtc)
        {
            public readonly Func<AuthResult> Work = work;
            public readonly DateTime DeadlineUtc = deadlineUtc;
            public readonly TaskCompletionSource<AuthResult> Result = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public readonly long Sequence = Interlocked.Increment(ref _sequence);
            public int Waiters = 1;
            public bool Started;
        }

        static long _sequence;
        readonly object _lock = new();
        readonly Dictionary<string, Job> _jobs = new(StringComparer.Ordinal);
        int _workers;

        public Task<AuthResult> RunAsync(string key, Func<AuthResult> work)
        {
            Job job;
            lock (_lock)
            {
                if (_jobs.TryGetValue(key, out var existing))
                {
                    existing.Waiters++;
                    return existing.Result.Task;
                }
                if (_jobs.Count >= maxPending)
                    return Task.FromResult(AuthResult.Busy);
                job = new Job(work, DateTime.UtcNow + queueTimeout);
                _jobs[key] = job;
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
                string? key = null;
                Job? next = null;
                lock (_lock)
                {
                    var now = DateTime.UtcNow;
                    List<string>? expired = null;
                    foreach (var (k, j) in _jobs)
                    {
                        if (j.Started)
                            continue;
                        if (now > j.DeadlineUtc)
                        {
                            (expired ??= []).Add(k);
                            continue;
                        }
                        if (next is null || j.Waiters > next.Waiters || (j.Waiters == next.Waiters && j.Sequence < next.Sequence))
                        {
                            next = j;
                            key = k;
                        }
                    }
                    foreach (var k in expired ?? [])
                    {
                        _jobs.Remove(k, out var gone);
                        gone!.Result.TrySetResult(AuthResult.Busy);
                    }
                    if (next is null)
                    {
                        _workers--;
                        return;
                    }
                    next.Started = true;
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
                    _jobs.Remove(key!);
                next.Result.TrySetResult(result);
            }
        }
    }
}
