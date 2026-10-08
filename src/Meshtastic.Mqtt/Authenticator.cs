using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Meshtastic.Mqtt;

/// <summary>Checks MQTT CONNECT credentials against the configured users.</summary>
/// <remarks>
/// PBKDF2 is deliberately slow, and thousands of nodes share the public meshdev credentials and reconnect
/// together after any broker restart. After a password verifies once, its SHA-256 digest is remembered
/// per user (one entry per configured user, so the cache is bounded by the config, not by clients);
/// later logins with the same password are a constant-time digest compare. Anything else, including
/// unknown usernames, pays the full PBKDF2 cost, throttled by a small concurrency limit so a flood of
/// bad logins cannot starve packet handling of CPU.
/// </remarks>
public sealed class Authenticator
{
    readonly Dictionary<string, PasswordHash> _users = new(StringComparer.Ordinal);
    readonly ConcurrentDictionary<string, byte[]> _verified = new(StringComparer.Ordinal);
    readonly PasswordHash _unknownUser;
    readonly SemaphoreSlim _kdfSlots;

    public Authenticator(IEnumerable<UserConfig> users, int? maxConcurrentKdf = null)
    {
        foreach (var user in users)
            _users[user.Username] = user.ParsedHash ?? throw new ArgumentException($"user '{user.Username}' has no parsed hash");
        var iterations = _users.Count > 0 ? _users.Values.Max(h => h.Iterations) : PasswordHasher.DefaultIterations;
        _unknownUser = PasswordHash.Unmatchable(iterations);
        var slots = maxConcurrentKdf ?? Math.Max(1, Environment.ProcessorCount / 2);
        _kdfSlots = new SemaphoreSlim(slots, slots);
    }

    public async Task<bool> AuthenticateAsync(string? username, byte[]? password, CancellationToken cancellationToken = default)
    {
        password ??= [];
        if (string.IsNullOrEmpty(username) || !_users.TryGetValue(username, out var hash))
        {
            await VerifyAsync(_unknownUser, password, cancellationToken).ConfigureAwait(false);
            return false;
        }

        var digest = SHA256.HashData(password);
        if (_verified.TryGetValue(username, out var known) && CryptographicOperations.FixedTimeEquals(known, digest))
            return true;

        if (!await VerifyAsync(hash, password, cancellationToken).ConfigureAwait(false))
            return false;
        _verified[username] = digest;
        return true;
    }

    async Task<bool> VerifyAsync(PasswordHash hash, byte[] password, CancellationToken cancellationToken)
    {
        await _kdfSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return hash.Verify(password);
        }
        finally
        {
            _kdfSlots.Release();
        }
    }
}
