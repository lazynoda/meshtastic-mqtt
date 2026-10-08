using System.Security.Cryptography;
using System.Text;

namespace Meshtastic.Mqtt;

/// <summary>
/// Password hashes for the broker config, encoded as
/// <c>pbkdf2-sha256$&lt;iterations&gt;$&lt;salt base64&gt;$&lt;hash base64&gt;</c>.
/// </summary>
/// <remarks>
/// PBKDF2-HMAC-SHA256 instead of bcrypt: it ships in the .NET base library (no third-party crypto
/// package to vet and keep patched), it is FIPS-approved, and unlike bcrypt it does not silently
/// truncate passwords at 72 bytes. The default work factor follows the OWASP Password Storage
/// Cheat Sheet for PBKDF2-HMAC-SHA256.
/// </remarks>
public static class PasswordHasher
{
    public const string Scheme = "pbkdf2-sha256";
    public const int DefaultIterations = 600_000;
    public const int MinIterations = 100_000;
    public const int MaxIterations = 10_000_000;
    public const int SaltBytes = 16;
    public const int HashBytes = 32;

    public static string Hash(string password, int iterations = DefaultIterations)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (iterations is < MinIterations or > MaxIterations)
            throw new ArgumentOutOfRangeException(nameof(iterations), $"iterations must be between {MinIterations} and {MaxIterations}");

        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, HashBytes);
        return $"{Scheme}${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool TryParse(string? encoded, out PasswordHash? parsed, out string? error)
    {
        parsed = null;
        error = null;
        var parts = (encoded ?? string.Empty).Split('$');
        if (parts.Length != 4 || parts[0] != Scheme)
        {
            error = $"expected '{Scheme}$<iterations>$<salt>$<hash>' (generate it with the hash-password command)";
            return false;
        }
        if (!int.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var iterations)
            || iterations is < MinIterations or > MaxIterations)
        {
            error = $"iterations must be an integer between {MinIterations} and {MaxIterations}";
            return false;
        }
        byte[] salt, hash;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            hash = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            error = "salt and hash must be base64";
            return false;
        }
        if (salt.Length < SaltBytes || hash.Length != HashBytes)
        {
            error = $"salt must be at least {SaltBytes} bytes and hash exactly {HashBytes} bytes";
            return false;
        }
        parsed = new PasswordHash(iterations, salt, hash);
        return true;
    }
}

public sealed class PasswordHash(int iterations, byte[] salt, byte[] hash)
{
    public int Iterations { get; } = iterations;

    /// <summary>Derives the candidate and compares it in constant time.</summary>
    public bool Verify(ReadOnlySpan<byte> password)
    {
        Span<byte> candidate = stackalloc byte[PasswordHasher.HashBytes];
        Rfc2898DeriveBytes.Pbkdf2(password, salt, candidate, Iterations, HashAlgorithmName.SHA256);
        return CryptographicOperations.FixedTimeEquals(candidate, hash);
    }

    /// <summary>A hash nothing can match, used to spend the same work on unknown usernames.</summary>
    public static PasswordHash Unmatchable(int iterations) =>
        new(iterations, RandomNumberGenerator.GetBytes(PasswordHasher.SaltBytes), RandomNumberGenerator.GetBytes(PasswordHasher.HashBytes));
}
