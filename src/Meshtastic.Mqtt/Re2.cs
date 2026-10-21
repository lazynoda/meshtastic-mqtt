using System.Buffers;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Meshtastic.Mqtt;

/// <summary>
/// The native library of the regular expressions of the filters: Google RE2 through the thin C shim
/// of <c>native/re2shim</c> (<c>libre2shim.so</c>), built against the RE2 of the distribution.
/// </summary>
internal static partial class Re2
{
    /// <summary>The name of the shim, as the runtime probes it (<c>libre2shim.so</c>).</summary>
    internal const string LibraryName = "re2shim";

    /// <summary>The version of the C API this code was written for (<c>re2shim_abi_version</c>).</summary>
    internal const int AbiVersion = 1;

    /// <summary>The error code of RE2 for a pattern whose program does not fit its memory.</summary>
    internal const int ErrorPatternTooLarge = 15;

    static readonly Lazy<string?> Availability = new(() => LoadError(LibraryName));

    /// <summary>
    /// Why the shim cannot be used, or null when it can. The result is read once per process.
    /// </summary>
    internal static string? UnavailableReason => Availability.Value;

    /// <summary>Throws the clear error of a missing shim, so nothing fails later with a bare DllNotFoundException.</summary>
    internal static void EnsureAvailable()
    {
        if (UnavailableReason is { } reason)
            throw new Re2UnavailableException(reason);
    }

    /// <summary>
    /// Loads a library the way the runtime loads the shim and checks the version of its API.
    /// </summary>
    /// <param name="libraryName">The name of the library (the tests pass a name that is not there).</param>
    /// <returns>Why the library cannot be used, or null when it can.</returns>
    internal static unsafe string? LoadError(string libraryName)
    {
        IntPtr library;
        try
        {
            library = NativeLibrary.Load(libraryName, typeof(Re2).Assembly, null);
        }
        catch (Exception ex) when (ex is DllNotFoundException or BadImageFormatException)
        {
            return Missing(libraryName, ex.Message);
        }
        if (!NativeLibrary.TryGetExport(library, "re2shim_abi_version", out var export))
            return Missing(libraryName, "the library has no re2shim_abi_version");
        var version = ((delegate* unmanaged<int>)export)();
        if (version != AbiVersion)
            return Missing(libraryName, $"the library has the API version {version}, the broker needs {AbiVersion}");
        return null;
    }

    static string Missing(string libraryName, string detail) =>
        $"the native library of the regular expressions (lib{libraryName}.so, Google RE2) cannot be loaded: "
        + $"{detail}. The Docker image ships it; outside Docker, install the RE2 of the system and build it "
        + "with native/re2shim/build.sh (see docs/operations.md, \"Running the tests\").";

    [LibraryImport(LibraryName, EntryPoint = "re2shim_compile")]
    internal static unsafe partial Re2Handle Compile(byte* pattern, nuint length, long maxMem);

    [LibraryImport(LibraryName, EntryPoint = "re2shim_error_code")]
    internal static partial int ErrorCode(Re2Handle re);

    [LibraryImport(LibraryName, EntryPoint = "re2shim_error")]
    internal static unsafe partial nuint Error(Re2Handle re, byte* buffer, nuint capacity);

    [LibraryImport(LibraryName, EntryPoint = "re2shim_partial_match")]
    internal static unsafe partial int PartialMatch(Re2Handle re, byte* text, nuint length);

    [LibraryImport(LibraryName, EntryPoint = "re2shim_free")]
    internal static partial void Free(IntPtr re);
}

/// <summary>The shim of RE2 cannot be loaded: the message says why and how to build it.</summary>
internal sealed class Re2UnavailableException(string message) : Exception(message);

/// <summary>
/// One compiled RE2 object. The native object is freed when the handle is disposed or, when nobody
/// disposes it, by its critical finalizer once no ruleset references it any more.
/// </summary>
internal sealed class Re2Handle : SafeHandleZeroOrMinusOneIsInvalid
{
    long _pressure;

    public Re2Handle()
        : base(ownsHandle: true)
    {
    }

    /// <summary>
    /// Tells the garbage collector how much native memory the object may hold (its <c>max_mem</c>),
    /// so a ruleset that is dropped on a reload is collected, and its native memory freed, without
    /// waiting for the managed heap to grow.
    /// </summary>
    internal void AddPressure(long bytes)
    {
        if (bytes <= 0 || _pressure != 0)
            return;
        GC.AddMemoryPressure(bytes);
        _pressure = bytes;
    }

    protected override bool ReleaseHandle()
    {
        Re2.Free(handle);
        if (_pressure > 0)
            GC.RemoveMemoryPressure(_pressure);
        return true;
    }
}

/// <summary>
/// A compiled pattern of a <c>regex</c> condition: a Google RE2 object, unanchored partial match on
/// the UTF-8 text, no captures.
/// </summary>
/// <remarks>
/// RE2 runs in time linear in the text and holds its memory under <c>max_mem</c>: the program and the
/// caches it builds while it matches. When a cache fills its share, RE2 flushes it and starts over (and
/// it falls back to its slower NFA when it flushes too often), so hostile text costs CPU, never memory.
/// <para>
/// Thread safety: one instance is shared by every condition with the same pattern and is matched from
/// many MQTT handlers at once, without a lock. That is safe because matching only calls the
/// <c>const</c> methods of RE2, which RE2 documents as safe to call from several threads at once on
/// one object (it guards the caches it builds lazily with its own mutexes), and the
/// <see cref="SafeHandle"/> keeps the native object alive for the length of every call, even when a
/// reload drops the ruleset in the middle of it.
/// </para>
/// </remarks>
internal sealed class Re2Pattern
{
    /// <summary>A text up to this many UTF-8 bytes is encoded on the stack (a packet text is about 240).</summary>
    const int StackBytes = 1024;

    readonly Re2Handle _handle;

    Re2Pattern(string pattern, Re2Handle handle)
    {
        Pattern = pattern;
        _handle = handle;
    }

    /// <summary>The pattern, as the file writes it.</summary>
    public string Pattern { get; }

    /// <summary>The native object (the tests check that a dropped ruleset frees it).</summary>
    internal Re2Handle Handle => _handle;

    /// <summary>Compiles a pattern with the options of the filters and a memory budget.</summary>
    /// <param name="pattern">The pattern, in RE2 syntax.</param>
    /// <param name="maxMemory">The <c>max_mem</c> of RE2: the most bytes the compiled program and
    /// its caches may use.</param>
    /// <param name="compiled">The compiled pattern.</param>
    /// <param name="error">Why the pattern is not used: the text of RE2, with a hint for the
    /// constructs of other dialects.</param>
    /// <exception cref="Re2UnavailableException">The shim cannot be loaded.</exception>
    public static unsafe bool TryCompile(string pattern, long maxMemory, out Re2Pattern? compiled, out string error)
    {
        Re2.EnsureAvailable();
        compiled = null;
        error = string.Empty;

        var bytes = Encoding.UTF8.GetBytes(pattern);
        Re2Handle handle;
        fixed (byte* p = bytes)
            handle = Re2.Compile(p, (nuint)bytes.Length, maxMemory);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            error = "the pattern cannot be compiled: the regex engine is out of memory";
            return false;
        }

        var code = Re2.ErrorCode(handle);
        if (code != 0)
        {
            var text = ErrorText(handle);
            handle.Dispose();
            error = code == Re2.ErrorPatternTooLarge
                ? $"the pattern is too big for the memory of one pattern ({maxMemory} bytes): {text}"
                : $"the pattern is not a valid RE2 regular expression: {text}{Hint(text)}";
            return false;
        }

        handle.AddPressure(maxMemory);
        compiled = new Re2Pattern(pattern, handle);
        return true;
    }

    static unsafe string ErrorText(Re2Handle handle)
    {
        var length = (int)Re2.Error(handle, null, 0);
        if (length == 0)
            return "unknown error";
        var buffer = new byte[length];
        fixed (byte* p = buffer)
            Re2.Error(handle, p, (nuint)buffer.Length);
        return Encoding.UTF8.GetString(buffer);
    }

    /// <summary>
    /// A hint for the constructs RE2 does not have, which are the usual reason a pattern written for
    /// another engine is refused.
    /// </summary>
    static string Hint(string error)
    {
        if (error.EndsWith("(?=", StringComparison.Ordinal) || error.EndsWith("(?!", StringComparison.Ordinal))
            return " (RE2 has no lookahead and no lookbehind)";
        if (error.Contains("(?<", StringComparison.Ordinal))
            return " (RE2 has no lookbehind; a named group is written (?P<name>...))";
        if (error.EndsWith("(?>", StringComparison.Ordinal))
            return " (RE2 has no atomic groups)";
        if (error.StartsWith("invalid escape sequence: \\", StringComparison.Ordinal)
            && error.Length > 26 && char.IsAsciiDigit(error[26]))
            return " (RE2 has no backreferences)";
        if (error.StartsWith("bad repetition operator: ", StringComparison.Ordinal) && error.EndsWith('+'))
            return " (RE2 has no possessive quantifiers)";
        if (error.EndsWith("\\Z", StringComparison.Ordinal))
            return " (write \\z, or $ without (?m))";
        return string.Empty;
    }

    /// <summary>Whether the pattern matches anywhere in the text.</summary>
    public unsafe bool IsMatch(string subject)
    {
        // RE2 reads UTF-8. The text is encoded into a buffer on the stack, or into a pooled one when it
        // is long: a match allocates nothing.
        var most = Encoding.UTF8.GetMaxByteCount(subject.Length);
        byte[]? rented = null;
        Span<byte> buffer = most <= StackBytes ? stackalloc byte[StackBytes] : (rented = ArrayPool<byte>.Shared.Rent(most));
        try
        {
            var length = Encoding.UTF8.GetBytes(subject, buffer);
            fixed (byte* p = buffer)
                return Re2.PartialMatch(_handle, p, (nuint)length) == 1;
        }
        finally
        {
            if (rented is not null)
                ArrayPool<byte>.Shared.Return(rented);
        }
    }

    public override string ToString() => Pattern;
}
