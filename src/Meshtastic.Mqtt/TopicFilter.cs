using System.Text;

namespace Meshtastic.Mqtt;

/// <summary>
/// MQTT topic-filter validation and coverage (MQTT 3.1.1 section 4.7 / MQTT 5 section 4.7).
/// </summary>
public static class TopicFilter
{
    public static bool IsValid(string? filter, out string? error)
    {
        error = null;
        if (string.IsNullOrEmpty(filter))
        {
            error = "topic filter is empty";
            return false;
        }
        if (filter.Contains('\0'))
        {
            error = "topic filter contains a NUL character";
            return false;
        }
        if (Encoding.UTF8.GetByteCount(filter) > 65535)
        {
            error = "topic filter is longer than 65535 bytes";
            return false;
        }
        var levels = filter.Split('/');
        for (var i = 0; i < levels.Length; i++)
        {
            var level = levels[i];
            if (level.Contains('#') && (level != "#" || i != levels.Length - 1))
            {
                error = $"'#' must be a whole level and the last one: '{filter}'";
                return false;
            }
            if (level.Contains('+') && level != "+")
            {
                error = $"'+' must be a whole level: '{filter}'";
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// True only if every topic that <paramref name="requested"/> can match is also matched by
    /// <paramref name="allowed"/>. Both must be valid filters. This is subset logic, not prefix logic:
    /// <c>msh/ES/2/e/#</c> covers <c>msh/ES/2/e/Test/#</c>, but nothing short of <c>#</c> covers <c>msh/#</c>.
    /// </summary>
    public static bool Covers(string allowed, string requested)
    {
        var a = allowed.Split('/');
        var r = requested.Split('/');

        // A filter whose first level is a wildcard never matches topics starting with '$' (spec 4.7.2),
        // so it cannot cover a request that targets $-topics such as $SYS/#.
        if (r[0].StartsWith('$') && (a[0] == "#" || a[0] == "+"))
            return false;

        for (var i = 0; ; i++)
        {
            if (i == a.Length)
                return r.Length == a.Length;  // allowed has no '#': only topics with exactly this many levels
            if (a[i] == "#")
                return true;                  // everything below (and the parent level itself) is allowed
            if (i == r.Length)
                return false;                 // requested matches a shorter topic that allowed does not
            if (r[i] == "#")
                return false;                 // requested reaches arbitrary depth, allowed does not
            if (a[i] == "+")
                continue;                     // any single level, literal or '+'
            if (r[i] == "+" || !string.Equals(a[i], r[i], StringComparison.Ordinal))
                return false;
        }
    }

    /// <summary>An empty allow-list denies everything.</summary>
    public static bool IsAllowed(IReadOnlyCollection<string> allowList, string? requested)
    {
        if (allowList.Count == 0 || !IsValid(requested, out _))
            return false;
        foreach (var allowed in allowList)
        {
            if (Covers(allowed, requested!))
                return true;
        }
        return false;
    }
}
