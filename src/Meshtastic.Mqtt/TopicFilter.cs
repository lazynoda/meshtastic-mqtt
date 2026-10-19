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

    /// <summary>
    /// A PUBLISH topic name: non-empty, no NUL, at most 65535 bytes, and no wildcard characters (spec 4.7.1: '+' and
    /// '#' are only for filters). MQTTnet 5.2.0 does not check this on the server side; it hands such a topic name to
    /// the publish hook as received.
    /// </summary>
    public static bool IsValidTopicName(string? topic, out string? error)
    {
        error = null;
        if (string.IsNullOrEmpty(topic))
            error = "topic name is empty";
        else if (topic.Contains('\0'))
            error = "topic name contains a NUL character";
        else if (topic.IndexOfAny(['+', '#']) >= 0)
            error = "topic name contains a wildcard ('+' or '#')";
        else if (Encoding.UTF8.GetByteCount(topic) > 65535)
            error = "topic name is longer than 65535 bytes";
        return error is null;
    }

    /// <summary>
    /// Whether the topic name <paramref name="topic"/> matches at least one filter of <paramref name="allowList"/>,
    /// with standard MQTT matching: '+' is one level, '#' that level and everything below, and a leading wildcard
    /// never matches a '$' topic. An empty allow-list or an invalid topic name matches nothing.
    /// </summary>
    public static bool MatchesAny(IReadOnlyCollection<string> allowList, string? topic)
    {
        if (allowList.Count == 0 || !IsValidTopicName(topic, out _))
            return false;
        // A topic name is a filter without wildcards, so "covers" is exactly "matches" here.
        foreach (var allowed in allowList)
        {
            if (Covers(allowed, topic!))
                return true;
        }
        return false;
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
