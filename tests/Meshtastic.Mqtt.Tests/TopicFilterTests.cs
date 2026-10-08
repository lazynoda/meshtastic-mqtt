using Meshtastic.Mqtt;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

public class TopicFilterTests
{
    [Theory]
    // Exact and wildcard coverage that must be granted.
    [InlineData("msh/ES/2/e/test/#", "msh/ES/2/e/test/#")]
    [InlineData("msh/ES/2/e/test/#", "msh/ES/2/e/test")]
    [InlineData("msh/ES/2/e/test/#", "msh/ES/2/e/test/!1a2b3c4d")]
    [InlineData("msh/ES/2/e/test/#", "msh/ES/2/e/test/+")]
    [InlineData("msh/ES/2/e/test/#", "msh/ES/2/e/test/+/#")]
    [InlineData("msh/ES/2/e/#", "msh/ES/2/e/Test/#")]
    [InlineData("msh/ES/2/e/#", "msh/ES/2/e/+/+")]
    [InlineData("msh/ES/2/e/+/#", "msh/ES/2/e/Valencia/#")]
    [InlineData("msh/+/2/e/#", "msh/ES/2/e/#")]
    [InlineData("msh/ES/2/e/+", "msh/ES/2/e/Test")]
    [InlineData("msh/ES/2/e/+", "msh/ES/2/e/+")]
    [InlineData("#", "msh/#")]
    [InlineData("#", "#")]
    [InlineData("+/#", "msh/ES/#")]
    [InlineData("a//b", "a//b")]
    [InlineData("a/+/b", "a//b")]
    public void Covers_Allows(string allowed, string requested) =>
        Assert.True(TopicFilter.Covers(allowed, requested));

    [Theory]
    // The StartsWith trap: a prefix must not open the parent tree.
    [InlineData("msh/ES/2/e/", "msh/#")]
    [InlineData("msh/ES/2/e/#", "msh/#")]
    [InlineData("msh/ES/2/e/#", "#")]
    [InlineData("msh/ES/2/e/#", "+/ES/2/e/#")]
    [InlineData("msh/ES/2/e/#", "msh/+/2/e/#")]
    [InlineData("msh/ES/2/e/#", "msh/ES/2/#")]
    [InlineData("msh/ES/2/e/test/#", "msh/ES/2/e/+/#")]
    [InlineData("msh/ES/2/e/test/#", "msh/ES/2/e/testing/#")]
    [InlineData("msh/ES/2/e/test/#", "msh/ES/2/e/tes")]
    [InlineData("msh/ES/2/e/test/#", "msh/ES/2/e/Test/#")]   // topics are case-sensitive
    [InlineData("msh/ES/2/e/test", "msh/ES/2/e/test/#")]
    [InlineData("msh/ES/2/e/test", "msh/ES/2/e/test/x")]
    [InlineData("msh/ES/2/e/+", "msh/ES/2/e/#")]
    [InlineData("msh/ES/2/e/+", "msh/ES/2/e/+/+")]
    [InlineData("msh/ES/2/e/+", "msh/ES/2/e")]
    [InlineData("msh/ES/2/e/+/#", "msh/ES/2/e/#")]          // '#' also matches the parent msh/ES/2/e
    [InlineData("msh/+/2/e/#", "msh/#")]
    // $-topics: leading wildcards never match them (MQTT 4.7.2).
    [InlineData("#", "$SYS/#")]
    [InlineData("#", "$SYS/broker/clients")]
    [InlineData("+/#", "$SYS/#")]
    [InlineData("+/broker/#", "$SYS/broker/#")]
    public void Covers_Refuses(string allowed, string requested) =>
        Assert.False(TopicFilter.Covers(allowed, requested));

    [Fact]
    public void Covers_ExplicitSysGrant()
    {
        Assert.True(TopicFilter.Covers("$SYS/#", "$SYS/broker/clients"));
        Assert.False(TopicFilter.Covers("$SYS/#", "msh/#"));
    }

    [Fact]
    public void EmptyAllowList_DeniesEverything()
    {
        string[] none = [];
        foreach (var filter in new[] { "#", "msh/#", "msh/ES/2/e/test/#", "a", "$SYS/#", "+" })
            Assert.False(TopicFilter.IsAllowed(none, filter));
    }

    [Fact]
    public void IsAllowed_AnyEntryMayCover()
    {
        string[] allow = ["msh/ES/2/e/test/#", "msh/ES/2/e/Bots/#"];
        Assert.True(TopicFilter.IsAllowed(allow, "msh/ES/2/e/Bots/!aabbccdd"));
        Assert.True(TopicFilter.IsAllowed(allow, "msh/ES/2/e/test/+"));
        Assert.False(TopicFilter.IsAllowed(allow, "msh/ES/2/e/+/#"));
        Assert.False(TopicFilter.IsAllowed(allow, "msh/#"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("msh/#/x")]
    [InlineData("msh/te#")]
    [InlineData("msh/te+/x")]
    [InlineData("msh/+x")]
    [InlineData("msh/\0")]
    public void InvalidFilters_AreRejected(string? filter)
    {
        Assert.False(TopicFilter.IsValid(filter, out var error));
        Assert.NotNull(error);
        Assert.False(TopicFilter.IsAllowed(["#"], filter));
    }

    [Fact]
    public void InvalidRequest_IsRefusedEvenUnderAnAllowedPrefix() =>
        Assert.False(TopicFilter.IsAllowed(["msh/ES/2/e/test/#"], "msh/ES/2/e/test/#/x"));

    [Theory]
    [InlineData("#")]
    [InlineData("+")]
    [InlineData("/")]
    [InlineData("msh/ES/2/e/+/#")]
    [InlineData("$SYS/#")]
    [InlineData("$share/group/msh/#")]
    public void ValidFilters_AreAccepted(string filter) =>
        Assert.True(TopicFilter.IsValid(filter, out _));

    [Fact]
    public void SharedSubscription_IsNotAWayAround()
    {
        // $share/<group>/<filter> is literally a $-topic filter: it is never covered by a non-$ grant.
        Assert.False(TopicFilter.IsAllowed(["msh/ES/2/e/test/#"], "$share/g/msh/ES/2/e/test/#"));
        Assert.False(TopicFilter.IsAllowed(["#"], "$share/g/msh/#"));
    }

    /// <summary>
    /// Brute-force check of the subset semantics: over a small topic universe, if Covers(a, r) then
    /// every topic matched by r is matched by a.
    /// </summary>
    [Fact]
    public void Covers_IsSoundOverSmallUniverse()
    {
        string[] levels = ["a", "b", "$x", ""];
        var topics = new List<string>();
        void Build(string prefix, int depth)
        {
            if (depth > 0) topics.Add(prefix);
            if (depth == 3) return;
            foreach (var l in levels)
                Build(depth == 0 ? l : prefix + "/" + l, depth + 1);
        }
        Build("", 0);

        string[] filters = ["#", "+", "a", "a/#", "a/+", "+/#", "+/+", "a/b", "a/+/#", "+/b/#", "$x/#", "a//#", "+/+/+", "a/b/#"];
        foreach (var allowed in filters)
        foreach (var requested in filters)
        {
            if (!TopicFilter.Covers(allowed, requested))
                continue;
            foreach (var topic in topics.Where(t => Matches(requested, t)))
                Assert.True(Matches(allowed, topic), $"'{allowed}' claims to cover '{requested}' but misses topic '{topic}'");
        }
    }

    /// <summary>Reference MQTT topic matcher (spec 4.7), used only to check Covers.</summary>
    static bool Matches(string filter, string topic)
    {
        var f = filter.Split('/');
        var t = topic.Split('/');
        if (t[0].StartsWith('$') && (f[0] == "#" || f[0] == "+"))
            return false;
        for (var i = 0; i < f.Length; i++)
        {
            if (f[i] == "#") return true;
            if (i >= t.Length) return false;
            if (f[i] != "+" && f[i] != t[i]) return false;
        }
        return f.Length == t.Length;
    }
}
