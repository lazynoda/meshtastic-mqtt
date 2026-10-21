using System.Runtime.CompilerServices;
using System.Text;
using Meshtastic.Mqtt;
using Serilog.Events;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The regular expressions of the filters run on Google RE2 (through the shim of native/re2shim): the
/// budget of the distinct patterns, the memory of one pattern, the RE2 dialect, the UTF-8 text, the
/// shared instances and the native library.
/// </summary>
public sealed class Re2FilterTests
{
    static readonly string[] Users = ["meshdev", "alice"];

    /// <summary>
    /// The spam filter of the review of the regex memory, distinct by its number. With the old engine
    /// its cache grew by ~27 MB when hostile texts were matched against it.
    /// </summary>
    static string ReviewPattern(int index) => $"(?i)https?://.{{0,100}}[.](ru|cn|tk)|zq{index}x";

    /// <summary>A file with one rule of one regex condition on the text of the messages.</summary>
    static string OneRegexRule(string pattern, string name = "spam") => $"""
        users:
          meshdev:
            - name: {name}
              drop_if:
                - field: payload.text
                  op: regex
                  value: '{pattern.Replace("'", "''", StringComparison.Ordinal)}'
                  portnum: TEXT_MESSAGE_APP
              unopened: allow
        """;

    /// <summary>The problems of a file that has to fail, as one text.</summary>
    static string LoadError(string yaml)
    {
        var ex = Assert.Throws<FilterException>(() => FilterLoader.Parse(yaml, Users, "filters.yaml"));
        return string.Join(Environment.NewLine, ex.Errors);
    }

    /// <summary>The compiled pattern of the only condition of a file.</summary>
    static Re2Pattern Compile(string pattern)
    {
        var ruleset = FilterLoader.Parse(OneRegexRule(pattern), Users, "filters.yaml");
        return Assert.IsType<Re2Pattern>(ruleset.Users["meshdev"][0].DropIf![0].Pattern);
    }

    // ---- D4: the bounds of the memory ---------------------------------------------------------------------

    [Fact]
    public void D4_TheBudgetIs128PatternsOf1MiB()
    {
        Assert.Equal(128, FilterLoader.MaxRegexPatterns);
        Assert.Equal(1_048_576, FilterLoader.RegexMaxMemory);
    }

    [Fact]
    public void D4_129DistinctPatterns_IsALoadErrorAndCompilesAtMost128()
    {
        var yaml = FilterFixtures.FileWithPatterns(129, ReviewPattern);
        var ex = Assert.Throws<FilterException>(() => FilterLoader.Parse(yaml, Users, "filters.yaml"));
        var error = Assert.Single(ex.Errors);
        Assert.Equal(
            "filters.yaml: the file holds more than 128 regex patterns "
            + "(the budget of regex patterns is 128, the file has 129)",
            error);
        Assert.True(ex.CompiledPatterns <= 128, $"the loader compiled {ex.CompiledPatterns} patterns");
    }

    [Fact]
    public void D4_128DistinctPatternsOfTheReviewShape_Load()
    {
        var ruleset = FilterLoader.Parse(FilterFixtures.FileWithPatterns(128, ReviewPattern), Users, "filters.yaml");
        Assert.Equal(128, ruleset.RegexPatternCount);
        Assert.Equal(128, ruleset.RuleCount);
    }

    [Fact]
    public void D4_TheBudgetCountsTheAliasesExpanded_4000ConditionsOfOnePatternCompileOneInstance()
    {
        // One pattern behind an anchor, repeated 4000 times through the aliases: one RE2 object.
        var builder = new StringBuilder();
        builder.AppendLine("users:");
        builder.AppendLine("  meshdev:");
        builder.AppendLine("    - name: rule-0");
        builder.AppendLine("      drop_if:");
        builder.AppendLine("        - &cond");
        builder.AppendLine("          field: payload.text");
        builder.AppendLine("          op: regex");
        builder.AppendLine($"          value: '{ReviewPattern(0)}'");
        builder.AppendLine("          portnum: TEXT_MESSAGE_APP");
        builder.AppendLine("      unopened: allow");
        for (var i = 1; i <= 4; i++)
        {
            builder.AppendLine($"    - name: rule-{i}");
            builder.AppendLine($"      drop_if: [{string.Join(", ", Enumerable.Repeat("*cond", i < 4 ? 1000 : 999))}]");
            builder.AppendLine("      unopened: allow");
        }

        var ruleset = FilterLoader.Parse(builder.ToString(), Users, "filters.yaml");
        var patterns = ruleset.Users["meshdev"].SelectMany(rule => rule.DropIf!).Select(c => c.Pattern).ToArray();
        Assert.Equal(4000, patterns.Length);
        Assert.Equal(1, ruleset.RegexPatternCount);
        var only = Assert.IsType<Re2Pattern>(Assert.Single(patterns.Distinct()));
        Assert.Same(only.Handle, ((Re2Pattern)patterns[3999]!).Handle);
    }

    [Fact]
    public void D4_APatternTooBigForTheMemoryOfOnePattern_IsALoadErrorWithTheTextOfRe2()
    {
        // 100 letters of any script: the program does not fit in 1 MiB.
        var message = LoadError(OneRegexRule(@"\p{L}{100}", "too-big"));
        Assert.Contains("users.meshdev[0] (rule 'too-big')", message);
        Assert.Contains("filters.yaml:", message);
        Assert.Contains("the pattern is too big for the memory of one pattern (1048576 bytes)", message);
        Assert.Contains("pattern too large - compile failed", message);
    }

    [Fact]
    public void D4_AHostileTextIsMatchedInBoundedTime_AndTheVerdictsStayRight()
    {
        // The attack of the review: thousands of distinct texts built to grow the cache of the pattern.
        // RE2 flushes its cache when it is full, so the matches keep working and stay right.
        var pattern = Compile(@"(?i)https?://.{0,100}\.(ru|cn|tk)");
        var random = new Random(42);
        var matches = 0;
        for (var i = 0; i < 2000; i++)
        {
            var text = new StringBuilder();
            while (text.Length < 200)
                text.Append(random.Next(2) == 0 ? "http://" : "https://").Append('x', random.Next(1, 12)).Append(".r");
            if (pattern.IsMatch(text.ToString(0, 200)))
                matches++;
        }
        Assert.Equal(0, matches);
        Assert.True(pattern.IsMatch("visit http://spam.example.ru now"));
    }

    // ---- D4: the native handles of a ruleset that is dropped ----------------------------------------------------

    [MethodImpl(MethodImplOptions.NoInlining)]
    static WeakReference CompileAndDrop()
    {
        var ruleset = FilterLoader.Parse(OneRegexRule("drop-me[0-9]+"), Users, "filters.yaml");
        var pattern = (Re2Pattern)ruleset.Users["meshdev"][0].DropIf![0].Pattern!;
        Assert.False(pattern.Handle.IsInvalid);
        return new WeakReference(pattern.Handle, trackResurrection: true);
    }

    [Fact]
    public void D4_TheNativeObjectOfARulesetThatIsDropped_IsFreed()
    {
        var handle = CompileAndDrop();
        for (var i = 0; i < 5 && handle.IsAlive; i++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }
        // The SafeHandle was finalized: its ReleaseHandle freed the RE2 object.
        Assert.False(handle.IsAlive);
    }

    // ---- D5: the dialect of RE2 ---------------------------------------------------------------------------

    [Fact]
    public void D5_ALookahead_IsALoadErrorWithTheMessageOfRe2()
    {
        var message = LoadError(OneRegexRule("(?=hola).*", "lookahead"));
        Assert.Contains("rule 'lookahead'", message);
        Assert.Contains("the pattern is not a valid RE2 regular expression: invalid perl operator: (?=", message);
        Assert.Contains("RE2 has no lookahead", message);
    }

    [Fact]
    public void D5_ABackreference_IsALoadErrorWithTheMessageOfRe2()
    {
        var message = LoadError(OneRegexRule(@"(a)\1", "backreference"));
        Assert.Contains("rule 'backreference'", message);
        Assert.Contains(@"the pattern is not a valid RE2 regular expression: invalid escape sequence: \1", message);
        Assert.Contains("RE2 has no backreferences", message);
    }

    [Theory]
    [InlineData("(?<=a)b", "invalid perl operator: (?<")]      // a lookbehind
    [InlineData("(?>ab)c", "invalid perl operator: (?>")]      // an atomic group
    [InlineData("a*+b", "bad repetition operator: *+")]         // a possessive quantifier
    [InlineData(@"end\Z", @"invalid escape sequence: \Z")]      // \Z of .NET
    [InlineData(@"\p{IsGreek}", "invalid character class range: \\p{IsGreek}")]   // a .NET-only class
    public void D5_TheConstructsRe2DoesNotHave_AreLoadErrors(string pattern, string re2Error)
    {
        var message = LoadError(OneRegexRule(pattern));
        Assert.Contains("the pattern is not a valid RE2 regular expression: " + re2Error, message);
    }

    [Fact]
    public void D5_DigitIsAsciiInRe2_AndPNdIsEveryDigit()
    {
        // \d is ASCII in RE2 (it was Unicode in .NET): an Arabic-Indic three is not \d, it is \p{Nd}.
        const string arabicIndicThree = "\u0663";
        Assert.False(Compile(@"\d").IsMatch(arabicIndicThree));
        Assert.True(Compile(@"\p{Nd}").IsMatch(arabicIndicThree));
        Assert.True(Compile(@"\d").IsMatch("canal 7"));
    }

    [Fact]
    public void D5_WordIsAsciiInRe2_AndPLIsEveryLetter()
    {
        Assert.False(Compile(@"^\w+$").IsMatch("señal"));
        Assert.True(Compile(@"^\p{L}+$").IsMatch("señal"));
        Assert.True(Compile(@"^[[:alpha:]]+$").IsMatch("senal"));
    }

    [Fact]
    public void D5_IgnoreCaseIsWrittenInThePattern()
    {
        Assert.True(Compile("(?i)COMPRA").IsMatch("compra ya"));
        Assert.False(Compile("COMPRA").IsMatch("compra ya"));
    }

    /// <summary>Every row of the tables of the dialect in docs/filters.md, as the docs state it.</summary>
    [Theory]
    [InlineData(@"\s", "\u00a0", false)]                 // \s is ASCII: a no-break space is not \s
    [InlineData(@"[\s\p{Z}]", "\u00a0", true)]
    [InlineData(@"\bal\b", "señal", true)]               // \b is ASCII: ñ is not a word character
    [InlineData(@"(^|[^\p{L}])al([^\p{L}]|$)", "señal", false)]
    [InlineData(@"(^|[^\p{L}])compra([^\p{L}]|$)", "compra ya", true)]
    [InlineData(@"^[\p{L}\p{N}_]+$", "señal_3", true)]
    [InlineData(@"^\w+$", "senal_3", true)]
    [InlineData(@"^[[:alpha:]]+$", "señal", false)]
    [InlineData(@"(?P<name>a)b", "ab", true)]            // a named group, the RE2 way
    [InlineData(@"fin\z", "el fin", true)]
    [InlineData(@"\p{L}+", "ñ", true)]
    public void D5_TheTablesOfTheDialectInTheDocs_AreRight(string pattern, string text, bool matches)
    {
        Assert.Equal(matches, Compile(pattern).IsMatch(text));
    }

    // ---- D3: the text is UTF-8 ----------------------------------------------------------------------------

    [Fact]
    public void D3_SpanishAccentsAndEmoji_MatchThroughTheUtf8Path()
    {
        Assert.True(Compile("(?i)ÁRBOL").IsMatch("un árbol caído en la vía"));
        Assert.True(Compile("señal débil").IsMatch("Buena señal débil desde Zaragoza 🙂"));
        Assert.True(Compile("🙂$").IsMatch("hola 🙂"));
        // One emoji is one character for RE2 (two UTF-16 units in .NET).
        Assert.True(Compile("^.$").IsMatch("🙂"));
        Assert.True(Compile("^ñ.o$").IsMatch("ñuo"));
        Assert.False(Compile("^ñ.o$").IsMatch("ñuuo"));
    }

    [Fact]
    public void D3_ALongTextIsMatchedThroughThePooledBuffer()
    {
        // Longer than the buffer on the stack: the pooled buffer is used, and the match is the same.
        var text = string.Concat(Enumerable.Repeat("ñ", 2000)) + " fin 🙂";
        Assert.True(Compile("^ñ+ fin 🙂$").IsMatch(text));
        Assert.False(Compile("^ñ+ fin$").IsMatch(text));
        Assert.True(Compile("^ñ+ fin$").IsMatch(text[..^3]));
        Assert.False(Compile("x").IsMatch(string.Empty));
        Assert.True(Compile("^$").IsMatch(string.Empty));
    }

    [Fact]
    public void D3_AMatchingTextPacketIsDropped_AndAnotherPasses()
    {
        var file = FilterFixtures.WriteFile(OneRegexRule("(?i)señal (débil|mala)", "bad-signal"));
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);
            var topic = FilterFixtures.Topic("Test", FilterFixtures.Gateway);

            var dropped = FilterFixtures.TextPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                "Aquí SEÑAL DÉBIL 🙁");
            var verdict = filter.Evaluate(FilterFixtures.Input(config, topic, dropped));
            Assert.False(verdict.Passed);
            Assert.Equal("bad-signal", verdict.RuleName);

            var passed = FilterFixtures.TextPacket(config, "Test", FilterFixtures.Node, 2, FilterFixtures.Gateway,
                "Aquí señal buena 🙂");
            Assert.True(filter.Evaluate(FilterFixtures.Input(config, topic, passed)).Passed);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    // ---- D6: one shared instance, many threads ------------------------------------------------------------------

    [Fact]
    public void D6_ASharedInstance_IsMatchedFromManyThreadsAtOnce()
    {
        var pattern = Compile(@"(?i)https?://.{0,100}\.(ru|cn|tk)");
        string[] texts =
        [
            "http://x.ru", "nada que ver", "https://a.b.c.cn/abc", "http://xx.r http://x.r", "HTTP://SPAM.TK",
            "señal 🙂 https://ejemplo.es",
        ];
        bool[] expected = [true, false, true, false, true, false];
        var failures = 0;
        Parallel.For(0, 64, new ParallelOptions { MaxDegreeOfParallelism = 16 }, worker =>
        {
            var random = new Random(worker);
            for (var i = 0; i < 2000; i++)
            {
                var k = random.Next(texts.Length);
                // A hostile text now and then, so the threads also flush and rebuild the cache at once.
                if (i % 50 == 0)
                    pattern.IsMatch(string.Concat(Enumerable.Repeat($"http://{worker}{i}.r", 20)));
                if (pattern.IsMatch(texts[k]) != expected[k])
                    Interlocked.Increment(ref failures);
            }
        });
        Assert.Equal(0, failures);
    }

    // ---- D2: the native library ---------------------------------------------------------------------------

    [Fact]
    public void D2_TheShimIsLoaded_AndHasTheApiOfThisCode()
    {
        // The suite runs on the real RE2: a host without the shim fails here with the clear message.
        Assert.Null(Re2.UnavailableReason);
    }

    [Fact]
    public void D2_AMissingNativeLibrary_IsAClearError()
    {
        var reason = Re2.LoadError("re2shim-that-is-not-there");
        Assert.NotNull(reason);
        Assert.StartsWith("the native library of the regular expressions (libre2shim-that-is-not-there.so, Google RE2) "
            + "cannot be loaded: ", reason);
        Assert.Contains("native/re2shim/build.sh", reason);
        Assert.Contains("docs/operations.md", reason);
    }

    // ---- R9: a bad file on reload keeps the rules in force ------------------------------------------------------

    [Theory]
    [InlineData("budget")]
    [InlineData("lookahead")]
    [InlineData("too-big")]
    public void R9_AReloadWithABadRegexFile_KeepsTheRulesInForceAndWarnsOnce(string bad)
    {
        var file = FilterFixtures.WriteFile(OneRegexRule("buy[ ]+now", "old"));
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, logs) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);
            var before = filter.Ruleset;

            var (yaml, expected) = bad switch
            {
                "budget" => (FilterFixtures.FileWithPatterns(129, ReviewPattern), "(the budget of regex patterns is 128, the file has 129)"),
                "lookahead" => (OneRegexRule("(?!x)y", "new"), "invalid perl operator: (?!"),
                _ => (OneRegexRule(@"\p{L}{100}", "new"), "pattern too large - compile failed"),
            };
            File.WriteAllText(file, yaml);
            File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddSeconds(5));
            filter.CheckForChange();
            filter.CheckForChange();

            Assert.Same(before, filter.Ruleset);
            var topic = FilterFixtures.Topic("Test", FilterFixtures.Gateway);
            var spam = FilterFixtures.TextPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway, "buy  now");
            Assert.Equal("old", filter.Evaluate(FilterFixtures.Input(config, topic, spam)).RuleName);
            var warning = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Warning);
            Assert.Contains(expected, warning.RenderMessage());
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void R9_AReloadChainOfRegexFiles_SwapsTheRules()
    {
        var file = FilterFixtures.WriteFile(string.Empty);
        try
        {
            var config = FilterFixtures.Config(file);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);
            for (var round = 0; round < 3; round++)
            {
                File.WriteAllText(file, FilterFixtures.FileWithPatterns(128, ReviewPattern));
                File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddSeconds(10 * round + 1));
                filter.CheckForChange();
                Assert.Equal(128, filter.Ruleset.RegexPatternCount);

                File.WriteAllText(file, string.Empty);
                File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddSeconds(10 * round + 6));
                filter.CheckForChange();
                Assert.Equal(0, filter.RuleCount);
            }
            Assert.Equal(0, filter.Ruleset.RegexPatternCount);
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }
}
