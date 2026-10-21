using System.Globalization;
using System.Text;
using Meshtastic.Mqtt;
using Meshtastic.Protobufs;
using Serilog.Events;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// A rules file the test drives by hand: it counts the reads of the content and it may block one of
/// them, so the tests of the reload never sleep.
/// </summary>
sealed class FakeFilterFile : IFilterFile
{
    readonly object _lock = new();
    string _text;
    DateTimeOffset _mtime = new(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);
    int _hashReads;
    int _textReads;
    bool _blockNext;
    bool _blocked;
    bool _released;

    public FakeFilterFile(string text) => _text = text;

    /// <summary>How many times the content of the file was read (the hash).</summary>
    public int HashReads
    {
        get { lock (_lock) return _hashReads; }
    }

    /// <summary>How many times the file was read to compile the rules.</summary>
    public int TextReads
    {
        get { lock (_lock) return _textReads; }
    }

    /// <summary>Changes the content of the file (and its time).</summary>
    public void Change(string text, DateTimeOffset? mtime = null)
    {
        lock (_lock)
        {
            _text = text;
            if (mtime is not null)
                _mtime = mtime.Value;
        }
    }

    /// <summary>The next read of the file blocks until the test releases it.</summary>
    public void BlockNextRead()
    {
        lock (_lock)
        {
            _blockNext = true;
            _blocked = false;
            _released = false;
        }
    }

    /// <summary>Waits until a read is blocked (the test waits for the signal, it does not sleep).</summary>
    public void WaitUntilBlocked()
    {
        lock (_lock)
        {
            var deadline = DateTime.UtcNow.AddSeconds(30);
            while (!_blocked && DateTime.UtcNow < deadline)
                Monitor.Wait(_lock, 20);
            Assert.True(_blocked, "the read of the file did not block");
        }
    }

    /// <summary>Releases the blocked read.</summary>
    public void Release()
    {
        lock (_lock)
        {
            _released = true;
            Monitor.PulseAll(_lock);
        }
    }

    public FilterFileInfo? Stat(string path)
    {
        lock (_lock)
        {
            return new FilterFileInfo(Encoding.UTF8.GetByteCount(_text), _mtime);
        }
    }

    public byte[]? ReadAllBytes(string path)
    {
        lock (_lock)
        {
            _hashReads++;
            return Encoding.UTF8.GetBytes(_text);
        }
    }

    public string? ReadAllText(string path)
    {
        lock (_lock)
        {
            _textReads++;
            var text = _text;
            if (_blockNext)
            {
                _blockNext = false;
                _blocked = true;
                Monitor.PulseAll(_lock);
                while (!_released)
                    Monitor.Wait(_lock, 20);
                _blocked = false;
            }
            return text;
        }
    }
}

/// <summary>
/// The hot reload of the rules file: the file is checked again and again, a valid change is applied at
/// once and an invalid one keeps the rules that are in force.
/// </summary>
public sealed class FilterReloadTests
{
    const string OneRule = """
        users:
          meshdev:
            - name: alpha
              channels:
                allow: [Iberia]
        """;

    const string TwoRules = """
        users:
          meshdev:
            - name: beta
              channels:
                allow: [Iberia]
            - name: gamma
              channels:
                allow: [Iberia]
        """;

    const string ThreeRules = """
        users:
          meshdev:
            - name: beta
              channels:
                allow: [Iberia]
            - name: gamma
              channels:
                allow: [Iberia]
            - name: delta
              channels:
                allow: [Iberia]
        """;

    /// <summary>The same rule with another name: the file keeps its size and its time.</summary>
    const string OneRuleWithAnotherName = """
        users:
          meshdev:
            - name: omega
              channels:
                allow: [Iberia]
        """;

    /// <summary>A file that is not valid: the rules that are in force stay in force.</summary>
    const string BrokenFile = """
        users:
          meshdev:
            - name: broken
              channels:
                allow: [Iberia]
                deny: [Test]
        """;

    static string Write(string path, string yaml)
    {
        File.WriteAllText(path, yaml);
        return path;
    }

    [Fact]
    public void R9_AValidChangeIsAppliedAtOnce()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mmqtt-filters-{Guid.NewGuid():N}.yaml");
        try
        {
            Write(path, OneRule);
            var config = FilterFixtures.Config(path);
            var (logger, logs) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);
            Assert.Equal(1, filter.RuleCount);

            Write(path, TwoRules);
            filter.CheckForChange();

            Assert.Equal(2, filter.RuleCount);
            var reload = Assert.Single(logs.Events, e => e.MessageTemplate.Text.StartsWith("Filters reloaded"));
            Assert.Equal(LogEventLevel.Information, reload.Level);
            Assert.Contains("2 rules", reload.RenderMessage());
            Assert.Contains("sha256", reload.RenderMessage());
        }
        finally
        {
            FilterFixtures.Delete(path);
        }
    }

    [Fact]
    public void R9_AnInvalidChangeKeepsTheRulesThatAreInForceAndIsReportedOnce()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mmqtt-filters-{Guid.NewGuid():N}.yaml");
        try
        {
            Write(path, OneRule);
            var config = FilterFixtures.Config(path);
            var (logger, logs) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            Write(path, "users:\n  meshdev:\n    - name: broken\n      channels:\n        allow: [Iberia]\n        deny: [Test]\n");
            filter.CheckForChange();

            // The rules that were in force are still in force.
            Assert.Equal(1, filter.RuleCount);
            var warning = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Warning);
            Assert.Contains("broken", warning.RenderMessage());
            Assert.Contains(path, warning.RenderMessage());

            // The second poll of the same file says nothing: the problem was already reported.
            filter.CheckForChange();
            Assert.Single(logs.Events, e => e.Level == LogEventLevel.Warning);

            // A new file is reported again.
            Write(path, "users:\n  meshdev:\n    - name: broken-again\n      channels:\n        allow: [Iberia]\n        deny: [Test]\n");
            filter.CheckForChange();
            Assert.Equal(2, logs.Events.Count(e => e.Level == LogEventLevel.Warning));
        }
        finally
        {
            FilterFixtures.Delete(path);
        }
    }

    [Fact]
    public void R9_AFileThatChangesNothingIsNotReadAgain()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mmqtt-filters-{Guid.NewGuid():N}.yaml");
        try
        {
            Write(path, OneRule);
            var config = FilterFixtures.Config(path);
            var (logger, logs) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            filter.CheckForChange();
            filter.CheckForChange();

            Assert.DoesNotContain(logs.Events, e => e.MessageTemplate.Text.StartsWith("Filters reloaded"));
        }
        finally
        {
            FilterFixtures.Delete(path);
        }
    }

    [Fact]
    public void R9_AnInvalidFileAtStartupIsAStartError()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mmqtt-filters-{Guid.NewGuid():N}.yaml");
        try
        {
            Write(path, "users:\n  meshdev:\n    - name: broken\n      channels:\n        allow: [Iberia]\n        deny: [Test]\n");
            var config = FilterFixtures.Config(path);
            var (logger, _) = FilterFixtures.Logger();

            var ex = Assert.Throws<FilterException>(() => new PacketFilter(config, logger, startWatcher: false));
            Assert.Contains("broken", ex.Message);

            // The broker of the tests and the real one are the same: the broker does not start either.
            Assert.Throws<FilterException>(() => BrokerServer.Create(config, logger));
        }
        finally
        {
            FilterFixtures.Delete(path);
        }
    }

    [Fact]
    public void R9_AMissingFileAtStartupIsAStartError()
    {
        var config = FilterFixtures.Config("/nonexistent/filters.yaml");
        var (logger, _) = FilterFixtures.Logger();
        Assert.Throws<FilterException>(() => new PacketFilter(config, logger, startWatcher: false));
    }

    [Fact]
    public async Task R9_TheCliExitsWithOneWhenTheFileIsNotValid()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mmqtt-filters-{Guid.NewGuid():N}.yaml");
        var configPath = Path.Combine(Path.GetTempPath(), $"mmqtt-config-{Guid.NewGuid():N}.yaml");
        try
        {
            Write(path, "users:\n  meshdev:\n    - name: broken\n      channels:\n        allow: [Iberia]\n        deny: [Test]\n");
            File.WriteAllText(configPath, $"users:\n  - username: meshdev\n    password_hash: \"{AuthTests.AliceHash}\"\nfilters:\n  file: \"{path}\"\n");

            Assert.Equal(1, await global::Cli.RunAsync([configPath]));
        }
        finally
        {
            FilterFixtures.Delete(path, configPath);
        }
    }

    [Fact]
    public void R9_TheReloadLine_SaysTheNumberOfRulesAndTheHashOfTheFile()
    {
        // The line of the reload, exactly as it is written.
        var path = Path.Combine(Path.GetTempPath(), $"mmqtt-filters-{Guid.NewGuid():N}.yaml");
        try
        {
            Write(path, TwoRules);
            var config = FilterFixtures.Config(path);
            var (logger, logs) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            Write(path, OneRule);
            filter.CheckForChange();

            var line = Assert.Single(logs.Events, e => e.MessageTemplate.Text.StartsWith("Filters reloaded"))
                .RenderMessage();
            Assert.Matches(@"^Filters reloaded: 1 rule \(1 user, 0 gateway, 0 node rules\), sha256 [0-9a-f]{8}$",
                line);
        }
        finally
        {
            FilterFixtures.Delete(path);
        }
    }

    [Fact]
    public void N2_TheReloadLine_PluralisesTheRules()
    {
        // One rule is "1 rule" and two rules are "2 rules".
        var file = new FakeFilterFile(OneRule);
        var config = FilterFixtures.Config("/fake/filters.yaml");
        var (logger, logs) = FilterFixtures.Logger();
        using var filter = new PacketFilter(config, logger, startWatcher: false, TimeProvider.System, file);

        file.Change(TwoRules);
        filter.CheckForChange();
        var two = Assert.Single(logs.Events, e => e.MessageTemplate.Text.StartsWith("Filters reloaded"));
        Assert.Contains("2 rules", two.RenderMessage());

        file.Change(OneRule);
        filter.CheckForChange();
        var one = Assert.Single(logs.Events, e => e.MessageTemplate.Text.StartsWith("Filters reloaded")
            && e.RenderMessage().Contains("1 rule"));
        Assert.Contains("1 rule", one.RenderMessage());
        Assert.DoesNotContain("1 rules", one.RenderMessage());
    }

    [Fact]
    public async Task N1_TwoConcurrentChecks_ReloadTheFileOnlyOnce()
    {
        // The timer and the SIGHUP of the operator may run at once: the file is read once and the
        // reload line is written once.
        var file = new FakeFilterFile(OneRule);
        var config = FilterFixtures.Config("/fake/filters.yaml");
        var (logger, logs) = FilterFixtures.Logger();
        using var filter = new PacketFilter(config, logger, startWatcher: false, TimeProvider.System, file);

        // The file changes and the read of it blocks: the check is inside the file.
        file.Change(TwoRules);
        file.BlockNextRead();
        var running = Task.Run(() => filter.CheckForChange(), TestContext.Current.CancellationToken);
        file.WaitUntilBlocked();

        // The second check finds a check running: it returns without doing anything.
        filter.CheckForChange();
        file.Release();
        await running;

        Assert.Equal(2, filter.RuleCount);
        Assert.Single(logs.Events, e => e.MessageTemplate.Text.StartsWith("Filters reloaded"));
    }

    [Fact]
    public async Task N1_ASighupWhileACheckRuns_RechecksAtTheEnd()
    {
        // The SIGHUP of the operator asks for a check: the one that is running re-checks at the end, so
        // a change that came while it was reading the file is not lost.
        var file = new FakeFilterFile(OneRule);
        var config = FilterFixtures.Config("/fake/filters.yaml");
        var (logger, logs) = FilterFixtures.Logger();
        using var filter = new PacketFilter(config, logger, startWatcher: false, TimeProvider.System, file);

        file.Change(TwoRules);
        file.BlockNextRead();
        var running = Task.Run(() => filter.CheckForChange(), TestContext.Current.CancellationToken);
        file.WaitUntilBlocked();

        // The file changes again and the operator asks for a reload.
        file.Change(ThreeRules);
        filter.ReloadNow();
        file.Release();
        await running;

        Assert.Equal(3, filter.RuleCount);
        Assert.Equal(2, logs.Events.Count(e => e.MessageTemplate.Text.StartsWith("Filters reloaded")));
    }

    [Fact]
    public void N5_TheFileIsNotRead_WhenItDidNotChange()
    {
        // The poll only looks at the size and the time of the file: a file that did not change is not
        // read again.
        var file = new FakeFilterFile(OneRule);
        var config = FilterFixtures.Config("/fake/filters.yaml");
        var (logger, logs) = FilterFixtures.Logger();
        using var filter = new PacketFilter(config, logger, startWatcher: false, TimeProvider.System, file);

        var reads = file.HashReads;
        filter.CheckForChange();
        filter.CheckForChange();

        Assert.Equal(reads, file.HashReads);
        Assert.DoesNotContain(logs.Events, e => e.MessageTemplate.Text.StartsWith("Filters reloaded"));
    }

    [Fact]
    public void N5_TheFileIsRead_WhenItsSizeOrItsTimeChanges()
    {
        var file = new FakeFilterFile(OneRule);
        var config = FilterFixtures.Config("/fake/filters.yaml");
        var (logger, logs) = FilterFixtures.Logger();
        using var filter = new PacketFilter(config, logger, startWatcher: false, TimeProvider.System, file);

        var reads = file.HashReads;

        // The size of the file changes.
        file.Change(TwoRules);
        filter.CheckForChange();
        Assert.Equal(reads + 1, file.HashReads);

        // The size is the same and the time of the file changes.
        file.Change(TwoRules, new DateTimeOffset(2024, 1, 1, 0, 1, 0, TimeSpan.Zero));
        filter.CheckForChange();
        Assert.Equal(reads + 2, file.HashReads);
    }

    [Fact]
    public void N5_TheFileIsReadAgain_AfterAMinuteEvenIfItDidNotChange()
    {
        // The safety net: a file that is edited with the same size and the same time is still seen.
        var clock = new FakeClock();
        var file = new FakeFilterFile(OneRule);
        var config = FilterFixtures.Config("/fake/filters.yaml");
        var (logger, logs) = FilterFixtures.Logger();
        using var filter = new PacketFilter(config, logger, startWatcher: false, clock, file);

        var reads = file.HashReads;
        filter.CheckForChange();
        Assert.Equal(reads, file.HashReads);

        clock.Advance(TimeSpan.FromSeconds(60));
        filter.CheckForChange();
        Assert.Equal(reads + 1, file.HashReads);

        // The hash that was just read is fresh: the file is not read again until the next minute.
        filter.CheckForChange();
        Assert.Equal(reads + 1, file.HashReads);

        clock.Advance(TimeSpan.FromSeconds(60));
        filter.CheckForChange();
        Assert.Equal(reads + 2, file.HashReads);
    }

    [Fact]
    public void N5_AFileWhoseLoadFailed_IsNotReadAgainUntilTheNextMinute()
    {
        // The same, for a file whose load failed: the problem is reported once and the file is not read
        // again until the next minute.
        var clock = new FakeClock();
        var file = new FakeFilterFile(OneRule);
        var config = FilterFixtures.Config("/fake/filters.yaml");
        var (logger, logs) = FilterFixtures.Logger();
        using var filter = new PacketFilter(config, logger, startWatcher: false, clock, file);

        // The file breaks: the rules that are in force stay in force and the problem is reported.
        file.Change(BrokenFile);
        filter.CheckForChange();
        Assert.Equal(1, filter.RuleCount);
        Assert.Single(logs.Events, e => e.Level == LogEventLevel.Warning);

        var reads = file.HashReads;
        filter.CheckForChange();
        Assert.Equal(reads, file.HashReads);
        Assert.Single(logs.Events, e => e.Level == LogEventLevel.Warning);

        clock.Advance(TimeSpan.FromSeconds(60));
        filter.CheckForChange();
        Assert.Equal(reads + 1, file.HashReads);
        Assert.Single(logs.Events, e => e.Level == LogEventLevel.Warning);

        filter.CheckForChange();
        Assert.Equal(reads + 1, file.HashReads);
    }

    [Fact]
    public void N5_ASighupReadsTheContent_EvenWhenTheSizeAndTheTimeDidNotChange()
    {
        // The SIGHUP of the operator always reads the file: an edit that keeps its size and its time is
        // applied at once. The poll of the timer does not read it.
        var clock = new FakeClock();
        var file = new FakeFilterFile(OneRule);
        var config = FilterFixtures.Config("/fake/filters.yaml");
        var (logger, logs) = FilterFixtures.Logger();
        using var filter = new PacketFilter(config, logger, startWatcher: false, clock, file);

        // The content changes and the size and the time of the file do not.
        file.Change(OneRuleWithAnotherName);
        var reads = file.HashReads;

        // The poll of the timer does not read the file.
        filter.CheckForChange();
        Assert.Equal(reads, file.HashReads);
        Assert.Equal("alpha", RuleThatRefused(filter));

        // The SIGHUP reads it: the rules are in force at once.
        filter.ReloadNow();
        Assert.Equal(reads + 1, file.HashReads);
        Assert.Equal("omega", RuleThatRefused(filter));
        Assert.Single(logs.Events, e => e.MessageTemplate.Text.StartsWith("Filters reloaded"));
    }

    /// <summary>The rule that refused a packet of a channel that is not in its allow-list.</summary>
    static string? RuleThatRefused(PacketFilter filter)
    {
        var input = new FilterInput("meshdev", "!a1b2c3d4", 0xa1b2c3d4, 0xdeadbeef, "Test",
            "msh/ES/2/e/Test/!a1b2c3d4", null, null, null);
        return filter.Evaluate(input).RuleName;
    }

    [Fact]
    public void R9_TheWarningOfABrokenFile_SaysWhatIsWrong()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mmqtt-filters-{Guid.NewGuid():N}.yaml");
        try
        {
            Write(path, OneRule);
            var config = FilterFixtures.Config(path);
            var (logger, logs) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            Write(path, "users:\n  meshdev:\n    - name: broken\n      channels:\n        allow: [Iberia]\n        deny: [Test]\n");
            filter.CheckForChange();

            // The warning, exactly as it is written: the file, the line and the problem.
            var message = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Warning).RenderMessage();
            Assert.StartsWith("The filters were not reloaded, the rules that are in force stay in force: ", message);
            Assert.Contains(path, message);
            Assert.Contains("'channels' has both 'allow' and 'deny'", message);
        }
        finally
        {
            FilterFixtures.Delete(path);
        }
    }

    [Fact]
    public void R9_ReloadNow_AppliesTheChangeAtOnce()
    {
        // This is what the SIGHUP of the operator does.
        var path = Path.Combine(Path.GetTempPath(), $"mmqtt-filters-{Guid.NewGuid():N}.yaml");
        try
        {
            Write(path, OneRule);
            var config = FilterFixtures.Config(path);
            var (logger, logs) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);
            Assert.Equal(1, filter.RuleCount);

            Write(path, TwoRules);
            filter.ReloadNow();

            Assert.Equal(2, filter.RuleCount);
            Assert.Single(logs.Events, e => e.MessageTemplate.Text.StartsWith("Filters reloaded"));
        }
        finally
        {
            FilterFixtures.Delete(path);
        }
    }

    [Fact]
    public async Task R9_TheReadersNeverSeeAHalfBuiltRuleset()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mmqtt-filters-{Guid.NewGuid():N}.yaml");
        try
        {
            Write(path, OneRule);
            var config = FilterFixtures.Config(path);
            var (logger, _) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            var packet = FilterFixtures.ChannelPacket(config, "Test", FilterFixtures.Node, 1, FilterFixtures.Gateway,
                PortNum.TextMessageApp, "hola"u8.ToArray());
            var input = FilterFixtures.Input(config, FilterFixtures.Topic("Test", FilterFixtures.Gateway), packet);

            var running = true;
            var failures = 0;
            var readers = Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
            {
                var rounds = 0;
                while (Volatile.Read(ref running) && rounds < 100_000)
                {
                    rounds++;
                    // The ruleset is one object: the rule that refused the packet and the number of
                    // rules of the file always belong to the same file.
                    var ruleset = filter.Ruleset;
                    var verdict = ruleset.Evaluate(input);
                    var expected = ruleset.RuleCount == 1 ? "alpha" : "beta";
                    if (verdict.RuleName != expected)
                        Interlocked.Increment(ref failures);
                }
            })).ToArray();

            for (var i = 0; i < 500; i++)
            {
                Write(path, i % 2 == 0 ? TwoRules : OneRule);
                filter.CheckForChange();
            }
            Volatile.Write(ref running, false);
            await Task.WhenAll(readers);

            Assert.Equal(0, failures);
        }
        finally
        {
            FilterFixtures.Delete(path);
        }
    }

    // ---- X1: a file that is over the budget of its patterns ---------------------------------------------------

    [Fact]
    public void X1_AFileWithTooManyPatternsOnReload_KeepsTheRulesInForce()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mmqtt-filters-{Guid.NewGuid():N}.yaml");
        try
        {
            Write(path, OneRule);
            var config = FilterFixtures.Config(path);
            var (logger, logs) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            // The shape of the review, one distinct pattern over the budget of the file: it does not
            // load.
            Write(path, FilterFixtures.FileWithPatterns(FilterLoader.MaxRegexPatterns + 1,
                index => $"(?i)https?://.{{0,100}}[.](ru|cn|tk)|zq{index}x"));
            filter.CheckForChange();

            // The rules that are in force stay in force, and the problem is reported once.
            Assert.Equal(1, filter.RuleCount);
            var warning = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Warning);
            Assert.Contains("regex patterns", warning.RenderMessage());
        }
        finally
        {
            FilterFixtures.Delete(path);
        }
    }

    // ---- X2: a file that is over the budget of its size --------------------------------------------------------

    [Fact]
    public void X2_AnOversizeFileAtStartup_IsASizeErrorAndTheFileIsNotRead()
    {
        var file = new FakeFilterFile(OversizeText());
        var config = FilterFixtures.Config("/fake/filters.yaml");
        var (logger, _) = FilterFixtures.Logger();

        var ex = Assert.Throws<FilterException>(() =>
            new PacketFilter(config, logger, startWatcher: false, TimeProvider.System, file));
        Assert.Contains("bigger than", ex.Message);
        Assert.Contains(FilterLoader.MaxFileBytes.ToString(CultureInfo.InvariantCulture), ex.Message);

        // The file was not read: its size was enough to refuse it.
        Assert.Equal(0, file.HashReads);
        Assert.Equal(0, file.TextReads);
    }

    [Fact]
    public void X2_AnOversizeFileOnReload_IsOneWarningAndTheRulesInForceStay()
    {
        var file = new FakeFilterFile(OneRule);
        var config = FilterFixtures.Config("/fake/filters.yaml");
        var (logger, logs) = FilterFixtures.Logger();
        using var filter = new PacketFilter(config, logger, startWatcher: false, TimeProvider.System, file);
        var hashReads = file.HashReads;
        var textReads = file.TextReads;

        // The file grows over the budget of its size.
        file.Change(OversizeText());
        filter.CheckForChange();

        // The rules that are in force stay in force, and the problem is reported once.
        Assert.Equal(1, filter.RuleCount);
        var warning = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Warning);
        Assert.Contains("bigger than", warning.RenderMessage());
        Assert.Contains(FilterLoader.MaxFileBytes.ToString(CultureInfo.InvariantCulture), warning.RenderMessage());

        // The file was not read: its size was enough to refuse it.
        Assert.Equal(hashReads, file.HashReads);
        Assert.Equal(textReads, file.TextReads);

        // The second poll of the same file does not report it again.
        filter.CheckForChange();
        Assert.Single(logs.Events, e => e.Level == LogEventLevel.Warning);
    }

    /// <summary>A file that is over the budget of its size.</summary>
    static string OversizeText() => new('x', FilterLoader.MaxFileBytes + 1);

    // ---- X4: the report of a file with many problems ----------------------------------------------------------

    [Fact]
    public void X4_TheWarningOfABrokenFileWithManyProblems_ListsTwentyAndCountsTheRest()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mmqtt-filters-{Guid.NewGuid():N}.yaml");
        try
        {
            Write(path, OneRule);
            var config = FilterFixtures.Config(path);
            var (logger, logs) = FilterFixtures.Logger();
            using var filter = new PacketFilter(config, logger, startWatcher: false);

            // Ten thousand rules with the same name: nine thousand nine hundred and ninety-nine
            // problems. The Warning lists the first twenty and counts the rest.
            Write(path, FilterFixtures.FileWithDuplicateNames());
            filter.CheckForChange();

            // The rules that are in force stay in force.
            Assert.Equal(1, filter.RuleCount);
            var message = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Warning).RenderMessage();
            Assert.Contains("... and 9979 more errors", message);
            Assert.Equal(FilterException.MaxReportedErrors + 1, message.Split("; ").Length);

            // The report is small: a broken file does not write a megabyte of log.
            Assert.True(message.Length < 8 * 1024, $"the report is {message.Length} characters");
        }
        finally
        {
            FilterFixtures.Delete(path);
        }
    }
}
