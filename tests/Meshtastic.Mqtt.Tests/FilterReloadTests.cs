using Meshtastic.Mqtt;
using Meshtastic.Protobufs;
using Serilog.Events;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

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
            Assert.Matches(@"^Filters reloaded: 1 rules \(1 user, 0 gateway, 0 node scopes\), sha256 [0-9a-f]{8}$",
                line);
        }
        finally
        {
            FilterFixtures.Delete(path);
        }
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
}
