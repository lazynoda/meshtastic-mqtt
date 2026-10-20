using Meshtastic.Mqtt;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Xunit;
using static Meshtastic.Mqtt.Tests.TestSupport;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The startup line: the address is written as it is, so the line reads without quotes around it.
/// </summary>
public sealed class StartupLineTests
{
    [Fact]
    public void TheStartupLine_RendersTheAddressWithoutQuotes()
    {
        var config = TestSupport.Config(1883);
        var logs = new LogSink();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger();

        StartupLine.Write(logger, config);

        var startup = Assert.Single(logs.Events, e => e.Level == LogEventLevel.Information);
        var message = startup.RenderMessage();

        // The line reads as it is: the address is not wrapped in quotes.
        Assert.DoesNotContain('"', message);
        Assert.Contains($"Listening on {config.BindAddress}:{config.Listener.Port} (plain MQTT)", message);

        // The address is rendered as a literal, so the formatter does not quote it.
        Assert.Contains("{Address:l}", startup.MessageTemplate.Text);
    }

    [Fact]
    public void TheStartupLine_SaysWhetherTheFiltersAreOnAndHowManyRulesTheyHold()
    {
        var config = TestSupport.Config(1883);
        var logs = new LogSink();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger();

        // The broker of Program, built the same way: without a filters section there are no filters,
        // even though the broker holds a filter object (the one that watches a file that is not there).
        var built = BrokerServer.Create(config, logger);
        try
        {
            StartupLine.Write(logger, config, built.Filter);
            Assert.Contains("filters=off", Assert.Single(logs.Events).RenderMessage());
        }
        finally
        {
            built.Filter.Dispose();
        }

        // With a rules file: the line says how many rules are in force.
        logs.Events.Clear();
        var file = FilterFixtures.WriteFile("""
            users:
              meshdev:
                - name: only-iberia
                  channels:
                    allow: [Iberia]
            """);
        try
        {
            var withFilters = FilterFixtures.Config(file);
            var withBuilt = BrokerServer.Create(withFilters, logger);
            try
            {
                StartupLine.Write(logger, withFilters, withBuilt.Filter);
                Assert.Contains("filters=on (1 rule)", Assert.Single(logs.Events).RenderMessage());
            }
            finally
            {
                withBuilt.Filter.Dispose();
            }
        }
        finally
        {
            FilterFixtures.Delete(file);
        }
    }

    [Fact]
    public void N2_TheStartupLine_PluralisesTheRules()
    {
        // One rule is "1 rule" and two rules are "2 rules".
        var logs = new LogSink();
        var logger = new LoggerConfiguration().MinimumLevel.Verbose().WriteTo.Sink(logs).CreateLogger();

        var one = FilterFixtures.WriteFile("""
            users:
              meshdev:
                - name: only-iberia
                  channels:
                    allow: [Iberia]
            """);
        var two = FilterFixtures.WriteFile("""
            users:
              meshdev:
                - name: only-iberia
                  channels:
                    allow: [Iberia]
                - name: no-private
                  channels:
                    deny: [Private]
            """);
        try
        {
            foreach (var (file, expected) in new[] { (one, "filters=on (1 rule)"), (two, "filters=on (2 rules)") })
            {
                var config = FilterFixtures.Config(file);
                var built = BrokerServer.Create(config, logger);
                try
                {
                    StartupLine.Write(logger, config, built.Filter);
                    Assert.Contains(expected, Assert.Single(logs.Events).RenderMessage());
                }
                finally
                {
                    built.Filter.Dispose();
                }
                logs.Events.Clear();
            }
        }
        finally
        {
            FilterFixtures.Delete(one, two);
        }
    }
}
