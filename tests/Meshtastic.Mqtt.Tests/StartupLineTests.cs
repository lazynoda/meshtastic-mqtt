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
}
