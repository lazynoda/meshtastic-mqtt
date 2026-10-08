using System.Net;
using Meshtastic.Mqtt;
using MQTTnet.Server;
using Serilog;

namespace Meshtastic.Mqtt.Tests;

/// <summary>Builds a broker with the hooks attached, listening on loopback only.</summary>
static class TestBroker
{
    public static MqttServer Create(BrokerConfig config, ILogger logger, int? maxConcurrentKdf = null, bool persistentSessions = false)
    {
        var options = new MqttServerOptionsBuilder().WithDefaultEndpoint().WithDefaultEndpointPort(config.Listener.Port)
            .WithPersistentSessions(persistentSessions).Build();
        options.DefaultEndpointOptions.BoundInterNetworkAddress = IPAddress.Loopback;
        options.DefaultEndpointOptions.BoundInterNetworkV6Address = IPAddress.None;
        var server = new MqttServerFactory().CreateMqttServer(options);
        new BrokerHooks(config, logger, maxConcurrentKdf).Attach(server);
        return server;
    }
}
