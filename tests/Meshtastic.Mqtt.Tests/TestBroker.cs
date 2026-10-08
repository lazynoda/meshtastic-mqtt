using Meshtastic.Mqtt;
using MQTTnet.Server;
using Serilog;

namespace Meshtastic.Mqtt.Tests;

/// <summary>Builds a broker wired exactly as Program does (listener, limits, hooks), on the config's address.</summary>
static class TestBroker
{
    public static MqttServer Create(BrokerConfig config, ILogger logger, int? maxConcurrentKdf = null, bool persistentSessions = false) =>
        BrokerServer.Create(config, logger, maxConcurrentKdf, persistentSessions).Server;
}
