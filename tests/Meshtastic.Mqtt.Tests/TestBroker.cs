using Meshtastic.Mqtt;
using MQTTnet.Server;
using Serilog;

namespace Meshtastic.Mqtt.Tests;

/// <summary>Builds a broker wired exactly as Program does (listener, limits, hooks), on the config's address.</summary>
static class TestBroker
{
    public static MqttServer Create(BrokerConfig config, ILogger logger, int? maxConcurrentKdf = null,
        bool persistentSessions = false, TimeProvider? time = null) =>
        CreateBuilt(config, logger, maxConcurrentKdf, persistentSessions, time).Server;

    /// <summary>Also returns a callback that writes the periodic drop summary now.</summary>
    public static (MqttServer Server, Action FlushDrops) CreateWithHooks(BrokerConfig config, ILogger logger,
        int? maxConcurrentKdf = null, bool persistentSessions = false, TimeProvider? time = null)
    {
        var built = CreateBuilt(config, logger, maxConcurrentKdf, persistentSessions, time);
        return (built.Server, built.Hooks.Drops.Flush);
    }

    /// <summary>Server plus the hooks behind it (claim table, authenticator), for tests that inspect them.</summary>
    public static BrokerServer.Built CreateBuilt(BrokerConfig config, ILogger logger, int? maxConcurrentKdf = null,
        bool persistentSessions = false, TimeProvider? time = null) =>
        BrokerServer.Create(config, logger, maxConcurrentKdf, persistentSessions, time: time);
}
