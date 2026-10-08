using MQTTnet.Server;
using Serilog;

namespace Meshtastic.Mqtt;

/// <summary>Builds the MQTTnet server with the broker's listener, limits and hooks. Shared by Program and the tests.</summary>
public static class BrokerServer
{
    public sealed record Built(MqttServer Server, BrokerHooks Hooks, PacketSizeLimitedTcpAdapter Listener);

    public static Built Create(BrokerConfig config, ILogger logger, int? maxConcurrentKdf = null, bool persistentSessions = false)
    {
        var limits = config.Limits ?? new LimitsConfig();
        var options = new MqttServerOptionsBuilder()
            .WithDefaultEndpoint()
            .WithDefaultEndpointPort(config.Listener.Port)
            // Bounds how long a socket may sit before sending CONNECT (MQTTnet's default is 100 s).
            .WithDefaultCommunicationTimeout(TimeSpan.FromSeconds(limits.CommunicationTimeoutSeconds ?? LimitsConfig.DefaultCommunicationTimeoutSeconds))
            .WithPersistentSessions(persistentSessions)
            .Build();

        // Our own listener replaces MQTTnet's stock TCP adapter so that oversized packets are refused before
        // MQTTnet allocates them. It binds only the configured address (one address family).
        var listener = new PacketSizeLimitedTcpAdapter(config.BindAddress,
            limits.MaxPacketSize ?? LimitsConfig.DefaultMaxPacketSize, logger);
        var server = new MqttServerFactory().CreateMqttServer(options, [listener]);
        var hooks = new BrokerHooks(config, logger, maxConcurrentKdf);
        hooks.Attach(server);
        return new Built(server, hooks, listener);
    }
}
