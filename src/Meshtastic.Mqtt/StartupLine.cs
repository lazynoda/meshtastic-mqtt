using Serilog;

namespace Meshtastic.Mqtt;

/// <summary>
/// The startup line: what the broker is running with.
/// </summary>
/// <remarks>
/// The line lists every limit of the configuration, so the operator sees the whole configuration in one
/// line, and the limits are attached to the line as a structured property as well, so the log store
/// keeps them as data and not only as text.
/// </remarks>
internal static class StartupLine
{
    /// <summary>Writes the startup line (Information).</summary>
    public static void Write(ILogger log, BrokerConfig config)
    {
        var limits = config.Limits!;
        // The limits are attached as a JSON object whose keys keep the order of EffectiveValues(): the
        // order of the enumeration of a plain dictionary is not guaranteed, so the value is built
        // explicitly.
        var limitValues = OrderedProperties.Object(limits.EffectiveValues());
        log.ForContext(OrderedProperties.Enricher("LimitValues", limitValues))
            .Information("Listening on {Address:l}:{Port} (plain MQTT). {Users} user(s), {Channels} channel key(s), drop_pki={DropPki}, limits: {Limits:l}",
                config.BindAddress, config.Listener.Port, config.Users!.Count, config.ChannelKeyMap.Count,
                config.DropPki, limits.Describe());
    }
}
