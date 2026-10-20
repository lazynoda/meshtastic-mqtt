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
    public static void Write(ILogger log, BrokerConfig config, PacketFilter? filter = null)
    {
        var limits = config.Limits!;
        // The limits are attached as a JSON object whose keys keep the order of EffectiveValues(): the
        // order of the enumeration of a plain dictionary is not guaranteed, so the value is built
        // explicitly.
        var limitValues = OrderedProperties.Object(limits.EffectiveValues());
        // The filters are part of what the broker is running with: whether they are on, and how many
        // rules they hold. A broker without a rules file has no filters, even though it holds a filter
        // object (the one that watches a file that is not there). The number of rules is written as
        // the reload line writes it.
        var filters = filter is null || !filter.Enabled ? "off" : $"on ({FilterSchema.Rules(filter.RuleCount)})";
        log.ForContext(OrderedProperties.Enricher("LimitValues", limitValues))
            .Information("Listening on {Address:l}:{Port} (plain MQTT). {Users} user(s), {Channels} channel key(s), drop_pki={DropPki}, filters={Filters:l}, limits: {Limits:l}",
                config.BindAddress, config.Listener.Port, config.Users!.Count, config.ChannelKeyMap.Count,
                config.DropPki, filters, limits.Describe());
    }
}
