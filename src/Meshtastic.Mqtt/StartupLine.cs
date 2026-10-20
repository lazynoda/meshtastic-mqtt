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
        log.ForContext("LimitValues", LimitValues(limits), destructureObjects: true)
            .Information("Listening on {Address}:{Port} (plain MQTT). {Users} user(s), {Channels} channel key(s), drop_undecryptable={DropUndecryptable}, drop_pki={DropPki}, limits: {Limits:l}",
                config.BindAddress, config.Listener.Port, config.Users!.Count, config.ChannelKeyMap.Count,
                config.DropUndecryptable, config.DropPki, limits.Describe());
    }

    /// <summary>
    /// The limits as Serilog writes them: a plain dictionary, so the JSON log holds an object keyed by
    /// the name of the limit. The ordered dictionary of <see cref="LimitsConfig.EffectiveValues"/> is
    /// written as a list of pairs instead, which a log store cannot read as a dictionary.
    /// </summary>
    static Dictionary<string, object> LimitValues(LimitsConfig limits) => new(limits.EffectiveValues());
}
