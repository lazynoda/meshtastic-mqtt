using System.Net;
using System.Net.Sockets;
using Serilog.Events;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Meshtastic.Mqtt;

/// <summary>Broker configuration as read from YAML (snake_case keys). See config.example.yaml.</summary>
public sealed class BrokerConfig
{
    public ListenerConfig Listener { get; set; } = new();
    public string LogLevel { get; set; } = "information";

    /// <summary>Drop channel packets the broker cannot decrypt with the key configured for their channel.</summary>
    public bool DropUndecryptable { get; set; } = true;

    /// <summary>Drop PKI-encrypted DMs (channel_id "PKI"). They can never be decrypted by the broker.</summary>
    public bool DropPki { get; set; } = true;

    /// <summary>Key for any channel not listed in <see cref="Channels"/>.</summary>
    public string DefaultPsk { get; set; } = "AQ==";

    /// <summary>Channel name (as in ServiceEnvelope.channel_id) to base64 PSK.</summary>
    public Dictionary<string, string>? Channels { get; set; } = new();

    public List<UserConfig>? Users { get; set; } = new();

    [YamlIgnore] public LogEventLevel MinimumLevel { get; private set; } = LogEventLevel.Information;
    [YamlIgnore] public IPAddress BindAddress { get; private set; } = IPAddress.Any;
    [YamlIgnore] public byte[] DefaultKey { get; private set; } = [];

    /// <summary>
    /// Expanded keys. Lookup is case-sensitive: the firmware hashes the channel name with its exact case
    /// (<c>Channels::generateHash()</c>), so <c>Test</c> and <c>test</c> are different channels on the mesh.
    /// </summary>
    [YamlIgnore] public IReadOnlyDictionary<string, byte[]> ChannelKeyMap { get; private set; } = new Dictionary<string, byte[]>();

    internal List<string> Validate()
    {
        var errors = new List<string>();
        Listener ??= new ListenerConfig();

        if (Listener.Port is < 1 or > 65535)
            errors.Add($"listener.port: {Listener.Port} is not a valid TCP port (1-65535)");
        if (!IPAddress.TryParse(Listener.BindAddress, out var bind)
            || bind.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
            errors.Add($"listener.bind_address: '{Listener.BindAddress}' is not an IPv4 or IPv6 address");
        else
            BindAddress = bind;

        if (!LogLevels.TryGetValue(LogLevel ?? string.Empty, out var level))
            errors.Add($"log_level: '{LogLevel}' is not one of {string.Join(", ", LogLevels.Keys)}");
        else
            MinimumLevel = level;

        if (!ChannelKeys.TryExpand(DefaultPsk, out var defaultKey, out var defaultError))
            errors.Add($"default_psk: {defaultError}");
        else
            DefaultKey = defaultKey;

        // Exact-case names, like the firmware channel hash. A name repeated with the same case is a YAML
        // duplicate key, not something this map can see.
        var keyMap = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var (name, psk) in Channels ?? [])
        {
            if (string.IsNullOrWhiteSpace(name) || name.IndexOfAny(['/', '+', '#', '\0']) >= 0)
            {
                errors.Add($"channels: '{name}' is not a usable channel name (empty, or contains '/', '+' or '#')");
                continue;
            }
            if (!ChannelKeys.TryExpand(psk, out var key, out var keyError))
            {
                errors.Add($"channels.{name}: {keyError}");
                continue;
            }
            keyMap[name] = key;
        }
        ChannelKeyMap = keyMap;

        if (Users is null || Users.Count == 0)
            errors.Add("users: at least one user is required");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < (Users?.Count ?? 0); i++)
        {
            var user = Users![i];
            var where = $"users[{i}]";
            if (user is null)
            {
                errors.Add($"{where}: empty entry");
                continue;
            }
            if (string.IsNullOrEmpty(user.Username))
                errors.Add($"{where}.username: required");
            else if (!seen.Add(user.Username))
                errors.Add($"{where}.username: '{user.Username}' is defined twice");
            else
                where = $"users[{user.Username}]";

            if (!PasswordHasher.TryParse(user.PasswordHash, out var hash, out var hashError))
                errors.Add($"{where}.password_hash: {hashError}");
            else
                user.ParsedHash = hash;

            user.SubscribeAllow ??= [];
            foreach (var filter in user.SubscribeAllow)
            {
                if (!TopicFilter.IsValid(filter, out var filterError))
                    errors.Add($"{where}.subscribe_allow: {filterError}");
            }
        }
        return errors;
    }

    static readonly Dictionary<string, LogEventLevel> LogLevels = new(StringComparer.OrdinalIgnoreCase)
    {
        ["verbose"] = LogEventLevel.Verbose,
        ["debug"] = LogEventLevel.Debug,
        ["information"] = LogEventLevel.Information,
        ["warning"] = LogEventLevel.Warning,
        ["error"] = LogEventLevel.Error,
        ["fatal"] = LogEventLevel.Fatal,
    };
}

public sealed class ListenerConfig
{
    public string BindAddress { get; set; } = "0.0.0.0";
    public int Port { get; set; } = 1883;
}

public sealed class UserConfig
{
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>MQTT topic filters this user may subscribe to. Empty or missing = no subscribe at all.</summary>
    public List<string>? SubscribeAllow { get; set; } = new();

    [YamlIgnore] public PasswordHash? ParsedHash { get; internal set; }
}

public sealed class ConfigException(string message) : Exception(message);

public static class ConfigLoader
{
    public const string EnvironmentVariable = "MESHTASTIC_MQTT_CONFIG";

    public static BrokerConfig LoadFile(string path)
    {
        string yaml;
        try
        {
            yaml = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ConfigException($"cannot read '{path}': {ex.Message}");
        }
        return Parse(yaml);
    }

    public static BrokerConfig Parse(string yaml)
    {
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .Build();

        BrokerConfig? config;
        try
        {
            config = deserializer.Deserialize<BrokerConfig>(yaml);
        }
        catch (YamlException ex)
        {
            var detail = ex.InnerException?.Message ?? ex.Message;
            throw new ConfigException($"line {ex.Start.Line}, column {ex.Start.Column}: {detail}");
        }
        if (config is null)
            throw new ConfigException("the file is empty");

        var errors = config.Validate();
        if (errors.Count > 0)
            throw new ConfigException(string.Join(Environment.NewLine, errors.Select(e => "- " + e)));
        return config;
    }
}
