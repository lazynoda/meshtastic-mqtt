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

    // The two security flags are nullable on the YAML side only so that an empty value
    // (`drop_pki:` or `drop_pki: ~`) is reported as an error instead of silently turning into false.
    [YamlMember(Alias = "drop_undecryptable", ApplyNamingConventions = false)]
    public bool? DropUndecryptableSetting { get; set; } = true;

    [YamlMember(Alias = "drop_pki", ApplyNamingConventions = false)]
    public bool? DropPkiSetting { get; set; } = true;

    /// <summary>Drop channel packets the broker cannot decrypt with the key configured for their channel.</summary>
    [YamlIgnore] public bool DropUndecryptable => DropUndecryptableSetting ?? true;

    /// <summary>Drop PKI-encrypted DMs (channel_id "PKI"). They can never be decrypted by the broker.</summary>
    [YamlIgnore] public bool DropPki => DropPkiSetting ?? true;

    /// <summary>Key for any channel not listed in <see cref="Channels"/>.</summary>
    public string? DefaultPsk { get; set; } = "AQ==";

    /// <summary>Channel name (as in ServiceEnvelope.channel_id) to base64 PSK.</summary>
    public Dictionary<string, string?>? Channels { get; set; } = new();

    public List<UserConfig>? Users { get; set; } = new();

    public LimitsConfig? Limits { get; set; } = new();

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

        if (DropUndecryptableSetting is null)
            errors.Add("drop_undecryptable: empty value; write true or false (leave the key out to use the default, true)");
        if (DropPkiSetting is null)
            errors.Add("drop_pki: empty value; write true or false (leave the key out to use the default, true)");

        if (Limits is null)
            errors.Add("limits: empty section; leave it out to use the defaults or set its keys");
        else
            Limits.Validate(errors);

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

        if (string.IsNullOrEmpty(DefaultPsk))
            errors.Add($"default_psk: {EmptyPskError}");
        else if (!ChannelKeys.TryExpand(DefaultPsk, out var defaultKey, out var defaultError))
            errors.Add($"default_psk: {defaultError}");
        else
            DefaultKey = defaultKey;

        // Exact-case names, like the firmware channel hash. Exact duplicates never get here: the YAML
        // parser rejects duplicate keys.
        var keyMap = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var (name, psk) in Channels ?? [])
        {
            if (string.IsNullOrWhiteSpace(name) || name.IndexOfAny(['/', '+', '#', '\0']) >= 0)
            {
                errors.Add($"channels: '{name}' is not a usable channel name (empty, or contains '/', '+' or '#')");
                continue;
            }
            if (string.IsNullOrEmpty(psk))
            {
                errors.Add($"channels.{name}: {EmptyPskError}");
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

            user.PublishAllow ??= [];
            foreach (var filter in user.PublishAllow)
            {
                if (!TopicFilter.IsValid(filter, out var filterError))
                    errors.Add($"{where}.publish_allow: {filterError}");
            }
        }
        return errors;
    }

    // The firmware reads an empty PSK on a secondary channel as "use the primary channel's key", not as
    // "no encryption", so an empty value here is ambiguous and almost always an editing mistake.
    const string EmptyPskError = "empty PSK; write the base64 key (\"AA==\" means no encryption, \"AQ==\" is the default key)";

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

/// <summary>Resource limits that protect the broker from hostile clients, before and during authentication.</summary>
public sealed class LimitsConfig
{
    public const int DefaultMaxPacketSize = 4096;
    public const int MinMaxPacketSize = 512;
    public const int MaxMaxPacketSize = 1024 * 1024;
    public const int DefaultCommunicationTimeoutSeconds = 10;
    public const int DefaultAuthQueueTimeoutSeconds = 3;
    public const int DefaultAuthMaxPending = 64;
    public const int DefaultAuthMaxPendingPerUser = 4;

    /// <summary>Connections one address may hold at once (0 = off).</summary>
    public const int DefaultMaxConnectionsPerIp = 16;

    /// <summary>Connections one address may open per minute (0 = off).</summary>
    public const int DefaultConnectRatePerIpPerMinute = 30;

    /// <summary>Burst of the per-address connect rate (0 = off).</summary>
    public const int DefaultConnectBurstPerIp = 10;

    /// <summary>Largest publish payload accepted, in bytes.</summary>
    public const int DefaultMaxPayloadSize = 512;

    /// <summary>Smallest publish payload cap that may be configured.</summary>
    public const int MinMaxPayloadSize = 64;

    /// <summary>Publishes one client may send per minute (0 = off).</summary>
    public const int DefaultPublishRatePerClientPerMinute = 120;

    /// <summary>Burst of the per-client publish rate (0 = off).</summary>
    public const int DefaultPublishBurstPerClient = 60;

    /// <summary>How long a packet is remembered for the cross-gateway dedupe, in seconds (0 = off).</summary>
    public const int DefaultDedupeWindowSeconds = 120;

    /// <summary>How many gateways may send the same packet before the copies are dropped.</summary>
    public const int DefaultDedupeMaxGatewaysPerPacket = 32;

    /// <summary>How many packets are remembered for the dedupe at once.</summary>
    public const int DefaultDedupeMaxEntries = 200_000;

    /// <summary>Packets one node may send per minute (0 = off).</summary>
    public const int DefaultPacketRatePerFromPerMinute = 30;

    /// <summary>Burst of the per-node packet rate (0 = off).</summary>
    public const int DefaultPacketBurstPerFrom = 15;

    /// <summary>Failed logins one IP address may make before it is banned (0 = off).</summary>
    public const int DefaultAuthFailMaxPerIp = 10;

    /// <summary>How long the failed logins of one IP address are counted, in seconds.</summary>
    public const int DefaultAuthFailWindowSeconds = 600;

    /// <summary>How long a banned IP address is refused, in seconds.</summary>
    public const int DefaultAuthBanSeconds = 3600;

    /// <summary>
    /// How many entries the bounded tables may hold at once: the per-IP, the per-client and the
    /// per-node rate tables, the table of failed logins and the table of bans.
    /// </summary>
    public const int DefaultMaxTrackedEntries = 100_000;

    /// <summary>Smallest entry cap that may be configured.</summary>
    public const int MinMaxTrackedEntries = 1_000;

    /// <summary>Largest entry cap that may be configured.</summary>
    public const int MaxMaxTrackedEntries = 10_000_000;

    /// <summary>How long an entry of a rate table survives without being used, in seconds.</summary>
    public const int DefaultRateIdleExpirySeconds = 600;

    /// <summary>Shortest idle expiry that may be configured, in seconds.</summary>
    public const int MinRateIdleExpirySeconds = 60;

    /// <summary>Longest idle expiry that may be configured, in seconds.</summary>
    public const int MaxRateIdleExpirySeconds = 86_400;

    /// <summary>
    /// Largest MQTT packet accepted, counted as the fixed header's Remaining Length. Enforced while the header is
    /// read, before MQTTnet allocates the body, so it also bounds unauthenticated CONNECTs.
    /// </summary>
    public int? MaxPacketSize { get; set; } = DefaultMaxPacketSize;

    /// <summary>MQTTnet's DefaultCommunicationTimeout: how long a client may take to send CONNECT, and a write may stall.</summary>
    public int? CommunicationTimeoutSeconds { get; set; } = DefaultCommunicationTimeoutSeconds;

    /// <summary>How long a login may wait for a password-hashing slot before it is answered "server unavailable".</summary>
    public int? AuthQueueTimeoutSeconds { get; set; } = DefaultAuthQueueTimeoutSeconds;

    /// <summary>Logins that may run or wait for password hashing at once, per lane; the rest get "server unavailable".</summary>
    public int? AuthMaxPending { get; set; } = DefaultAuthMaxPending;

    /// <summary>
    /// Distinct (username, password) checks one configured username may have pending at once; the rest get
    /// "server unavailable". Keeps one username's wrong passwords from filling the queue for every other user.
    /// </summary>
    public int? AuthMaxPendingPerUser { get; set; } = DefaultAuthMaxPendingPerUser;

    /// <summary>
    /// Connections one IP address may hold open at once. Enforced when the connection is accepted, before
    /// any MQTT byte is read. 0 turns the cap off.
    /// </summary>
    public int? MaxConnectionsPerIp { get; set; } = DefaultMaxConnectionsPerIp;

    /// <summary>
    /// Connections one IP address may open per minute (token bucket, see <see cref="ConnectBurstPerIp"/>).
    /// Enforced when the connection is accepted. 0 turns the rate off.
    /// </summary>
    public int? ConnectRatePerIpPerMinute { get; set; } = DefaultConnectRatePerIpPerMinute;

    /// <summary>
    /// Burst of the per-IP connect rate: how many connections one address may open at once. 0 turns the
    /// rate off.
    /// </summary>
    public int? ConnectBurstPerIp { get; set; } = DefaultConnectBurstPerIp;

    /// <summary>
    /// Largest publish payload accepted, in bytes. Checked in the publish hook, before the packet is
    /// parsed. Cannot be larger than <see cref="MaxPacketSize"/>.
    /// </summary>
    public int? MaxPayloadSize { get; set; } = DefaultMaxPayloadSize;

    /// <summary>
    /// Publishes one client (session owner and client id) may send per minute (token bucket, see
    /// <see cref="PublishBurstPerClient"/>). 0 turns the rate off.
    /// </summary>
    public int? PublishRatePerClientPerMinute { get; set; } = DefaultPublishRatePerClientPerMinute;

    /// <summary>
    /// Burst of the per-client publish rate: how many publishes one client may send at once. 0 turns the
    /// rate off.
    /// </summary>
    public int? PublishBurstPerClient { get; set; } = DefaultPublishBurstPerClient;

    /// <summary>
    /// How long a packet is remembered for the cross-gateway dedupe, in seconds. 0 turns the dedupe off.
    /// </summary>
    public int? DedupeWindowSeconds { get; set; } = DefaultDedupeWindowSeconds;

    /// <summary>
    /// How many gateways may send the same packet before the further copies are dropped.
    /// </summary>
    public int? DedupeMaxGatewaysPerPacket { get; set; } = DefaultDedupeMaxGatewaysPerPacket;

    /// <summary>
    /// How many packets are remembered for the dedupe at once; the oldest are evicted when the cap is hit.
    /// </summary>
    public int? DedupeMaxEntries { get; set; } = DefaultDedupeMaxEntries;

    /// <summary>
    /// Packets one node (the packet's <c>from</c>) may send per minute (token bucket, see
    /// <see cref="PacketBurstPerFrom"/>). 0 turns the rate off.
    /// </summary>
    public int? PacketRatePerFromPerMinute { get; set; } = DefaultPacketRatePerFromPerMinute;

    /// <summary>
    /// Burst of the per-node packet rate: how many packets one node may send at once. 0 turns the rate off.
    /// </summary>
    public int? PacketBurstPerFrom { get; set; } = DefaultPacketBurstPerFrom;

    /// <summary>
    /// Failed logins one IP address may make before it is banned. Only a wrong password (or an unknown
    /// user, or an unsupported authentication method) counts. 0 turns the bans off.
    /// </summary>
    public int? AuthFailMaxPerIp { get; set; } = DefaultAuthFailMaxPerIp;

    /// <summary>
    /// How long the failed logins of one IP address are counted, in seconds. The window starts with the
    /// first failure; when it has passed, the next failure starts a new one.
    /// </summary>
    public int? AuthFailWindowSeconds { get; set; } = DefaultAuthFailWindowSeconds;

    /// <summary>
    /// How long a banned IP address is refused, in seconds. The ban is in memory only: a restart forgets it.
    /// </summary>
    public int? AuthBanSeconds { get; set; } = DefaultAuthBanSeconds;

    /// <summary>
    /// IP ranges (CIDR, IPv4 or IPv6) whose failed logins are never counted and which are never banned.
    /// Empty by default.
    /// </summary>
    public List<string>? AuthBanExempt { get; set; } = new();

    /// <summary>
    /// How many entries the bounded tables may hold at once: the per-IP, the per-client and the per-node
    /// rate tables, the table of failed logins and the table of bans. The dedupe table has its own cap
    /// (<see cref="DedupeMaxEntries"/>).
    /// </summary>
    public int? MaxTrackedEntries { get; set; } = DefaultMaxTrackedEntries;

    /// <summary>
    /// How long an entry of a rate table survives without being used, in seconds: the per-IP, the
    /// per-client and the per-node rate tables.
    /// </summary>
    public int? RateIdleExpirySeconds { get; set; } = DefaultRateIdleExpirySeconds;

    internal void Validate(List<string> errors)
    {
        Check(errors, "max_packet_size", MaxPacketSize, MinMaxPacketSize, MaxMaxPacketSize);
        Check(errors, "communication_timeout_seconds", CommunicationTimeoutSeconds, 1, 300);
        Check(errors, "auth_queue_timeout_seconds", AuthQueueTimeoutSeconds, 1, 60);
        Check(errors, "auth_max_pending", AuthMaxPending, 1, 100_000);
        Check(errors, "auth_max_pending_per_user", AuthMaxPendingPerUser, 1, 100_000);

        Check(errors, "max_connections_per_ip", MaxConnectionsPerIp, 0, 100_000);
        Check(errors, "connect_rate_per_ip_per_minute", ConnectRatePerIpPerMinute, 0, 1_000_000);
        Check(errors, "connect_burst_per_ip", ConnectBurstPerIp, 0, 1_000_000);
        Check(errors, "publish_rate_per_client_per_minute", PublishRatePerClientPerMinute, 0, 1_000_000);
        Check(errors, "publish_burst_per_client", PublishBurstPerClient, 0, 1_000_000);
        Check(errors, "dedupe_window_seconds", DedupeWindowSeconds, 0, 86_400);
        Check(errors, "dedupe_max_gateways_per_packet", DedupeMaxGatewaysPerPacket, 1, 100_000);
        Check(errors, "dedupe_max_entries", DedupeMaxEntries, 1, 10_000_000);
        Check(errors, "packet_rate_per_from_per_minute", PacketRatePerFromPerMinute, 0, 1_000_000);
        Check(errors, "packet_burst_per_from", PacketBurstPerFrom, 0, 1_000_000);

        Check(errors, "auth_fail_max_per_ip", AuthFailMaxPerIp, 0, 100_000);
        Check(errors, "auth_fail_window_seconds", AuthFailWindowSeconds, 10, 86_400);
        Check(errors, "auth_ban_seconds", AuthBanSeconds, 60, 604_800);

        Check(errors, "max_tracked_entries", MaxTrackedEntries, MinMaxTrackedEntries, MaxMaxTrackedEntries);
        Check(errors, "rate_idle_expiry_seconds", RateIdleExpirySeconds, MinRateIdleExpirySeconds, MaxRateIdleExpirySeconds);

        // The exempt ranges: an invalid one is a typo the operator must see at startup.
        foreach (var range in AuthBanExempt ?? [])
        {
            if (!IpCidr.TryParse(range, out _, out var rangeError))
                errors.Add($"limits.auth_ban_exempt: {rangeError}");
        }

        // The payload cap can never be larger than the packet the broker is willing to read.
        var maxPacket = MaxPacketSize is >= MinMaxPacketSize and <= MaxMaxPacketSize
            ? MaxPacketSize.Value
            : DefaultMaxPacketSize;
        if (MaxPayloadSize is null || MaxPayloadSize < MinMaxPayloadSize || MaxPayloadSize > maxPacket)
            errors.Add($"limits.max_payload_size: {(MaxPayloadSize is null ? "empty value" : MaxPayloadSize.ToString())} is not an integer between {MinMaxPayloadSize} and {maxPacket}");
    }

    static void Check(List<string> errors, string key, int? value, int min, int max)
    {
        if (value is null || value < min || value > max)
            errors.Add($"limits.{key}: {(value is null ? "empty value" : value.ToString())} is not an integer between {min} and {max}");
    }

    /// <summary>
    /// Every limit with the value the broker will use, as the startup line shows it:
    /// "key=value, key=value, ...". The exempt ranges are listed as they are written in the config, so
    /// the operator sees the whole configuration in one line.
    /// </summary>
    /// <remarks>
    /// The line is built from <see cref="EffectiveValues"/>, so there is one source of truth: the
    /// dictionary the startup log attaches and the text of the line never disagree.
    /// </remarks>
    public string Describe() => string.Join(", ",
        EffectiveValues().Select(entry => $"{entry.Key}={DescribeValue(entry.Value)}"));

    /// <summary>
    /// Every limit with the value the broker will use (the value of the config, or the default when it
    /// is not set), in the order the startup line shows them. The exempt ranges are a list of strings.
    /// </summary>
    /// <remarks>
    /// The order is the order of the keys as they are added: the dictionary is an ordered one, so the
    /// order is part of its type and not of the enumeration of a plain dictionary. The startup log
    /// attaches it as a structured property, so the log store keeps the limits of that run as data and
    /// not only as text.
    /// </remarks>
    public IReadOnlyDictionary<string, object> EffectiveValues()
    {
        var values = new OrderedDictionary<string, object>(StringComparer.Ordinal)
        {
            ["max_packet_size"] = MaxPacketSize ?? DefaultMaxPacketSize,
            ["communication_timeout_seconds"] = CommunicationTimeoutSeconds ?? DefaultCommunicationTimeoutSeconds,
            ["auth_queue_timeout_seconds"] = AuthQueueTimeoutSeconds ?? DefaultAuthQueueTimeoutSeconds,
            ["auth_max_pending"] = AuthMaxPending ?? DefaultAuthMaxPending,
            ["auth_max_pending_per_user"] = AuthMaxPendingPerUser ?? DefaultAuthMaxPendingPerUser,
            ["max_connections_per_ip"] = MaxConnectionsPerIp ?? DefaultMaxConnectionsPerIp,
            ["connect_rate_per_ip_per_minute"] = ConnectRatePerIpPerMinute ?? DefaultConnectRatePerIpPerMinute,
            ["connect_burst_per_ip"] = ConnectBurstPerIp ?? DefaultConnectBurstPerIp,
            ["max_payload_size"] = MaxPayloadSize ?? DefaultMaxPayloadSize,
            ["publish_rate_per_client_per_minute"] = PublishRatePerClientPerMinute ?? DefaultPublishRatePerClientPerMinute,
            ["publish_burst_per_client"] = PublishBurstPerClient ?? DefaultPublishBurstPerClient,
            ["dedupe_window_seconds"] = DedupeWindowSeconds ?? DefaultDedupeWindowSeconds,
            ["dedupe_max_gateways_per_packet"] = DedupeMaxGatewaysPerPacket ?? DefaultDedupeMaxGatewaysPerPacket,
            ["dedupe_max_entries"] = DedupeMaxEntries ?? DefaultDedupeMaxEntries,
            ["packet_rate_per_from_per_minute"] = PacketRatePerFromPerMinute ?? DefaultPacketRatePerFromPerMinute,
            ["packet_burst_per_from"] = PacketBurstPerFrom ?? DefaultPacketBurstPerFrom,
            ["auth_fail_max_per_ip"] = AuthFailMaxPerIp ?? DefaultAuthFailMaxPerIp,
            ["auth_fail_window_seconds"] = AuthFailWindowSeconds ?? DefaultAuthFailWindowSeconds,
            ["auth_ban_seconds"] = AuthBanSeconds ?? DefaultAuthBanSeconds,
            ["auth_ban_exempt"] = AuthBanExempt ?? new List<string>(),
            ["max_tracked_entries"] = MaxTrackedEntries ?? DefaultMaxTrackedEntries,
            ["rate_idle_expiry_seconds"] = RateIdleExpirySeconds ?? DefaultRateIdleExpirySeconds,
        };
        return values;
    }

    /// <summary>The value as the startup line shows it (the exempt ranges as the list they are in).</summary>
    static string DescribeValue(object value) =>
        value is List<string> ranges ? "[" + string.Join(", ", ranges) + "]" : value.ToString() ?? string.Empty;
}

public sealed class UserConfig
{
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>MQTT topic filters this user may subscribe to. Empty or missing = no subscribe at all.</summary>
    public List<string>? SubscribeAllow { get; set; } = new();

    /// <summary>
    /// MQTT topic filters a PUBLISH topic name must match for this user. Empty or missing = no publish at all.
    /// </summary>
    public List<string>? PublishAllow { get; set; } = new();

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
            .WithDuplicateKeyChecking()   // a repeated key (users:, a channel) must not silently replace the first
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
