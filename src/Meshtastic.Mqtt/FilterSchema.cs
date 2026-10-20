using System.Reflection;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using Meshtastic.Protobufs;

namespace Meshtastic.Mqtt;

/// <summary>
/// The vocabulary of the rules file: the keys of its scopes, of a rule, of a constraint and of a
/// condition, the operators of a condition, the prefixes of the path of a field and the portnums whose
/// payload the filter can decode.
/// </summary>
/// <remarks>
/// The lists of this class are the ones the loader accepts, and the doc-drift test derives the check of
/// the documentation from them: a key, an operator or a prefix that is added here and not to
/// <c>docs/filters.md</c> fails the build.
/// </remarks>
public static class FilterSchema
{
    /// <summary>The three scopes of the file: by user, by gateway and by node.</summary>
    public static readonly IReadOnlyList<string> ScopeKeys;

    /// <summary>The keys of a rule.</summary>
    public static readonly IReadOnlyList<string> RuleKeys;

    /// <summary>The keys of a constraint: <c>allow</c> or <c>deny</c>.</summary>
    public static readonly IReadOnlyList<string> ConstraintKeys;

    /// <summary>The keys of a condition of <c>drop_if</c>.</summary>
    public static readonly IReadOnlyList<string> ConditionKeys;

    /// <summary>The operators of a condition.</summary>
    public static readonly IReadOnlyList<string> Ops;

    /// <summary>The prefixes of the path of a field.</summary>
    public static readonly IReadOnlyList<string> FieldPrefixes;

    /// <summary>The two values of <c>unopened</c>.</summary>
    public static readonly IReadOnlyList<string> UnopenedValues;

    /// <summary>The name of each scope, as the line of a filtered packet writes it.</summary>
    public static readonly IReadOnlyList<string> ScopeKinds;

    /// <summary>The portnum whose payload is plain text and not a protobuf.</summary>
    public static readonly int TextMessageApp;

    /// <summary>The portnum whose payload is a <c>Position</c>.</summary>
    public static readonly int PositionApp;

    /// <summary>The portnum whose payload is a <c>User</c>.</summary>
    public static readonly int NodeInfoApp;

    /// <summary>The portnum whose payload is a <c>Telemetry</c>.</summary>
    public static readonly int TelemetryApp;

    /// <summary>The portnum whose payload is a <c>Waypoint</c>.</summary>
    public static readonly int WaypointApp;

    /// <summary>The portnum whose payload is a <c>NeighborInfo</c>.</summary>
    public static readonly int NeighborInfoApp;

    /// <summary>The portnum whose payload is a <c>MapReport</c>.</summary>
    public static readonly int MapReportApp;

    /// <summary>The portnum whose payload is a <c>Routing</c>.</summary>
    public static readonly int RoutingApp;

    /// <summary>The message each decodable portnum carries, by the number of the portnum.</summary>
    public static readonly IReadOnlyDictionary<int, MessageDescriptor> PayloadMessages;

    /// <summary>The names of the portnums whose payload the filter can decode, sorted.</summary>
    public static readonly IReadOnlyList<string> PayloadPortnumNames;

    /// <summary>The names of the messages the payload of a portnum is decoded as, sorted.</summary>
    public static readonly IReadOnlyList<string> PayloadMessageNames;

    /// <summary>The highest number a portnum may have (the range of the protobufs).</summary>
    public static readonly int MaxPortNum;

    /// <summary>The number of every portnum, by the name the firmware writes (TEXT_MESSAGE_APP).</summary>
    static readonly Dictionary<string, int> PortNumNumbers;

    /// <summary>The name of every portnum, by its number.</summary>
    static readonly Dictionary<int, string> PortNumNames;

    static FilterSchema()
    {
        ScopeKeys = ["users", "gateways", "nodes"];
        RuleKeys = ["name", "channels", "topics", "portnums", "drop_if", "unopened"];
        ConstraintKeys = ["allow", "deny"];
        ConditionKeys = ["field", "op", "value", "portnum"];
        Ops = ["eq", "ne", "in", "contains", "regex", "lt", "le", "gt", "ge"];
        FieldPrefixes = ["packet.", "data.", "payload."];
        UnopenedValues = ["drop", "allow"];
        ScopeKinds = ["user", "gateway", "node"];

        // The names of the portnums come from the protobuf attributes: the C# names of the enum
        // (TextMessageApp) are not the names the firmware writes (TEXT_MESSAGE_APP).
        var names = new Dictionary<int, string>();
        foreach (var field in typeof(PortNum).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            if (field.GetCustomAttribute<OriginalNameAttribute>() is { } original)
                names[Convert.ToInt32(field.GetValue(null))] = original.Name;
        }
        PortNumNames = names;

        var numbers = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var (number, name) in names)
            numbers[name] = number;
        PortNumNumbers = numbers;

        TextMessageApp = numbers["TEXT_MESSAGE_APP"];
        PositionApp = numbers["POSITION_APP"];
        NodeInfoApp = numbers["NODEINFO_APP"];
        TelemetryApp = numbers["TELEMETRY_APP"];
        WaypointApp = numbers["WAYPOINT_APP"];
        NeighborInfoApp = numbers["NEIGHBORINFO_APP"];
        MapReportApp = numbers["MAP_REPORT_APP"];
        RoutingApp = numbers["ROUTING_APP"];

        PayloadMessages = new Dictionary<int, MessageDescriptor>
        {
            [PositionApp] = Position.Descriptor,
            [NodeInfoApp] = User.Descriptor,
            [TelemetryApp] = Telemetry.Descriptor,
            [WaypointApp] = Waypoint.Descriptor,
            [NeighborInfoApp] = NeighborInfo.Descriptor,
            [MapReportApp] = MapReport.Descriptor,
            [RoutingApp] = Routing.Descriptor,
        };

        PayloadPortnumNames = names
            .Where(entry => PayloadMessages.ContainsKey(entry.Key) || entry.Key == TextMessageApp)
            .Select(entry => entry.Value)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        PayloadMessageNames = PayloadMessages.Values
            .Select(descriptor => descriptor.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        MaxPortNum = MaxPortNumOf();
    }

    /// <summary>
    /// The highest number a portnum may have. The enum of the protobufs has a MAX member, and its
    /// value is the bound; the range of the firmware is the fallback.
    /// </summary>
    static int MaxPortNumOf()
    {
        var max = typeof(PortNum).GetField("Max", BindingFlags.Public | BindingFlags.Static);
        if (max is not null)
            return Convert.ToInt32(max.GetValue(null));
        return 511;
    }

    /// <summary>The number of rules and its word: "1 rule", "2 rules".</summary>
    public static string Rules(int count) => $"{count} {RuleWord(count)}";

    /// <summary>The word of a number of rules: "rule" or "rules".</summary>
    public static string RuleWord(int count) => count == 1 ? "rule" : "rules";

    /// <summary>The name of a portnum as the firmware writes it (TEXT_MESSAGE_APP).</summary>
    public static string PortNumName(int portnum) =>
        PortNumNames.TryGetValue(portnum, out var name) ? name : portnum.ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>
    /// The number of a portnum, by the name the firmware writes. The name may be a number too.
    /// Returns false when the name is not a portnum of the firmware.
    /// </summary>
    public static bool TryPortNumNumber(string name, out int number)
    {
        if (PortNumNumbers.TryGetValue(name, out number))
            return true;
        return int.TryParse(name, System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture, out number);
    }

    /// <summary>
    /// Whether the number is a portnum of the firmware (0 to <see cref="MaxPortNum"/>). A number
    /// outside the range is not a portnum, whatever the file says.
    /// </summary>
    public static bool IsPortNumNumber(int number) => number >= 0 && number <= MaxPortNum;

    /// <summary>The node id of a node number, as the firmware writes it (! and 8 lowercase hex digits).</summary>
    public static string NodeId(uint node) => $"!{node:x8}";
}
