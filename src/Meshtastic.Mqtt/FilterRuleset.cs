using System.Globalization;
using System.Text.RegularExpressions;
using Google.Protobuf;
using Google.Protobuf.Reflection;
using Meshtastic.Protobufs;

namespace Meshtastic.Mqtt;

/// <summary>The operator of a condition of <c>drop_if</c>.</summary>
public enum FilterOp
{
    /// <summary>The value is the one of the field.</summary>
    Eq,

    /// <summary>The value is not the one of the field (and it is true when the field is not there).</summary>
    Ne,

    /// <summary>The value of the field is one of the values of the list.</summary>
    In,

    /// <summary>The text of the field holds the value.</summary>
    Contains,

    /// <summary>The text of the field matches the pattern.</summary>
    Regex,

    /// <summary>The value of the field is smaller than the value.</summary>
    Lt,

    /// <summary>The value of the field is not bigger than the value.</summary>
    Le,

    /// <summary>The value of the field is bigger than the value.</summary>
    Gt,

    /// <summary>The value of the field is not smaller than the value.</summary>
    Ge,
}

/// <summary>What the filter decided about one published packet.</summary>
/// <param name="Passed">True when no rule refused the packet.</param>
/// <param name="RuleName">The name of the rule that refused it.</param>
/// <param name="Scope">The scope of that rule: user, gateway or node.</param>
/// <param name="ScopeKey">The key of that scope: the user name, the gateway id or the node id.</param>
public readonly record struct FilterVerdict(bool Passed, string? RuleName, string? Scope, string? ScopeKey)
{
    /// <summary>The verdict of a packet no rule refused.</summary>
    public static readonly FilterVerdict Pass = new(true, null, null, null);
}

/// <summary>What the filter needs to know about one published packet.</summary>
/// <param name="User">The user that owns the session (the identity the publish ACL uses).</param>
/// <param name="Gateway">The gateway of the topic, as it is written (! and 8 hex digits).</param>
/// <param name="GatewayNode">The number of the gateway of the topic.</param>
/// <param name="From">The number of the node that sent the packet (the cleartext header).</param>
/// <param name="Channel">The channel of the packet, or null for a map report.</param>
/// <param name="Topic">The topic of the publish.</param>
/// <param name="Packet">The cleartext header of the packet.</param>
/// <param name="Data">The decoded data of the packet, or null when the broker could not open it.</param>
/// <param name="Portnum">The portnum of the packet, when it is known.</param>
public readonly record struct FilterInput(
    string? User,
    string? Gateway,
    uint GatewayNode,
    uint From,
    string? Channel,
    string? Topic,
    MeshPacket? Packet,
    Protobufs.Data? Data,
    PortNum? Portnum);

/// <summary>How many payloads the filter decoded (for the tests).</summary>
public sealed class FilterMetrics
{
    long _payloadDecodes;

    /// <summary>How many payloads were decoded since the filter was built.</summary>
    public long PayloadDecodes => Interlocked.Read(ref _payloadDecodes);

    internal void PayloadDecoded() => Interlocked.Increment(ref _payloadDecodes);
}

/// <summary>The kind of the value a condition compares with.</summary>
internal enum CompiledValueKind
{
    String,
    Number,
    Bool,
    Enum,
}

/// <summary>A value of a condition, already checked against the type of its field.</summary>
/// <remarks>
/// A whole number is kept as an <see cref="Int128"/>: every integer of the protobufs (int32, int64,
/// uint32, uint64, fixed, sfixed) fits in it exactly, so a 64-bit unsigned field with the high bit
/// put is compared without an overflow.
/// </remarks>
internal readonly struct CompiledValue
{
    public readonly CompiledValueKind Kind;
    public readonly string Text;
    public readonly double Number;
    public readonly Int128 Integer;
    public readonly bool IsInteger;
    public readonly bool Bool;

    CompiledValue(CompiledValueKind kind, string text, double number, Int128 integer, bool isInteger, bool boolean)
    {
        Kind = kind;
        Text = text;
        Number = number;
        Integer = integer;
        IsInteger = isInteger;
        Bool = boolean;
    }

    public static CompiledValue ForString(string text) =>
        new(CompiledValueKind.String, text, 0, 0, false, false);

    public static CompiledValue ForNumber(double number, bool isInteger, Int128 integer) =>
        new(CompiledValueKind.Number, string.Empty, number, integer, isInteger, false);

    public static CompiledValue ForBool(bool value) =>
        new(CompiledValueKind.Bool, string.Empty, 0, 0, false, value);
}

/// <summary>What a rule does with a packet the broker could not open.</summary>
internal enum UnopenedPolicy
{
    /// <summary>The rule does not need an opened packet.</summary>
    None,

    /// <summary>An unopened packet fails the rule: it is dropped.</summary>
    Drop,

    /// <summary>An unopened packet skips the constraints that need an opened packet.</summary>
    Allow,
}

/// <summary>The path of a field: the prefix and the fields to walk, in the protobuf descriptor.</summary>
internal sealed class FieldPath
{
    /// <summary>One of packet, data or payload.</summary>
    public string Prefix = "";

    /// <summary>The fields to walk, from the root of the message to the leaf.</summary>
    public FieldDescriptor[] Fields = [];

    /// <summary>True for the text of a TEXT_MESSAGE_APP (the payload is bytes, not a message).</summary>
    public bool IsText;

    /// <summary>The kind of the value the leaf holds.</summary>
    public CompiledValueKind Kind;

    /// <summary>The field of the leaf (its enum descriptor is needed to read a value of an enum).</summary>
    public FieldDescriptor? Leaf;

    /// <summary>The value of the field of a packet, or false when the field is not there.</summary>
    public bool TryResolve(FilterContext context, out object? value)
    {
        value = null;
        if (IsText)
        {
            var text = context.Text;
            if (text is null)
                return false;
            value = text;
            return true;
        }

        IMessage? current;
        if (Prefix == "packet")
            current = context.Input.Packet;
        else if (Prefix == "data")
            current = context.Input.Data;
        else
            current = context.Payload;
        if (current is null)
            return false;

        for (var i = 0; i < Fields.Length - 1; i++)
        {
            var field = Fields[i];
            if (IsAbsent(current, field))
                return false;
            current = field.Accessor.GetValue(current) as IMessage;
            if (current is null)
                return false;
        }

        var last = Fields[^1];
        if (IsAbsent(current, last))
            return false;
        value = last.Accessor.GetValue(current);
        return true;
    }

    /// <summary>
    /// Whether the field is not there: a message field that is not set, a field of a oneof that is not
    /// the one of the packet, or a proto3 field with an explicit presence that is not set. A proto3 field
    /// without an explicit presence is always there: it holds its default value.
    /// </summary>
    static bool IsAbsent(IMessage message, FieldDescriptor field) =>
        field.HasPresence && !field.Accessor.HasValue(message);
}

/// <summary>A list of names the packet has to be (or not to be) in.</summary>
internal sealed class NameListConstraint
{
    public bool Allow;
    public string[] Values = [];

    /// <summary>
    /// Whether the constraint is satisfied. A packet with no channel (a map report) is not in an
    /// allow-list and is in no deny-list.
    /// </summary>
    public bool Satisfied(string? value)
    {
        var found = value is not null && Array.IndexOf(Values, value) >= 0;
        return Allow ? found : !found;
    }
}

/// <summary>A list of MQTT topic filters the publish topic has to match (or not to match).</summary>
internal sealed class TopicConstraint
{
    public bool Allow;
    public string[] Filters = [];

    public bool Satisfied(string? topic)
    {
        var matches = TopicFilter.MatchesAny(Filters, topic);
        return Allow ? matches : !matches;
    }
}

/// <summary>A list of portnums the packet has to be (or not to be) in.</summary>
internal sealed class PortnumConstraint
{
    public bool Allow;
    public int[] Values = [];

    public bool Satisfied(PortNum? portnum)
    {
        var found = portnum is not null && Array.IndexOf(Values, Convert.ToInt32(portnum.Value)) >= 0;
        return Allow ? found : !found;
    }
}

/// <summary>One condition of the <c>drop_if</c> of a rule.</summary>
internal sealed class FilterCondition
{
    public string Field = "";
    public FilterOp Op;
    public CompiledValue[] Values = [];
    public int? Portnum;
    public bool NeedsOpening;
    public FieldPath Path = new();
    public Regex? Pattern;

    /// <summary>Whether the condition is true for this packet (and then the rule fails).</summary>
    public bool IsTrue(FilterContext context)
    {
        // A condition with a portnum only applies to the packets of that portnum.
        if (Portnum is int only)
        {
            if (context.Input.Portnum is not PortNum portnum || Convert.ToInt32(portnum) != only)
                return false;
        }

        if (!Path.TryResolve(context, out var actual))
        {
            // The field is not there: the condition is false, except "ne", which is then true.
            return Op == FilterOp.Ne;
        }

        return Compare(actual);
    }

    bool Compare(object? actual) => Op switch
    {
        FilterOp.Eq => Matches(actual, Values[0]),
        FilterOp.Ne => !Matches(actual, Values[0]),
        FilterOp.In => Values.Any(value => Matches(actual, value)),
        FilterOp.Contains => actual is string text && text.Contains(Values[0].Text, StringComparison.Ordinal),
        FilterOp.Regex => actual is string subject && Pattern is not null && Pattern.IsMatch(subject),
        FilterOp.Lt => CompareNumbers(actual, Values[0]) < 0,
        FilterOp.Le => CompareNumbers(actual, Values[0]) <= 0,
        FilterOp.Gt => CompareNumbers(actual, Values[0]) > 0,
        FilterOp.Ge => CompareNumbers(actual, Values[0]) >= 0,
        _ => false,
    };

    static bool Matches(object? actual, CompiledValue expected) => expected.Kind switch
    {
        CompiledValueKind.String => actual is string text && string.Equals(text, expected.Text, StringComparison.Ordinal),
        CompiledValueKind.Bool => actual is bool flag && flag == expected.Bool,
        _ => actual is not null && Numbers(actual, expected),
    };

    static bool Numbers(object actual, CompiledValue expected)
    {
        if (actual is string)
            return false;
        // A float on one of the two sides: the two are compared as doubles.
        if (actual is float or double or decimal)
            return Convert.ToDouble(actual) == expected.Number;
        if (!TryInteger(actual, out var number))
            return false;
        // Two whole numbers: they are compared exactly, whatever their size.
        if (expected.IsInteger)
            return number == expected.Integer;
        return (double)number == expected.Number;
    }

    static int CompareNumbers(object? actual, CompiledValue expected)
    {
        if (actual is null)
            return int.MinValue;   // the field is not there: it never reaches here
        // A float on one of the two sides: the two are compared as doubles.
        if (actual is float or double or decimal)
            return Convert.ToDouble(actual).CompareTo(expected.Number);
        if (!TryInteger(actual, out var number))
            return int.MinValue;
        // Two whole numbers: they are compared exactly, whatever their size.
        if (expected.IsInteger)
            return number.CompareTo(expected.Integer);
        return ((double)number).CompareTo(expected.Number);
    }

    /// <summary>
    /// The value of a numeric field as an exact integer. Every integer of the protobufs fits in an
    /// <see cref="Int128"/>, so a 64-bit unsigned field with the high bit put is never an overflow.
    /// The conversion never throws: a value that is not an integer is not a number.
    /// </summary>
    static bool TryInteger(object actual, out Int128 number)
    {
        switch (actual)
        {
            case sbyte value: number = value; return true;
            case byte value: number = value; return true;
            case short value: number = value; return true;
            case ushort value: number = value; return true;
            case int value: number = value; return true;
            case uint value: number = value; return true;
            case long value: number = value; return true;
            case ulong value: number = value; return true;
            case Enum value:
                // The enums of the protobufs are int32, but an enum of a library may not be.
                try
                {
                    number = Convert.ToInt64(value);
                    return true;
                }
                catch (OverflowException)
                {
                    number = 0;
                    return false;
                }
            default:
                number = 0;
                return false;
        }
    }
}

/// <summary>One rule of the file, compiled.</summary>
internal sealed class FilterRule
{
    public string Name = "";
    public NameListConstraint? Channels;
    public TopicConstraint? Topics;
    public PortnumConstraint? Portnums;
    public FilterCondition[]? DropIf;
    public UnopenedPolicy Unopened;

    /// <summary>True when the rule needs a packet the broker could open.</summary>
    public bool NeedsOpening => Portnums is not null || (DropIf?.Any(condition => condition.NeedsOpening) ?? false);

    /// <summary>Whether the packet passes the rule (every constraint of the rule is satisfied).</summary>
    public bool Passes(FilterContext context)
    {
        var opened = context.Opened;
        if (!opened)
        {
            // The broker could not open the packet.
            if (Unopened == UnopenedPolicy.Drop)
                return false;
            // "allow": the constraints that need an opened packet are skipped, the rest still applies.
        }
        else if (Portnums is not null && !Portnums.Satisfied(context.Input.Portnum))
        {
            return false;
        }

        if (DropIf is not null)
        {
            foreach (var condition in DropIf)
            {
                if (condition.NeedsOpening && !opened)
                    continue;   // skipped for a packet the broker could not open
                if (condition.IsTrue(context))
                    return false;
            }
        }

        if (Channels is not null && !Channels.Satisfied(context.Input.Channel))
            return false;
        if (Topics is not null && !Topics.Satisfied(context.Input.Topic))
            return false;
        return true;
    }
}

/// <summary>What the filter knows about the packet it is judging.</summary>
internal sealed class FilterContext
{
    readonly FilterMetrics? _metrics;
    IMessage? _payload;
    bool _payloadRead;
    string? _text;
    bool _textRead;

    public FilterContext(FilterInput input, FilterMetrics? metrics)
    {
        Input = input;
        _metrics = metrics;
    }

    public FilterInput Input { get; }

    /// <summary>True when the broker opened the packet (it has the decoded data).</summary>
    public bool Opened => Input.Data is not null;

    /// <summary>
    /// The text of a text message, read once and only when a rule needs it. Null when the packet was
    /// not opened.
    /// </summary>
    public string? Text
    {
        get
        {
            if (_textRead)
                return _text;
            _textRead = true;
            var data = Input.Data;
            if (data is null)
                return null;
            _metrics?.PayloadDecoded();
            _text = data.Payload.ToStringUtf8();
            return _text;
        }
    }

    /// <summary>
    /// The decoded payload of the packet, decoded once and only when a rule needs it. Null when the
    /// packet was not opened or when its payload does not parse.
    /// </summary>
    public IMessage? Payload
    {
        get
        {
            if (_payloadRead)
                return _payload;
            _payloadRead = true;
            _payload = Decode(Input, _metrics);
            return _payload;
        }
    }

    static IMessage? Decode(FilterInput input, FilterMetrics? metrics)
    {
        var data = input.Data;
        if (data is null)
            return null;
        metrics?.PayloadDecoded();
        return Parse(Convert.ToInt32(input.Portnum ?? PortNum.UnknownApp), data.Payload);
    }

    /// <summary>The payload of the packet, decoded as the message of its portnum.</summary>
    static IMessage? Parse(int portnum, ByteString payload)
    {
        try
        {
            if (portnum == FilterSchema.PositionApp)
                return Position.Parser.ParseFrom(payload);
            if (portnum == FilterSchema.NodeInfoApp)
                return User.Parser.ParseFrom(payload);
            if (portnum == FilterSchema.TelemetryApp)
                return Telemetry.Parser.ParseFrom(payload);
            if (portnum == FilterSchema.WaypointApp)
                return Waypoint.Parser.ParseFrom(payload);
            if (portnum == FilterSchema.NeighborInfoApp)
                return NeighborInfo.Parser.ParseFrom(payload);
            if (portnum == FilterSchema.MapReportApp)
                return MapReport.Parser.ParseFrom(payload);
            if (portnum == FilterSchema.RoutingApp)
                return Routing.Parser.ParseFrom(payload);
        }
        catch (InvalidProtocolBufferException)
        {
            return null;   // the payload is not the message of its portnum: the field is not there
        }
        return null;
    }
}

/// <summary>
/// The rules of the file, compiled. Immutable: the broker swaps one reference when the file changes
/// and the readers never lock.
/// </summary>
public sealed class FilterRuleset
{
    /// <summary>An empty ruleset: no rule, nothing is filtered.</summary>
    public static readonly FilterRuleset Empty = new(
        new Dictionary<string, FilterRule[]>(StringComparer.Ordinal), null,
        new Dictionary<uint, FilterRule[]>(), null,
        new Dictionary<uint, FilterRule[]>(), null, 0, 0, 0, 0, 0);

    internal readonly Dictionary<string, FilterRule[]> Users;
    internal readonly FilterRule[]? UsersStar;
    internal readonly Dictionary<uint, FilterRule[]> Gateways;
    internal readonly FilterRule[]? GatewaysStar;
    internal readonly Dictionary<uint, FilterRule[]> Nodes;
    internal readonly FilterRule[]? NodesStar;

    internal FilterRuleset(
        Dictionary<string, FilterRule[]> users, FilterRule[]? usersStar,
        Dictionary<uint, FilterRule[]> gateways, FilterRule[]? gatewaysStar,
        Dictionary<uint, FilterRule[]> nodes, FilterRule[]? nodesStar,
        int userRules, int gatewayRules, int nodeRules, int regexPatternCount, long regexBytes)
    {
        Users = users;
        UsersStar = usersStar;
        Gateways = gateways;
        GatewaysStar = gatewaysStar;
        Nodes = nodes;
        NodesStar = nodesStar;
        UserRuleCount = userRules;
        GatewayRuleCount = gatewayRules;
        NodeRuleCount = nodeRules;
        RegexPatternCount = regexPatternCount;
        RegexBytes = regexBytes;
    }

    /// <summary>The number of rules of the file.</summary>
    public int RuleCount => UserRuleCount + GatewayRuleCount + NodeRuleCount;

    /// <summary>The number of rules of the user scopes.</summary>
    public int UserRuleCount { get; }

    /// <summary>The number of rules of the gateway scopes.</summary>
    public int GatewayRuleCount { get; }

    /// <summary>The number of rules of the node scopes.</summary>
    public int NodeRuleCount { get; }

    /// <summary>
    /// How many distinct patterns of regular expressions the file holds. The same pattern is
    /// compiled once and shared by every condition that uses it, so this is the number of compiled
    /// patterns and not the number of conditions.
    /// </summary>
    internal int RegexPatternCount { get; }

    /// <summary>
    /// How many bytes the distinct patterns of the file allocated when they were compiled. The cost
    /// of a pattern depends on its shape, so it is measured and not counted.
    /// </summary>
    internal long RegexBytes { get; }

    /// <summary>
    /// Judges one packet: it has to pass every rule of every scope that applies to it (its user, the
    /// star of the users, its gateway, the star of the gateways, its node and the star of the nodes).
    /// </summary>
    public FilterVerdict Evaluate(in FilterInput input, FilterMetrics? metrics = null)
    {
        FilterRule[]? userRules = null;
        if (input.User is not null && Users.TryGetValue(input.User, out var foundUsers))
            userRules = foundUsers;
        var userStar = UsersStar;

        FilterRule[]? gatewayRules = null;
        if (Gateways.TryGetValue(input.GatewayNode, out var foundGateways))
            gatewayRules = foundGateways;
        var gatewayStar = GatewaysStar;

        FilterRule[]? nodeRules = null;
        if (Nodes.TryGetValue(input.From, out var foundNodes))
            nodeRules = foundNodes;
        var nodeStar = NodesStar;

        // Nothing applies to this packet: no rule is read and nothing is allocated.
        if (userRules is null && userStar is null && gatewayRules is null && gatewayStar is null
            && nodeRules is null && nodeStar is null)
        {
            return FilterVerdict.Pass;
        }

        var context = new FilterContext(input, metrics);

        if (userRules is not null)
        {
            var verdict = Check(userRules, context, FilterSchema.ScopeKinds[0], input.User!);
            if (!verdict.Passed)
                return verdict;
        }
        if (userStar is not null)
        {
            var verdict = Check(userStar, context, FilterSchema.ScopeKinds[0], "*");
            if (!verdict.Passed)
                return verdict;
        }
        if (gatewayRules is not null)
        {
            var verdict = Check(gatewayRules, context, FilterSchema.ScopeKinds[1], input.Gateway ?? FilterSchema.NodeId(input.GatewayNode));
            if (!verdict.Passed)
                return verdict;
        }
        if (gatewayStar is not null)
        {
            var verdict = Check(gatewayStar, context, FilterSchema.ScopeKinds[1], "*");
            if (!verdict.Passed)
                return verdict;
        }
        if (nodeRules is not null)
        {
            var verdict = Check(nodeRules, context, FilterSchema.ScopeKinds[2], FilterSchema.NodeId(input.From));
            if (!verdict.Passed)
                return verdict;
        }
        if (nodeStar is not null)
        {
            var verdict = Check(nodeStar, context, FilterSchema.ScopeKinds[2], "*");
            if (!verdict.Passed)
                return verdict;
        }
        return FilterVerdict.Pass;
    }

    static FilterVerdict Check(FilterRule[] rules, FilterContext context, string scope, string scopeKey)
    {
        foreach (var rule in rules)
        {
            if (!rule.Passes(context))
                return new FilterVerdict(false, rule.Name, scope, scopeKey);
        }
        return FilterVerdict.Pass;
    }
}
