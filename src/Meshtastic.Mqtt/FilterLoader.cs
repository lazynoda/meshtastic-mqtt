using System.Globalization;
using System.Text.RegularExpressions;
using Google.Protobuf.Reflection;
using Meshtastic.Protobufs;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Meshtastic.Mqtt;

/// <summary>
/// The rules file cannot be read or is not valid: every problem it found is in
/// <see cref="Errors"/>, one per line (at most the first <see cref="MaxReportedErrors"/> of them,
/// and then one line that counts the ones that are not listed).
/// </summary>
public sealed class FilterException : Exception
{
    /// <summary>
    /// The most problems a report lists: a file with more problems is reported with the first ones
    /// and with the number of the ones that are not listed.
    /// </summary>
    public const int MaxReportedErrors = 20;

    /// <summary>
    /// The problems of the file, one per line: at most the first
    /// <see cref="MaxReportedErrors"/> of them, and then one line that counts the ones that are not
    /// listed.
    /// </summary>
    public IReadOnlyList<string> Errors { get; }

    /// <summary>How many problems the file had, the ones that are listed and the ones that are not.</summary>
    public int TotalErrors { get; }

    /// <summary>
    /// How many values the loader had compiled when it refused the file. It is the budget of the
    /// values of the file, and the tests use it to check that the load stops at the budget.
    /// </summary>
    internal int CompiledValues { get; init; }

    /// <summary>
    /// How many distinct patterns of regular expressions the loader had compiled when it refused the
    /// file. It is the budget of the patterns of the file, and the tests use it to check that the
    /// load stops at the budget.
    /// </summary>
    internal int CompiledPatterns { get; init; }

    /// <summary>
    /// How many bytes the distinct patterns of the regular expressions of the file allocated when
    /// they were compiled. It is the budget of the memory of the patterns of the file, and the tests
    /// use it to check that the load stops at the budget.
    /// </summary>
    internal long RegexBytes { get; init; }

    /// <summary>The problems of the file, and the report that lists them.</summary>
    /// <param name="errors">Every problem of the file.</param>
    public FilterException(IReadOnlyList<string> errors)
        : this(Report(errors), errors.Count)
    {
    }

    FilterException(IReadOnlyList<string> reported, int total)
        : base(string.Join(Environment.NewLine, reported))
    {
        Errors = reported;
        TotalErrors = total;
    }

    /// <summary>
    /// The report of a file with many problems: the first ones, and the number of the ones that are
    /// not listed. A file with a thousand problems does not write a thousand lines.
    /// </summary>
    static IReadOnlyList<string> Report(IReadOnlyList<string> errors)
    {
        if (errors.Count <= MaxReportedErrors)
            return errors;
        var reported = new List<string>(MaxReportedErrors + 1);
        for (var i = 0; i < MaxReportedErrors; i++)
            reported.Add(errors[i]);
        reported.Add($"... and {errors.Count - MaxReportedErrors} more errors");
        return reported;
    }
}

/// <summary>
/// The file is over one of its budgets: the load stops at once, without compiling the rest of the
/// file.
/// </summary>
sealed class FilterBudgetException(string message) : Exception(message);

/// <summary>
/// Reads the rules file and compiles it into a <see cref="FilterRuleset"/>.
/// </summary>
/// <remarks>
/// The whole file is read and checked before anything is compiled: a file with one problem is a file
/// that is not loaded at all, and the broker keeps the rules it had. Every problem is reported, with
/// the line the YAML gives.
/// </remarks>
public static class FilterLoader
{
    /// <summary>The most rules a file may hold.</summary>
    public const int MaxRules = 10_000;

    /// <summary>The most items a list of the file may hold.</summary>
    public const int MaxListItems = 1_000;

    /// <summary>
    /// The most conditions a file may hold, counted after the aliases are expanded.
    /// </summary>
    public const int MaxConditions = 100_000;

    /// <summary>
    /// The most values a file may compile (the items of the lists of channels, topics and portnums
    /// and the values of the operator <c>in</c>), counted after the aliases are expanded.
    /// </summary>
    public const int MaxCompiledValues = 1_000_000;

    /// <summary>
    /// The most distinct patterns of regular expressions a file may hold, counted after the aliases
    /// are expanded. The memory the patterns allocate is bounded by <see cref="MaxRegexBytes"/>.
    /// </summary>
    public const int MaxRegexPatterns = 1_000;

    /// <summary>
    /// The most bytes the distinct patterns of the regular expressions of a file may allocate when
    /// they are compiled. The cost of a pattern depends on its shape, so the memory is measured
    /// while the patterns are compiled and not counted.
    /// </summary>
    public const long MaxRegexBytes = 134_217_728;

    /// <summary>The most bytes a file may have.</summary>
    public const int MaxFileBytes = 1_048_576;

    /// <summary>The most characters of a string value of the file.</summary>
    public const int MaxValueLength = 512;

    /// <summary>The most characters of the pattern of a regular expression.</summary>
    public const int MaxRegexLength = 512;

    /// <summary>The most characters of the name of a rule.</summary>
    public const int MaxNameLength = 64;

    /// <summary>How long a regular expression may run before it is given up.</summary>
    static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// The operators, from the vocabulary of the schema and the enum of the code: a name of
    /// <see cref="FilterSchema.Ops"/> that is not an operator is not accepted, and an operator that is
    /// not in the schema is not read either.
    /// </summary>
    static readonly Dictionary<string, FilterOp> Ops = BuildOps();

    static Dictionary<string, FilterOp> BuildOps()
    {
        var map = new Dictionary<string, FilterOp>(StringComparer.Ordinal);
        foreach (var name in FilterSchema.Ops)
        {
            if (Enum.TryParse<FilterOp>(name, ignoreCase: true, out var op))
                map[name] = op;
        }
        return map;
    }

    /// <summary>Reads the file and compiles it.</summary>
    /// <param name="path">The path of the rules file.</param>
    /// <param name="knownUsers">The user names of the config (a rule of an unknown user is an error).</param>
    public static FilterRuleset LoadFile(string path, IReadOnlyCollection<string> knownUsers)
    {
        string yaml;
        try
        {
            var info = new System.IO.FileInfo(path);
            if (info.Exists && info.Length > MaxFileBytes)
            {
                throw new FilterException([$"{path}: {SizeMessage(info.Length)}"]);
            }
            yaml = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new FilterException([$"{path}: the file cannot be read: {ex.Message}"]);
        }
        return Parse(yaml, knownUsers, path);
    }

    /// <summary>Compiles the rules of a file that is already in memory.</summary>
    /// <param name="yaml">The text of the file.</param>
    /// <param name="knownUsers">The user names of the config (a rule of an unknown user is an error).</param>
    /// <param name="source">The name of the file, as the messages of the errors write it.</param>
    public static FilterRuleset Parse(string yaml, IReadOnlyCollection<string> knownUsers, string source = "filters.yaml") =>
        Parse(yaml, knownUsers, source, MaxRegexBytes);

    /// <summary>
    /// Compiles the rules of a file that is already in memory, with a budget of the memory of the
    /// patterns of its own.
    /// </summary>
    /// <param name="yaml">The text of the file.</param>
    /// <param name="knownUsers">The user names of the config (a rule of an unknown user is an error).</param>
    /// <param name="source">The name of the file, as the messages of the errors write it.</param>
    /// <param name="maxRegexBytes">The most bytes the patterns of the file may allocate when they
    /// are compiled.</param>
    internal static FilterRuleset Parse(string yaml, IReadOnlyCollection<string> knownUsers, string source,
        long maxRegexBytes)
    {
        // The size of the file is checked before parsing it: a file that is too big is not read.
        var size = System.Text.Encoding.UTF8.GetByteCount(yaml);
        if (size > MaxFileBytes)
            throw new FilterException([$"{source}: {SizeMessage(size)}"]);

        var builder = new RulesetBuilder(knownUsers, source, maxRegexBytes);
        try
        {
            var stream = new YamlStream();
            stream.Load(new StringReader(yaml));
            foreach (var document in stream.Documents)
                builder.ReadDocument(document);
        }
        catch (FilterBudgetException ex)
        {
            // The file is over one of its budgets: the load stops at once.
            builder.Errors.Add(ex.Message);
        }
        catch (YamlException ex)
        {
            builder.Errors.Add($"{source}:{ex.Start.Line}: the file is not valid YAML: {ex.Message}");
        }
        catch (ArgumentException ex)
        {
            // A key that is written twice: the representation model refuses it.
            builder.Errors.Add($"{source}: the file cannot be read: {ex.Message}");
        }
        if (builder.Errors.Count > 0)
        {
            throw new FilterException(builder.Errors)
            {
                CompiledValues = builder.CompiledValues,
                CompiledPatterns = builder.CompiledPatterns,
                RegexBytes = builder.RegexBytes,
            };
        }
        return builder.Build();
    }

    /// <summary>The message of a file that is over the budget of its size.</summary>
    internal static string SizeMessage(long size) =>
        $"the file is bigger than {MaxFileBytes} bytes (the budget of the size is {MaxFileBytes} bytes, the file has {size})";

    /// <summary>
    /// Walks the parts of a path in the descriptor of a protobuf and checks every one of them: a
    /// repeated field and a bytes field are not a value, and a part that is not a message cannot be
    /// walked into.
    /// </summary>
    internal static bool TryWalkFields(MessageDescriptor root, string[] parts, out FieldDescriptor[] fields,
        out string error)
    {
        fields = [];
        error = string.Empty;
        var found = new List<FieldDescriptor>();
        var current = root;
        for (var i = 0; i < parts.Length; i++)
        {
            var part = parts[i];
            if (part.Length == 0)
            {
                error = "the path of the field has an empty part";
                return false;
            }
            var descriptor = current.FindFieldByName(part);
            if (descriptor is null)
            {
                error = $"'{part}' is not a field of {current.Name}";
                return false;
            }
            if (descriptor.IsRepeated)
            {
                error = $"'{part}' is a repeated field and cannot be read";
                return false;
            }
            if (descriptor.FieldType == FieldType.Bytes)
            {
                error = $"'{part}' is a bytes field and cannot be read";
                return false;
            }
            if (i < parts.Length - 1)
            {
                if (descriptor.FieldType is not (FieldType.Message or FieldType.Group))
                {
                    error = $"'{part}' is not a message: a nested path needs a message field";
                    return false;
                }
                current = descriptor.MessageType!;
            }
            else if (descriptor.FieldType is FieldType.Message or FieldType.Group)
            {
                error = $"'{part}' is a message: read one of its fields";
                return false;
            }
            found.Add(descriptor);
        }
        fields = found.ToArray();
        return true;
    }

    /// <summary>
    /// The prefixes of the path of a field the loader accepts. They are the ones of the schema: the
    /// loader and the documentation never drift apart.
    /// </summary>
    internal static IReadOnlyList<string> AcceptedFieldPrefixes => FilterSchema.FieldPrefixes;

    /// <summary>
    /// Builds the path of a field and checks it against the protobuf it belongs to.
    /// </summary>
    /// <param name="field">The path of the field, with its prefix.</param>
    /// <param name="portnum">The portnum of the condition (the payload is decoded as its message).</param>
    /// <param name="path">The path of the field, when it is read.</param>
    /// <param name="needsOpening">Whether the path needs a packet the broker could open.</param>
    /// <param name="error">Why the path is not read.</param>
    internal static bool TryBuildPath(string field, int? portnum, out FieldPath path, out bool needsOpening,
        out string error)
    {
        path = new FieldPath();
        needsOpening = false;
        error = string.Empty;

        // The prefixes are the ones of the schema: the loader and the documentation never drift apart.
        var prefix = FilterSchema.FieldPrefixes
            .FirstOrDefault(candidate => field.StartsWith(candidate, StringComparison.Ordinal));
        if (prefix is null)
        {
            error = $"the field must start with one of {string.Join(", ", FilterSchema.FieldPrefixes)}";
            return false;
        }

        MessageDescriptor root;
        var rest = field[prefix.Length..];
        switch (prefix)
        {
            case "packet.":
                root = MeshPacket.Descriptor;
                break;
            case "data.":
                root = Protobufs.Data.Descriptor;
                needsOpening = true;
                break;
            case "payload.":
                needsOpening = true;
                if (portnum is null)
                {
                    error = "a payload condition needs a portnum (the payload is decoded as the message "
                        + "of its portnum)";
                    return false;
                }
                if (portnum == FilterSchema.TextMessageApp)
                {
                    if (rest != "text")
                    {
                        error = "the payload of a TEXT_MESSAGE_APP is text: the only field of it is 'text'";
                        return false;
                    }
                    path.Prefix = "payload";
                    path.IsText = true;
                    path.Kind = CompiledValueKind.String;
                    return true;
                }
                if (!FilterSchema.PayloadMessages.TryGetValue(portnum.Value, out var descriptor))
                {
                    error = $"the portnum '{FilterSchema.PortNumName(portnum.Value)}' has no payload the filter "
                        + $"can decode (the decoded ones are {string.Join(", ", FilterSchema.PayloadPortnumNames)})";
                    return false;
                }
                root = descriptor;
                break;
            default:
                error = $"the prefix '{prefix}' is not handled by the loader";
                return false;
        }

        var parts = rest.Split('.');
        if (!TryWalkFields(root, parts, out var fields, out error))
            return false;

        path.Prefix = prefix.TrimEnd('.');
        path.Fields = fields;
        path.Kind = KindOf(fields[^1]);
        path.Leaf = fields[^1];
        return true;
    }

    /// <summary>The kind of the value a field holds.</summary>
    static CompiledValueKind KindOf(FieldDescriptor field) => field.FieldType switch
    {
        FieldType.Bool => CompiledValueKind.Bool,
        FieldType.String => CompiledValueKind.String,
        FieldType.Enum => CompiledValueKind.Enum,
        _ => CompiledValueKind.Number,
    };

    /// <summary>The kind of a scalar of the file, as the YAML resolves it.</summary>
    enum ScalarKind
    {
        Null,
        String,
        Integer,
        Number,
        Bool,
    }

    /// <summary>Reads the file and builds the ruleset.</summary>
    sealed class RulesetBuilder
    {
        readonly IReadOnlyCollection<string> _knownUsers;
        readonly string _source;
        readonly long _maxRegexBytes;
        readonly Dictionary<string, List<FilterRule>> _users = new(StringComparer.Ordinal);
        readonly Dictionary<uint, List<FilterRule>> _gateways = [];
        readonly Dictionary<uint, List<FilterRule>> _nodes = [];
        readonly HashSet<string> _names = new(StringComparer.Ordinal);
        readonly Dictionary<string, Regex> _regexes = new(StringComparer.Ordinal);
        List<FilterRule>? _usersStar;
        List<FilterRule>? _gatewaysStar;
        List<FilterRule>? _nodesStar;
        int _ruleCount;
        int _conditionCount;
        int _compiledValueCount;
        int _userRules;
        int _gatewayRules;
        int _nodeRules;
        long _regexBytes;

        public RulesetBuilder(IReadOnlyCollection<string> knownUsers, string source, long maxRegexBytes)
        {
            _knownUsers = knownUsers;
            _source = source;
            _maxRegexBytes = maxRegexBytes;
        }

        /// <summary>Every problem of the file, one per line.</summary>
        public List<string> Errors { get; } = [];

        /// <summary>How many values the file has compiled so far.</summary>
        public int CompiledValues => _compiledValueCount;

        /// <summary>How many distinct patterns of regular expressions the file has compiled.</summary>
        public int CompiledPatterns => _regexes.Count;

        /// <summary>How many bytes the distinct patterns of the file allocated when they were compiled.</summary>
        public long RegexBytes => _regexBytes;

        /// <summary>Records one problem of the file.</summary>
        public void Error(YamlNode? node, string message)
        {
            var line = node?.Start.Line ?? 0;
            Errors.Add(line > 0 ? $"{_source}:{line}: {message}" : $"{_source}: {message}");
        }

        /// <summary>
        /// The file is over one of its budgets: the load stops at once, without compiling the rest of
        /// the file.
        /// </summary>
        void OverBudget(string what, int limit, int count) =>
            throw new FilterBudgetException(
                $"{_source}: the file holds more than {limit} {what} (the budget of {what} is {limit}, the file has {count})");

        /// <summary>
        /// The patterns of the file allocate more memory than the budget allows: the load stops at
        /// once, with the pattern that crossed the budget.
        /// </summary>
        /// <param name="limit">The budget of the memory of the patterns, in bytes.</param>
        /// <param name="total">The bytes the patterns of the file have allocated.</param>
        /// <param name="pattern">The pattern that crossed the budget.</param>
        /// <param name="where">The rule the condition is in.</param>
        /// <param name="line">The line of the condition, or 0 when it has none.</param>
        void OverRegexMemory(long limit, long total, string pattern, string where, long line)
        {
            var message = $"{where}: the regex patterns of the file allocate more than {limit} bytes when compiled "
                + $"(the budget of regex memory is {limit} bytes, the file reached {total} bytes "
                + $"at the pattern '{pattern}')";
            throw new FilterBudgetException(line > 0 ? $"{_source}:{line}: {message}" : $"{_source}: {message}");
        }

        /// <summary>Counts one condition of the file and refuses it when the budget is over.</summary>
        void CountCondition()
        {
            if (++_conditionCount > MaxConditions)
                OverBudget("conditions", MaxConditions, _conditionCount);
        }

        /// <summary>Counts one value the file compiles and refuses it when the budget is over.</summary>
        void CountValue()
        {
            if (++_compiledValueCount > MaxCompiledValues)
                OverBudget("compiled values", MaxCompiledValues, _compiledValueCount);
        }

        /// <summary>Reads one document of the file (a file may hold several).</summary>
        public void ReadDocument(YamlDocument document)
        {
            var root = document.RootNode;
            if (root is null)
                return;   // an empty file: no rules
            if (root is not YamlMappingNode map)
            {
                Error(root, "the file must be a map of scopes: users, gateways and nodes");
                return;
            }
            foreach (var (keyNode, valueNode) in map.Children)
            {
                var key = Text(keyNode);
                if (!FilterSchema.ScopeKeys.Contains(key, StringComparer.Ordinal))
                {
                    Error(keyNode, $"unknown scope '{key}' (the scopes are {string.Join(", ", FilterSchema.ScopeKeys)})");
                    continue;
                }
                ReadScope(key, valueNode);
            }
        }

        /// <summary>Reads one scope: a map of keys to lists of rules.</summary>
        void ReadScope(string scope, YamlNode node)
        {
            if (node is not YamlMappingNode map)
            {
                Error(node, $"the scope '{scope}' must be a map of keys to lists of rules");
                return;
            }
            foreach (var (keyNode, valueNode) in map.Children)
            {
                var key = Text(keyNode);
                uint? nodeId = null;
                if (scope == FilterSchema.ScopeKeys[0])
                {
                    if (key != "*" && !_knownUsers.Contains(key))
                    {
                        Error(keyNode, $"unknown user '{key}' (the users of the config are {string.Join(", ", _knownUsers)})");
                        continue;
                    }
                }
                else if (key != "*")
                {
                    if (!PacketInspector.TryParseGatewayId(key, out var number))
                    {
                        Error(keyNode, $"'{key}' is not a node id (! and 8 lowercase hex digits) and not '*'");
                        continue;
                    }
                    nodeId = number;
                }
                ReadRules(scope, key, nodeId, valueNode);
            }
        }

        /// <summary>Reads the list of rules of one key of a scope.</summary>
        void ReadRules(string scope, string key, uint? nodeId, YamlNode node)
        {
            if (node is not YamlSequenceNode sequence)
            {
                Error(node, $"'{scope}.{key}' must be a list of rules");
                return;
            }
            if (sequence.Children.Count > MaxListItems)
            {
                Error(node, $"'{scope}.{key}' holds more than {MaxListItems} rules");
                return;
            }
            var index = 0;
            foreach (var child in sequence.Children)
                ReadRule(scope, key, nodeId, index++, child);
        }

        /// <summary>Reads one rule.</summary>
        void ReadRule(string scope, string key, uint? nodeId, int index, YamlNode node)
        {
            var where = $"{scope}.{key}[{index}]";
            if (node is not YamlMappingNode map)
            {
                Error(node, $"{where}: a rule must be a map with a name and its constraints");
                return;
            }
            if (++_ruleCount > MaxRules)
            {
                OverBudget("rules", MaxRules, _ruleCount);
            }

            // The name is read first: every other message of the rule names it.
            var hasName = false;
            string? name = null;
            foreach (var (keyNode, valueNode) in map.Children)
            {
                if (Text(keyNode) != "name")
                    continue;
                hasName = true;
                name = ReadName(where, valueNode);
                break;
            }
            if (!hasName)
            {
                Error(node, $"{where}: a rule needs a name");
                return;
            }
            if (name is null)
                return;   // the name was refused: the problem is already recorded
            if (!_names.Add(name))
            {
                Error(node, $"{where}: the name '{name}' is used twice (the names are unique in the file)");
                return;
            }
            where = $"{where} (rule '{name}')";

            var rule = new FilterRule { Name = name };
            var constraints = 0;
            foreach (var (keyNode, valueNode) in map.Children)
            {
                var ruleKey = Text(keyNode);
                // The vocabulary of the schema is the one that is accepted: a key that is not in it is
                // refused, so the documentation and the loader never drift apart.
                if (!FilterSchema.RuleKeys.Contains(ruleKey, StringComparer.Ordinal))
                {
                    Error(keyNode, $"{where}: unknown key '{ruleKey}' in a rule "
                        + $"(the keys are {string.Join(", ", FilterSchema.RuleKeys)})");
                    continue;
                }
                switch (ruleKey)
                {
                    case "name":
                        break;
                    case "channels":
                        rule.Channels = ReadNames(where, valueNode, "channels");
                        constraints++;
                        break;
                    case "topics":
                        rule.Topics = ReadTopics(where, valueNode);
                        constraints++;
                        break;
                    case "portnums":
                        rule.Portnums = ReadPortnums(where, valueNode);
                        constraints++;
                        break;
                    case "drop_if":
                        rule.DropIf = ReadConditions(where, valueNode);
                        constraints++;
                        break;
                    case "unopened":
                        rule.Unopened = ReadUnopened(where, valueNode);
                        break;
                    default:
                        Error(keyNode, $"{where}: the key '{ruleKey}' of a rule is not handled by the loader");
                        break;
                }
            }

            if (constraints == 0)
            {
                Error(node, $"{where}: a rule needs at least one constraint "
                    + "(channels, topics, portnums or drop_if)");
                return;
            }
            if (rule.NeedsOpening && rule.Unopened == UnopenedPolicy.None)
            {
                Error(node, $"{where}: the rule needs a packet the broker could open (it has portnums, "
                    + "or a data. or a payload. condition): write 'unopened: drop' or 'unopened: allow'");
                return;
            }

            AddRule(scope, key, nodeId, rule);
        }

        /// <summary>Reads the name of a rule.</summary>
        string? ReadName(string where, YamlNode node)
        {
            if (!TryScalar(node, out var text, out var kind) || kind != ScalarKind.String)
            {
                Error(node, $"{where}: the name of a rule must be a text");
                return null;
            }
            if (text.Length == 0 || text.Length > MaxNameLength)
            {
                Error(node, $"{where}: the name '{text}' must hold between 1 and {MaxNameLength} characters");
                return null;
            }
            foreach (var c in text)
            {
                if (!char.IsAsciiLetterOrDigit(c) && c is not ('_' or '.' or '-'))
                {
                    Error(node, $"{where}: the name '{text}' may only hold letters, digits, '_', '.' and '-'");
                    return null;
                }
            }
            return text;
        }

        /// <summary>Reads a constraint of names (the channels).</summary>
        NameListConstraint? ReadNames(string where, YamlNode node, string what) =>
            ReadConstraint(where, node, what, child => ReadStringList(where, child, what), out var allow, out var deny)
                ? new NameListConstraint { Allow = allow is not null, Values = (allow ?? deny!).ToArray() }
                : null;

        /// <summary>Reads a constraint of topic filters.</summary>
        TopicConstraint? ReadTopics(string where, YamlNode node)
        {
            var read = (YamlNode child) =>
            {
                var values = ReadStringList(where, child, "topics");
                if (values is null)
                    return null;
                foreach (var filter in values)
                {
                    if (!TopicFilter.IsValid(filter, out var error))
                    {
                        Error(child, $"{where}: 'topics' has an invalid topic filter: {error}");
                        return null;
                    }
                }
                return values;
            };
            return ReadConstraint(where, node, "topics", read, out var allow, out var deny)
                ? new TopicConstraint { Allow = allow is not null, Filters = (allow ?? deny!).ToArray() }
                : null;
        }

        /// <summary>Reads a constraint of portnums.</summary>
        PortnumConstraint? ReadPortnums(string where, YamlNode node) =>
            ReadConstraint(where, node, "portnums", child => ReadPortnumList(where, child), out var allow, out var deny)
                ? new PortnumConstraint { Allow = allow is not null, Values = (allow ?? deny!).ToArray() }
                : null;

        /// <summary>
        /// Reads a constraint: a map with an <c>allow</c> or a <c>deny</c> list, never with both.
        /// </summary>
        bool ReadConstraint<T>(string where, YamlNode node, string what, Func<YamlNode, List<T>?> read,
            out List<T>? allow, out List<T>? deny)
        {
            allow = null;
            deny = null;
            if (node is not YamlMappingNode map)
            {
                Error(node, $"{where}: '{what}' must be a map with 'allow' or 'deny'");
                return false;
            }
            foreach (var (keyNode, valueNode) in map.Children)
            {
                var key = Text(keyNode);
                // The vocabulary of the schema is the one that is accepted.
                if (!FilterSchema.ConstraintKeys.Contains(key, StringComparer.Ordinal))
                {
                    Error(keyNode, $"{where}: unknown key '{key}' in '{what}' "
                        + $"(the keys are {string.Join(", ", FilterSchema.ConstraintKeys)})");
                    continue;
                }
                var values = read(valueNode);
                if (values is null)
                    return false;
                if (key == "allow")
                    allow = values;
                else
                    deny = values;
            }
            if (allow is not null && deny is not null)
            {
                Error(node, $"{where}: '{what}' has both 'allow' and 'deny' (a constraint is one or the other)");
                return false;
            }
            if (allow is null && deny is null)
            {
                Error(node, $"{where}: '{what}' has neither 'allow' nor 'deny'");
                return false;
            }
            return true;
        }

        /// <summary>Reads a list of texts.</summary>
        List<string>? ReadStringList(string where, YamlNode node, string what)
        {
            if (node is not YamlSequenceNode sequence)
            {
                Error(node, $"{where}: '{what}' must be a list");
                return null;
            }
            if (sequence.Children.Count > MaxListItems)
            {
                Error(node, $"{where}: '{what}' holds more than {MaxListItems} items");
                return null;
            }
            var values = new List<string>();
            foreach (var child in sequence.Children)
            {
                CountValue();
                if (!TryScalar(child, out var text, out var kind) || kind != ScalarKind.String)
                {
                    Error(child, $"{where}: the items of '{what}' must be texts");
                    return null;
                }
                if (text.Length > MaxValueLength)
                {
                    Error(child, $"{where}: an item of '{what}' is longer than {MaxValueLength} characters");
                    return null;
                }
                values.Add(text);
            }
            return values;
        }

        /// <summary>Reads a list of portnums (their names or their numbers).</summary>
        List<int>? ReadPortnumList(string where, YamlNode node)
        {
            if (node is not YamlSequenceNode sequence)
            {
                Error(node, $"{where}: 'portnums' must be a list");
                return null;
            }
            if (sequence.Children.Count > MaxListItems)
            {
                Error(node, $"{where}: 'portnums' holds more than {MaxListItems} items");
                return null;
            }
            var values = new List<int>();
            foreach (var child in sequence.Children)
            {
                CountValue();
                if (!TryScalar(child, out var text, out var kind) || kind == ScalarKind.Null)
                {
                    Error(child, $"{where}: the items of 'portnums' must be portnum names or numbers");
                    return null;
                }
                if (kind == ScalarKind.Integer)
                {
                    if (!int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number))
                    {
                        Error(child, $"{where}: '{text}' is not a portnum of the firmware");
                        return null;
                    }
                    // A number outside the range of the protobufs is not a portnum.
                    if (!FilterSchema.IsPortNumNumber(number))
                    {
                        Error(child, $"{where}: '{number}' is not a portnum of the firmware "
                            + $"(the portnums are 0 to {FilterSchema.MaxPortNum})");
                        return null;
                    }
                    values.Add(number);
                    continue;
                }
                if (kind != ScalarKind.String || !FilterSchema.TryPortNumNumber(text, out var portnum))
                {
                    Error(child, $"{where}: '{text}' is not a portnum of the firmware");
                    return null;
                }
                values.Add(portnum);
            }
            return values;
        }

        /// <summary>Reads the <c>unopened</c> key of a rule.</summary>
        UnopenedPolicy ReadUnopened(string where, YamlNode node)
        {
            if (!TryScalar(node, out var text, out var kind) || kind != ScalarKind.String)
            {
                Error(node, $"{where}: 'unopened' must be 'drop' or 'allow'");
                return UnopenedPolicy.None;
            }
            switch (text)
            {
                case "drop":
                    return UnopenedPolicy.Drop;
                case "allow":
                    return UnopenedPolicy.Allow;
                default:
                    Error(node, $"{where}: 'unopened' must be 'drop' or 'allow' "
                        + $"(the values are {string.Join(", ", FilterSchema.UnopenedValues)})");
                    return UnopenedPolicy.None;
            }
        }

        /// <summary>Reads the list of conditions of <c>drop_if</c>.</summary>
        FilterCondition[]? ReadConditions(string where, YamlNode node)
        {
            if (node is not YamlSequenceNode sequence)
            {
                Error(node, $"{where}: 'drop_if' must be a list of conditions");
                return null;
            }
            if (sequence.Children.Count > MaxListItems)
            {
                Error(node, $"{where}: 'drop_if' holds more than {MaxListItems} conditions");
                return null;
            }
            var conditions = new List<FilterCondition>();
            foreach (var child in sequence.Children)
            {
                CountCondition();
                var condition = ReadCondition(where, child);
                if (condition is not null)
                    conditions.Add(condition);
            }
            return conditions.ToArray();
        }

        /// <summary>Reads one condition of <c>drop_if</c>.</summary>
        FilterCondition? ReadCondition(string where, YamlNode node)
        {
            if (node is not YamlMappingNode map)
            {
                Error(node, $"{where}: a condition of 'drop_if' must be a map with a field, an op and a value");
                return null;
            }

            string? field = null;
            string? op = null;
            string? portnumText = null;
            YamlNode? valueNode = null;
            foreach (var (keyNode, item) in map.Children)
            {
                var key = Text(keyNode);
                // The vocabulary of the schema is the one that is accepted.
                if (!FilterSchema.ConditionKeys.Contains(key, StringComparer.Ordinal))
                {
                    Error(keyNode, $"{where}: unknown key '{key}' in a condition "
                        + $"(the keys are {string.Join(", ", FilterSchema.ConditionKeys)})");
                    continue;
                }
                switch (key)
                {
                    case "field":
                        field = Text(item);
                        break;
                    case "op":
                        op = Text(item);
                        break;
                    case "portnum":
                        portnumText = Text(item);
                        break;
                    case "value":
                        valueNode = item;
                        break;
                    default:
                        Error(keyNode, $"{where}: the key '{key}' of a condition is not handled by the loader");
                        break;
                }
            }

            if (field is null)
            {
                Error(node, $"{where}: a condition of 'drop_if' needs a field");
                return null;
            }
            if (op is null)
            {
                Error(node, $"{where}: the condition on '{field}' needs an op");
                return null;
            }
            if (valueNode is null)
            {
                Error(node, $"{where}: the condition on '{field}' needs a value");
                return null;
            }
            if (!TryParseOp(op, out var filterOp))
            {
                Error(node, $"{where}: '{op}' is not an operator "
                    + $"(the operators are {string.Join(", ", FilterSchema.Ops)})");
                return null;
            }

            int? portnum = null;
            if (portnumText is not null)
            {
                if (!FilterSchema.TryPortNumNumber(portnumText, out var number))
                {
                    Error(node, $"{where}: '{portnumText}' is not a portnum of the firmware");
                    return null;
                }
                // A number outside the range of the protobufs is not a portnum.
                if (!FilterSchema.IsPortNumNumber(number))
                {
                    Error(node, $"{where}: '{portnumText}' is not a portnum of the firmware "
                        + $"(the portnums are 0 to {FilterSchema.MaxPortNum})");
                    return null;
                }
                portnum = number;
            }

            if (!TryBuildPath(field, portnum, out var path, out var needsOpening, out var pathError))
            {
                Error(node, $"{where}: the condition on '{field}': {pathError}");
                return null;
            }
            if (!TryCompileValues(filterOp, path, valueNode, out var values, out var valueError))
            {
                Error(node, $"{where}: the condition on '{field}': {valueError}");
                return null;
            }

            Regex? pattern = null;
            if (filterOp == FilterOp.Regex && !TryGetRegex(values[0].Text, node, where, out pattern, out var regexError))
            {
                Error(node, $"{where}: the condition on '{field}': {regexError}");
                return null;
            }

            return new FilterCondition
            {
                Field = field,
                Op = filterOp,
                Values = values,
                Portnum = portnum,
                NeedsOpening = needsOpening,
                Path = path,
                Pattern = pattern,
            };
        }

        /// <summary>Reads the value (or the values) of a condition and checks its type.</summary>
        bool TryCompileValues(FilterOp op, FieldPath path, YamlNode node, out CompiledValue[] values, out string error)
        {
            values = [];
            switch (op)
            {
                case FilterOp.Contains:
                case FilterOp.Regex:
                    if (path.Kind != CompiledValueKind.String)
                    {
                        error = $"the operator '{op}' only works on a text field";
                        return false;
                    }
                    break;
                case FilterOp.Lt:
                case FilterOp.Le:
                case FilterOp.Gt:
                case FilterOp.Ge:
                    if (path.Kind != CompiledValueKind.Number && path.Kind != CompiledValueKind.Enum)
                    {
                        error = $"the operator '{op}' only works on a number field";
                        return false;
                    }
                    break;
            }

            if (op == FilterOp.In)
            {
                if (node is not YamlSequenceNode sequence)
                {
                    error = "the operator 'in' needs a list of values";
                    return false;
                }
                if (sequence.Children.Count > MaxListItems)
                {
                    error = $"the operator 'in' holds more than {MaxListItems} values";
                    return false;
                }
                var list = new List<CompiledValue>();
                foreach (var child in sequence.Children)
                {
                    CountValue();
                    if (!TryCompileValue(path, child, out var value, out error))
                        return false;
                    list.Add(value);
                }
                values = list.ToArray();
                return CheckPortnumValues(op, path, values, out error);
            }

            if (node is YamlSequenceNode)
            {
                error = $"the operator '{op}' needs one value, not a list";
                return false;
            }
            if (!TryCompileValue(path, node, out var single, out error))
                return false;
            values = [single];
            return CheckPortnumValues(op, path, values, out error);
        }

        /// <summary>
        /// Checks the values that are compared with the portnum of the packet: a number outside the
        /// range of the protobufs is not a portnum, whatever the operator is.
        /// </summary>
        bool CheckPortnumValues(FilterOp op, FieldPath path, CompiledValue[] values, out string error)
        {
            error = string.Empty;
            if (op is not (FilterOp.Eq or FilterOp.Ne or FilterOp.In
                or FilterOp.Lt or FilterOp.Le or FilterOp.Gt or FilterOp.Ge) || !IsPortNumField(path))
                return true;
            foreach (var value in values)
            {
                if (value.IsInteger && !IsPortNumValue(value.Integer))
                {
                    error = $"'{value.Integer}' is not a portnum of the firmware "
                        + $"(the portnums are 0 to {FilterSchema.MaxPortNum})";
                    return false;
                }
            }
            return true;
        }

        /// <summary>Reads one value of a condition and checks it against the type of its field.</summary>
        bool TryCompileValue(FieldPath path, YamlNode node, out CompiledValue value, out string error)
        {
            value = default;
            if (!TryScalar(node, out var text, out var kind))
            {
                error = "the value must be a scalar";
                return false;
            }

            switch (path.Kind)
            {
                case CompiledValueKind.String:
                    if (kind != ScalarKind.String)
                    {
                        error = $"the value must be a text, not {Describe(kind)}";
                        return false;
                    }
                    if (text.Length > MaxValueLength)
                    {
                        error = $"the value is longer than {MaxValueLength} characters";
                        return false;
                    }
                    value = CompiledValue.ForString(text);
                    error = string.Empty;
                    return true;

                case CompiledValueKind.Bool:
                    if (kind != ScalarKind.Bool)
                    {
                        error = "the value must be true or false";
                        return false;
                    }
                    value = CompiledValue.ForBool(text.Equals("true", StringComparison.OrdinalIgnoreCase));
                    error = string.Empty;
                    return true;

                case CompiledValueKind.Enum:
                {
                    if (kind == ScalarKind.Integer)
                    {
                        if (!TryWholeNumber(text, out var number))
                        {
                            error = $"'{text}' is not a value of the enum";
                            return false;
                        }
                        value = CompiledValue.ForNumber((double)number, true, number);
                        error = string.Empty;
                        return true;
                    }
                    if (kind != ScalarKind.String)
                    {
                        error = $"the value must be the name of a value of the enum or its number, not {Describe(kind)}";
                        return false;
                    }
                    var enumType = path.Leaf?.EnumType;
                    var enumValue = enumType?.FindValueByName(text);
                    if (enumValue is null)
                    {
                        error = $"'{text}' is not a value of the enum {enumType?.Name ?? "?"}";
                        return false;
                    }
                    value = CompiledValue.ForNumber(enumValue.Number, true, enumValue.Number);
                    error = string.Empty;
                    return true;
                }

                default:
                    if (kind == ScalarKind.Integer)
                    {
                        if (!TryWholeNumber(text, out var number))
                        {
                            error = $"'{text}' is out of range (a whole number is between "
                                + $"{long.MinValue} and {ulong.MaxValue})";
                            return false;
                        }
                        value = CompiledValue.ForNumber((double)number, true, number);
                        error = string.Empty;
                        return true;
                    }
                    if (kind == ScalarKind.Number)
                    {
                        var number = double.Parse(text, CultureInfo.InvariantCulture);
                        value = CompiledValue.ForNumber(number, false, 0);
                        error = string.Empty;
                        return true;
                    }
                    error = $"the value must be a number, not {Describe(kind)}";
                    return false;
            }
        }

        /// <summary>Whether the field is the portnum of the decoded data.</summary>
        static bool IsPortNumField(FieldPath path) =>
            path.Prefix == "data" && path.Leaf is not null && path.Leaf.Name == "portnum";

        /// <summary>Whether the number is a portnum of the firmware.</summary>
        static bool IsPortNumValue(Int128 number) =>
            number >= 0 && number <= FilterSchema.MaxPortNum;

        /// <summary>
        /// The pattern of a regular expression. The same pattern is compiled once and shared by every
        /// condition that uses it, so a rule that repeats a pattern costs nothing extra, and the file
        /// may not hold more than <see cref="MaxRegexPatterns"/> distinct patterns nor allocate more
        /// than <see cref="MaxRegexBytes"/> bytes when they are compiled.
        /// </summary>
        /// <param name="pattern">The pattern of the condition.</param>
        /// <param name="node">The node of the condition, for the line of the errors.</param>
        /// <param name="where">The rule the condition is in, for the errors.</param>
        /// <param name="regex">The compiled pattern, shared with the conditions that use it.</param>
        /// <param name="error">Why the pattern is not used.</param>
        bool TryGetRegex(string pattern, YamlNode? node, string where, out Regex? regex, out string error)
        {
            regex = null;
            error = string.Empty;
            if (_regexes.TryGetValue(pattern, out var shared))
            {
                // The pattern is already compiled: the condition shares it, and it costs nothing.
                regex = shared;
                return true;
            }
            if (pattern.Length > MaxRegexLength)
            {
                error = $"the pattern is longer than {MaxRegexLength} characters";
                return false;
            }
            // The budget of the distinct patterns of the file: the load stops before it compiles the
            // pattern that goes over it.
            if (_regexes.Count >= MaxRegexPatterns)
                OverBudget("regex patterns", MaxRegexPatterns, _regexes.Count + 1);
            if (!TryCompileRegex(pattern, out regex, out error, out var allocated))
                return false;
            _regexes[pattern] = regex!;

            // The memory of the file: the cost of a pattern depends on its shape, so it is measured
            // while the patterns are compiled and not counted.
            _regexBytes += allocated;
            if (_regexBytes > _maxRegexBytes)
                OverRegexMemory(_maxRegexBytes, _regexBytes, pattern, where, node?.Start.Line ?? 0);
            return true;
        }

        /// <summary>Compiles the pattern of a regular expression.</summary>
        /// <param name="pattern">The pattern to compile.</param>
        /// <param name="regex">The compiled pattern.</param>
        /// <param name="error">Why the pattern is not valid.</param>
        /// <param name="allocated">The bytes the compilation allocated on this thread.</param>
        static bool TryCompileRegex(string pattern, out Regex? regex, out string error, out long allocated)
        {
            regex = null;
            error = string.Empty;
            allocated = 0;
            try
            {
                // The engine without backtracking: a pattern cannot make the broker hang, and the
                // constructs it does not support (lookarounds, backreferences) are refused.
                var before = GC.GetAllocatedBytesForCurrentThread();
                regex = new Regex(pattern, RegexOptions.NonBacktracking | RegexOptions.CultureInvariant, RegexTimeout);
                allocated = GC.GetAllocatedBytesForCurrentThread() - before;
                regex.IsMatch(string.Empty);   // the analysis of the pattern happens here
            }
            catch (NotSupportedException ex)
            {
                error = "the pattern cannot be used: the engine without backtracking does not support "
                    + $"the lookarounds and the backreferences ({ex.Message})";
                return false;
            }
            catch (ArgumentException ex)
            {
                error = $"the pattern is not a valid regular expression ({ex.Message})";
                return false;
            }
            catch (RegexMatchTimeoutException)
            {
                error = "the pattern did not finish in time";
                return false;
            }
            return true;
        }

        /// <summary>Reads an operator: the vocabulary of the schema is the one that is accepted.</summary>
        static bool TryParseOp(string text, out FilterOp op) => Ops.TryGetValue(text, out op);

        /// <summary>Puts a rule in its scope.</summary>
        void AddRule(string scope, string key, uint? nodeId, FilterRule rule)
        {
            if (scope == FilterSchema.ScopeKeys[0])
            {
                if (key == "*")
                    (_usersStar ??= []).Add(rule);
                else
                    GetOrAdd(_users, key).Add(rule);
                _userRules++;
            }
            else if (scope == FilterSchema.ScopeKeys[1])
            {
                if (key == "*")
                    (_gatewaysStar ??= []).Add(rule);
                else
                    GetOrAdd(_gateways, nodeId!.Value).Add(rule);
                _gatewayRules++;
            }
            else
            {
                if (key == "*")
                    (_nodesStar ??= []).Add(rule);
                else
                    GetOrAdd(_nodes, nodeId!.Value).Add(rule);
                _nodeRules++;
            }
        }

        static List<FilterRule> GetOrAdd<TKey>(Dictionary<TKey, List<FilterRule>> map, TKey key) where TKey : notnull
        {
            if (!map.TryGetValue(key, out var list))
            {
                list = [];
                map[key] = list;
            }
            return list;
        }

        /// <summary>The ruleset the file holds.</summary>
        public FilterRuleset Build() => new(
            _users.ToDictionary(entry => entry.Key, entry => entry.Value.ToArray(), StringComparer.Ordinal),
            _usersStar?.ToArray(),
            _gateways.ToDictionary(entry => entry.Key, entry => entry.Value.ToArray()),
            _gatewaysStar?.ToArray(),
            _nodes.ToDictionary(entry => entry.Key, entry => entry.Value.ToArray()),
            _nodesStar?.ToArray(),
            _userRules, _gatewayRules, _nodeRules, _regexes.Count, _regexBytes);
    }

    /// <summary>The text of a scalar node ("" when it is not a scalar).</summary>
    static string Text(YamlNode? node) => node is YamlScalarNode scalar ? scalar.Value ?? string.Empty : string.Empty;

    /// <summary>Reads a scalar and says what it holds.</summary>
    static bool TryScalar(YamlNode? node, out string text, out ScalarKind kind)
    {
        text = string.Empty;
        kind = ScalarKind.Null;
        if (node is not YamlScalarNode scalar)
            return false;
        text = scalar.Value ?? string.Empty;
        if (scalar.Style != ScalarStyle.Plain)
        {
            kind = text.Length == 0 ? ScalarKind.Null : ScalarKind.String;
            return true;
        }
        if (text.Length == 0 || text == "~" || text.Equals("null", StringComparison.OrdinalIgnoreCase))
        {
            kind = ScalarKind.Null;
            return true;
        }
        if (text.Equals("true", StringComparison.OrdinalIgnoreCase) || text.Equals("false", StringComparison.OrdinalIgnoreCase))
        {
            kind = ScalarKind.Bool;
            return true;
        }
        // A whole number is a sign and digits: it is not a number with a fraction, and it is not a
        // number too big for a long, which is a load error and not a floating point value.
        if (IsWholeNumber(text))
        {
            kind = ScalarKind.Integer;
            return true;
        }
        if (double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out _))
        {
            kind = ScalarKind.Number;
            return true;
        }
        kind = ScalarKind.String;
        return true;
    }

    /// <summary>Whether the text is a whole number: a sign and digits, and nothing else.</summary>
    static bool IsWholeNumber(string text)
    {
        var start = 0;
        if (text.Length > 0 && (text[0] == '-' || text[0] == '+'))
            start = 1;
        if (start >= text.Length)
            return false;
        for (var i = start; i < text.Length; i++)
        {
            if (text[i] is < '0' or > '9')
                return false;
        }
        return true;
    }

    /// <summary>
    /// Reads a whole number of the file as an exact integer. A whole number that does not fit in the
    /// range of the file (between <see cref="long.MinValue"/> and <see cref="ulong.MaxValue"/>) is not
    /// a value the filter can compare with.
    /// </summary>
    static bool TryWholeNumber(string text, out Int128 number)
    {
        if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var signed))
        {
            number = signed;
            return true;
        }
        if (ulong.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var unsigned))
        {
            number = unsigned;
            return true;
        }
        number = 0;
        return false;
    }

    /// <summary>How a kind of scalar is written in an error.</summary>
    static string Describe(ScalarKind kind) => kind switch
    {
        ScalarKind.Null => "an empty value",
        ScalarKind.String => "a text",
        ScalarKind.Integer => "a whole number",
        ScalarKind.Number => "a number",
        ScalarKind.Bool => "true or false",
        _ => "another value",
    };
}
