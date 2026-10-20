using System.Globalization;
using System.Text;
using Meshtastic.Mqtt;
using Xunit;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The problems of the rules file: every one of them is a load error, and the message names the rule
/// and the problem.
/// </summary>
public sealed class FilterLoadTests
{
    static readonly string[] Users = ["meshdev", "alice"];

    /// <summary>
    /// The pattern of the review: the shape that costs the most memory when it is compiled (a
    /// case-insensitive alternation and a character class).
    /// </summary>
    static readonly Func<int, string> ReviewPattern = index => $"(?i)buy (cheap|free) [a-z]+ now {index}";

    /// <summary>Compiles a file that has to fail, and returns the problems it found.</summary>
    static IReadOnlyList<string> Load(string yaml)
    {
        var ex = Assert.Throws<FilterException>(() => FilterLoader.Parse(yaml, Users, "filters.yaml"));
        Assert.NotEmpty(ex.Errors);
        return ex.Errors;
    }

    /// <summary>The message of the problems, as one text.</summary>
    static string Message(string yaml) => string.Join(Environment.NewLine, Load(yaml));

    // ---- R4: the rules -------------------------------------------------------------------------------------

    [Fact]
    public void R4_AllowAndDenyInTheSameConstraint_AreALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: both
                  channels:
                    allow: [Iberia]
                    deny: [Test]
            """);
        Assert.Contains("both", message);
        Assert.Contains("allow", message);
        Assert.Contains("deny", message);
    }

    [Fact]
    public void R4_AnUnknownPortnumName_IsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: bad-portnum
                  portnums:
                    allow: [NOT_A_PORTNUM]
                  unopened: drop
            """);
        Assert.Contains("bad-portnum", message);
        Assert.Contains("NOT_A_PORTNUM", message);
    }

    [Fact]
    public void R2_AnUnknownUser_IsALoadError()
    {
        var message = Message("""
            users:
              mallory:
                - name: who
                  channels:
                    allow: [Iberia]
            """);
        Assert.Contains("mallory", message);
        Assert.Contains("user", message);
    }

    [Fact]
    public void R2_ANodeIdThatIsNotOne_IsALoadError()
    {
        var message = Message("""
            nodes:
              "deadbeef":
                - name: who
                  channels:
                    allow: [Iberia]
            """);
        Assert.Contains("deadbeef", message);
        Assert.Contains("node id", message);
    }

    [Fact]
    public void R4_ARuleWithoutAName_IsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - channels:
                    allow: [Iberia]
            """);
        Assert.Contains("name", message);
    }

    [Fact]
    public void R4_ARepeatedName_IsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: twice
                  channels:
                    allow: [Iberia]
            gateways:
              "!a1b2c3d4":
                - name: twice
                  channels:
                    allow: [Iberia]
            """);
        Assert.Contains("twice", message);
    }

    [Fact]
    public void R4_ANameWithOtherCharacters_IsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: "not a name!"
                  channels:
                    allow: [Iberia]
            """);
        Assert.Contains("not a name!", message);
    }

    [Fact]
    public void R4_ARuleWithoutAConstraint_IsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: empty
            """);
        Assert.Contains("empty", message);
        Assert.Contains("constraint", message);
    }

    [Fact]
    public void R4_AnUnknownKeyIsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: typo
                  chanel:
                    allow: [Iberia]
            """);
        Assert.Contains("typo", message);
        Assert.Contains("chanel", message);
    }

    [Fact]
    public void R4_AnUnknownScopeIsALoadError()
    {
        var message = Message("""
            routers:
              meshdev:
                - name: typo
                  channels:
                    allow: [Iberia]
            """);
        Assert.Contains("routers", message);
    }

    [Fact]
    public void R4_AnInvalidTopicFilterIsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: bad-topic
                  topics:
                    allow: ["msh/#/x"]
            """);
        Assert.Contains("bad-topic", message);
        Assert.Contains("topic filter", message);
    }

    [Fact]
    public void R5_ARepeatedFieldIsALoadError()
    {
        // A repeated field is not a value, it is a list: the loader refuses it. The check is made on
        // the descriptor of the protobuf, so the test uses a message that has one.
        var list = Google.Protobuf.WellKnownTypes.ListValue.Descriptor;
        Assert.True(list.FindFieldByName("values")!.IsRepeated);
        Assert.False(FilterLoader.TryWalkFields(list, ["values"], out _, out var error));
        Assert.Contains("repeated", error);
        Assert.Contains("values", error);

        // And when one of the messages the filter decodes has a repeated field, the loader says so in
        // the message of the rule that uses it.
        var repeated = RepeatedFieldOfTheDecodedMessages();
        if (repeated is null)
            return;
        var message = Message($$"""
            users:
              meshdev:
                - name: repeated-field
                  drop_if:
                    - field: payload.{{repeated.Value.Field}}
                      op: eq
                      value: x
                      portnum: {{repeated.Value.Portnum}}
                  unopened: allow
            """);
        Assert.Contains("repeated-field", message);
        Assert.Contains("repeated", message);
    }

    /// <summary>A repeated field of the messages the filter can decode, if there is one.</summary>
    static (string Portnum, string Field)? RepeatedFieldOfTheDecodedMessages()
    {
        foreach (var (portnum, descriptor) in FilterSchema.PayloadMessages)
        {
            var field = descriptor.Fields.InFieldNumberOrder().FirstOrDefault(f => f.IsRepeated);
            if (field is not null)
                return (FilterSchema.PortNumName(portnum), field.Name);
        }
        return null;
    }

    [Fact]
    public void R5_APatternWithABackreferenceIsALoadError()
    {
        // The engine without backtracking refuses the backreferences, like the lookarounds.
        var message = Message("""
            users:
              meshdev:
                - name: backreference
                  drop_if:
                    - field: payload.text
                      op: regex
                      value: '(a)\1'
                      portnum: TEXT_MESSAGE_APP
                  unopened: allow
            """);
        Assert.Contains("backreference", message);
        Assert.Contains("pattern", message);
    }

    [Fact]
    public void R4_AnUnopenedWithAnotherValueIsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: bad-unopened
                  portnums:
                    allow: [TEXT_MESSAGE_APP]
                  unopened: maybe
            """);
        Assert.Contains("bad-unopened", message);
        Assert.Contains("unopened", message);
        Assert.Contains("drop", message);
        Assert.Contains("allow", message);
    }

    [Fact]
    public void R5_AFieldWithAnotherPrefixIsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: bad-prefix
                  drop_if:
                    - field: envelope.gateway_id
                      op: eq
                      value: x
            """);
        Assert.Contains("bad-prefix", message);
        Assert.Contains("must start with", message);
    }

    [Fact]
    public void R5_TheInOperatorWithAValueThatIsNotAListIsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: bad-in
                  drop_if:
                    - field: packet.id
                      op: in
                      value: 42
            """);
        Assert.Contains("bad-in", message);
        Assert.Contains("list", message);
    }

    [Fact]
    public void R5_ANumberOperatorOnATextFieldIsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: lt-on-a-text
                  drop_if:
                    - field: payload.long_name
                      op: lt
                      value: 20
                      portnum: NODEINFO_APP
                  unopened: allow
            """);
        Assert.Contains("lt-on-a-text", message);
        Assert.Contains("number field", message);
    }

    [Fact]
    public void R5_AContainsOnANumberFieldIsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: contains-on-a-number
                  drop_if:
                    - field: packet.hop_limit
                      op: contains
                      value: "2"
            """);
        Assert.Contains("contains-on-a-number", message);
        Assert.Contains("text field", message);
    }

    [Fact]
    public void R4_ARuleNameLongerThanTheBound_IsALoadError()
    {
        var name = new string('n', FilterLoader.MaxNameLength + 1);
        var message = Message($"""
            users:
              meshdev:
                - name: "{name}"
                  channels:
                    allow: [Iberia]
            """);
        Assert.Contains(name, message);
        Assert.Contains($"{FilterLoader.MaxNameLength} characters", message);
    }

    // ---- R5: the conditions ---------------------------------------------------------------------------------

    [Fact]
    public void R5_AnUnknownFieldIsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: bad-field
                  drop_if:
                    - field: payload.no_such_field
                      op: eq
                      value: x
                      portnum: POSITION_APP
                  unopened: allow
            """);
        Assert.Contains("bad-field", message);
        Assert.Contains("no_such_field", message);
    }

    [Fact]
    public void R5_ABytesFieldIsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: bytes-field
                  drop_if:
                    - field: data.payload
                      op: eq
                      value: x
            """);
        Assert.Contains("bytes-field", message);
        Assert.Contains("bytes", message);
    }

    [Fact]
    public void R5_APayloadConditionWithoutAPortnumIsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: no-portnum
                  drop_if:
                    - field: payload.long_name
                      op: eq
                      value: x
                  unopened: allow
            """);
        Assert.Contains("no-portnum", message);
        Assert.Contains("portnum", message);
    }

    [Fact]
    public void R5_APortnumWithNoDecodablePayloadIsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: bad-portnum
                  drop_if:
                    - field: payload.long_name
                      op: eq
                      value: x
                      portnum: DETECTION_SENSOR_APP
                  unopened: allow
            """);
        Assert.Contains("bad-portnum", message);
        Assert.Contains("DETECTION_SENSOR_APP", message);
    }

    [Fact]
    public void R5_ARegexOnANumberIsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: regex-on-a-number
                  drop_if:
                    - field: packet.id
                      op: regex
                      value: "42"
            """);
        Assert.Contains("regex-on-a-number", message);
        Assert.Contains("text field", message);
    }

    [Fact]
    public void R5_APatternWithALookaheadIsALoadError()
    {
        // The engine without backtracking refuses the lookaheads: the file does not load at all.
        var message = Message("""
            users:
              meshdev:
                - name: lookahead
                  drop_if:
                    - field: payload.text
                      op: regex
                      value: "(?=hola).*"
                      portnum: TEXT_MESSAGE_APP
                  unopened: allow
            """);
        Assert.Contains("lookahead", message);
        Assert.Contains("pattern", message);
    }

    [Fact]
    public void R5_AnUnknownOperatorIsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: bad-op
                  drop_if:
                    - field: packet.id
                      op: same
                      value: 42
            """);
        Assert.Contains("bad-op", message);
        Assert.Contains("same", message);
    }

    [Fact]
    public void R5_AValueOfTheWrongTypeIsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: wrong-type
                  drop_if:
                    - field: packet.id
                      op: eq
                      value: "forty two"
            """);
        Assert.Contains("wrong-type", message);
        Assert.Contains("number", message);
    }

    // ---- R6: the packets the broker could not open ----------------------------------------------------------

    [Fact]
    public void R6_ARuleThatNeedsAnOpenedPacket_WithoutUnopened_IsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: needs-unopened
                  portnums:
                    allow: [TEXT_MESSAGE_APP]
            """);
        Assert.Contains("needs-unopened", message);
        Assert.Contains("unopened", message);
    }

    [Fact]
    public void R6_ARuleWithAPayloadCondition_WithoutUnopened_IsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: needs-unopened
                  drop_if:
                    - field: payload.text
                      op: contains
                      value: hola
                      portnum: TEXT_MESSAGE_APP
            """);
        Assert.Contains("needs-unopened", message);
        Assert.Contains("unopened", message);
    }

    // ---- R10: the bounds -------------------------------------------------------------------------------------

    [Fact]
    public void R10_MoreRulesThanTheBound_IsALoadError()
    {
        var rules = string.Join("\n", Enumerable.Range(0, FilterLoader.MaxRules + 1)
            .Select(i => $"    - name: rule-{i}\n      channels:\n        allow: [Iberia]"));
        var message = Message($"users:\n  meshdev:\n{rules}\n");
        Assert.Contains("rules", message);
    }

    [Fact]
    public void R10_MoreItemsInAListThanTheBound_IsALoadError()
    {
        var channels = string.Join(", ", Enumerable.Range(0, FilterLoader.MaxListItems + 1).Select(i => $"C{i}"));
        var message = Message($"""
            users:
              meshdev:
                - name: too-many
                  channels:
                    allow: [{channels}]
            """);
        Assert.Contains("too-many", message);
        Assert.Contains("items", message);
    }

    [Fact]
    public void R10_AStringValueLongerThanTheBound_IsALoadError()
    {
        var channel = new string('x', FilterLoader.MaxValueLength + 1);
        var message = Message($"""
            users:
              meshdev:
                - name: too-long
                  channels:
                    allow: ["{channel}"]
            """);
        Assert.Contains("too-long", message);
        Assert.Contains("characters", message);
    }

    [Fact]
    public void R10_APatternLongerThanTheBound_IsALoadError()
    {
        var pattern = new string('a', FilterLoader.MaxRegexLength + 1);
        var message = Message($"""
            users:
              meshdev:
                - name: too-long
                  drop_if:
                    - field: payload.text
                      op: regex
                      value: "{pattern}"
                      portnum: TEXT_MESSAGE_APP
                  unopened: allow
            """);
        Assert.Contains("too-long", message);
        Assert.Contains("characters", message);
    }

    [Fact]
    public void R11_TheOperatorsOfTheSchemaAreTheOnesOfTheCode()
    {
        // The vocabulary of the schema and the enum of the code are the same: the doc-drift test checks
        // the schema against the documentation, so the two have to agree.
        Assert.Equal(
            FilterSchema.Ops.OrderBy(op => op, StringComparer.Ordinal),
            Enum.GetNames<FilterOp>().Select(op => op.ToLowerInvariant()).OrderBy(op => op, StringComparer.Ordinal));
    }

    // ---- M2: the budgets of the file ------------------------------------------------------------------------

    [Fact]
    public void M2_AnAliasExplosion_IsALoadErrorAndTheLoadStopsAtTheBudget()
    {
        // The repro of the review: the aliases of the YAML multiply the values of the file. The file is
        // small, but the values it holds are not: the load stops at the budget of the values.
        var values = string.Join(", ", Enumerable.Range(0, 1000)
            .Select(i => i.ToString(CultureInfo.InvariantCulture)));
        var builder = new StringBuilder();
        builder.AppendLine("users:");
        builder.AppendLine("  meshdev:");
        builder.AppendLine("    - name: the-first");
        builder.AppendLine("      drop_if:");
        builder.AppendLine("        - &cond");
        builder.AppendLine("          field: packet.id");
        builder.AppendLine("          op: in");
        builder.AppendLine($"          value: [{values}]");
        for (var i = 0; i < 49; i++)
            builder.AppendLine("        - *cond");
        builder.AppendLine("      unopened: allow");
        for (var i = 0; i < 199; i++)
        {
            builder.AppendLine($"    - name: rule-{i}");
            builder.AppendLine("      drop_if:");
            for (var j = 0; j < 50; j++)
                builder.AppendLine("        - *cond");
            builder.AppendLine("      unopened: allow");
        }
        var yaml = builder.ToString();

        // The file is small: it is the aliases that make it hold ten million values.
        Assert.True(yaml.Length < 512 * 1024, yaml.Length.ToString(CultureInfo.InvariantCulture));

        var ex = Assert.Throws<FilterException>(() => FilterLoader.Parse(yaml, Users, "filters.yaml"));
        Assert.Contains("budget", ex.Message);
        Assert.Contains(FilterLoader.MaxCompiledValues.ToString(CultureInfo.InvariantCulture), ex.Message);
        // The load stopped at the budget: it did not compile the ten million values of the file.
        Assert.True(ex.CompiledValues <= FilterLoader.MaxCompiledValues + 1,
            $"the loader compiled {ex.CompiledValues} values");
    }

    [Fact]
    public void M2_AFileBiggerThanTheBudgetOfTheSize_IsALoadError()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mmqtt-filters-{Guid.NewGuid():N}.yaml");
        try
        {
            // A file of more than 1 MiB: it is not even parsed.
            var builder = new StringBuilder("users:\n  meshdev:\n");
            while (builder.Length <= FilterLoader.MaxFileBytes)
                builder.Append("    - name: rule\n      channels:\n        allow: [Iberia]\n");
            File.WriteAllText(path, builder.ToString());
            Assert.True(new FileInfo(path).Length > FilterLoader.MaxFileBytes);

            var ex = Assert.Throws<FilterException>(() => FilterLoader.LoadFile(path, Users));
            Assert.Contains("bigger than", ex.Message);
            Assert.Contains(FilterLoader.MaxFileBytes.ToString(CultureInfo.InvariantCulture), ex.Message);
        }
        finally
        {
            FilterFixtures.Delete(path);
        }
    }

    [Fact]
    public void M2_AFileExactlyAtTheBudgetOfTheRules_Loads()
    {
        // The rules are spread over the scopes: a scope key holds at most 1000 rules.
        var builder = new StringBuilder("gateways:\n");
        var index = 0;
        for (var scope = 1; scope <= 10; scope++)
        {
            builder.Append($"  \"!{scope:x8}\":\n");
            for (var i = 0; i < 1000; i++, index++)
                builder.Append($"    - name: rule-{index}\n      channels:\n        allow: [Iberia]\n");
        }

        var ruleset = FilterLoader.Parse(builder.ToString(), Users, "filters.yaml");
        Assert.Equal(FilterLoader.MaxRules, ruleset.RuleCount);
    }

    [Fact]
    public void M2_AFileExactlyAtTheBudgetOfTheConditions_Loads()
    {
        // The conditions come from the aliases: the file holds a hundred thousand conditions and it is
        // still small.
        var builder = new StringBuilder();
        builder.AppendLine("gateways:");
        builder.AppendLine("  \"!00000001\":");
        builder.AppendLine("    - name: the-first");
        builder.AppendLine("      drop_if:");
        builder.AppendLine("        - &cond");
        builder.AppendLine("          field: packet.id");
        builder.AppendLine("          op: eq");
        builder.AppendLine("          value: 1");
        for (var i = 0; i < 49; i++)
            builder.AppendLine("        - *cond");
        builder.AppendLine("      unopened: allow");
        var aliases = string.Join(", ", Enumerable.Repeat("*cond", 50));
        for (var i = 0; i < 999; i++)
        {
            builder.AppendLine($"    - name: rule-1-{i}");
            builder.AppendLine($"      drop_if: [{aliases}]");
            builder.AppendLine("      unopened: allow");
        }
        builder.AppendLine("  \"!00000002\":");
        for (var i = 0; i < 1000; i++)
        {
            builder.AppendLine($"    - name: rule-2-{i}");
            builder.AppendLine($"      drop_if: [{aliases}]");
            builder.AppendLine("      unopened: allow");
        }
        var yaml = builder.ToString();
        Assert.True(yaml.Length < FilterLoader.MaxFileBytes, yaml.Length.ToString(CultureInfo.InvariantCulture));

        var ruleset = FilterLoader.Parse(yaml, Users, "filters.yaml");
        Assert.Equal(2000, ruleset.RuleCount);
    }

    [Fact]
    public void M2_AFileExactlyAtTheBudgetOfTheValues_Loads()
    {
        // A million values, through the aliases: a thousand rules with a list of a thousand values.
        var values = string.Join(", ", Enumerable.Range(0, 1000)
            .Select(i => i.ToString(CultureInfo.InvariantCulture)));
        var builder = new StringBuilder();
        builder.AppendLine("gateways:");
        builder.AppendLine("  \"!00000001\":");
        builder.AppendLine("    - name: the-first");
        builder.AppendLine("      drop_if:");
        builder.AppendLine("        - field: packet.id");
        builder.AppendLine("          op: in");
        builder.AppendLine($"          value: &vals [{values}]");
        builder.AppendLine("      unopened: allow");
        for (var i = 0; i < 499; i++)
        {
            builder.AppendLine($"    - name: rule-1-{i}");
            builder.AppendLine("      drop_if:");
            builder.AppendLine("        - field: packet.id");
            builder.AppendLine("          op: in");
            builder.AppendLine("          value: *vals");
            builder.AppendLine("      unopened: allow");
        }
        builder.AppendLine("  \"!00000002\":");
        for (var i = 0; i < 500; i++)
        {
            builder.AppendLine($"    - name: rule-2-{i}");
            builder.AppendLine("      drop_if:");
            builder.AppendLine("        - field: packet.id");
            builder.AppendLine("          op: in");
            builder.AppendLine("          value: *vals");
            builder.AppendLine("      unopened: allow");
        }
        var yaml = builder.ToString();
        Assert.True(yaml.Length < FilterLoader.MaxFileBytes, yaml.Length.ToString(CultureInfo.InvariantCulture));

        var ruleset = FilterLoader.Parse(yaml, Users, "filters.yaml");
        Assert.Equal(1000, ruleset.RuleCount);
    }

    [Fact]
    public void M2_AFileExactlyAtTheBudgetOfTheSize_Loads()
    {
        var path = Path.Combine(Path.GetTempPath(), $"mmqtt-filters-{Guid.NewGuid():N}.yaml");
        try
        {
            // A file of exactly 1 MiB: it loads. The rules are the ones of the budget of the rules and
            // the rest of the file is a comment.
            var builder = new StringBuilder("gateways:\n");
            var index = 0;
            for (var scope = 1; scope <= 10; scope++)
            {
                builder.Append($"  \"!{scope:x8}\":\n");
                for (var i = 0; i < 1000; i++, index++)
                    builder.Append($"    - name: rule-{index}\n      channels:\n        allow: [Iberia]\n");
            }
            var remaining = FilterLoader.MaxFileBytes - builder.Length;
            Assert.True(remaining >= 3);
            builder.Append('#').Append(new string('x', remaining - 2)).Append('\n');
            Assert.Equal(FilterLoader.MaxFileBytes, builder.Length);
            File.WriteAllText(path, builder.ToString());

            var ruleset = FilterLoader.LoadFile(path, Users);
            Assert.Equal(FilterLoader.MaxRules, ruleset.RuleCount);
        }
        finally
        {
            FilterFixtures.Delete(path);
        }
    }

    // ---- N3: the prefixes of the paths ----------------------------------------------------------------------

    [Fact]
    public void N3_ThePrefixesTheLoaderAccepts_AreTheOnesOfTheSchema()
    {
        // The loader takes the prefixes of the schema, and the doc-drift test derives the check of the
        // documentation from them: the two never drift apart.
        Assert.Equal(
            FilterSchema.FieldPrefixes.OrderBy(prefix => prefix, StringComparer.Ordinal),
            FilterLoader.AcceptedFieldPrefixes.OrderBy(prefix => prefix, StringComparer.Ordinal));

        foreach (var prefix in FilterSchema.FieldPrefixes)
        {
            Assert.Contains(prefix, FilterLoader.AcceptedFieldPrefixes);
            // The loader reads a field with that prefix.
            Assert.True(AnyFieldOfThePrefixIsRead(prefix), prefix);
        }

        // And a prefix that is not one of the schema is refused.
        Assert.False(FilterLoader.TryBuildPath("envelope.gateway_id", null, out _, out _, out var error));
        Assert.Contains("must start with", error);
    }

    /// <summary>Whether the loader reads a field with the prefix.</summary>
    static bool AnyFieldOfThePrefixIsRead(string prefix)
    {
        foreach (var field in new[] { "id", "portnum", "text" })
        {
            if (FilterLoader.TryBuildPath(prefix + field, FilterSchema.TextMessageApp, out _, out _, out _))
                return true;
        }
        return false;
    }

    // ---- N6: the numbers of the portnums -------------------------------------------------------------------

    [Fact]
    public void N6_APortnumNumberOutOfRange_IsALoadError()
    {
        // The range of the portnums is the one of the protobufs (the MAX of the enum).
        Assert.Equal(511, FilterSchema.MaxPortNum);

        var message = Message("""
            users:
              meshdev:
                - name: bad-portnum
                  portnums:
                    allow: [9999]
                  unopened: drop
            """);
        Assert.Contains("bad-portnum", message);
        Assert.Contains("9999", message);
        Assert.Contains("portnum", message);
    }

    [Fact]
    public void N6_APortnumNumberInRangeWithoutAName_IsAccepted()
    {
        // A number inside the range of the protobufs is a portnum, even when the firmware has no name
        // for it.
        var ruleset = FilterLoader.Parse("""
            users:
              meshdev:
                - name: a-number
                  portnums:
                    allow: [499]
                  unopened: drop
            """, Users, "filters.yaml");
        Assert.Equal(1, ruleset.RuleCount);
    }

    [Fact]
    public void N6_AConditionWithAPortnumNumberOutOfRange_IsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: bad-portnum
                  drop_if:
                    - field: payload.text
                      op: contains
                      value: hola
                      portnum: 9999
                  unopened: allow
            """);
        Assert.Contains("bad-portnum", message);
        Assert.Contains("9999", message);
    }

    [Fact]
    public void N6_AValueOfThePortnumOutOfRange_IsALoadError()
    {
        var message = Message("""
            users:
              meshdev:
                - name: bad-value
                  drop_if:
                    - field: data.portnum
                      op: eq
                      value: 9999
                  unopened: allow
            """);
        Assert.Contains("bad-value", message);
        Assert.Contains("9999", message);

        var inList = Message("""
            users:
              meshdev:
                - name: bad-list
                  drop_if:
                    - field: data.portnum
                      op: in
                      value: [1, 9999]
                  unopened: allow
            """);
        Assert.Contains("bad-list", inList);
        Assert.Contains("9999", inList);
    }

    [Fact]
    public void N6_AValueOfThePortnumInRange_IsAccepted()
    {
        var ruleset = FilterLoader.Parse("""
            users:
              meshdev:
                - name: a-number
                  drop_if:
                    - field: data.portnum
                      op: in
                      value: [1, 499]
                  unopened: allow
                - name: a-threshold
                  drop_if:
                    - field: data.portnum
                      op: lt
                      value: 511
                  unopened: allow
            """, Users, "filters.yaml");
        Assert.Equal(2, ruleset.RuleCount);
    }

    // ---- M1: the range of the whole numbers -----------------------------------------------------------------

    [Fact]
    public void M1_AWholeNumberOutOfRange_IsALoadError()
    {
        // A whole number that does not fit in the range of the file (between long.MinValue and
        // ulong.MaxValue) is not a value the filter can compare with.
        var tooBig = Message("""
            users:
              meshdev:
                - name: too-big
                  drop_if:
                    - field: packet.id
                      op: eq
                      value: 18446744073709551616
            """);
        Assert.Contains("too-big", tooBig);
        Assert.Contains("out of range", tooBig);

        var tooSmall = Message("""
            users:
              meshdev:
                - name: too-small
                  drop_if:
                    - field: packet.id
                      op: eq
                      value: -9223372036854775809
            """);
        Assert.Contains("too-small", tooSmall);
        Assert.Contains("out of range", tooSmall);

        var inAList = Message("""
            users:
              meshdev:
                - name: too-big-in-a-list
                  drop_if:
                    - field: packet.id
                      op: in
                      value: [1, 18446744073709551616]
            """);
        Assert.Contains("too-big-in-a-list", inAList);
        Assert.Contains("out of range", inAList);
    }

    [Fact]
    public void M1_AWholeNumberAtTheEndsOfTheRange_Loads()
    {
        var ruleset = FilterLoader.Parse("""
            users:
              meshdev:
                - name: the-ends
                  drop_if:
                    - field: packet.id
                      op: in
                      value: [18446744073709551615, -9223372036854775808]
            """, Users, "filters.yaml");
        Assert.Equal(1, ruleset.RuleCount);
    }

    // ---- X1: the budget of the patterns of the regular expressions --------------------------------------------

    [Fact]
    public void X1_AFileOverTheRegexMemoryBudget_IsALoadErrorAndStopsEarly()
    {
        // The shape of the review: the most expensive pattern of the measurements. A thousand of them
        // allocate more memory than the budget of the file, so the load stops long before the last
        // one.
        var yaml = FilterFixtures.FileWithPatterns(FilterLoader.MaxRegexPatterns, ReviewPattern);
        var ex = Assert.Throws<FilterException>(() => FilterLoader.Parse(yaml, Users, "filters.yaml"));
        Assert.Contains("regex memory", ex.Message);
        Assert.Contains(FilterLoader.MaxRegexBytes.ToString(CultureInfo.InvariantCulture), ex.Message);
        // The message names the pattern that crossed the budget.
        Assert.Contains("(?i)buy (cheap|free) [a-z]+ now ", ex.Message);

        // The load stopped at the budget: it did not compile the thousand patterns of the file.
        Assert.True(ex.CompiledPatterns < FilterLoader.MaxRegexPatterns,
            $"the loader compiled {ex.CompiledPatterns} patterns");
        Assert.True(ex.RegexBytes > FilterLoader.MaxRegexBytes,
            $"the patterns of the file allocated {ex.RegexBytes} bytes");
    }

    [Fact]
    public void X1_CheapLiteralsUnderTheBudget_Load()
    {
        // Two hundred cheap literals: the file loads, and the memory it allocates is under the budget.
        var ruleset = FilterLoader.Parse(FilterFixtures.FileWithPatterns(200, index => $"spam{index}"),
            Users, "filters.yaml");
        Assert.Equal(200, ruleset.RegexPatternCount);
        Assert.True(ruleset.RegexBytes > 0);
        Assert.True(ruleset.RegexBytes <= FilterLoader.MaxRegexBytes,
            $"the patterns of the file allocated {ruleset.RegexBytes} bytes");
    }

    [Fact]
    public void X1_AFileExactlyAtTheBudgetOfThePatterns_Loads()
    {
        // A thousand distinct patterns: the file loads, and every pattern is compiled once. The budget
        // of the memory is out of the way, so only the count of the patterns is checked.
        var ruleset = FilterLoader.Parse(FilterFixtures.FileWithPatterns(FilterLoader.MaxRegexPatterns),
            Users, "filters.yaml", long.MaxValue);
        Assert.Equal(FilterLoader.MaxRegexPatterns, ruleset.RegexPatternCount);
    }

    [Fact]
    public void X1_ThousandAndOneDistinctPatterns_IsALoadErrorAndStopsCompiling()
    {
        // One pattern over the budget: the file does not load at all, and the load stops before it
        // compiles the pattern that goes over the budget.
        var yaml = FilterFixtures.FileWithPatterns(FilterLoader.MaxRegexPatterns + 1);
        var ex = Assert.Throws<FilterException>(() => FilterLoader.Parse(yaml, Users, "filters.yaml", long.MaxValue));
        Assert.Contains("budget", ex.Message);
        Assert.Contains("regex patterns", ex.Message);
        Assert.Contains(FilterLoader.MaxRegexPatterns.ToString(CultureInfo.InvariantCulture), ex.Message);
        Assert.Contains((FilterLoader.MaxRegexPatterns + 1).ToString(CultureInfo.InvariantCulture), ex.Message);

        // The load stopped at the budget: it did not compile the thousand and first pattern.
        Assert.True(ex.CompiledPatterns <= FilterLoader.MaxRegexPatterns,
            $"the loader compiled {ex.CompiledPatterns} patterns");
    }

    [Fact]
    public void X1_ASmallBudgetOfTheMemory_StopsAtTheFirstPattern()
    {
        // A budget of one byte: the first pattern goes over it, and the load stops there.
        var yaml = FilterFixtures.FileWithPatterns(3);
        var ex = Assert.Throws<FilterException>(() => FilterLoader.Parse(yaml, Users, "filters.yaml", 1));
        Assert.Contains("regex memory", ex.Message);
        Assert.Contains("buy[ ]+now-0", ex.Message);
        Assert.Contains("1 bytes", ex.Message);

        // The load stopped at the first pattern: no other pattern was compiled.
        Assert.Equal(1, ex.CompiledPatterns);
    }

    [Fact]
    public void X1_FourThousandConditionsWithTheSamePattern_CompileOneRegex()
    {
        // The same pattern four thousand times, through the aliases of the YAML: it is compiled once
        // and shared by every condition, so the file costs the memory of one pattern.
        var builder = new StringBuilder();
        builder.AppendLine("users:");
        builder.AppendLine("  meshdev:");
        builder.AppendLine("    - name: rule-0");
        builder.AppendLine("      drop_if:");
        builder.AppendLine("        - &cond");
        builder.AppendLine("          field: payload.text");
        builder.AppendLine("          op: regex");
        builder.AppendLine("          value: \"buy[ ]+now\"");
        builder.AppendLine("          portnum: TEXT_MESSAGE_APP");
        builder.AppendLine("      unopened: allow");
        for (var i = 1; i <= 3; i++)
        {
            builder.AppendLine($"    - name: rule-{i}");
            builder.AppendLine($"      drop_if: [{Aliases(1000)}]");
            builder.AppendLine("      unopened: allow");
        }
        builder.AppendLine("    - name: rule-4");
        builder.AppendLine($"      drop_if: [{Aliases(999)}]");
        builder.AppendLine("      unopened: allow");

        var ruleset = FilterLoader.Parse(builder.ToString(), Users, "filters.yaml");
        var conditions = ruleset.Users["meshdev"]
            .SelectMany(rule => rule.DropIf ?? Enumerable.Empty<FilterCondition>())
            .ToArray();
        Assert.Equal(4000, conditions.Length);

        // One pattern, one compiled regular expression, shared by the four thousand conditions.
        Assert.Equal(1, ruleset.RegexPatternCount);
        Assert.Single(conditions.Select(condition => condition.Pattern).Distinct());

        // The pattern is compiled once, so the memory of the file is the memory of one pattern.
        Assert.True(ruleset.RegexBytes < 5 * 1024 * 1024,
            $"the patterns of the file allocated {ruleset.RegexBytes} bytes");
    }

    [Fact]
    public void X1_TwoRulesWithTheSamePattern_ShareTheCompiledRegex()
    {
        var ruleset = FilterLoader.Parse("""
            users:
              meshdev:
                - name: the-first
                  drop_if:
                    - field: payload.text
                      op: regex
                      value: "buy[ ]+now"
                      portnum: TEXT_MESSAGE_APP
                  unopened: allow
                - name: the-second
                  drop_if:
                    - field: payload.text
                      op: regex
                      value: "buy[ ]+now"
                      portnum: TEXT_MESSAGE_APP
                  unopened: allow
            """, Users, "filters.yaml");

        var first = ruleset.Users["meshdev"][0].DropIf![0].Pattern;
        var second = ruleset.Users["meshdev"][1].DropIf![0].Pattern;
        Assert.NotNull(first);
        Assert.Same(first, second);
        Assert.Equal(1, ruleset.RegexPatternCount);
    }

    /// <summary>A list of aliases of the anchor of the file.</summary>
    static string Aliases(int count) => string.Join(", ", Enumerable.Repeat("*cond", count));

    // ---- X4: the report of a file with many problems ----------------------------------------------------------

    [Fact]
    public void X4_ABrokenFileWithManyProblems_ReportsTheFirstTwentyAndCountsTheRest()
    {
        // Ten thousand rules with the same name: nine thousand nine hundred and ninety-nine problems.
        // The report lists the first twenty and counts the rest.
        var ex = Assert.Throws<FilterException>(() =>
            FilterLoader.Parse(FilterFixtures.FileWithDuplicateNames(), Users, "filters.yaml"));
        Assert.Equal(FilterException.MaxReportedErrors + 1, ex.Errors.Count);
        Assert.Equal("... and 9979 more errors", ex.Errors[^1]);
        Assert.Equal(9999, ex.TotalErrors);

        // The report is small: a broken file does not write a megabyte of log.
        Assert.True(ex.Message.Length < 8 * 1024, $"the report is {ex.Message.Length} characters");
    }

    // ---- X5: the range of the values compared with the portnum -----------------------------------------------

    [Fact]
    public void X5_AComparisonWithAPortnumOutOfRange_IsALoadError()
    {
        // The comparisons are checked like the equality: a value outside the range of the firmware is
        // not a portnum.
        foreach (var op in new[] { "lt", "le", "gt", "ge" })
        {
            var message = Message($$"""
                users:
                  meshdev:
                    - name: bad-threshold
                      drop_if:
                        - field: data.portnum
                          op: {{op}}
                          value: 9999
                      unopened: allow
                """);
            Assert.Contains("bad-threshold", message);
            Assert.Contains("9999", message);
            Assert.Contains("portnum", message);
        }
    }

    [Fact]
    public void X5_AComparisonWithAPortnumInRange_IsAccepted()
    {
        var ruleset = FilterLoader.Parse("""
            users:
              meshdev:
                - name: a-threshold
                  drop_if:
                    - field: data.portnum
                      op: lt
                      value: 511
                  unopened: allow
                - name: another-threshold
                  drop_if:
                    - field: data.portnum
                      op: ge
                      value: 0
                  unopened: allow
            """, Users, "filters.yaml");
        Assert.Equal(2, ruleset.RuleCount);
    }

    // ---- the file itself -------------------------------------------------------------------------------------

    [Fact]
    public void AnEmptyFile_IsNoRules()
    {
        var ruleset = FilterLoader.Parse("", Users, "filters.yaml");
        Assert.Equal(0, ruleset.RuleCount);
    }

    [Fact]
    public void TheExampleFile_IsValid()
    {
        // The example of the repository has to be a file the broker accepts.
        var ruleset = FilterLoader.LoadFile(Path.Combine(AppContext.BaseDirectory, "filters.example.yaml"),
            ["meshdev"]);
        Assert.True(ruleset.RuleCount > 0);
        Assert.True(ruleset.UserRuleCount > 0);
        Assert.True(ruleset.GatewayRuleCount > 0);
        Assert.True(ruleset.NodeRuleCount > 0);
    }

    [Fact]
    public void AFileThatIsNotYaml_IsALoadError()
    {
        var message = Message("users:\n  - [unclosed\n");
        Assert.Contains("filters.yaml", message);
    }

    [Fact]
    public void AMissingFileIsALoadError()
    {
        var ex = Assert.Throws<FilterException>(() =>
            FilterLoader.LoadFile("/nonexistent/filters.yaml", Users));
        Assert.Contains("cannot be read", ex.Message);
    }
}
