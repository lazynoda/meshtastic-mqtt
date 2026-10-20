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
