using System.Reflection;
using System.Text.RegularExpressions;
using Meshtastic.Mqtt;
using Xunit;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Meshtastic.Mqtt.Tests;

/// <summary>
/// The configuration reference must not drift from the code: every key the loader accepts has to be
/// mentioned in <c>docs/configuration.md</c>.
/// </summary>
/// <remarks>
/// The keys are derived from the config classes themselves, with the naming convention the loader uses
/// (<c>UnderscoredNamingConvention</c>, the one <see cref="ConfigLoader"/> builds its deserializer
/// with) and from the effective values of the limits section. Nothing is hard-coded here, so a key that
/// is added to the code fails this test until the reference mentions it.
/// </remarks>
public sealed class DocDriftTests
{
    /// <summary>The reference the keys have to be in.</summary>
    static readonly string ReferencePath = Path.Combine(AppContext.BaseDirectory, "docs", "configuration.md");

    /// <summary>The naming convention of the loader.</summary>
    static readonly INamingConvention Naming = UnderscoredNamingConvention.Instance;

    /// <summary>The classes the config file is made of.</summary>
    static readonly Type[] ConfigTypes =
    [
        typeof(BrokerConfig), typeof(ListenerConfig), typeof(LimitsConfig), typeof(UserConfig),
    ];

    [Fact]
    public void EveryConfigKey_IsMentionedInTheConfigurationReference()
    {
        var reference = File.ReadAllText(ReferencePath);
        var missing = ConfigKeys()
            .Where(key => !IsMentioned(reference, key))
            .OrderBy(key => key, StringComparer.Ordinal)
            .ToArray();

        Assert.True(missing.Length == 0,
            "docs/configuration.md does not mention: " + string.Join(", ", missing));
    }

    [Fact]
    public void TheDerivedLimitKeys_AreTheOnesOfTheEffectiveValues()
    {
        // The naming convention the test derives the keys with has to be the one the loader uses: the
        // keys of the limits class are compared with the ones the broker itself publishes.
        var derived = KeysOf(typeof(LimitsConfig))
            .Select(key => key.Key)
            .OrderBy(key => key, StringComparer.Ordinal)
            .ToArray();
        var effective = new LimitsConfig().EffectiveValues().Keys
            .OrderBy(key => key, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(effective, derived);
    }

    /// <summary>Every key of the config file, as the loader knows it.</summary>
    static IEnumerable<string> ConfigKeys()
    {
        // The limits, with the names the startup line gives them.
        foreach (var key in new LimitsConfig().EffectiveValues().Keys)
            yield return key;

        // The top-level keys, and the keys of the sections they open.
        foreach (var (key, section) in KeysOf(typeof(BrokerConfig)))
        {
            yield return key;
            if (section is null)
                continue;   // a scalar or a map: there are no keys under it
            foreach (var (child, _) in KeysOf(section.Type))
            {
                if (section.IsList)
                    yield return child;             // a list of objects: the keys of the items
                else
                    yield return $"{key}.{child}";  // a nested section: <section>.<key>
            }
        }
    }

    /// <summary>The YAML keys of a config class, with the naming convention the loader uses.</summary>
    static List<(string Key, Section? Section)> KeysOf(Type type)
    {
        var keys = new List<(string, Section?)>();
        foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property.SetMethod is null || !property.SetMethod.IsPublic)
                continue;   // not writable from the outside: not a key of the file
            if (property.GetCustomAttribute<YamlIgnoreAttribute>() is not null)
                continue;   // [YamlIgnore]: not a key of the file
            var member = property.GetCustomAttribute<YamlMemberAttribute>();
            var key = member?.Alias is { Length: > 0 } alias
                ? alias
                : Naming.Apply(property.Name);
            keys.Add((key, SectionOf(property.PropertyType)));
        }
        return keys;
    }

    /// <summary>A config class a property opens, when it opens one.</summary>
    static Section? SectionOf(Type type)
    {
        var isList = false;
        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(List<>))
        {
            type = type.GetGenericArguments()[0];   // a list of objects: the keys of the items
            isList = true;
        }
        return ConfigTypes.Contains(type) ? new Section(type, isList) : null;
    }

    /// <summary>Whether the text mentions the key as a word of its own.</summary>
    static bool IsMentioned(string text, string key) =>
        Regex.IsMatch(text, $@"(?<![\w-]){Regex.Escape(key)}(?![\w-])");

    /// <summary>The config class a property opens.</summary>
    sealed record Section(Type Type, bool IsList);
}
