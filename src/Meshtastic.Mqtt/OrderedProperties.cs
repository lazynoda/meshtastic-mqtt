using Serilog.Core;
using Serilog.Events;

namespace Meshtastic.Mqtt;

/// <summary>
/// A structured property whose keys keep a guaranteed order: the JSON object is built explicitly, so
/// the order of the keys is part of the value and not the enumeration of a plain dictionary (whose
/// order is not guaranteed).
/// </summary>
/// <remarks>
/// The value is a <see cref="StructureValue"/> without a type tag, so the JSON object has no "$type",
/// and it is attached to the event with a small enricher, so it is written as it is.
/// </remarks>
internal static class OrderedProperties
{
    /// <summary>
    /// The value of a JSON object: the keys keep the order of the pairs, the numbers stay numbers and
    /// a list of strings stays a list of strings.
    /// </summary>
    public static StructureValue Object<TValue>(IEnumerable<KeyValuePair<string, TValue>> values)
    {
        var properties = new List<LogEventProperty>();
        foreach (var (key, value) in values)
            properties.Add(new LogEventProperty(key, Value(value)));
        return new StructureValue(properties);
    }

    /// <summary>The enricher that attaches the property to the event, as it is.</summary>
    public static ILogEventEnricher Enricher(string name, LogEventPropertyValue value) =>
        new PropertyEnricher(name, value);

    /// <summary>The value of one property: a number stays a number, a list of strings a list.</summary>
    static LogEventPropertyValue Value<TValue>(TValue value) => value switch
    {
        int i => new ScalarValue(i),
        long l => new ScalarValue(l),
        double d => new ScalarValue(d),
        bool b => new ScalarValue(b),
        string s => new ScalarValue(s),
        IEnumerable<string> strings => new SequenceValue(strings.Select(s => new ScalarValue(s))),
        _ => new ScalarValue(value is null ? string.Empty : value.ToString() ?? string.Empty),
    };

    sealed class PropertyEnricher(string name, LogEventPropertyValue value) : ILogEventEnricher
    {
        public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory) =>
            logEvent.AddPropertyIfAbsent(new LogEventProperty(name, value));
    }
}
