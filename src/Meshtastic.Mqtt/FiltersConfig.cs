using YamlDotNet.Serialization;

namespace Meshtastic.Mqtt;

/// <summary>
/// The <c>filters</c> section of the config: where the rules file is and how often it is checked.
/// </summary>
/// <remarks>
/// The section is optional: without it the broker has no filters and every packet that passes the other
/// checks is forwarded. See <c>docs/filters.md</c>.
/// </remarks>
public sealed class FiltersConfig
{
    /// <summary>How often the rules file is checked, in seconds, when the config does not say.</summary>
    public const int DefaultReloadCheckSeconds = 5;

    /// <summary>The shortest period of the check of the rules file, in seconds.</summary>
    public const int MinReloadCheckSeconds = 1;

    /// <summary>The longest period of the check of the rules file, in seconds.</summary>
    public const int MaxReloadCheckSeconds = 3600;

    /// <summary>
    /// The path of the rules file. Empty or missing = no filters. The file is read at startup and
    /// checked again every <see cref="EffectiveReloadCheckSeconds"/> seconds.
    /// </summary>
    public string? File { get; set; }

    /// <summary>How often the rules file is checked, in seconds.</summary>
    public int? ReloadCheckSeconds { get; set; } = DefaultReloadCheckSeconds;

    /// <summary>The period of the check, as the broker will use it.</summary>
    [YamlIgnore] public int EffectiveReloadCheckSeconds => ReloadCheckSeconds ?? DefaultReloadCheckSeconds;

    internal void Validate(List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(File))
        {
            errors.Add("filters.file: the filters section needs the path of the rules file "
                + "(leave the whole section out to have no filters)");
        }

        if (ReloadCheckSeconds is null)
        {
            errors.Add($"filters.reload_check_seconds: empty value; write an integer between "
                + $"{MinReloadCheckSeconds} and {MaxReloadCheckSeconds}");
        }
        else if (ReloadCheckSeconds < MinReloadCheckSeconds || ReloadCheckSeconds > MaxReloadCheckSeconds)
        {
            errors.Add($"filters.reload_check_seconds: {ReloadCheckSeconds} is not an integer between "
                + $"{MinReloadCheckSeconds} and {MaxReloadCheckSeconds}");
        }
    }
}
