using System.Text.Json;

namespace AethelEye.Core.Models;

/// <summary>Small, forgiving readers so modules do not depend on a specific config shape.</summary>
public static class CheckSettingsExtensions
{
    public static JsonElement? Find(this CheckSettings settings, string key)
    {
        if (settings.Options.TryGetValue(key, out var option))
        {
            return option;
        }

        foreach (var (name, value) in settings.Extra)
        {
            if (string.Equals(name, key, StringComparison.OrdinalIgnoreCase))
            {
                return value;
            }
        }

        return null;
    }

    public static string? GetString(this CheckSettings settings, string key)
    {
        var option = settings.Find(key);
        return option?.ValueKind switch
        {
            JsonValueKind.String => option.Value.GetString(),
            JsonValueKind.Number => option.Value.ToString(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null,
        };
    }

    public static int GetInt(this CheckSettings settings, string key, int fallback)
    {
        var option = settings.Find(key);
        if (option is null)
        {
            return fallback;
        }

        return option.Value.ValueKind switch
        {
            JsonValueKind.Number when option.Value.TryGetInt32(out var value) => value,
            JsonValueKind.String when int.TryParse(option.Value.GetString(), out var value) => value,
            _ => fallback,
        };
    }

    public static bool GetBool(this CheckSettings settings, string key, bool fallback)
    {
        var option = settings.Find(key);
        if (option is null)
        {
            return fallback;
        }

        return option.Value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String when bool.TryParse(option.Value.GetString(), out var value) => value,
            _ => fallback,
        };
    }

    public static IReadOnlyList<string> GetStringList(this CheckSettings settings, string key)
    {
        var option = settings.Find(key);
        if (option is null)
        {
            return [];
        }

        if (option.Value.ValueKind == JsonValueKind.Array)
        {
            return option.Value.EnumerateArray()
                .Where(item => item.ValueKind == JsonValueKind.String)
                .Select(item => item.GetString()!)
                .Where(item => item.Length > 0)
                .ToArray();
        }

        if (option.Value.ValueKind == JsonValueKind.String)
        {
            var text = option.Value.GetString();
            return string.IsNullOrWhiteSpace(text)
                ? []
                : text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        return [];
    }
}
