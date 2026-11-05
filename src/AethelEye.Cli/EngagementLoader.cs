using System.Text.Json;
using System.Text.Json.Serialization;
using AethelEye.Core.Models;

namespace AethelEye.Cli;

public static class EngagementLoader
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static Engagement Load(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Engagement file not found: {path}", path);
        }

        Engagement? engagement;
        try
        {
            engagement = JsonSerializer.Deserialize<Engagement>(File.ReadAllText(path), Options);
        }
        catch (JsonException error)
        {
            throw new InvalidDataException($"Invalid engagement file {path}: {error.Message}", error);
        }

        if (engagement is null)
        {
            throw new InvalidDataException($"Engagement file is empty: {path}");
        }

        Normalize(engagement);
        if (engagement.Targets.Count > 0)
        {
            engagement.Targets = TargetExpander.Expand(engagement.Targets).ToList();
        }

        return engagement;
    }

    public static Engagement CreateOneOff(
        IEnumerable<string> targets,
        IEnumerable<string>? sources = null,
        IEnumerable<string>? paths = null)
    {
        var values = TargetExpander
            .Expand(targets, paths)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToArray();
        var sourceValues = (sources ?? [])
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(Path.GetFullPath)
            .ToArray();

        if (values.Length == 0 && sourceValues.Length == 0)
        {
            throw new ArgumentException("At least one target or source is required.");
        }

        if (values.Length == 0)
        {
            return CreateSourceOnly(sourceValues);
        }

        var parsed = values.Select(value => Target.Parse(value)).ToArray();
        var name = parsed.Length == 1
            ? parsed[0].Host
            : $"{parsed[0].Host}-and-{parsed.Length - 1}-more";

        var engagement = new Engagement
        {
            Name = name,
            Targets = values.ToList(),
            Sources = sourceValues.ToList(),
            Scope = new ScopeSettings
            {
                AllowedHosts = parsed.Select(target => target.Host).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            },
        };

        Normalize(engagement);
        return engagement;
    }

    public static Engagement CreateSourceOnly(IEnumerable<string> sources)
    {
        var values = sources
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (values.Length == 0)
        {
            throw new ArgumentException("At least one source path is required.");
        }

        var engagement = new Engagement
        {
            Name = values.Length == 1
                ? Path.GetFileName(values[0].TrimEnd(Path.DirectorySeparatorChar))
                : $"source-{values.Length}-items",
            Targets = [],
            Sources = values.ToList(),
        };

        if (string.IsNullOrWhiteSpace(engagement.Name))
        {
            engagement.Name = "source";
        }

        Normalize(engagement);
        return engagement;
    }

    public static IReadOnlyList<string> ReadTargetFile(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Target file not found: {path}", path);
        }

        var values = new List<string>();
        foreach (var line in File.ReadLines(path))
        {
            var text = line.Trim();
            if (text.Length == 0 || text.StartsWith('#'))
            {
                continue;
            }

            // Allow an inline comment after the value.
            var comment = text.IndexOf(" #", StringComparison.Ordinal);
            if (comment > 0)
            {
                text = text[..comment].Trim();
            }

            if (text.Length > 0)
            {
                values.Add(text);
            }
        }

        return values;
    }

    public static void Save(Engagement engagement, string path)
    {
        var json = JsonSerializer.Serialize(engagement, Options);
        File.WriteAllText(path, json + Environment.NewLine);
    }

    private static void Normalize(Engagement engagement)
    {
        engagement.Targets ??= [];
        engagement.Sources ??= [];
        engagement.Scope ??= new ScopeSettings();
        engagement.Http ??= new HttpSettings();
        engagement.Engine ??= new EngineSettings();
        engagement.GitHub ??= new GitHubSettings();
        engagement.Leaks ??= new LeakSettings();
        engagement.Output ??= new OutputSettings();
        engagement.Tools ??= [];

        engagement.Scope.AllowedHosts ??= [];
        engagement.Scope.ExcludedHosts ??= [];
        engagement.Http.Headers ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        engagement.Browser ??= new BrowserSettings();
        engagement.Output.Formats ??= ["text"];
        engagement.Output.Directory = string.IsNullOrWhiteSpace(engagement.Output.Directory)
            ? "results"
            : engagement.Output.Directory;

        engagement.Checks = engagement.Checks is null
            ? new Dictionary<string, CheckSettings>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, CheckSettings>(engagement.Checks, StringComparer.OrdinalIgnoreCase);

        foreach (var settings in engagement.Checks.Values)
        {
            settings.Options = settings.Options is null
                ? new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, JsonElement>(settings.Options, StringComparer.OrdinalIgnoreCase);
            settings.Extra ??= [];
        }
    }
}
