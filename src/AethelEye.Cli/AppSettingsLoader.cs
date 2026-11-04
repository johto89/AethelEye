using System.Text.Json;
using AethelEye.Core.Models;

namespace AethelEye.Cli;

public sealed class AppSettings
{
    public AethelEyeSettings AethelEye { get; set; } = new();
}

public sealed class AethelEyeSettings
{
    public string? GitHubToken { get; set; }

    public string? BreachDirectoryApiKey { get; set; }

    public string? GitleaksPath { get; set; }

    public string? Proxy { get; set; }

    public string? UserAgent { get; set; }

    public int? MaxExternalRequests { get; set; }

    /// <summary>Cache directory for the Retire repository and future feeds.</summary>
    public string? DataDirectory { get; set; }
}

/// <summary>
/// Reads appsettings.json without adding a configuration package, so the tool still builds and
/// runs on an isolated machine. Environment variables override the file; CLI flags override both.
/// </summary>
public static class AppSettingsLoader
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public static AppSettings Load()
    {
        var settings = new AppSettings();
        foreach (var path in CandidatePaths())
        {
            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                var parsed = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path), Options);
                if (parsed?.AethelEye is not null)
                {
                    Merge(settings.AethelEye, parsed.AethelEye);
                }
            }
            catch (JsonException error)
            {
                throw new InvalidDataException($"Invalid appsettings file {path}: {error.Message}", error);
            }
        }

        return settings;
    }

    public static void Apply(Engagement engagement, AethelEyeSettings settings)
    {
        if (!string.IsNullOrWhiteSpace(settings.GitHubToken))
        {
            engagement.GitHub.Token = settings.GitHubToken;
        }

        if (!string.IsNullOrWhiteSpace(settings.BreachDirectoryApiKey))
        {
            engagement.Leaks.BreachDirectoryApiKey = settings.BreachDirectoryApiKey;
        }

        if (!string.IsNullOrWhiteSpace(settings.GitleaksPath))
        {
            engagement.GitHub.GitleaksPath = settings.GitleaksPath;
        }

        if (!string.IsNullOrWhiteSpace(settings.Proxy))
        {
            engagement.Http.Proxy = settings.Proxy;
        }

        if (!string.IsNullOrWhiteSpace(settings.UserAgent))
        {
            engagement.Http.UserAgent = settings.UserAgent;
        }

        if (settings.MaxExternalRequests is > 0)
        {
            engagement.Http.MaxExternalRequests = settings.MaxExternalRequests.Value;
        }

        ApplyEnvironment(engagement);
    }

    public static string ResolveDataDirectory(AethelEyeSettings settings)
    {
        if (!string.IsNullOrWhiteSpace(settings.DataDirectory))
        {
            return Path.GetFullPath(settings.DataDirectory);
        }

        // Portable default: keep the database and fingerprints next to the executable, so the
        // whole folder can be copied to another machine and used as-is.
        return Path.Combine(AppContext.BaseDirectory, "data");
    }

    private static void ApplyEnvironment(Engagement engagement)
    {
        var token = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        if (!string.IsNullOrWhiteSpace(token))
        {
            engagement.GitHub.Token = token;
        }

        var breach = Environment.GetEnvironmentVariable("BREACHDIRECTORY_API_KEY");
        if (!string.IsNullOrWhiteSpace(breach))
        {
            engagement.Leaks.BreachDirectoryApiKey = breach;
        }

        var gitleaks = Environment.GetEnvironmentVariable("GITLEAKS_PATH");
        if (!string.IsNullOrWhiteSpace(gitleaks))
        {
            engagement.GitHub.GitleaksPath = gitleaks;
        }

        var proxy = Environment.GetEnvironmentVariable("HTTPS_PROXY")
            ?? Environment.GetEnvironmentVariable("HTTP_PROXY");
        if (!string.IsNullOrWhiteSpace(proxy))
        {
            engagement.Http.Proxy = proxy;
        }

    }

    private static IEnumerable<string> CandidatePaths()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var baseDirectory = AppContext.BaseDirectory;
        var current = Directory.GetCurrentDirectory();

        foreach (var directory in new[] { baseDirectory, current })
        {
            foreach (var fileName in new[] { "appsettings.json", "appsettings.local.json" })
            {
                var path = Path.Combine(directory, fileName);
                if (seen.Add(Path.GetFullPath(path)))
                {
                    yield return path;
                }
            }
        }
    }

    private static void Merge(AethelEyeSettings target, AethelEyeSettings source)
    {
        target.GitHubToken = source.GitHubToken ?? target.GitHubToken;
        target.BreachDirectoryApiKey = source.BreachDirectoryApiKey ?? target.BreachDirectoryApiKey;
        target.GitleaksPath = source.GitleaksPath ?? target.GitleaksPath;
        target.Proxy = source.Proxy ?? target.Proxy;
        target.UserAgent = source.UserAgent ?? target.UserAgent;
        target.MaxExternalRequests = source.MaxExternalRequests ?? target.MaxExternalRequests;
        target.DataDirectory = source.DataDirectory ?? target.DataDirectory;
    }
}
