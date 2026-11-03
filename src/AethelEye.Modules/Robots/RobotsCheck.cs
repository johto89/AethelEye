using AethelEye.Core.Abstractions;
using AethelEye.Core.Models;

namespace AethelEye.Modules.Robots;

/// <summary>
/// Fetches /robots.txt once and reports sensitive paths disclosed by it. Absence of the file is
/// not a vulnerability; it simply means there is nothing to review here.
/// </summary>
public sealed class RobotsCheck : ICheck
{
    private static readonly string[] SensitiveTokens =
    [
        "admin", "backup", "bak", "git", "svn", "env", "config", "secret",
        "private", "internal", "database", "db", "sql", "dump", "log", "staging",
        "phpmyadmin", "cgi",
    ];

    public string Id => "robots";

    public string Name => "robots.txt";

    public string Description => "Reads robots.txt and reviews disclosed paths and sitemaps.";

    public int Order => 10;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var appRoot = new Uri(context.Target.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
        var appRobots = new Uri(appRoot, "robots.txt");
        var url = appRobots.ToString();
        var response = await context.Pages.GetAsync(appRobots, context.CancellationToken);

        if (response.StatusCode == 404
            && appRoot.AbsolutePath.TrimEnd('/').Length > 0)
        {
            var rootRobots = new Uri(
                context.Target.RootUrl.TrimEnd('/') + "/robots.txt",
                UriKind.Absolute);
            var rootResponse = await context.Pages.GetAsync(rootRobots, context.CancellationToken);
            if (rootResponse.IsSuccess)
            {
                response = rootResponse;
                url = rootRobots.ToString();
            }
        }

        if (response.StatusCode == 404)
        {
            return CheckResult.NoRisk(
                Id,
                Name,
                "robots.txt is not present (HTTP 404).");
        }

        if (response.StatusCode is 401 or 403)
        {
            return CheckResult.NoRisk(
                Id,
                Name,
                $"robots.txt returned HTTP {response.StatusCode}; content is not accessible.");
        }

        if (!response.IsSuccess)
        {
            return CheckResult.NoRisk(
                Id,
                Name,
                $"robots.txt returned HTTP {response.StatusCode}.");
        }

        var text = response.Text;
        if (text.Length == 0)
        {
            return CheckResult.NoRisk(Id, Name, "robots.txt is empty.");
        }

        if (text.TrimStart().StartsWith('<'))
        {
            return CheckResult.NoRisk(
                Id,
                Name,
                "robots.txt returned HTML, which usually means a soft 404 page.");
        }

        var document = RobotsDocument.Parse(text);
        var result = new CheckResult
        {
            CheckId = Id,
            CheckName = Name,
            Metrics =
            {
                ["groups"] = document.Groups.Count.ToString(),
                ["rules"] = document.Rules.Count.ToString(),
                ["sitemaps"] = document.Sitemaps.Count.ToString(),
            },
        };

        if (response.Truncated)
        {
            result.Notes.Add("robots.txt exceeded the body limit and was truncated.");
        }

        foreach (var sitemap in document.Sitemaps)
        {
            result.Notes.Add($"Sitemap disclosed: {sitemap}");
        }

        var disallows = document.Rules
            .Where(rule => rule.Directive == "disallow" && rule.Value.Length > 1 && rule.Value != "/")
            .Select(rule => rule.Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var sensitive = disallows
            .Where(IsSensitivePath)
            .Take(20)
            .ToList();

        foreach (var path in sensitive)
        {
            var severity = IsHighSignal(path) ? Severity.Medium : Severity.Low;
            result.Findings.Add(new Finding
            {
                CheckId = Id,
                Title = "Sensitive path disclosed in robots.txt",
                Description =
                    "robots.txt advertises a path that may be useful to an attacker. " +
                    "The path itself was not accessed by this check.",
                Severity = severity,
                Confidence = Confidence.Medium,
                Target = context.Target.BaseUrl,
                Url = url,
                Evidence = new Dictionary<string, string>
                {
                    ["path"] = path,
                    ["source"] = "robots.txt Disallow",
                },
                Remediation =
                    "Remove sensitive paths from robots.txt. robots.txt is public; " +
                    "protect the resource itself with authentication and authorization.",
            });
        }

        result.Summary =
            $"Parsed {document.Rules.Count} rule(s) in {document.Groups.Count} group(s), " +
            $"{document.Sitemaps.Count} sitemap(s), {sensitive.Count} sensitive path(s).";

        result.Status = result.RiskFindingCount > 0 ? CheckStatus.Findings : CheckStatus.NoRisk;
        return result;
    }

    private static bool IsSensitivePath(string path)
    {
        if (path.Contains("server-status", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var segments = path.Split(
            ['/', '\\', '-', '_', '.'],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        return segments.Any(segment =>
            SensitiveTokens.Contains(segment, StringComparer.OrdinalIgnoreCase));
    }

    private static bool IsHighSignal(string path) =>
        path.Contains(".git", StringComparison.OrdinalIgnoreCase)
        || path.Contains(".svn", StringComparison.OrdinalIgnoreCase)
        || path.Contains(".env", StringComparison.OrdinalIgnoreCase)
        || path.Contains("backup", StringComparison.OrdinalIgnoreCase)
        || path.Contains("dump", StringComparison.OrdinalIgnoreCase)
        || path.Contains("sql", StringComparison.OrdinalIgnoreCase)
        || path.Contains("config", StringComparison.OrdinalIgnoreCase);
}
