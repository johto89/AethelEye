using System.Text.RegularExpressions;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;

namespace AethelEye.Modules.Seo;

/// <summary>
/// Discovers sitemap.xml through robots.txt and common paths, inspired by recon-web's sitemap
/// handler. Sitemaps are public by design; this check inventories the exposed URL surface.
/// </summary>
public sealed partial class SitemapCheck : ICheck
{
    [GeneratedRegex(@"^\s*sitemap\s*:\s*(?<url>\S+)", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex SitemapDirective();

    [GeneratedRegex(@"<(?:(?:[a-z0-9]+):)?loc>\s*(?<url>[^<\s]+)\s*</(?:(?:[a-z0-9]+):)?loc>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LocElement();

    public string Id => "sitemap";

    public string Name => "Sitemap discovery";

    public string Description =>
        "Finds sitemap.xml through robots.txt and common paths and inventories the disclosed URLs.";

    public int Order => 11;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        var root = context.Target.RootUrl.TrimEnd('/');
        var appRoot = new Uri(context.Target.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
        var candidates = new List<(string Url, string Source)>();

        var robotsUri = new Uri(appRoot, "robots.txt");
        try
        {
            var robots = await context.Pages.GetAsync(robotsUri, context.CancellationToken);
            if (robots.IsSuccess)
            {
                foreach (Match match in SitemapDirective().Matches(robots.Text))
                {
                    var value = match.Groups["url"].Value.Trim();
                    if (Uri.TryCreate(value, UriKind.Absolute, out var absolute))
                    {
                        candidates.Add((absolute.ToString(), "robots.txt"));
                    }
                }
            }
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            result.Notes.Add($"robots.txt: {error.Message}");
        }

        foreach (var path in new[] { "/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml" })
        {
            candidates.Add((root + path, "direct"));
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in candidates)
        {
            if (!seen.Add(candidate.Url)
                || !Uri.TryCreate(candidate.Url, UriKind.Absolute, out var uri)
                || !context.Scope.IsAllowed(uri))
            {
                continue;
            }

            HttpResponseData response;
            try
            {
                response = await context.Http.GetAsync(uri, context.CancellationToken);
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                result.Notes.Add($"{candidate.Url}: {error.Message}");
                continue;
            }

            if (!response.IsSuccess)
            {
                continue;
            }

            var text = response.Text.TrimStart();
            if (!text.StartsWith('<'))
            {
                continue;
            }

            var urls = LocElement().Matches(response.Text)
                .Select(match => match.Groups["url"].Value.Trim())
                .Where(value => value.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var isIndex = text.Contains("<sitemapindex", StringComparison.OrdinalIgnoreCase);

            result.Metrics["sitemap"] = candidate.Url;
            result.Metrics["source"] = candidate.Source;
            result.Metrics["type"] = isIndex ? "sitemapindex" : "urlset";
            result.Metrics["urls"] = urls.Count.ToString();

            if (urls.Count == 0)
            {
                result.Status = CheckStatus.NoRisk;
                result.Summary = $"Sitemap found at {candidate.Url} but no <loc> entries were parsed.";
                return result;
            }

            result.Findings.Add(new Finding
            {
                CheckId = Id,
                Title = $"Sitemap exposes {urls.Count} URL(s)",
                Description =
                    "A sitemap is public and lists URLs for the application. Review the inventory " +
                    "for staging, admin, backup or forgotten endpoints.",
                Severity = Severity.Info,
                Confidence = Confidence.High,
                Target = context.Target.BaseUrl,
                Url = candidate.Url,
                Evidence = new Dictionary<string, string>
                {
                    ["source"] = candidate.Source,
                    ["type"] = isIndex ? "sitemapindex" : "urlset",
                    ["count"] = urls.Count.ToString(),
                    ["urls"] = string.Join(", ", urls.Take(300)),
                },
            });

            result.Status = CheckStatus.NoRisk;
            result.Summary =
                $"Found a {(isIndex ? "sitemap index" : "sitemap")} at {candidate.Url} " +
                $"with {urls.Count} <loc> entries.";
            return result;
        }

        result.Status = CheckStatus.NoRisk;
        result.Summary = "No sitemap.xml was found through robots.txt or common paths.";
        return result;
    }
}
