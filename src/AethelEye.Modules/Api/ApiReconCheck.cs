using System.Text.Json;
using System.Text.RegularExpressions;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;
using AethelEye.Modules.Recon;

namespace AethelEye.Modules.Api;

/// <summary>
/// API endpoint discovery inspired by API-Hunter (MIT). Passive sources (Wayback Machine CDX and
/// CommonCrawl) plus JavaScript bundle parsing are combined, then endpoints are normalized,
/// deduplicated, given inferred HTTP methods and tagged by risk. Endpoints are inventory data;
/// high-signal endpoints are surfaced as low/medium findings for review, never as confirmed issues.
/// </summary>
public sealed partial class ApiReconCheck : ICheck
{
    public string Id => "api";

    public string Name => "API endpoint discovery";

    public string Description =>
        "Discovers API endpoints from the Wayback Machine, CommonCrawl and JavaScript bundles, " +
        "then infers methods and tags each endpoint by risk.";

    public int Order => 13;

    // ---------------------------------------------------------------------------------------
    // JavaScript parsing patterns (adapted from API-Hunter's jsparser.go).
    // ---------------------------------------------------------------------------------------

    [GeneratedRegex(@"<\s*script\b[^>]*\bsrc\s*=\s*[""'](?<src>[^""']+)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ScriptSrc();

    [GeneratedRegex(@"(?:api_?base_?url|api_?url|base_?url|api_?endpoint|api_?host|server_?url)\s*[:=]\s*[""'`]\s*(?<url>https?://[^""'`\s]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BaseUrl();

    [GeneratedRegex(@"(?:api_?url|api_?base_?url|base_?url|api_?endpoint|endpoint|api_?host|server_?url)\s*\+\s*[""'`](?<path>[A-Za-z0-9][A-Za-z0-9_/.-]*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ConcatPath();

    [GeneratedRegex(@"(?:api_?url|api_?base_?url|base_?url|api_?endpoint|endpoint|api_?host|server_?url)\}(?<path>[A-Za-z0-9][A-Za-z0-9_/.-]*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TemplatePath();

    [GeneratedRegex(@"[A-Za-z0-9_]*(?:api_?url|api_?path|endpoint)\s*:\s*[""'](?<path>[A-Za-z0-9][A-Za-z0-9_/.-]+)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PropApi();

    [GeneratedRegex(@"[""'](?<path>/(?:api|v[0-9]+|rest|graphql)[A-Za-z0-9_/.-]*)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ApiPath();

    [GeneratedRegex(@"[""'](?<url>https?://[^""'\s]+)[""']", RegexOptions.CultureInvariant)]
    private static partial Regex FullUrl();

    [GeneratedRegex(@"[""'](?<path>[A-Z][A-Za-z0-9]+(?:/[A-Za-z0-9_-]+)+)[""']", RegexOptions.CultureInvariant)]
    private static partial Regex CtrlAction();

    [GeneratedRegex(@"[""'](?<file>[A-Za-z0-9_./-]+\.js)[""']", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex JsChunk();

    [GeneratedRegex(@"\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|html?|webp|mp4|webm|scss|less)(?:\?|#|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AssetExt();

    [GeneratedRegex(@"^(?:d{1,4}|m{1,4}|y{2,4}|h{1,2}|s{1,2}|a)(?:/(?:d{1,4}|m{1,4}|y{2,4}|h{1,2}|s{1,2}|a))+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DateFormat();

    // ---------------------------------------------------------------------------------------
    // Path-parameter normalization (adapted from API-Hunter's normalizer.go).
    // ---------------------------------------------------------------------------------------

    private static readonly (Regex Pattern, string Name)[] ParamPatterns =
    [
        (new Regex(@"/\d+(/|$)", RegexOptions.CultureInvariant), "id"),
        (new Regex(@"/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(/|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), "uuid"),
        (new Regex(@"/[a-f0-9]{24}(/|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), "objectId"),
        (new Regex(@"/\d{4}-\d{2}-\d{2}(/|$)", RegexOptions.CultureInvariant), "date"),
    ];

    // ---------------------------------------------------------------------------------------
    // HTTP method inference (adapted from API-Hunter's inferrer.go).
    // ---------------------------------------------------------------------------------------

    private static readonly (Regex Pattern, string[] Methods)[] MethodPatterns =
    [
        (new Regex(@"/(?:login|signin|authenticate)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["POST"]),
        (new Regex(@"/(?:logout|signout)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["POST"]),
        (new Regex(@"/(?:register|signup)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["POST"]),
        (new Regex(@"/upload", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["POST"]),
        (new Regex(@"/download", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["GET"]),
        (new Regex(@"/export", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["GET", "POST"]),
        (new Regex(@"/import", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["POST"]),
        (new Regex(@"/search", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["GET", "POST"]),
        (new Regex(@"/delete", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["POST", "DELETE"]),
        (new Regex(@"/create", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["POST"]),
        (new Regex(@"/update", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["POST", "PUT", "PATCH"]),
        (new Regex(@"/activate|/enable", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["POST"]),
        (new Regex(@"/deactivate|/disable", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["POST"]),
        (new Regex(@"/verify|/confirm", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["POST", "GET"]),
        (new Regex(@"/reset", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["POST"]),
        (new Regex(@"/callback|/webhook", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["POST"]),
        (new Regex(@"(?:^|/)(?:get|fetch|list|all|by[a-z]|view|report|download|export)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["GET"]),
        (new Regex(@"(?:^|/)(?:save|add|insert|new|submit|bulk)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["POST"]),
        (new Regex(@"(?:^|/)(?:edit|modify|change)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["PUT", "PATCH"]),
        (new Regex(@"(?:^|/)(?:remove|del)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), ["DELETE", "POST"]),
    ];

    // ---------------------------------------------------------------------------------------
    // Risk tagging (adapted from API-Hunter's tagger.go). Severity is intentionally capped at
    // Medium: a discovered endpoint is inventory, not a confirmed vulnerability.
    // ---------------------------------------------------------------------------------------

    private static readonly (Regex Pattern, Severity Severity, string Tag)[] RiskPatterns =
    [
        (new Regex(@"/auth|/login|/signin|/oauth", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Severity.Medium, "auth"),
        (new Regex(@"/admin", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Severity.Medium, "admin"),
        (new Regex(@"/upload|/import", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Severity.Medium, "file-upload"),
        (new Regex(@"/password|/passwd|/pwd", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Severity.Medium, "password"),
        (new Regex(@"/token|/jwt|/refresh", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Severity.Medium, "token"),
        (new Regex(@"/payment|/checkout|/billing", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Severity.Medium, "payment"),
        (new Regex(@"/\.env|/config\.|/debug", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Severity.Medium, "sensitive-file"),
        (new Regex(@"/graphql", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Severity.Medium, "graphql"),
        (new Regex(@"/user|/profile|/account", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Severity.Low, "pii"),
        (new Regex(@"/export|/download", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Severity.Low, "data-export"),
        (new Regex(@"/api[_-]?key|/secret|/credential", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Severity.Low, "secrets"),
        (new Regex(@"/config|/setting", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Severity.Low, "config"),
        (new Regex(@"/internal|/private", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Severity.Low, "internal"),
        (new Regex(@"/search|/query|/filter", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), Severity.Info, "injection-point"),
    ];

    private sealed class Endpoint
    {
        public required string Url { get; init; }

        public required string Source { get; set; }

        public required string NormalizedPath { get; init; }

        public string[] Methods { get; set; } = [];

        public Severity Risk { get; set; } = Severity.Info;

        public List<string> Tags { get; } = [];
    }

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        var host = context.Target.Host;
        var maxResults = Math.Clamp(context.Settings.GetInt("maxResults", 500), 1, 5000);
        var maxScripts = Math.Clamp(context.Settings.GetInt("maxScripts", 40), 1, 100);

        var endpoints = new Dictionary<string, Endpoint>(StringComparer.OrdinalIgnoreCase);
        var sourceCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        void Add(string url, string source)
        {
            var normalized = Normalize(url);
            if (normalized is null)
            {
                return;
            }

            if (endpoints.TryGetValue(normalized.Value.Key, out var existing))
            {
                if (existing.Source == source)
                {
                    return;
                }

                existing.Source = existing.Source + "+" + source;
                return;
            }

            endpoints[normalized.Value.Key] = new Endpoint
            {
                Url = normalized.Value.Url,
                Source = source,
                NormalizedPath = normalized.Value.Path,
            };
            sourceCounts[source] = sourceCounts.GetValueOrDefault(source) + 1;
        }

        // Passive sources need Internet access.
        if (context.Engagement.Offline)
        {
            result.Notes.Add("Offline mode: Wayback Machine and CommonCrawl were skipped.");
        }
        else
        {
            await CollectWaybackAsync(context, host, maxResults, Add, result);
            await CollectCommonCrawlAsync(context, host, maxResults, Add, result);
        }

        // Active source: parse JavaScript bundles from the target page (scope-aware).
        await CollectJavaScriptAsync(context, maxScripts, Add, result);

        // Analyze: infer methods and tag risk for every collected endpoint.
        foreach (var endpoint in endpoints.Values)
        {
            endpoint.Methods = InferMethods(endpoint.NormalizedPath);
            TagRisk(endpoint);
        }

        var ordered = endpoints.Values
            .OrderByDescending(endpoint => endpoint.Risk)
            .ThenBy(endpoint => endpoint.Url, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var critical = ordered.Count(endpoint => endpoint.Risk == Severity.Medium);
        var low = ordered.Count(endpoint => endpoint.Risk == Severity.Low);

        result.Metrics["endpoints"] = ordered.Length.ToString();
        result.Metrics["sources"] = sourceCounts.Count.ToString();
        result.Metrics["mediumRisk"] = critical.ToString();
        result.Metrics["lowRisk"] = low.ToString();

        if (ordered.Length == 0)
        {
            result.Status = CheckStatus.Partial;
            result.Summary = "No API endpoints could be discovered from passive sources or JavaScript bundles.";
            return result;
        }

        result.Findings.Add(new Finding
        {
            CheckId = Id,
            Title = $"Discovered {ordered.Length} API endpoint(s)",
            Description =
                "Endpoints observed in the Wayback Machine, CommonCrawl and JavaScript bundles. " +
                "This expands the known API attack surface; high-signal endpoints are reported " +
                "separately for review against the authorized scope.",
            Severity = Severity.Info,
            Confidence = Confidence.Medium,
            Target = context.Target.BaseUrl,
            Url = context.Target.BaseUrl,
            Evidence = new Dictionary<string, string>
            {
                ["host"] = host,
                ["count"] = ordered.Length.ToString(),
                ["sources"] = string.Join(", ", sourceCounts.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).Select(pair => $"{pair.Key}={pair.Value}")),
                ["mediumRisk"] = critical.ToString(),
                ["lowRisk"] = low.ToString(),
                ["endpoints"] = string.Join(", ", ordered.Take(100).Select(endpoint => endpoint.Url)),
            },
        });

        foreach (var endpoint in ordered.Where(endpoint => endpoint.Risk > Severity.Info).Take(25))
        {
            result.Findings.Add(new Finding
            {
                CheckId = Id,
                Title = "High-signal API endpoint discovered",
                Description =
                    "This endpoint was discovered through public sources or JavaScript bundles and " +
                    "matches a sensitive pattern. Verify that it is authorized, correctly " +
                    "authenticated and access-controlled.",
                Severity = endpoint.Risk,
                Confidence = Confidence.Medium,
                Target = context.Target.BaseUrl,
                Url = endpoint.Url,
                Evidence = new Dictionary<string, string>
                {
                    ["url"] = endpoint.Url,
                    ["source"] = endpoint.Source,
                    ["methods"] = string.Join(", ", endpoint.Methods),
                    ["tags"] = string.Join(", ", endpoint.Tags),
                },
                Remediation =
                    "Review the endpoint against the authorized scope, confirm authentication and " +
                    "authorization, and remove or protect any endpoint that should not be public.",
            });
        }

        result.Summary =
            $"Discovered {ordered.Length} unique API endpoint(s) across {sourceCounts.Count} source(s); " +
            $"{critical} medium-risk, {low} low-risk.";
        result.Status = result.RiskFindingCount > 0 ? CheckStatus.Findings : CheckStatus.NoRisk;
        return result;
    }

    // ---------------------------------------------------------------------------------------
    // Passive sources.
    // ---------------------------------------------------------------------------------------

    private static async Task CollectWaybackAsync(
        ICheckContext context,
        string host,
        int maxResults,
        Action<string, string> add,
        CheckResult result)
    {
        var url = "https://web.archive.org/cdx/search/cdx" +
                  $"?url={Uri.EscapeDataString(host + "/*")}&output=json&collapse=urlkey&fl=original";
        var response = await ReconSupport.TryGetJsonAsync(
            context.ExternalHttp,
            url,
            context.CancellationToken,
            warn: message => result.Notes.Add(message));
        if (response is null)
        {
            result.Notes.Add("Wayback Machine did not return usable JSON.");
            return;
        }

        try
        {
            using var document = JsonDocument.Parse(response.Body);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            var added = 0;
            foreach (var row in document.RootElement.EnumerateArray())
            {
                if (added >= maxResults)
                {
                    break;
                }

                // The first row is the header ("original").
                if (row.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var cell in row.EnumerateArray())
                {
                    if (cell.ValueKind == JsonValueKind.String
                        && cell.GetString() is { Length: > 0 } value
                        && !value.Equals("original", StringComparison.OrdinalIgnoreCase))
                    {
                        add(value, "wayback");
                        added++;
                        break;
                    }
                }
            }

            result.Notes.Add($"Wayback Machine returned {added} record(s) for {host}.");
        }
        catch (JsonException error)
        {
            result.Notes.Add("Wayback Machine response could not be parsed: " + error.Message);
        }
    }

    private static async Task CollectCommonCrawlAsync(
        ICheckContext context,
        string host,
        int maxResults,
        Action<string, string> add,
        CheckResult result)
    {
        var index = await LatestCommonCrawlIndexAsync(context, result);
        var url = $"{index}?url={Uri.EscapeDataString(host + "/*")}&output=json";
        HttpResponseData? response;
        try
        {
            response = await context.ExternalHttp.GetAsync(url, context.CancellationToken);
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            result.Notes.Add($"CommonCrawl {index}: {error.Message}");
            return;
        }

        if (!response.IsSuccess)
        {
            result.Notes.Add($"CommonCrawl {index}: HTTP {response.StatusCode}");
            return;
        }

        var added = 0;
        foreach (var line in response.Text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (added >= maxResults)
            {
                break;
            }

            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed[0] != '{')
            {
                continue;
            }

            try
            {
                using var document = JsonDocument.Parse(trimmed);
                if (document.RootElement.TryGetProperty("url", out var value)
                    && value.ValueKind == JsonValueKind.String
                    && value.GetString() is { Length: > 0 } found)
                {
                    add(found, "commoncrawl");
                    added++;
                }
            }
            catch (JsonException)
            {
                // Skip malformed lines; CommonCrawl output is newline-delimited JSON.
            }
        }

        result.Notes.Add($"CommonCrawl returned {added} record(s) for {host}.");
    }

    private static async Task<string> LatestCommonCrawlIndexAsync(ICheckContext context, CheckResult result)
    {
        const string fallback = "https://index.commoncrawl.org/CC-MAIN-2025-08-index";
        try
        {
            var response = await context.ExternalHttp.GetAsync(
                "https://index.commoncrawl.org/collinfo.json",
                context.CancellationToken);
            if (!response.IsSuccess)
            {
                return fallback;
            }

            using var document = JsonDocument.Parse(response.Body);
            foreach (var entry in document.RootElement.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.Object
                    && entry.TryGetProperty("cdx-api", out var api)
                    && api.ValueKind == JsonValueKind.String
                    && api.GetString() is { Length: > 0 } value)
                {
                    return value;
                }
            }
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            result.Notes.Add("CommonCrawl index lookup failed: " + error.Message);
        }

        return fallback;
    }

    // ---------------------------------------------------------------------------------------
    // JavaScript bundle parsing (scope-aware).
    // ---------------------------------------------------------------------------------------

    private static async Task CollectJavaScriptAsync(
        ICheckContext context,
        int maxScripts,
        Action<string, string> add,
        CheckResult result)
    {
        var baseUri = context.Target.BaseUri;
        var page = await context.Pages.GetAsync(baseUri, context.CancellationToken);
        if (!page.IsSuccess)
        {
            result.Notes.Add($"Base page returned HTTP {page.StatusCode}; JavaScript parsing skipped.");
            return;
        }

        // Collect script files from the entry HTML, then follow lazily-loaded chunks.
        var queue = new Queue<string>();
        foreach (Match match in ScriptSrc().Matches(page.Text))
        {
            var src = match.Groups["src"].Value;
            if (Uri.TryCreate(baseUri, src, out var absolute))
            {
                queue.Enqueue(absolute.ToString());
            }
        }

        var fetched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var contents = new List<string>();
        var scriptCount = 0;

        while (queue.Count > 0 && fetched.Count < maxScripts)
        {
            var file = queue.Dequeue();
            if (!fetched.Add(file))
            {
                continue;
            }

            if (!Uri.TryCreate(file, UriKind.Absolute, out var uri)
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
                continue;
            }

            if (!response.IsSuccess)
            {
                continue;
            }

            scriptCount++;
            var content = response.Text;
            contents.Add(content);

            // Discover further chunk files referenced inside this script (same host only).
            foreach (Match match in JsChunk().Matches(content))
            {
                if (Uri.TryCreate(uri, match.Groups["file"].Value, out var chunk)
                    && string.Equals(chunk.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase))
                {
                    queue.Enqueue(chunk.ToString());
                }
            }
        }

        if (scriptCount == 0)
        {
            return;
        }

        result.Notes.Add($"Parsed {scriptCount} JavaScript file(s) from the target.");
        var apiBase = DiscoverApiBase(contents);

        // Only endpoints on the target's own hosts are in scope; third-party constants are noise.
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { baseUri.Host };
        if (apiBase is not null)
        {
            allowed.Add(apiBase.Host);
        }

        var extractors = new[] { ConcatPath(), TemplatePath(), PropApi(), ApiPath(), FullUrl(), CtrlAction() };
        foreach (var content in contents)
        {
            foreach (var extractor in extractors)
            {
                foreach (Match match in extractor.Matches(content))
                {
                    var raw = match.Groups.Count > 1 ? match.Groups[1].Value : match.Value;
                    if (TryResolve(raw, baseUri, apiBase, allowed, out var resolved))
                    {
                        add(resolved, "jsparser");
                    }
                }
            }
        }
    }

    private static Uri? DiscoverApiBase(IReadOnlyList<string> contents)
    {
        foreach (var content in contents)
        {
            var match = BaseUrl().Match(content);
            if (match.Success
                && Uri.TryCreate(match.Groups["url"].Value.Trim(), UriKind.Absolute, out var uri)
                && !string.IsNullOrEmpty(uri.Host))
            {
                return uri;
            }
        }

        return null;
    }

    private static bool TryResolve(
        string raw,
        Uri site,
        Uri? apiBase,
        HashSet<string> allowed,
        out string resolved)
    {
        resolved = string.Empty;
        raw = raw.Trim();

        // Cut off any template-literal remnant.
        var cut = raw.IndexOfAny(['$', '{', '`']);
        if (cut >= 0)
        {
            raw = raw[..cut];
        }

        raw = raw.TrimEnd('/', '.');
        if (raw.Length < 3 || raw.IndexOfAny(['<', '>', '(', ')', '[', ']', '{', '}', '\\', ' ']) >= 0)
        {
            return false;
        }

        if (DateFormat().IsMatch(raw))
        {
            return false;
        }

        string full;
        if (raw.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || raw.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(raw, UriKind.Absolute, out var absolute) || !allowed.Contains(absolute.Host))
            {
                return false;
            }

            full = raw;
        }
        else if (raw.StartsWith('/'))
        {
            full = site.Scheme + "://" + site.Host + raw;
        }
        else
        {
            // Relative Controller/Action must look path-like.
            if (!raw.Contains('/') && raw[0] is not (>= 'A' and <= 'Z'))
            {
                return false;
            }

            if (apiBase is not null)
            {
                full = apiBase.GetLeftPart(UriPartial.Authority).TrimEnd('/') + "/" + raw;
            }
            else
            {
                full = site.Scheme + "://" + site.Host + "/" + raw;
            }
        }

        if (AssetExt().IsMatch(full))
        {
            return false;
        }

        resolved = full;
        return true;
    }

    // ---------------------------------------------------------------------------------------
    // Normalization, method inference and risk tagging.
    // ---------------------------------------------------------------------------------------

    private static (string Key, string Url, string Path)? Normalize(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || uri.Scheme is not ("http" or "https")
            || string.IsNullOrEmpty(uri.Host))
        {
            return null;
        }

        if (AssetExt().IsMatch(uri.AbsolutePath))
        {
            return null;
        }

        var path = NormalizePath(uri.AbsolutePath);
        var key = uri.IdnHost.ToLowerInvariant() + path;
        return (key, uri.GetLeftPart(UriPartial.Path), path);
    }

    private static string NormalizePath(string path)
    {
        var result = path;
        foreach (var (pattern, name) in ParamPatterns)
        {
            result = pattern.Replace(result, "/{" + name + "}/");
        }

        return result.TrimEnd('/');
    }

    private static string[] InferMethods(string path)
    {
        foreach (var (pattern, methods) in MethodPatterns)
        {
            if (pattern.IsMatch(path))
            {
                return methods;
            }
        }

        if (path.EndsWith("Id}", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith("id}", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith("uuid}", StringComparison.OrdinalIgnoreCase))
        {
            return ["GET", "PUT", "PATCH", "DELETE"];
        }

        return ["GET", "POST"];
    }

    private static void TagRisk(Endpoint endpoint)
    {
        var highest = Severity.Info;
        foreach (var (pattern, severity, tag) in RiskPatterns)
        {
            if (pattern.IsMatch(endpoint.NormalizedPath))
            {
                if (severity > highest)
                {
                    highest = severity;
                }

                endpoint.Tags.Add(tag);
            }
        }

        endpoint.Risk = highest;
    }
}
