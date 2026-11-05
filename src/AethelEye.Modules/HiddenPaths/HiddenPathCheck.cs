using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;

namespace AethelEye.Modules.HiddenPaths;

/// <summary>
/// Probes a broad catalog of exposed files plus backup names derived from the host and
/// application segment. A random-path baseline suppresses soft 404 pages, and each candidate
/// needs a status, content-type, marker or magic-byte signature that makes sense for its type.
/// </summary>
public sealed class HiddenPathCheck : ICheck
{

    public string Id => "hidden-paths";

    public string Name => "Hidden paths and backups";

    public string Description =>
        "Checks common exposed files: .git, .env, backups, SQL dumps, logs and debug endpoints.";

    public int Order => 30;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        var custom = context.Settings.GetStringList("paths");
        var entries = custom.Count > 0
            ? custom.Select(path => new HiddenPath(
                path.StartsWith('/') ? path : "/" + path,
                Severity.High,
                HiddenPathValidation.None,
                null,
                "Custom path from the engagement configuration.",
                AllowHtml: true)).ToList()
            : HiddenPathCatalog.All.ToList();

        // Backups are often named after the host or the application segment and placed at the
        // site root, for example /merchant.zip for http://host/merchant. Probe those too, but
        // only when the operator did not supply an explicit custom path list.
        if (custom.Count == 0)
        {
            entries.AddRange(BuildDerivedBackupEntries(context));
        }

        // 0 means "probe the whole catalog". Set maxPaths to bound request volume on a
        // rate-limited or fragile target. When capping, keep the highest-severity entries.
        var maxPaths = Math.Clamp(context.Settings.GetInt("maxPaths", 0), 0, 5000);
        if (maxPaths > 0 && entries.Count > maxPaths)
        {
            result.Notes.Add($"Path list capped at {maxPaths} of {entries.Count} entries.");
            entries = entries
                .OrderByDescending(entry => entry.Severity)
                .ThenBy(entry => entry.Path, StringComparer.Ordinal)
                .Take(maxPaths)
                .ToList();
        }

        if (context.Engagement.Http.Evasion)
        {
            entries = entries.OrderBy(_ => Random.Shared.Next()).ToList();
            result.Notes.Add("Evasion profile: path probes are shuffled and sent one at a time.");
        }

        var parallelism = context.Engagement.Http.Evasion
            ? 1
            : Math.Clamp(context.Settings.GetInt("parallelism", 4), 1, 10);
        // Each application path is its own root: /abc/.git/HEAD and /xyz/.git/HEAD are separate.
        // Derived backup names such as /merchant.zip live at the site root instead.
        var appRoot = new Uri(context.Target.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
        var siteRoot = new Uri(context.Target.RootUrl.TrimEnd('/') + "/", UriKind.Absolute);
        var baselinePath = $"/.aetheleye-{Guid.NewGuid():N}";
        var baseline = await GetBaselineAsync(context, appRoot, baselinePath, result);
        var siteBaseline = entries.Any(entry => entry.SiteRoot)
            ? await GetBaselineAsync(context, siteRoot, baselinePath, result)
            : null;

        var findings = new ConcurrentBag<Finding>();
        var notes = new ConcurrentBag<string>();
        var failures = 0;
        var skipped = 0;

        using var gate = new SemaphoreSlim(parallelism);
        await Task.WhenAll(entries.Select(async entry =>
        {
            await gate.WaitAsync(context.CancellationToken);
            try
            {
                var entryRoot = entry.SiteRoot ? siteRoot : appRoot;
                var entryBaseline = entry.SiteRoot ? siteBaseline : baseline;
                var uri = new Uri(entryRoot, entry.Path.TrimStart('/'));
                if (!context.Scope.IsAllowed(uri))
                {
                    Interlocked.Increment(ref skipped);
                    return;
                }

                HttpResponseData response;
                try
                {
                    response = await context.Http.GetAsync(uri, context.CancellationToken);
                }
                catch (Exception error) when (error is not OperationCanceledException)
                {
                    Interlocked.Increment(ref failures);
                    notes.Add($"{entry.Path}: {error.Message}");
                    return;
                }

                if (response.StatusCode is 401 or 403)
                {
                    Interlocked.Increment(ref skipped);
                    return;
                }

                if (response.StatusCode is not (200 or 206))
                {
                    return;
                }

                if (entryBaseline is not null && LooksLikeSoftNotFound(response, entryBaseline, baselinePath, entry.Path))
                {
                    return;
                }

                if (!Matches(entry, response))
                {
                    return;
                }

                var confidence = entry.Validation == HiddenPathValidation.None
                    ? Confidence.Medium
                    : Confidence.High;

                findings.Add(new Finding
                {
                    CheckId = Id,
                    Title = $"Exposed sensitive path: {entry.Path}",
                    Description = entry.Description,
                    Severity = entry.Severity,
                    Confidence = confidence,
                    Target = context.Target.BaseUrl,
                    Url = uri.ToString(),
                    Evidence = new Dictionary<string, string>
                    {
                        ["path"] = entry.Path,
                        ["status"] = response.StatusCode.ToString(),
                        ["contentType"] = response.ContentType ?? string.Empty,
                        ["bytes"] = response.Body.Length.ToString(),
                        ["validation"] = entry.Validation.ToString(),
                        ["marker"] = entry.Marker ?? string.Empty,
                    },
                    Remediation =
                        "Remove the file from the web root, block it at the reverse proxy, " +
                        "and rotate any secret it contained.",
                });
            }
            finally
            {
                gate.Release();
            }
        }));

        foreach (var finding in findings.OrderByDescending(finding => finding.Severity)
                     .ThenBy(finding => finding.Url, StringComparer.Ordinal))
        {
            result.Findings.Add(finding);
        }

        foreach (var note in notes.Take(10))
        {
            result.Notes.Add(note);
        }

        result.Metrics["probed"] = entries.Count.ToString();
        result.Metrics["exposed"] = result.Findings.Count.ToString();
        result.Metrics["requestFailures"] = failures.ToString();
        result.Metrics["skipped"] = skipped.ToString();

        result.Summary =
            $"Probed {entries.Count} path(s); {result.Findings.Count} exposed, " +
            $"{skipped} skipped, {failures} request failure(s).";
        result.Status = result.RiskFindingCount > 0
            ? CheckStatus.Findings
            : failures > 0 ? CheckStatus.Partial : CheckStatus.NoRisk;
        return result;
    }

    private static async Task<HttpResponseData?> GetBaselineAsync(
        ICheckContext context,
        Uri root,
        string baselinePath,
        CheckResult result)
    {
        try
        {
            var baseline = await context.Http.GetAsync(
                new Uri(root, baselinePath.TrimStart('/')),
                context.CancellationToken);
            result.Notes.Add(
                $"Soft-404 baseline ({root}): HTTP {baseline.StatusCode}, {baseline.Body.Length} bytes.");
            return baseline;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            result.Notes.Add($"Soft-404 baseline ({root}) failed: {error.Message}");
            return null;
        }
    }

    private static readonly HashSet<string> IgnoredDerivedSegments = new(StringComparer.OrdinalIgnoreCase)
    {
        "api", "v1", "v2", "v3", "static", "assets", "css", "js", "images", "img",
        "index.html", "index.php", "index.htm",
    };

    private static readonly string[] DerivedBackupExtensions =
    [
        ".zip", ".tar.gz", ".7z", ".sql", ".bak", ".old",
    ];

    private static readonly string[] DerivedBackupWrappers =
    [
        "{name}{ext}",
        "{name}_backup{ext}",
        "backup_{name}{ext}",
    ];

    /// <summary>
    /// Builds backup names from the host and application segment, mirroring backup_finder.py:
    /// for http://host/merchant it probes /merchant.zip and /merchant/merchant.zip. An IP is
    /// used whole and never split into octets. These entries are resolved against the site root.
    /// </summary>
    private static IEnumerable<HiddenPath> BuildDerivedBackupEntries(ICheckContext context)
    {
        var tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var appTokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var host = context.Target.Host;
        AddDerivedToken(tokens, host);
        if (!System.Net.IPAddress.TryParse(host, out _))
        {
            AddDerivedToken(tokens, host.Split('.', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault());
        }

        var segments = context.Target.BaseUri.AbsolutePath
            .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(segment => segment.Length > 1 && !IgnoredDerivedSegments.Contains(segment))
            .ToList();
        var appPath = string.Empty;
        if (segments.Count > 0)
        {
            appPath = string.Join("/", segments);
            AddDerivedToken(tokens, segments[^1]);
            AddDerivedToken(appTokens, segments[^1]);
            if (segments.Count > 1)
            {
                var joined = string.Join("-", segments);
                AddDerivedToken(tokens, joined);
                AddDerivedToken(appTokens, joined);
            }
        }

        foreach (var name in context.Settings.GetStringList("names"))
        {
            AddDerivedToken(tokens, name);
            AddDerivedToken(appTokens, name);
        }

        var entries = new List<HiddenPath>();
        foreach (var token in tokens)
        {
            foreach (var extension in DerivedBackupExtensions)
            {
                foreach (var wrapper in DerivedBackupWrappers)
                {
                    var name = wrapper
                        .Replace("{name}", token, StringComparison.Ordinal)
                        .Replace("{ext}", extension, StringComparison.Ordinal);
                    entries.Add(DerivedEntry("/" + name, extension));
                    if (appPath.Length > 0 && appTokens.Contains(token))
                    {
                        entries.Add(DerivedEntry("/" + appPath + "/" + name, extension));
                    }
                }
            }
        }

        return entries.DistinctBy(entry => entry.Path, StringComparer.OrdinalIgnoreCase);
    }

    private static HiddenPath DerivedEntry(string path, string extension) =>
        new(
            path,
            Severity.High,
            extension switch
            {
                ".sql" => HiddenPathValidation.SqlDump,
                ".bak" or ".old" => HiddenPathValidation.None,
                _ => HiddenPathValidation.Archive,
            },
            null,
            extension is ".bak" or ".old"
                ? "Backup copy of the application is exposed."
                : "Backup archive or dump named after the application is exposed.",
            SiteRoot: true);

    private static void AddDerivedToken(HashSet<string> tokens, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var cleaned = new string(value.Trim()
            .Select(character =>
                char.IsLetterOrDigit(character) || character is '.' or '-' or '_'
                    ? character
                    : '-')
            .ToArray())
            .Trim('-', '.', '_');
        if (cleaned.Length > 1)
        {
            tokens.Add(cleaned);
        }
    }

    private static bool Matches(HiddenPath entry, HttpResponseData response)
    {
        var text = response.Text;
        return entry.Validation switch
        {
            HiddenPathValidation.None => entry.AllowHtml
                || (response.ContentType?.Contains("html", StringComparison.OrdinalIgnoreCase) != true
                    && !text.TrimStart().StartsWith('<')),
            HiddenPathValidation.Contains => text.Contains(entry.Marker!, StringComparison.OrdinalIgnoreCase),
            HiddenPathValidation.Regex => Regex.IsMatch(
                text,
                entry.Marker!,
                RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant),
            HiddenPathValidation.EnvFile => LooksLikeEnvFile(text),
            HiddenPathValidation.SqlDump => Regex.IsMatch(
                text,
                @"(INSERT\s+INTO|CREATE\s+TABLE|--\s*MySQL|PostgreSQL database dump)",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant),
            // A 200 with an archive content type is often an HTML soft-404. Only the magic bytes
            // prove that the response really is an archive or database file.
            HiddenPathValidation.Archive => FileSignatures.Identify(response.Body) is not null,
            _ => false,
        };
    }

    private static bool LooksLikeEnvFile(string text)
    {
        var keys = new List<string>();
        foreach (var raw in text.Split('\n').Take(200))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith('<'))
            {
                continue;
            }

            var separator = line.IndexOf('=');
            if (separator <= 0)
            {
                continue;
            }

            var key = line[..separator].Trim();
            if (key.Length > 0 && key.All(character =>
                    char.IsLetterOrDigit(character) || character is '_' or '.'))
            {
                keys.Add(key);
            }
        }

        return keys.Count >= 1 && keys.Any(key =>
            key.Contains("SECRET", StringComparison.OrdinalIgnoreCase)
            || key.Contains("KEY", StringComparison.OrdinalIgnoreCase)
            || key.Contains("PASSWORD", StringComparison.OrdinalIgnoreCase)
            || key.Contains("TOKEN", StringComparison.OrdinalIgnoreCase)
            || key.Contains("DB_", StringComparison.OrdinalIgnoreCase)
            || key.Contains("APP_", StringComparison.OrdinalIgnoreCase)
            || key.Contains("AWS_", StringComparison.OrdinalIgnoreCase)
            || key.Contains("SMTP", StringComparison.OrdinalIgnoreCase));
    }

    private static bool LooksLikeSoftNotFound(
        HttpResponseData candidate,
        HttpResponseData baseline,
        string baselinePath,
        string candidatePath) =>
        Soft404Detector.LooksLikeSoftNotFound(candidate, baseline, baselinePath, candidatePath);
}
