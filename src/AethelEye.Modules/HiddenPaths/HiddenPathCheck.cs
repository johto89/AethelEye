using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;
using AethelEye.Modules.Backup;

namespace AethelEye.Modules.HiddenPaths;

/// <summary>
/// Probes a broad catalog of exposed files under the target application plus backup archives
/// derived from that same application path. A random-path baseline suppresses soft 404 pages,
/// and each candidate needs a status, content-type, marker or magic-byte signature that makes
/// sense for its type.
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

        // Name-based backups are generated automatically in four places: the application stem
        // inside (/merchant/merchant.zip) and next to it (/merchant.zip), plus the complete
        // host inside (/merchant/192.168.1.2.zip) and at the web root (/192.168.1.2.zip).
        // No sibling application names or wrappers are generated, and only when the operator
        // did not supply an explicit custom path list.
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
        // Name-based backups inside the application are relative to that root; the sibling and
        // host entries are flagged SiteRoot and resolved against the origin root instead.
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

    /// <summary>
    /// Builds only the name-based backup entries automatically: the application stem inside
    /// (/usertest/usertest.zip) and next to it (/usertest.zip), plus the complete host inside
    /// (/usertest/192.168.1.2.zip) and at the web root (/192.168.1.2.zip). No wrappers or
    /// sibling application names are generated.
    /// </summary>
    private static IEnumerable<HiddenPath> BuildDerivedBackupEntries(ICheckContext context)
    {
        var appPath = context.Target.BaseUri.AbsolutePath.TrimEnd('/');
        foreach (var candidate in ApplicationBackupScope.Build(context))
        {
            if (candidate.SiteRoot)
            {
                // /usertest.zip, /192.168.1.2.zip, ... resolved against the site root.
                yield return new HiddenPath(
                    candidate.UrlPath,
                    Severity.High,
                    HiddenPathValidation.Archive,
                    null,
                    "Backup archive named after the application or host is exposed.",
                    SiteRoot: true);
                continue;
            }

            // Inside the application: convert the absolute path back to an app-relative one.
            var path = candidate.UrlPath;
            if (appPath.Length > 0
                && path.StartsWith(appPath, StringComparison.Ordinal))
            {
                path = path[appPath.Length..];
            }

            if (!path.StartsWith('/'))
            {
                path = "/" + path;
            }

            yield return new HiddenPath(
                path,
                Severity.High,
                HiddenPathValidation.Archive,
                null,
                "Backup archive named after the application is exposed.");
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
