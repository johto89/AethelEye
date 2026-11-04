using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;

namespace AethelEye.Modules.HiddenPaths;

/// <summary>
/// Probes a small, curated list of exposed files. A random-path baseline suppresses soft 404 pages,
/// and each candidate needs a status, content-type or marker that makes sense for that file type.
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

        if (context.Engagement.Http.Evasion)
        {
            entries = entries.OrderBy(_ => Random.Shared.Next()).ToList();
            result.Notes.Add("Evasion profile: path probes are shuffled and sent one at a time.");
        }

        var parallelism = context.Engagement.Http.Evasion
            ? 1
            : Math.Clamp(context.Settings.GetInt("parallelism", 4), 1, 10);
        // Each application path is its own root: /abc/.git/HEAD and /xyz/.git/HEAD are separate.
        var root = new Uri(context.Target.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
        var baselinePath = $"/.aetheleye-{Guid.NewGuid():N}";
        HttpResponseData? baseline = null;
        try
        {
            baseline = await context.Http.GetAsync(new Uri(root, baselinePath.TrimStart('/')), context.CancellationToken);
            result.Notes.Add($"Soft-404 baseline: HTTP {baseline.StatusCode}, {baseline.Body.Length} bytes.");
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            result.Notes.Add($"Soft-404 baseline failed: {error.Message}");
        }

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
                var uri = new Uri(root, entry.Path.TrimStart('/'));
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

                if (baseline is not null && LooksLikeSoftNotFound(response, baseline, baselinePath, entry.Path))
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
