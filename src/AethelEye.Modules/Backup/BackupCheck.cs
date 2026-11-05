using System.Collections.Concurrent;
using System.Net;
using System.Text;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;

namespace AethelEye.Modules.Backup;

/// <summary>
/// Finds backup archives and database dumps named after the application path or an explicit
/// --name-token. Inspired by backup_finder.py. It never splits an IP into octets; for an IP it
/// only tries the complete address (for example 1.1.1.1.zip).
/// </summary>
public sealed class BackupCheck : ICheck
{
    private static readonly string[] Extensions =
    [
        ".zip", ".tar.gz", ".7z", ".sql", ".bak", ".old",
    ];

    private static readonly string[] Wrappers =
    [
        "{name}{ext}",
        "{name}_backup{ext}",
        "backup_{name}{ext}",
    ];

    private static readonly HashSet<string> IgnoredPathSegments = new(StringComparer.OrdinalIgnoreCase)
    {
        "api", "v1", "v2", "v3", "static", "assets", "css", "js", "images", "img",
        "index.html", "index.php", "index.htm",
    };

    private static readonly HashSet<string> SqlContentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "application/sql",
        "application/x-sql",
        "text/x-sql",
        "text/plain",
        "application/octet-stream",
    };

    public string Id => "backup";

    public string Name => "Backup archives and dumps";

    public string Description =>
        "Probes backup archives named after the application path or --name-token; " +
        "validates archives with magic bytes instead of trusting a 200 response.";

    public int Order => 31;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        var (tokens, appTokens, nameTokens) = BuildTokens(context);
        var candidates = BuildCandidates(context, tokens, appTokens, nameTokens);
        var maxCandidates = Math.Clamp(context.Settings.GetInt("maxCandidates", 150), 1, 2000);
        if (candidates.Count > maxCandidates)
        {
            result.Notes.Add(
                $"Candidate list capped at {maxCandidates} of {candidates.Count} entries.");
            candidates = candidates.Take(maxCandidates).ToList();
        }

        result.Metrics["tokens"] = string.Join(", ", tokens);
        result.Metrics["candidates"] = candidates.Count.ToString();
        result.Metrics["candidateUrls"] = string.Join(
            ", ",
            candidates.Select(candidate => context.Target.RootUrl.TrimEnd('/') + candidate));
        result.Notes.Add(
            $"Backup stems: {string.Join(", ", tokens)}. " +
            "An IP address is used whole; it is never split into octets.");
        if (candidates.Count == 0)
        {
            result.Status = CheckStatus.NoRisk;
            result.Summary = "No backup name token was available for this target.";
            return result;
        }

        var notes = new ConcurrentBag<string>();
        var baselineUri = new Uri(
            context.Target.RootUrl.TrimEnd('/') + $"/.aetheleye-{Guid.NewGuid():N}",
            UriKind.Absolute);
        var baseline = await TryGetAsync(context, baselineUri, notes);
        var findings = new ConcurrentBag<Finding>();
        var confirmed = 0;
        var protectedFiles = 0;
        var failures = 0;
        var parallelism = context.Engagement.Http.Evasion
            ? 1
            : Math.Clamp(context.Settings.GetInt("parallelism", 4), 1, 10);

        using var gate = new SemaphoreSlim(parallelism);
        await Task.WhenAll(candidates.Select(async candidate =>
        {
            await gate.WaitAsync(context.CancellationToken);
            try
            {
                var uri = new Uri(
                    context.Target.RootUrl.TrimEnd('/') + candidate,
                    UriKind.Absolute);
                if (!context.Scope.IsAllowed(uri))
                {
                    return;
                }

                var response = await TryGetAsync(context, uri, notes);
                if (response is null)
                {
                    Interlocked.Increment(ref failures);
                    return;
                }

                if (response.StatusCode is 401 or 403)
                {
                    Interlocked.Increment(ref protectedFiles);
                    notes.Add($"{candidate}: HTTP {response.StatusCode} (protected)");
                    return;
                }

                if (response.StatusCode is not (200 or 206))
                {
                    return;
                }

                if (baseline is not null && LooksLikeSoftNotFound(response, baseline))
                {
                    return;
                }

                var magic = FileSignatures.Identify(response.Body);
                var contentType = response.ContentType ?? string.Empty;
                if (magic is null)
                {
                    // No binary signature: only a genuine text SQL dump is acceptable. A 200
                    // response whose body is an HTML/JSON soft-404 page is not a backup, even
                    // when the server mislabels it as application/zip or octet-stream.
                    var mediaType = contentType.Split(';')[0].Trim();
                    if (!SqlContentTypes.Contains(mediaType)
                        || LooksLikeMarkup(response.Body)
                        || !LooksLikeSqlDump(response.Body))
                    {
                        return;
                    }

                    magic = "SQL/text database dump";
                }

                Interlocked.Increment(ref confirmed);
                findings.Add(new Finding
                {
                    CheckId = Id,
                    Title = $"{DescribeMagic(magic)} is exposed: {candidate}",
                    Description =
                        "A backup archive or database dump is reachable. It can disclose source " +
                        "code, configuration, credentials and customer data.",
                    Severity = Severity.Critical,
                    Confidence = Confidence.High,
                    Target = context.Target.BaseUrl,
                    Url = uri.ToString(),
                    Evidence = new Dictionary<string, string>
                    {
                        ["candidate"] = candidate,
                        ["status"] = response.StatusCode.ToString(),
                        ["contentType"] = contentType,
                        ["bytes"] = response.Body.Length.ToString(),
                        ["magic"] = magic,
                        ["token"] = TokenFor(candidate, tokens),
                    },
                    Remediation =
                        "Remove the backup from the web root, block archive/dump extensions at the " +
                        "reverse proxy, and rotate any credentials it contained.",
                });
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                notes.Add($"{candidate}: {error.Message}");
            }
            finally
            {
                gate.Release();
            }
        }));

        foreach (var finding in findings
                     .OrderByDescending(finding => finding.Severity)
                     .ThenBy(finding => finding.Title, StringComparer.Ordinal))
        {
            result.Findings.Add(finding);
        }

        foreach (var note in notes.Distinct(StringComparer.OrdinalIgnoreCase).Take(15))
        {
            result.Notes.Add(note);
        }

        result.Metrics["confirmed"] = confirmed.ToString();
        result.Metrics["protected"] = protectedFiles.ToString();
        result.Metrics["failures"] = failures.ToString();
        result.Summary =
            $"Probed {candidates.Count} backup candidate(s) from {tokens.Count} token(s); " +
            $"{confirmed} confirmed, {protectedFiles} protected.";
        result.Status = result.RiskFindingCount > 0 ? CheckStatus.Findings : CheckStatus.NoRisk;
        return result;
    }

    private static (List<string> Tokens, HashSet<string> AppTokens, HashSet<string> NameTokens) BuildTokens(ICheckContext context)
    {
        var tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var appTokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var nameTokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var host = context.Target.Host;
        var isIp = IPAddress.TryParse(host, out _);

        if (isIp)
        {
            // Never split an IP into 1, 1.1, 1.1.1. The full address is the only useful stem.
            AddToken(tokens, host);
        }
        else
        {
            AddToken(tokens, host);
            var labels = host.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (labels.Length > 1)
            {
                AddToken(tokens, labels[0]);
            }
        }

        var segments = context.Target.BaseUri.AbsolutePath
            .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(segment => segment.Length > 1 && !IgnoredPathSegments.Contains(segment))
            .ToList();
        if (segments.Count > 0)
        {
            AddToken(tokens, segments[^1]);
            AddToken(appTokens, segments[^1]);
            if (segments.Count > 1)
            {
                var fullPath = string.Join("-", segments);
                AddToken(tokens, fullPath);
                AddToken(appTokens, fullPath);
            }
        }

        foreach (var name in context.Settings.GetStringList("names"))
        {
            AddToken(tokens, name);
            AddToken(appTokens, name);
            AddToken(nameTokens, name);
        }

        return (tokens.ToList(), appTokens, nameTokens);
    }

    private static List<string> BuildCandidates(
        ICheckContext context,
        IReadOnlyList<string> tokens,
        HashSet<string> appTokens,
        HashSet<string> nameTokens)
    {
        var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var appPath = context.Target.BaseUri.AbsolutePath.TrimEnd('/');
        foreach (var token in tokens)
        {
            foreach (var extension in Extensions)
            {
                foreach (var wrapper in Wrappers)
                {
                    var name = wrapper
                        .Replace("{name}", token, StringComparison.Ordinal)
                        .Replace("{ext}", extension, StringComparison.Ordinal);
                    var file = "/" + name.TrimStart('/');
                    candidates.Add(file);
                    if (appPath.Length > 1 && appTokens.Contains(token))
                    {
                        candidates.Add(appPath + "/" + name.TrimStart('/'));
                    }

                    // A --name-token also names a directory, so probe /token/token.ext too.
                    if (nameTokens.Contains(token))
                    {
                        candidates.Add("/" + token.TrimStart('/') + "/" + name.TrimStart('/'));
                    }
                }
            }
        }

        return candidates.OrderBy(candidate => candidate, StringComparer.Ordinal).ToList();
    }

    private static void AddToken(HashSet<string> tokens, string? value)
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

    private static async Task<HttpResponseData?> TryGetAsync(
        ICheckContext context,
        Uri uri,
        ConcurrentBag<string> notes)
    {
        if (!context.Scope.IsAllowed(uri))
        {
            return null;
        }

        try
        {
            return await context.Http.GetAsync(uri, context.CancellationToken);
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            notes.Add($"{uri.AbsolutePath}: {error.Message}");
            return null;
        }
    }

    private static bool LooksLikeSoftNotFound(HttpResponseData candidate, HttpResponseData baseline) =>
        Soft404Detector.LooksLikeSoftNotFound(candidate, baseline);

    /// <summary>
    /// True when the body is an HTML, XML or JSON document. A soft-404 page can be returned with
    /// HTTP 200 and even an archive content type, so markup must never be treated as a backup.
    /// </summary>
    private static bool LooksLikeMarkup(byte[] body)
    {
        var length = Math.Min(body.Length, 1024);
        if (length == 0)
        {
            return false;
        }

        var text = Encoding.UTF8.GetString(body, 0, length).TrimStart('\uFEFF', ' ', '\t', '\r', '\n');
        if (text.Length == 0)
        {
            return false;
        }

        if (text[0] is '<' or '{' or '[')
        {
            return true;
        }

        var head = text[..Math.Min(text.Length, 512)];
        return head.Contains("<!doctype html", StringComparison.OrdinalIgnoreCase)
               || head.Contains("<html", StringComparison.OrdinalIgnoreCase)
               || head.Contains("<head", StringComparison.OrdinalIgnoreCase)
               || head.Contains("<body", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True for a text SQL dump; markup has already been rejected by the caller.</summary>
    private static bool LooksLikeSqlDump(byte[] body)
    {
        if (body.Length < 512)
        {
            return false;
        }

        var text = Encoding.UTF8.GetString(body, 0, Math.Min(body.Length, 4096));
        var upper = text.ToUpperInvariant();
        return upper.Contains("-- MYSQL DUMP", StringComparison.Ordinal)
               || upper.Contains("-- MARIADB DUMP", StringComparison.Ordinal)
               || upper.Contains("-- POSTGRESQL DATABASE DUMP", StringComparison.Ordinal)
               || upper.Contains("-- PHPMYADMIN SQL DUMP", StringComparison.Ordinal)
               || upper.Contains("DROP TABLE IF EXISTS", StringComparison.Ordinal)
               || upper.Contains("CREATE TABLE", StringComparison.Ordinal)
               || upper.Contains("INSERT INTO", StringComparison.Ordinal);
    }

    private static string DescribeMagic(string magic) =>
        magic.Contains("dump", StringComparison.OrdinalIgnoreCase)
            || magic.Contains("database", StringComparison.OrdinalIgnoreCase)
            ? "Database dump"
            : "Backup archive";

    private static string TokenFor(string candidate, IReadOnlyList<string> tokens) =>
        tokens.FirstOrDefault(token =>
            candidate.Contains(token, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;
}
