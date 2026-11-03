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

    private static readonly HashSet<string> ArchiveContentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "application/zip",
        "application/x-rar-compressed",
        "application/x-7z-compressed",
        "application/gzip",
        "application/x-gzip",
        "application/x-tar",
        "application/x-bzip2",
        "application/octet-stream",
        "application/sql",
        "application/x-sql",
        "text/x-sql",
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
        var (tokens, appTokens) = BuildTokens(context);
        var candidates = BuildCandidates(context, tokens, appTokens);
        var maxCandidates = Math.Clamp(context.Settings.GetInt("maxCandidates", 150), 1, 2000);
        if (candidates.Count > maxCandidates)
        {
            result.Notes.Add(
                $"Candidate list capped at {maxCandidates} of {candidates.Count} entries.");
            candidates = candidates.Take(maxCandidates).ToList();
        }

        result.Metrics["tokens"] = string.Join(", ", tokens);
        result.Metrics["candidates"] = candidates.Count.ToString();
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

                var magic = IdentifyMagic(response.Body);
                var contentType = response.ContentType ?? string.Empty;
                var isArchive = ArchiveContentTypes.Contains(contentType.Split(';')[0].Trim());
                if (magic is null && !isArchive)
                {
                    return;
                }

                if (magic is null && response.Body.Length <= 1024)
                {
                    return;
                }

                Interlocked.Increment(ref confirmed);
                var severity = magic is null ? Severity.High : Severity.Critical;
                findings.Add(new Finding
                {
                    CheckId = Id,
                    Title = magic is null
                        ? $"Backup file is exposed: {candidate}"
                        : $"{DescribeMagic(magic)} is exposed: {candidate}",
                    Description =
                        "A backup archive or database dump is reachable. It can disclose source " +
                        "code, configuration, credentials and customer data.",
                    Severity = severity,
                    Confidence = magic is null ? Confidence.Medium : Confidence.High,
                    Target = context.Target.BaseUrl,
                    Url = uri.ToString(),
                    Evidence = new Dictionary<string, string>
                    {
                        ["candidate"] = candidate,
                        ["status"] = response.StatusCode.ToString(),
                        ["contentType"] = contentType,
                        ["bytes"] = response.Body.Length.ToString(),
                        ["magic"] = magic ?? string.Empty,
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

    private static (List<string> Tokens, HashSet<string> AppTokens) BuildTokens(ICheckContext context)
    {
        var tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var appTokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
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
        }

        return (tokens.ToList(), appTokens);
    }

    private static List<string> BuildCandidates(
        ICheckContext context,
        IReadOnlyList<string> tokens,
        HashSet<string> appTokens)
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
                    candidates.Add("/" + name.TrimStart('/'));
                    if (appPath.Length > 1 && appTokens.Contains(token))
                    {
                        candidates.Add(appPath + "/" + name.TrimStart('/'));
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

    private static bool LooksLikeSoftNotFound(HttpResponseData candidate, HttpResponseData baseline)
    {
        if (candidate.StatusCode != baseline.StatusCode)
        {
            return false;
        }

        if (candidate.Body.Length == baseline.Body.Length
            && candidate.Text.Equals(baseline.Text, StringComparison.Ordinal))
        {
            return true;
        }

        return baseline.Body.Length > 0
            && candidate.ContentType?.Contains("html", StringComparison.OrdinalIgnoreCase) == true
            && Math.Abs(candidate.Body.Length - baseline.Body.Length) <= Math.Max(64, baseline.Body.Length / 20);
    }

    private static string? IdentifyMagic(byte[] body)
    {
        if (body.Length == 0)
        {
            return null;
        }

        if (StartsWith(body, [0x50, 0x4B, 0x03, 0x04])
            || StartsWith(body, [0x50, 0x4B, 0x05, 0x06])
            || StartsWith(body, [0x50, 0x4B, 0x07, 0x08]))
        {
            return "ZIP archive";
        }

        if (StartsWith(body, [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]))
        {
            return "RAR archive";
        }

        if (StartsWith(body, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]))
        {
            return "7-Zip archive";
        }

        if (StartsWith(body, [0x1F, 0x8B]))
        {
            return "GZIP archive";
        }

        if (StartsWith(body, [0x42, 0x5A, 0x68]))
        {
            return "BZIP2 archive";
        }

        if (StartsWith(body, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]))
        {
            return "XZ archive";
        }

        if (body.Length > 262
            && body[257] == (byte)'u'
            && body[258] == (byte)'s'
            && body[259] == (byte)'t'
            && body[260] == (byte)'a'
            && body[261] == (byte)'r')
        {
            return "TAR archive";
        }

        if (StartsWith(body, Encoding.ASCII.GetBytes("SQLite format 3\0")))
        {
            return "SQLite database";
        }

        var text = Encoding.UTF8.GetString(body, 0, Math.Min(body.Length, 2048));
        var upper = text.ToUpperInvariant();
        if (upper.Contains("-- MYSQL DUMP", StringComparison.Ordinal)
            || upper.Contains("-- MARIADB DUMP", StringComparison.Ordinal)
            || upper.Contains("-- POSTGRESQL DATABASE DUMP", StringComparison.Ordinal)
            || upper.Contains("-- PHPMYADMIN SQL DUMP", StringComparison.Ordinal)
            || upper.Contains("DROP TABLE IF EXISTS", StringComparison.Ordinal)
            || upper.Contains("CREATE TABLE", StringComparison.Ordinal)
            || upper.Contains("INSERT INTO", StringComparison.Ordinal))
        {
            return "SQL/text database dump";
        }

        return null;
    }

    private static bool StartsWith(byte[] body, byte[] signature) =>
        body.Length >= signature.Length && body.AsSpan(0, signature.Length).SequenceEqual(signature);

    private static string DescribeMagic(string magic) =>
        magic.Contains("dump", StringComparison.OrdinalIgnoreCase)
            || magic.Contains("database", StringComparison.OrdinalIgnoreCase)
            ? "Database dump"
            : "Backup archive";

    private static string TokenFor(string candidate, IReadOnlyList<string> tokens) =>
        tokens.FirstOrDefault(token =>
            candidate.Contains(token, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;
}
