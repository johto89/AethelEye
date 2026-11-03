using AethelEye.Core.Abstractions;
using RetireSharp.Advisories;
using RetireModel = RetireSharp.Model;

namespace AethelEye.Modules.Advisories;

/// <summary>
/// Local SQLite advisory store built by <c>aetheleye --update db</c>. The same file can be copied
/// to an isolated machine, so an offline scan can still use OSV, KEV and EPSS data.
/// </summary>
public static class AdvisoryDatabaseStore
{
    public const string DefaultFileName = "aetheleye.db";

    public static string DefaultPath(string dataDirectory) =>
        Path.Combine(dataDirectory, DefaultFileName);

    public static string ResolvePath(string dataDirectory, string? configuredPath) =>
        string.IsNullOrWhiteSpace(configuredPath)
            ? DefaultPath(dataDirectory)
            : Path.GetFullPath(configuredPath);

    /// <summary>Returns null when the database does not exist; a corrupt database is also non-fatal.</summary>
    public static AdvisoryDatabase? OpenIfExists(string path, ILog? log = null)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return null;
        }

        try
        {
            return AdvisoryDatabase.OpenReadOnly(path);
        }
        catch (Exception error) when (error is SqliteException or IOException or InvalidOperationException)
        {
            log?.Warn($"Advisory database could not be opened ({path}): {error.Message}");
            return null;
        }
    }

    public static async Task<bool> UpdateAsync(
        string path,
        UpdateOptions options,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        using var database = AdvisoryDatabase.OpenForUpdate(path);
        return await FeedUpdater.UpdateAsync(database, options, cancellationToken);
    }

    /// <summary>
    /// Adds OSV advisories from the database to a Retire component, then adds KEV/EPSS context.
    /// Retire and OSV often describe the same CVE, so records are deduplicated by identifier.
    /// </summary>
    public static int MergeAdvisories(
        AdvisoryDatabase database,
        RetireModel.Component component,
        Action<string>? warn = null)
    {
        if (string.IsNullOrWhiteSpace(component.Version) || component.Version == "undefined")
        {
            return 0;
        }

        var package = component.NpmName ?? component.Name;
        List<RetireModel.Vulnerability> found;
        try
        {
            found = package.Equals("node", StringComparison.OrdinalIgnoreCase)
                ? database.Lookup("node", component.Version, "nodejs")
                : database.Lookup(package, component.Version);
        }
        catch (Exception error) when (error is SqliteException or InvalidOperationException)
        {
            warn?.Invoke($"Advisory lookup failed for {package} {component.Version}: {error.Message}");
            return 0;
        }

        if (found.Count == 0)
        {
            return 0;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var existing in component.Vulnerabilities ?? [])
        {
            foreach (var key in Keys(existing))
            {
                seen.Add(key);
            }
        }

        var added = 0;
        foreach (var vulnerability in found)
        {
            var keys = Keys(vulnerability).ToList();
            if (keys.Any(seen.Contains))
            {
                continue;
            }

            database.Enrich(vulnerability);
            var poc = ThreatContext.ClassifyPoc(vulnerability.Info);
            if (poc.Count > 0)
            {
                vulnerability.PocUrls = poc;
            }

            component.Vulnerabilities ??= [];
            component.Vulnerabilities.Add(vulnerability);
            foreach (var key in keys)
            {
                seen.Add(key);
            }

            added++;
        }

        return added;
    }

    private static IEnumerable<string> Keys(RetireModel.Vulnerability vulnerability)
    {
        var identifiers = vulnerability.Identifiers;
        if (identifiers is null)
        {
            yield break;
        }

        foreach (var cve in identifiers.Cve ?? [])
        {
            yield return "CVE:" + cve;
        }

        if (identifiers.GithubId is { Length: > 0 } github)
        {
            yield return "GHSA:" + github;
        }

        var advisory = identifiers.Get("advisory") as string;
        if (advisory is { Length: > 0 })
        {
            yield return "ADVISORY:" + advisory;
        }
    }
}
