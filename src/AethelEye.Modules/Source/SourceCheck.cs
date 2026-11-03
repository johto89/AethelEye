using System.Collections.Concurrent;
using System.IO.Compression;
using System.Text.Json;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;
using AethelEye.Modules.Advisories;
using AethelEye.Modules.Technology;
using RetireSharp.Advisories;
using RetireSharp.Engine;
using RetireSharp.Manifest;
using RetireSharp.Query;
using RetireSharp.Reporting;
using RetireSharp.Scan;
using RetireModel = RetireSharp.Model;

namespace AethelEye.Modules.Source;

/// <summary>
/// Scans a downloaded source tree or .zip with RetireSharp: JavaScript files are fingerprinted
/// directly, and lockfiles/node_modules are read by RetireSharp's ManifestScanner. This is the
/// source-code counterpart to the live web technology check, so a leaked abc.zip can be assessed
/// without exposing a web endpoint.
/// </summary>
public sealed class SourceCheck : ICheck
{
    private const long MaxFileBytes = 10 * 1024 * 1024;
    private const long MaxArchiveBytes = 500 * 1024 * 1024;
    private const int MaxArchiveEntries = 20_000;
    private const int MaxJsFiles = 5_000;

    public string Id => "source";

    public string Name => "Source code dependencies";

    public string Description =>
        "Scans a local source tree, .zip or single JS/manifest file with RetireSharp.";

    public int Order => 35;

    public bool RunsOncePerScan => true;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        var sources = context.Engagement.Sources;
        if (sources.Count == 0)
        {
            result.Status = CheckStatus.Skipped;
            result.Summary = "No source path configured.";
            return result;
        }

        var databasePath = AdvisoryDatabaseStore.ResolvePath(
            context.DataDirectory,
            context.Engagement.AdvisoryDatabasePath);
        using var database = AdvisoryDatabaseStore.OpenIfExists(databasePath, context.Log);
        RetireModel.Repository? repository = database?.LoadRepository();
        if (repository is not null)
        {
            result.Notes.Add($"Loaded {databasePath} advisory database.");
        }
        else
        {
            repository = await RetireRepositoryStore.LoadAsync(
                context.ExternalHttp,
                context.Log,
                context.DataDirectory,
                context.Settings.GetString("retireRepository"),
                context.Engagement.Offline,
                context.CancellationToken);

            if (repository is null)
            {
                result.Notes.Add(context.Engagement.Offline
                    ? "Offline mode: no advisory database or cached Retire repository. " +
                      "Run 'aetheleye --update db' on a connected machine and copy the file."
                    : "Could not download/parse the Retire repository. " +
                      "Run 'aetheleye --update db' for a local advisory database.");
            }
        }

        if (repository is not null)
        {
            Focus.ApplyExtractors(repository);
        }

        var focusText = context.Settings.GetString("focus");
        var focus = Focus.TryParseGroup(focusText, out var focusGroup)
            ? focusGroup
            : FocusGroup.All;
        var components = new ConcurrentDictionary<string, ComponentHit>(
            StringComparer.OrdinalIgnoreCase);
        var warnings = new ConcurrentBag<string>();
        var failures = 0;
        var files = 0;

        if (repository is not null)
        {
            foreach (var source in sources)
            {
                var outcome = await ScanSourceAsync(
                    context,
                    repository,
                    source,
                    components,
                    warnings);

                failures += outcome.Failures;
                files += outcome.Files;
            }
        }

        var vulnerable = 0;
        var maxFindings = Math.Clamp(context.Settings.GetInt("maxFindings", 200), 1, 1000);

        foreach (var hit in components.Values
                     .OrderBy(hit => hit.Component.Name, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(hit => hit.Component.Version, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(hit => hit.File, StringComparer.OrdinalIgnoreCase))
        {
            var component = hit.Component;
            var package = component.NpmName ?? component.Name;
            if (focus != FocusGroup.All && !Focus.IsFocused(package, focus))
            {
                continue;
            }

            if (database is not null)
            {
                AdvisoryDatabaseStore.MergeAdvisories(database, component, message => warnings.Add(message));
            }

            if (component.Vulnerabilities is not { Count: > 0 })
            {
                continue;
            }

            var cves = component.Vulnerabilities
                .SelectMany(vulnerability => vulnerability.Identifiers?.Cve ?? [])
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var advisories = component.Vulnerabilities
                .SelectMany(vulnerability => vulnerability.Identifiers?.Cve
                    ?? (vulnerability.Identifiers?.GithubId is { Length: > 0 } ghsa ? [ghsa] : []))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            vulnerable++;
            if (result.Findings.Count >= maxFindings)
            {
                result.Notes.Add($"Finding list capped at {maxFindings} entries.");
                break;
            }

            var details = component.Vulnerabilities
                .Select(vulnerability => Describe(vulnerability))
                .Where(text => text.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(5)
                .ToList();
            var severity = component.Vulnerabilities
                .Select(vulnerability => MapSeverity(vulnerability.Severity))
                .DefaultIfEmpty(Severity.Medium)
                .Max();
            var kev = component.Vulnerabilities.Any(vulnerability => vulnerability.Kev);
            var epss = component.Vulnerabilities
                .Where(vulnerability => vulnerability.Epss is not null)
                .Select(vulnerability => vulnerability.Epss!.Value)
                .DefaultIfEmpty(0)
                .Max();
            var poc = component.Vulnerabilities
                .SelectMany(vulnerability => vulnerability.PocUrls ?? [])
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var licenses = EvaluateLicenses(repository!, component);

            result.Findings.Add(new Finding
            {
                CheckId = Id,
                Title = hit.Origin == "manifest"
                    ? $"Vulnerable dependency in source: {component.Name} {component.Version}"
                    : $"Vulnerable JavaScript library in source: {component.Name} {component.Version}",
                Description =
                    "Retire.js and the local OSV advisory database report known vulnerabilities for " +
                    "this component in the downloaded source. Confirm that the file is used by the " +
                    "deployed application.",
                Severity = severity,
                Confidence = ConfidenceFor(component.Detection),
                Target = context.Target.BaseUrl,
                Url = hit.File,
                Evidence = new Dictionary<string, string>
                {
                    ["source"] = hit.Source,
                    ["file"] = hit.File,
                    ["origin"] = hit.Origin,
                    ["component"] = component.Name,
                    ["version"] = component.Version,
                    ["npm"] = component.NpmName ?? string.Empty,
                    ["purl"] = Purl(component),
                    ["detection"] = component.Detection ?? string.Empty,
                    ["cves"] = string.Join(", ", cves),
                    ["advisories"] = string.Join(", ", advisories),
                    ["details"] = string.Join(" | ", details),
                    ["licenses"] = string.Join(", ", licenses),
                    ["kev"] = kev ? "yes" : "no",
                    ["epss"] = epss > 0 ? epss.ToString("0.000") : string.Empty,
                    ["poc"] = string.Join(", ", poc),
                },
                Remediation =
                    "Upgrade the component to a version outside the vulnerable range and redeploy.",
                References = cves
                    .Select(cve => $"https://nvd.nist.gov/vuln/detail/{cve}")
                    .Concat(poc)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
            });
        }

        foreach (var warning in warnings.Distinct(StringComparer.OrdinalIgnoreCase).Take(20))
        {
            result.Notes.Add(warning);
        }

        result.Metrics["sources"] = sources.Count.ToString();
        result.Metrics["files"] = files.ToString();
        result.Metrics["components"] = components.Count.ToString();
        result.Metrics["vulnerable"] = vulnerable.ToString();
        result.Metrics["advisoryDatabase"] = database is null ? "not found" : databasePath;
        result.Metrics["failures"] = failures.ToString();

        var repositoryUnavailable = sources.Count > 0 && repository is null;
        result.Summary =
            $"Scanned {sources.Count} source item(s), {files} file(s), {components.Count} component(s); " +
            $"{vulnerable} vulnerable component(s); advisory database: " +
            $"{(database is null ? "not found" : databasePath)}.";
        result.Status = result.RiskFindingCount > 0
            ? CheckStatus.Findings
            : repositoryUnavailable || failures > 0
                ? CheckStatus.Partial
                : CheckStatus.NoRisk;
        return result;
    }

    private static async Task<(int Files, int Failures)> ScanSourceAsync(
        ICheckContext context,
        RetireModel.Repository repository,
        string source,
        ConcurrentDictionary<string, ComponentHit> components,
        ConcurrentBag<string> warnings)
    {
        var failures = 0;
        var files = 0;
        string? temporaryRoot = null;

        try
        {
            string path = source;

            if (Uri.TryCreate(source, UriKind.Absolute, out var uri)
                && uri.Scheme is "http" or "https")
            {
                if (context.Engagement.Offline)
                {
                    warnings.Add($"{source}: offline mode, source URL was not downloaded.");
                    return (0, 1);
                }

                if (!context.Scope.IsAllowed(uri))
                {
                    warnings.Add($"{source}: outside target scope; download it and use --src with a local path.");
                    return (0, 1);
                }

                temporaryRoot = CreateTemporaryRoot();
                var fileName = Path.GetFileName(uri.LocalPath);
                if (string.IsNullOrWhiteSpace(fileName))
                {
                    fileName = "download.bin";
                }

                var local = Path.Combine(temporaryRoot, fileName);
                var response = await context.Http.GetAsync(uri, context.CancellationToken);
                if (!response.IsSuccess)
                {
                    warnings.Add($"{source}: HTTP {response.StatusCode}.");
                    return (0, 1);
                }

                await File.WriteAllBytesAsync(local, response.Body, context.CancellationToken);
                path = local;
            }
            else if (!File.Exists(path) && !Directory.Exists(path))
            {
                warnings.Add($"{source}: source path not found.");
                return (0, 1);
            }

            if (Directory.Exists(path))
            {
                var root = path;
                var (dirFiles, dirFailures) = await Task.Run(
                    () => ScanDirectory(context, repository, root, root, components, warnings),
                    context.CancellationToken);
                files += dirFiles;
                failures += dirFailures;
            }
            else if (path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                temporaryRoot ??= CreateTemporaryRoot();
                var extract = Path.Combine(temporaryRoot, "extract");
                failures += ExtractZip(path, extract, warnings);
                var (dirFiles, dirFailures) = await Task.Run(
                    () => ScanDirectory(context, repository, extract, source, components, warnings),
                    context.CancellationToken);
                files += dirFiles;
                failures += dirFailures;
            }
            else
            {
                var (fileFiles, fileFailures) = ScanSingleFile(context, repository, path, source, components, warnings);
                files += fileFiles;
                failures += fileFailures;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            warnings.Add($"{source}: {error.Message}");
            failures++;
        }
        finally
        {
            if (temporaryRoot is not null)
            {
                try
                {
                    if (Directory.Exists(temporaryRoot))
                    {
                        Directory.Delete(temporaryRoot, recursive: true);
                    }
                }
                catch (IOException)
                {
                    // Best effort cleanup.
                }
            }
        }

        return (files, failures);
    }

    private static (int Files, int Failures) ScanDirectory(
        ICheckContext context,
        RetireModel.Repository repository,
        string root,
        string sourceLabel,
        ConcurrentDictionary<string, ComponentHit> components,
        ConcurrentBag<string> warnings)
    {
        var failures = 0;
        var files = 0;
        var manifestDeclarations = 0;
        var deep = context.Settings.GetBool("deep", false);

        foreach (var manifest in ManifestScanner.Scan(root, warnings.Add))
        {
            foreach (var package in manifest.Packages)
            {
                if (package.DeclaredRange is not null)
                {
                    manifestDeclarations++;
                    continue;
                }

                foreach (var component in CheckPackage(repository, package.Name, package.Version))
                {
                    AddComponent(
                        components,
                        component,
                        Path.GetRelativePath(root, manifest.File),
                        sourceLabel,
                        "manifest");
                }
            }

            files++;
        }

        if (manifestDeclarations > 0)
        {
            warnings.Add(
                $"{manifestDeclarations} package.json declaration(s) have version ranges and were " +
                "not treated as exact versions; a lockfile gives precise results.");
        }

        var logger = new RetireSharp.Reporting.Logger
        {
            Info = _ => { },
            Debug = _ => { },
            Warn = warnings.Add,
            Error = warnings.Add,
            Close = static () => { },
        };
        var options = new ScanOptions
        {
            Log = logger,
            Ext = "js,mjs,cjs",
            CacheDir = context.DataDirectory,
        };
        options.PruneDirectories.Add("node_modules");
        options.PruneDirectories.Add(".git");

        FileResolver.ScanJsFiles(
            root,
            options,
            onJsFile: file =>
            {
                if (context.CancellationToken.IsCancellationRequested || files >= MaxJsFiles)
                {
                    return;
                }

                ScanJsFile(repository, file, root, sourceLabel, components, deep, warnings);
                files++;
            },
            onBowerFile: file =>
            {
                ScanBowerFile(repository, file, root, sourceLabel, components, warnings);
                files++;
            },
            onFail: (_, message) =>
            {
                failures++;
                warnings.Add(message);
            });

        return (files, failures);
    }

    private static (int Files, int Failures) ScanSingleFile(
        ICheckContext context,
        RetireModel.Repository repository,
        string path,
        string sourceLabel,
        ConcurrentDictionary<string, ComponentHit> components,
        ConcurrentBag<string> warnings)
    {
        var name = Path.GetFileName(path);
        if (name.Equals("package.json", StringComparison.OrdinalIgnoreCase)
            || name.Equals("package-lock.json", StringComparison.OrdinalIgnoreCase)
            || name.Equals("npm-shrinkwrap.json", StringComparison.OrdinalIgnoreCase)
            || name.Equals("yarn.lock", StringComparison.OrdinalIgnoreCase)
            || name.Equals("pnpm-lock.yaml", StringComparison.OrdinalIgnoreCase)
            || name.Equals(".nvmrc", StringComparison.OrdinalIgnoreCase)
            || name.Equals(".node-version", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("Dockerfile", StringComparison.OrdinalIgnoreCase))
        {
            var failures = 0;
            foreach (var manifest in ManifestScanner.Scan(path, warnings.Add))
            {
                foreach (var package in manifest.Packages)
                {
                    if (package.DeclaredRange is not null)
                    {
                        continue;
                    }

                    foreach (var component in CheckPackage(repository, package.Name, package.Version))
                    {
                        AddComponent(components, component, Path.GetFileName(path), sourceLabel, "manifest");
                    }
                }
            }

            return (1, failures);
        }

        if (path.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".cjs", StringComparison.OrdinalIgnoreCase))
        {
            ScanJsFile(
                repository,
                path,
                Path.GetDirectoryName(path) ?? ".",
                sourceLabel,
                components,
                context.Settings.GetBool("deep", false),
                warnings);
            return (1, 0);
        }

        warnings.Add($"{path}: unsupported source file type; use a directory, .zip, JS or manifest.");
        return (0, 1);
    }

    private static void ScanJsFile(
        RetireModel.Repository repository,
        string file,
        string root,
        string sourceLabel,
        ConcurrentDictionary<string, ComponentHit> components,
        bool deep,
        ConcurrentBag<string> warnings)
    {
        try
        {
            var info = new FileInfo(file);
            if (info.Length > MaxFileBytes)
            {
                warnings.Add($"Skipped oversized JavaScript file: {file}");
                return;
            }

            var relative = Path.GetRelativePath(root, file);
            var found = RetireEngine.ScanFileName(file, repository, includeUri: true, warnings.Add);
            var content = info.Length > 0 ? SafeFile.ReadText(file) : string.Empty;
            if (found.Count == 0 && content.Length > 0)
            {
                found = RetireEngine.ScanFileContent(content, repository, warnings.Add);
            }

            if (deep && content.Length > 0)
            {
                try
                {
                    found.AddRange(DeepScanner.Scan(content, repository, TimeSpan.FromMinutes(2)));
                }
                catch (Exception error) when (error is not OutOfMemoryException)
                {
                    warnings.Add($"Deep scan failed for {file}: {error.Message}");
                }
            }

            foreach (var component in found)
            {
                AddComponent(components, component, relative, sourceLabel, "javascript");
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            warnings.Add($"Could not read {file}: {error.Message}");
        }
    }

    private static void ScanBowerFile(
        RetireModel.Repository repository,
        string file,
        string root,
        string sourceLabel,
        ConcurrentDictionary<string, ComponentHit> components,
        ConcurrentBag<string> warnings)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(file));
            var rootElement = document.RootElement;
            if (rootElement.ValueKind != JsonValueKind.Object
                || !rootElement.TryGetProperty("version", out var version)
                || version.ValueKind != JsonValueKind.String
                || version.GetString() is not { Length: > 0 } value)
            {
                return;
            }

            var name = rootElement.TryGetProperty("name", out var nameValue)
                ? nameValue.GetString() ?? "undefined"
                : "undefined";
            foreach (var component in CheckPackage(repository, name, value))
            {
                AddComponent(
                    components,
                    component,
                    Path.GetRelativePath(root, file),
                    sourceLabel,
                    "manifest");
            }
        }
        catch (JsonException error)
        {
            warnings.Add($"Could not parse {file}: {error.Message}");
        }
    }

    private static List<RetireModel.Component> CheckPackage(
        RetireModel.Repository repository,
        string name,
        string version)
    {
        var results = RetireEngine.Check(name, version, repository);
        if (results.Any(component => component.Vulnerabilities is { Count: > 0 }))
        {
            return results;
        }

        var mapped = repository.Entries.FirstOrDefault(entry =>
            string.Equals(entry.NpmName, name, StringComparison.OrdinalIgnoreCase));
        if (mapped is null)
        {
            return results;
        }

        var byRetireName = RetireEngine.Check(mapped.Name, version, repository);
        return byRetireName.Any(component => component.Vulnerabilities is { Count: > 0 })
            ? byRetireName
            : results;
    }

    private static void AddComponent(
        ConcurrentDictionary<string, ComponentHit> components,
        RetireModel.Component component,
        string file,
        string source,
        string origin)
    {
        var key = $"{component.Name}|{component.Version}|{file}";
        components.TryAdd(key, new ComponentHit(component, file, source, origin));
    }

    private static int ExtractZip(string zipPath, string destination, ConcurrentBag<string> warnings)
    {
        var failures = 0;
        long total = 0;
        var entries = 0;
        var root = Path.GetFullPath(destination) + Path.DirectorySeparatorChar;

        Directory.CreateDirectory(destination);
        using var archive = ZipFile.OpenRead(zipPath);
        foreach (var entry in archive.Entries)
        {
            if (string.IsNullOrEmpty(entry.Name))
            {
                continue;
            }

            if (++entries > MaxArchiveEntries)
            {
                throw new InvalidDataException($"Archive has more than {MaxArchiveEntries} entries.");
            }

            if (entry.Length > MaxArchiveBytes || total + entry.Length > MaxArchiveBytes)
            {
                throw new InvalidDataException($"Archive expands beyond {MaxArchiveBytes / 1024 / 1024} MB.");
            }

            // Unix symlink bit; never materialise symlinks from an untrusted archive.
            if (((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000)
            {
                warnings.Add($"Skipped symlink in archive: {entry.FullName}");
                continue;
            }

            var relative = entry.FullName.Replace('\\', '/');
            if (relative.StartsWith('/')
                || relative.Contains("../", StringComparison.Ordinal)
                || relative.Contains("..\\", StringComparison.Ordinal))
            {
                warnings.Add($"Skipped unsafe archive entry: {entry.FullName}");
                failures++;
                continue;
            }

            var destinationPath = Path.GetFullPath(Path.Combine(destination, relative));
            if (!destinationPath.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                warnings.Add($"Skipped archive entry outside destination: {entry.FullName}");
                failures++;
                continue;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
            try
            {
                entry.ExtractToFile(destinationPath, overwrite: true);
                total += entry.Length;
            }
            catch (IOException error)
            {
                warnings.Add($"Could not extract {entry.FullName}: {error.Message}");
                failures++;
            }
        }

        return failures;
    }

    private static string CreateTemporaryRoot()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "aetheleye-source",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static string Purl(RetireModel.Component component)
    {
        var basePurl = component.BasePurl;
        if (string.IsNullOrWhiteSpace(basePurl))
        {
            basePurl = "pkg:npm/" + (component.NpmName ?? component.Name);
        }

        var at = basePurl.LastIndexOf('@');
        return at > basePurl.LastIndexOf('/')
            ? basePurl
            : basePurl + "@" + component.Version;
    }

    private static Confidence ConfidenceFor(string? detection) => detection?.ToLowerInvariant() switch
    {
        "hash" or "lockfile" or "node_modules" or "manifest" => Confidence.High,
        "filename" or "uri" => Confidence.High,
        "filecontent" or "filecontentreplace" => Confidence.Medium,
        _ => Confidence.Medium,
    };

    private static IReadOnlyList<string> EvaluateLicenses(
        RetireModel.Repository repository,
        RetireModel.Component component)
    {
        var entry = repository.Find(component.Name);
        if (entry?.Licenses is not { Count: > 0 })
        {
            return [];
        }

        try
        {
            return LicenseEvaluator.Evaluate(entry.Licenses, component.Version);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            return [];
        }
    }

    private static string Describe(RetireModel.Vulnerability vulnerability)
    {
        if (!string.IsNullOrWhiteSpace(vulnerability.Details))
        {
            return vulnerability.Details;
        }

        if (vulnerability.Identifiers?.Summary is { Length: > 0 } summary)
        {
            return summary;
        }

        return string.Join("; ", vulnerability.Info);
    }

    private static Severity MapSeverity(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "critical" => Severity.Critical,
        "high" => Severity.High,
        "medium" => Severity.Medium,
        "low" => Severity.Low,
        _ => Severity.Medium,
    };

    private sealed record ComponentHit(
        RetireModel.Component Component,
        string File,
        string Source,
        string Origin);
}
