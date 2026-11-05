using System.Text.Json;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Engine;
using AethelEye.Core.Http;
using AethelEye.Core.Models;
using AethelEye.Core.Reporting;
using AethelEye.Modules;
using AethelEye.Modules.Advisories;
using AethelEye.Modules.Browser;
using AethelEye.Modules.Technology;
using RetireSharp.Advisories;

namespace AethelEye.Cli;

internal static class Program
{
    private const string Version = AethelEye.Core.VersionInfo.Current;

    private const string Usage = """
        AETHELeye - Omniscient Reconnaissance Framework for the Modern Era

        Usage:
          aetheleye --update db [--db <path>]
          aetheleye --url <domain/url> [--url <domain/url> ...] [--mode <modes>] [options]
          aetheleye --src <dir|zip|file> [--src ...] [--mode source] [options]
          aetheleye --url <domain/url> --src <dir|zip> --mode all [options]
          aetheleye <domain|url|engagement.json> [options]   (legacy shorthand)
          aetheleye init [name]
          aetheleye checks

        Modes (comma separated):
          all              all checks (default); adds source when --src is present
          web              domain + target checks: dns, rdap, subdomains, social,
                           robots, sitemap, cms, api, waf, technology, security,
                           exposure, hidden-paths
          technology       Wappalyzer/Retire + CMS + default-page/API/debug exposure
                           (same as fingerprint,cms,exposure)
          fingerprint      Runtime technology detection only (no CMS/exposure)
          cms              CMS fingerprint only (WordPress/Joomla/Drupal/Magento)
          exposure         Default admin/API/Tomcat/Swagger/Actuator/debug pages only
          external         github, leaked-account
          source           local source/dependency scan

        Any check ID can also be used as a mode token, for example:
          --mode dns,rdap,subdomains,social
          --mode security,sitemap,backup

        Defaults:
          - Online mode: every selected check runs.
          - --offline: limited scan. GitHub/leak APIs and live feeds are skipped; target,
            source and advisory-database checks still work.
          - Writes results/<name>-<timestamp>.txt. Use --format json for JSON.
          - Run "aetheleye --update db" once to build the local SQLite advisory database.

        Options:
          --url <value>       Web target. Repeatable, and comma-separated is accepted.
                              A bare IPv4 range/CIDR/wildcard is expanded too.
          --ip-range <value>  IPv4 range, CIDR or wildcard: 10.0.0.1-10.0.0.20,
                              10.0.0.0/24, 10.0.0.*. Repeatable/comma-separated.
          --path <list>       Application path(s) added to every range host and to
                              root URLs: --path /abc,/xyz. Repeatable.
          --target-file <f>   One URL, IP, CIDR or range per line (# comments allowed).
          --src <path>        Local source directory, .zip (extracted locally), .js or manifest. Repeatable.
          --mode <list>       Check mode(s), default: all
          --update db         Download OSV/Retire/KEV/EPSS feeds into the SQLite database.
          --db <path>         Database file (default: <data dir>/aetheleye.db).
          --offline           Offline scan. No GitHub/leak APIs or live feeds.
          --chromium [path]   Enable headless Chromium; optionally give the executable path.
          --timeout <sec>     HTTP and headless navigation timeout (default: 20).
          --proxy <url>       HTTP(S) proxy for the target and headless Chromium,
                              for example ipproxy:8080 or http://ipproxy:8080.
                              A bare host:port is normalized to http://host:port.
          --evasion           Low-and-slow, browser-like request profile for authorized
                              WAF/IDS testing (not a guarantee of bypass).
          --concurrency <n>   Parallel targets (default: 1).
          --random-agent      Rotate a browser User-Agent for every target request.
          --authen <file>     Raw headers copied from Burp (Cookie/Authorization) for an
                              authenticated scan. Values are never written to reports.
          --name-token <name> Extra backup filename stem (repeatable/comma-separated).
                              Path tokens are derived automatically; an IP is never split.
          --allow-uat         UAT/lab preset: allow private/loopback hosts, self-signed TLS
                              and non-standard ports. Does not bypass scope or authorization.
                              Also restricts requests to the target origin (no other host,
                              subdomain or port).
          --same-origin-only  Restrict HTTP and headless-browser requests to the target origin
                              (no third-party CDN/analytics traffic).
          --allow-third-party Opt out of the strict same-origin policy under --allow-uat.
          --osint-domain <d>  Public brand domain for github/leaked-accounts when the scan
                              target is an internal host such as an IP or UAT name.
          --out <dir>         Output directory (default: results)
          --format <list>     text,json (default: text)
          --exploited         Keep only High/Critical findings in the report.
          --deep              AST-based JavaScript detection (slower, RetireSharp deep scan).
          --verbose           Show check details, evidence and internal HTTP retries
          --json-log          Emit structured JSON log lines (for SIEM / pipeline ingestion)
          --no-banner         Suppress the ASCII banner (useful in CI)
          --version           Show version
          -h, --help          Show this help

        Examples:
          aetheleye --update db
          aetheleye --url example.com --mode all
          aetheleye --url example.com --mode web
          aetheleye --url example.com --mode dns,rdap,subdomains,social
          aetheleye --url example.com --mode technology --chromium --timeout 30
          aetheleye --url example.com --mode external --offline
          aetheleye --url http://10.0.0.5/abc --url http://10.0.0.5/xyz --mode all --allow-uat
          aetheleye --ip-range 10.0.0.1-10.0.0.20 --path /abc,/xyz --mode web --allow-uat --concurrency 4
          aetheleye --src C:\downloads\abc.zip --mode source
          aetheleye --url example.com --src C:\downloads\abc.zip --mode all --format json

        Only scan systems you own or are explicitly authorized to test.
        """;

    private static async Task<int> Main(string[] args)
    {
        try
        {
            var options = CliOptions.Parse(args);
            if (options.Help || options.Command == "help")
            {
                if (!options.NoBanner)
                {
                    Banner.Show();
                }

                Console.Out.WriteLine(Usage);
                return 0;
            }

            if (options.Command is "banner" or "about")
            {
                Banner.Show();
                Console.Out.WriteLine("AETHELeye - Omniscient Reconnaissance Framework for the Modern Era");
                Console.Out.WriteLine("Run 'aetheleye --help' for usage.");
                return 0;
            }

            if (options.Command == "version")
            {
                if (!options.NoBanner)
                {
                    Banner.Show();
                }

                Console.Out.WriteLine($"aetheleye {Version}");
                return 0;
            }

            if (options.Command == "checks")
            {
                PrintChecks();
                return 0;
            }

            if (options.Command == "init")
            {
                return Init(options);
            }

            if (options.UpdateTarget is not null)
            {
                return await UpdateDatabaseAsync(options);
            }

            return await ScanAsync(options);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Cancelled.");
            return 130;
        }
        catch (Exception error) when (error is ArgumentException
                                          or IOException
                                          or JsonException
                                          or HttpRequestException
                                          or InvalidOperationException
                                          or UnauthorizedAccessException
                                          or AggregateException
                                          or SqliteException)
        {
            Console.Error.WriteLine("error: " + error.Message);
            return 2;
        }
    }

    private static async Task<int> ScanAsync(CliOptions options)
    {
        if (!options.NoBanner)
        {
            Banner.Show();
        }

        var settings = AppSettingsLoader.Load();
        var engagement = BuildEngagement(options);
        if (engagement is null)
        {
            Console.Out.WriteLine(Usage);
            return 0;
        }

        AppSettingsLoader.Apply(engagement, settings.AethelEye);

        // Online by default; --offline forces an offline scan.
        if (options.Offline)
        {
            engagement.Offline = true;
        }

        if (options.AllowUat)
        {
            engagement.Scope.AllowPrivateAddresses = true;
            engagement.Scope.AllowNonStandardPorts = true;
            engagement.Http.Insecure = true;
        }

        if (!string.IsNullOrWhiteSpace(options.OsintDomain))
        {
            engagement.OsintDomain = options.OsintDomain.Trim();
        }

        if (options.Headless)
        {
            engagement.Browser.Headless = true;
        }

        if (options.SameOriginOnly)
        {
            engagement.Browser.SameOriginOnly = true;
        }
        else if (options.AllowUat && !options.AllowThirdParty)
        {
            // A UAT scan is a single-target engagement: do not let the HTTP client or browser
            // contact another host, subdomain or port unless the operator opts in.
            engagement.Browser.SameOriginOnly = true;
        }

        if (!string.IsNullOrWhiteSpace(options.ChromiumPath))
        {
            engagement.Browser.ChromiumPath = options.ChromiumPath;
        }

        if (options.TimeoutSeconds is { } timeout)
        {
            engagement.Http.TimeoutSeconds = timeout;
            engagement.Browser.TimeoutSeconds = timeout;
        }

        // The hidden-path catalog is intentionally broad. At the default 5 requests/second a
        // full pass needs more than the 120-second engine default, so give this one check a
        // longer budget unless the engagement file already set one.
        engagement.SettingsFor("hidden-paths").TimeoutSeconds ??= 300;

        // CLI overrides appsettings/environment. Normalize here so both the .NET client and
        // Chromium receive a real proxy URL; "ipproxy:8080" alone parses as a URI scheme.
        if (!string.IsNullOrWhiteSpace(options.Proxy))
        {
            engagement.Http.Proxy = ProxyUrl.Normalize(options.Proxy);
        }

        if (options.Evasion)
        {
            EvasionProfile.Apply(engagement.Http);
        }

        if (options.Concurrency is { } concurrency)
        {
            engagement.Engine.TargetConcurrency = concurrency;
        }

        if (options.RandomAgent)
        {
            engagement.Http.RandomUserAgent = true;
        }

        if (!string.IsNullOrWhiteSpace(options.AuthFile))
        {
            var headers = AuthHeaderFile.Load(options.AuthFile);
            foreach (var (name, value) in headers)
            {
                engagement.Http.Headers[name] = value;
            }
        }

        if (options.NameTokens.Count > 0)
        {
            var names = JsonSerializer.SerializeToElement(options.NameTokens);
            engagement.SettingsFor("backup").Options["names"] = names;
            engagement.SettingsFor("hidden-paths").Options["names"] = names;
        }

        if (options.Deep)
        {
            engagement.SettingsFor("technology").Options["deep"] =
                JsonSerializer.SerializeToElement(true);
            engagement.SettingsFor("source").Options["deep"] =
                JsonSerializer.SerializeToElement(true);
        }

        if (!string.IsNullOrWhiteSpace(options.OutputDirectory))
        {
            engagement.Output.Directory = options.OutputDirectory;
        }

        if (!string.IsNullOrWhiteSpace(options.Format))
        {
            engagement.Output.Formats = options.Format
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(NormalizeFormat)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        var dataDirectory = AppSettingsLoader.ResolveDataDirectory(settings.AethelEye);
        Directory.CreateDirectory(dataDirectory);
        engagement.AdvisoryDatabasePath = AdvisoryDatabaseStore.ResolvePath(
            dataDirectory,
            options.DatabasePath);

        var checks = SelectChecks(engagement, options);

        var log = new ConsoleLog(options.Verbose, jsonOutput: options.JsonLog);
        if (engagement.Offline)
        {
            log.Info("Offline mode: GitHub/leak APIs and live feeds are skipped.");
        }

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };

        var browserFetcher = engagement.Browser.Headless
            ? new ChromiumPageFetcher(engagement, log)
            : null;
        await using var orchestrator = new ScanOrchestrator(checks, log, browserFetcher);
        var report = await orchestrator.RunAsync(engagement, dataDirectory, cancellation.Token);
        if (options.Exploited)
        {
            FilterReport(report);
        }

        var written = await WriteReports(report, engagement);
        PrintSummary(report, written, engagement);
        if (options.Verbose)
        {
            PrintVerboseDetails(report);
        }

        return report.HasHighRisk ? 1 : 0;
    }

    private static string NormalizeFormat(string value) => value.Trim().ToLowerInvariant() switch
    {
        "json" => "json",
        "sarif" => "sarif",
        "text" or "txt" => "text",
        _ => throw new ArgumentException(
            $"Unsupported report format: {value}. Use text, json or sarif."),
    };

    private static Engagement? BuildEngagement(CliOptions options)
    {
        var urls = new List<string>(options.Urls);
        foreach (var file in options.TargetFiles)
        {
            urls.AddRange(EngagementLoader.ReadTargetFile(file));
        }

        if (urls.Count > 0 || options.Sources.Count > 0)
        {
            if (options.Inputs.Count > 0)
            {
                throw new ArgumentException(
                    "Use either positional input or --url/--src, not both.");
            }

            var sources = ValidateSources(options.Sources);
            return urls.Count > 0
                ? EngagementLoader.CreateOneOff(urls, sources, options.Paths)
                : EngagementLoader.CreateSourceOnly(sources);
        }

        if (options.Inputs.Count == 0)
        {
            return null;
        }

        if (options.Inputs.Count == 1 && IsEngagementFile(options.Inputs[0]))
        {
            return EngagementLoader.Load(options.Inputs[0]);
        }

        var legacyUrls = new List<string>();
        var legacySources = new List<string>();
        foreach (var input in options.Inputs)
        {
            if (LooksLikeLocalPath(input))
            {
                legacySources.Add(input);
            }
            else
            {
                legacyUrls.Add(input);
            }
        }

        var resolvedSources = ValidateSources(legacySources);
        return legacyUrls.Count > 0
            ? EngagementLoader.CreateOneOff(legacyUrls, resolvedSources, options.Paths)
            : EngagementLoader.CreateSourceOnly(resolvedSources);
    }

    private static IReadOnlyList<ICheck> SelectChecks(Engagement engagement, CliOptions options)
    {
        var checks = CheckCatalog.CreateAll();
        var known = checks.Select(check => check.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var hasSourceInput = engagement.Sources.Count > 0;
        var hasDomainTargets = engagement.Targets.Any(IsDomainTarget);
        var requested = CheckModes.Expand(
            options.Mode,
            engagement.Targets.Count > 0,
            hasSourceInput,
            hasDomainTargets);

        foreach (var id in requested)
        {
            if (!known.Contains(id))
            {
                Console.Error.WriteLine(
                    $"warning: unknown check '{id}'. Use 'aetheleye checks' to list check IDs.");
            }
        }

        if (requested.Contains("source") && !hasSourceInput)
        {
            throw new ArgumentException(
                "The source check needs --src <dir|zip|file> or a 'sources' entry " +
                "in the engagement file.");
        }

        if (requested.Any(id => id != "source") && engagement.Targets.Count == 0)
        {
            throw new ArgumentException(
                "Web checks need --url <domain/url>. A local --src path only supports --mode source.");
        }

        var selected = checks
            .Where(check => requested.Contains(check.Id))
            .ToList();

        if (selected.Count == 0)
        {
            throw new ArgumentException(
                $"No checks selected. Modes: {CheckModes.Usage}.");
        }

        return selected;
    }

    /// <summary>
    /// True when the target string contains a hostname. An IP, CIDR or IP range has no
    /// subdomains, so domain-only checks are dropped for those targets.
    /// </summary>
    private static bool IsDomainTarget(string value)
    {
        if (System.Net.IPAddress.TryParse(value.Trim('[', ']'), out _))
        {
            return false;
        }

        if (Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return !System.Net.IPAddress.TryParse(uri.Host.Trim('[', ']'), out _);
        }

        var slash = value.IndexOf('/');
        if (slash > 0 && System.Net.IPAddress.TryParse(value[..slash], out _))
        {
            return false;
        }

        var dash = value.IndexOf('-');
        return dash <= 0
               || !System.Net.IPAddress.TryParse(value[..dash], out _)
               || !System.Net.IPAddress.TryParse(value[(dash + 1)..], out _);
    }

    private static List<string> ValidateSources(IEnumerable<string> values)
    {
        var sources = new List<string>();
        foreach (var value in values)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            var full = Path.GetFullPath(value);
            if (!File.Exists(full) && !Directory.Exists(full))
            {
                throw new FileNotFoundException($"Source path not found: {value}", value);
            }

            sources.Add(full);
        }

        return sources
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static bool LooksLikeLocalPath(string value)
    {
        if (Directory.Exists(value) || File.Exists(value))
        {
            return true;
        }

        if (value.StartsWith('.') || value.StartsWith('~') || value.Contains('\\'))
        {
            return true;
        }

        if (value.Length >= 2 && char.IsLetter(value[0]) && value[1] == ':')
        {
            return true;
        }

        return value.EndsWith('/') || value.EndsWith('\\');
    }

    private static bool IsEngagementFile(string path)
    {
        if (!File.Exists(path) || !path.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (property.NameEquals("targets")
                    || property.NameEquals("Targets")
                    || property.NameEquals("scope")
                    || property.NameEquals("Scope")
                    || property.NameEquals("checks")
                    || property.NameEquals("Checks"))
                {
                    return true;
                }
            }
        }
        catch (JsonException)
        {
            return false;
        }

        return false;
    }

    private static async Task<List<string>> WriteReports(ScanReport report, Engagement engagement)
    {
        var directory = string.IsNullOrWhiteSpace(engagement.Output.Directory)
            ? "results"
            : engagement.Output.Directory;

        var configuredName = string.IsNullOrWhiteSpace(engagement.Output.FileName)
            || engagement.Output.FileName == "aetheleye-report"
            ? engagement.Name
            : engagement.Output.FileName;

        var baseName = Sanitize($"{configuredName}-{DateTime.Now:yyyyMMdd-HHmmss}");
        var formats = engagement.Output.Formats.Count > 0
            ? engagement.Output.Formats
            : ["text"];

        var written = new List<string>();
        foreach (var format in formats)
        {
            var writer = ReportWriterFactory.Create(format);
            var path = Path.Combine(directory, baseName + writer.Extension);
            await writer.WriteAsync(report, path);
            written.Add(path);
        }

        return written;
    }

    private static void PrintSummary(
        ScanReport report,
        IReadOnlyList<string> written,
        Engagement engagement)
    {
        Console.Out.WriteLine();
        Console.Out.WriteLine($"Targets: {report.Targets.Count}");
        Console.Out.WriteLine(
            $"Findings: {report.FindingCount} " +
            $"(critical {report.CountBySeverity(Severity.Critical)}, " +
            $"high {report.CountBySeverity(Severity.High)}, " +
            $"medium {report.CountBySeverity(Severity.Medium)}, " +
            $"low {report.CountBySeverity(Severity.Low)}, " +
            $"info {report.CountBySeverity(Severity.Info)})");
        if (engagement.Offline)
        {
            Console.Out.WriteLine("Mode: offline (no GitHub/leak APIs or live feeds)");
        }

        if (engagement.Http.Evasion)
        {
            Console.Out.WriteLine("Profile: evasion (low-and-slow, browser-like requests)");
        }

        if (engagement.Browser.Headless)
        {
            Console.Out.WriteLine("Browser: headless Chromium runtime detection enabled");
        }

        if (!string.IsNullOrWhiteSpace(engagement.AdvisoryDatabasePath))
        {
            var state = File.Exists(engagement.AdvisoryDatabasePath) ? "found" : "not found";
            Console.Out.WriteLine($"Advisory DB: {engagement.AdvisoryDatabasePath} ({state})");
        }

        foreach (var path in written)
        {
            Console.Out.WriteLine("Report: " + Path.GetFullPath(path));
        }
    }

    /// <summary>Keeps only High/Critical findings, for a prioritized attack-surface report.</summary>
    private static void FilterReport(ScanReport report)
    {
        foreach (var target in report.Targets)
        {
            target.Checks.RemoveAll(check =>
            {
                var keep = check.Findings
                    .Where(finding => finding.Severity >= Severity.High)
                    .ToList();
                check.Findings.Clear();
                check.Findings.AddRange(keep);
                if (keep.Count > 0)
                {
                    check.Status = CheckStatus.Findings;
                }

                return keep.Count == 0;
            });
        }
    }

    private static void PrintVerboseDetails(ScanReport report)
    {
        Console.Out.WriteLine();
        Console.Out.WriteLine("Check details");
        Console.Out.WriteLine(new string('-', 78));
        foreach (var targetReport in report.Targets)
        {
            foreach (var check in targetReport.Checks)
            {
                Console.Out.WriteLine(
                    $"[{check.CheckId}] {check.CheckName}: {check.Status} " +
                    $"({check.Findings.Count} finding(s), {check.Duration.TotalSeconds:0.0}s)");
                if (!string.IsNullOrWhiteSpace(check.Summary))
                {
                    Console.Out.WriteLine("  " + check.Summary);
                }

                foreach (var note in check.Notes)
                {
                    Console.Out.WriteLine("  note: " + note);
                }

                foreach (var finding in check.Findings)
                {
                    Console.Out.WriteLine($"  [{finding.Severity.ToLabel()}] {finding.Title}");
                    foreach (var (key, value) in finding.Evidence)
                    {
                        if (value.Length > 0)
                        {
                            Console.Out.WriteLine($"    {key}: {value}");
                        }
                    }
                }
            }
        }
    }

    private static async Task<int> UpdateDatabaseAsync(CliOptions options)
    {
        if (!string.Equals(options.UpdateTarget, "db", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"Unknown --update target '{options.UpdateTarget}'. Use: --update db.");
        }

        if (options.Offline)
        {
            throw new ArgumentException(
                "--update db needs network access. Build the database on a connected machine " +
                "and copy the .db file to the isolated machine.");
        }

        var settings = AppSettingsLoader.Load();
        var dataDirectory = AppSettingsLoader.ResolveDataDirectory(settings.AethelEye);
        var path = AdvisoryDatabaseStore.ResolvePath(dataDirectory, options.DatabasePath);
        var proxy = settings.AethelEye.Proxy;
        if (string.IsNullOrWhiteSpace(proxy))
        {
            proxy = Environment.GetEnvironmentVariable("HTTPS_PROXY")
                ?? Environment.GetEnvironmentVariable("HTTP_PROXY");
        }

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };

        Console.Out.WriteLine("Updating advisory database: " + Path.GetFullPath(path));
        var success = await AdvisoryDatabaseStore.UpdateAsync(
            path,
            new UpdateOptions
            {
                Http = new RetireSharp.Net.HttpSettings(
                    proxy,
                    options.AllowUat,
                    null,
                    Offline: false),
                Log = message => Console.Out.WriteLine(message),
                Warn = message => Console.Error.WriteLine("warning: " + message),
            },
            cancellation.Token);

        Console.Out.WriteLine(success
            ? $"Database ready: {Path.GetFullPath(path)}"
            : $"Database was written with warnings: {Path.GetFullPath(path)}");

        Console.Out.WriteLine("Updating Wappalyzer fingerprints...");
        var fingerprintPath = WappalyzerFingerprintStore.DefaultPath(dataDirectory);
        await WappalyzerFingerprintStore.UpdateAsync(
            fingerprintPath,
            proxy,
            options.AllowUat,
            message => Console.Out.WriteLine(message),
            message => Console.Error.WriteLine("warning: " + message),
            cancellation.Token);

        Console.Out.WriteLine("Copy the database and fingerprint file to an isolated machine if needed.");
        return success ? 0 : 1;
    }

    private static int Init(CliOptions options)
    {
        var name = options.Inputs.Count > 0 ? options.Inputs[0] : "engagement";
        var engagementPath = Path.Combine(Directory.GetCurrentDirectory(), "engagement.json");
        var appSettingsPath = Path.Combine(Directory.GetCurrentDirectory(), "appsettings.json");

        if (File.Exists(engagementPath))
        {
            Console.Error.WriteLine($"error: {engagementPath} already exists; not overwriting it.");
            return 2;
        }

        var engagement = new Engagement
        {
            Name = name,
            Client = "Client name",
            AuthorizedBy = "Written authorization reference",
            Notes = "Review scope before scanning. Only test systems you are authorized to test.",
            Targets = ["https://example.com"],
            Scope = new ScopeSettings
            {
                AllowedHosts = ["example.com"],
            },
        };

        EngagementLoader.Save(engagement, engagementPath);

        if (!File.Exists(appSettingsPath))
        {
            var settings = new AppSettings
            {
                AethelEye = new AethelEyeSettings
                {
                    GitHubToken = string.Empty,
                    BreachDirectoryApiKey = string.Empty,
                    GitleaksPath = string.Empty,
                    DataDirectory = string.Empty,
                },
            };
            File.WriteAllText(
                appSettingsPath,
                JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }) +
                Environment.NewLine);
        }

        Console.Out.WriteLine($"Created {engagementPath}");
        Console.Out.WriteLine($"Created {appSettingsPath}");
        Console.Out.WriteLine();
        Console.Out.WriteLine("Next: edit the target and scope, then run:");
        Console.Out.WriteLine("  aetheleye engagement.json");
        return 0;
    }

    private static void PrintChecks()
    {
        foreach (var check in CheckCatalog.CreateAll())
        {
            Console.Out.WriteLine($"{check.Id,-16} {check.Name}");
            Console.Out.WriteLine($"{"",-16} {check.Description}");
        }
    }

    private static string Sanitize(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var characters = value.Select(character =>
            invalid.Contains(character) || character is ' ' or ':' or '/' ? '-' : character);
        return new string(characters.ToArray());
    }
}
