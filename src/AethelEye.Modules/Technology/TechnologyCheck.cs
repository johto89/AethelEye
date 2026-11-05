using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;
using AethelEye.Modules.Advisories;
using RetireSharp.Advisories;
using RetireSharp.Engine;
using RetireSharp.Query;
using RetireSharp.Web;
using WappalyzerSharp;
using WappalyzerSharp.Headless;
using WappalyzerSharp.Matching;
using WappalyzerSharp.Models;
using RetireModel = RetireSharp.Model;

namespace AethelEye.Modules.Technology;

/// <summary>
/// Runs WappalyzerSharp over headers/body, optionally with headless Chromium runtime evidence,
/// then checks referenced JavaScript and inline/runtime scripts with RetireSharp. The framework
/// owns HTTP, scope and rate limits; the browser is used only for the authorized target page.
/// </summary>
public sealed class TechnologyCheck : ICheck, IAsyncDisposable
{
    private static readonly Lazy<Wappalyzer> WappalyzerEngine = new(
        () => Wappalyzer.Create(new WappalyzerOptions { ScanBudget = TimeSpan.FromSeconds(30) }),
        LazyThreadSafetyMode.ExecutionAndPublication);

    private static readonly ConcurrentDictionary<string, Wappalyzer> FingerprintEngines =
        new(StringComparer.OrdinalIgnoreCase);

    private static Wappalyzer GetEngine(ICheckContext context)
    {
        var file = context.Settings.GetString("fingerprints");
        if (string.IsNullOrWhiteSpace(file))
        {
            var downloaded = WappalyzerFingerprintStore.DefaultPath(context.DataDirectory);
            if (File.Exists(downloaded))
            {
                file = downloaded;
            }
        }

        if (string.IsNullOrWhiteSpace(file))
        {
            return WappalyzerEngine.Value;
        }

        try
        {
            return FingerprintEngines.GetOrAdd(
                Path.GetFullPath(file),
                path => Wappalyzer.FromFile(
                    path,
                    loadEmbedded: true,
                    supersede: true,
                    new WappalyzerOptions
                    {
                        ScanBudget = TimeSpan.FromSeconds(30),
                        MaxBodyBytes = context.Engagement.Http.MaxBodyBytes,
                    }));
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            context.Log.Warn(
                $"Wappalyzer fingerprint file could not be loaded ({file}): {error.Message}");
            return WappalyzerEngine.Value;
        }
    }

    private readonly SemaphoreSlim _browserGate = new(1, 1);
    private ChromiumBrowser? _browser;
    private bool _browserUnavailable;

    public string Id => "technology";

    public string Name => "Technology fingerprint";

    public string Description =>
        "Identifies web technologies (WappalyzerSharp) and vulnerable JavaScript libraries " +
        "(RetireSharp), with optional headless Chromium runtime evidence.";

    public int Order => 20;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        var headless = context.Settings.GetBool("headless", context.Engagement.Browser.Headless);

        HttpResponseData? page = null;
        Exception? httpError = null;
        BrowserCapture? capture = null;

        if (headless)
        {
            // Go straight to the browser. The HTTP client may be tarpitted by the target, and the
            // page cache is browser-backed too, so fetching here would render the page twice.
            capture = await TryCaptureAsync(context, null, result);
        }

        if (capture is null)
        {
            try
            {
                page = await context.Pages.GetAsync(context.Target.BaseUri, context.CancellationToken);
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                if (!headless)
                {
                    throw;
                }

                httpError = error;
            }
        }

        if (page is null && capture is null)
        {
            throw httpError ?? new HttpRequestException("The target did not return a response.");
        }

        var finalUri = capture?.FinalUri ?? page!.FinalUri;
        var headers = capture?.Headers ?? page!.Headers;
        var body = capture?.Body is { Length: > 0 } capturedBody
            ? capturedBody
            : page?.Body ?? [];
        var engine = GetEngine(context);
        var scan = engine.ScanWithTitle(headers, body);
        var technologies = scan.Technologies;
        if (capture is not null)
        {
            technologies = [.. technologies, .. capture.Technologies];
            result.Metrics["headless"] = "true";
            result.Metrics["runtimeTechnologies"] = capture.Technologies.Count.ToString();
            result.Metrics["browserUrl"] = capture.FinalUri.ToString();
            result.Metrics["browserStatus"] = capture.StatusCode.ToString();
            result.Metrics["browserBodyBytes"] = capture.Body.Length.ToString();
            if (httpError is not null)
            {
                result.Notes.Add(
                    $"HTTP client failed ({httpError.Message}); the headless browser got a response.");
            }

            if (capture.Headers.Count == 0 && capture.Body.Length == 0)
            {
                result.Notes.Add(
                    "The headless browser returned no document headers or body; the target may " +
                    "have blocked the browser or redirected to an empty page.");
            }

            if (capture.Partial)
            {
                result.Notes.Add("The headless page did not finish loading within the timeout; results are partial.");
            }

            if (capture.Error is not null)
            {
                result.Notes.Add("Runtime collection: " + capture.Error);
            }
        }
        else
        {
            result.Metrics["headless"] = "false";
        }

        var orderedTechnologies = technologies.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToList();
        result.Metrics["technologies"] = orderedTechnologies.Count.ToString();
        result.Metrics["pageTitle"] = scan.Title;
        if (scan.BudgetExceeded)
        {
            result.Notes.Add("Wappalyzer scan budget was exceeded; some fingerprints were skipped.");
        }

        var pageHtml = IsHtml(headers, body) ? Encoding.UTF8.GetString(body) : string.Empty;
        var hints = HtmlExtractor.Parse(pageHtml, 0);
        var technologyDetails = new List<string>();
        foreach (var technology in orderedTechnologies)
        {
            var name = technology.Split(':')[0];
            if (engine.CompiledFingerprints.TryGetValue(name, out var fingerprint))
            {
                var info = Wappalyzer.AppInfoFromFingerprint(fingerprint);
                technologyDetails.Add(
                    $"{name} | cpe={info.Cpe} | categories={string.Join(", ", info.Categories)}" +
                    (info.Website.Length > 0 ? $" | {info.Website}" : string.Empty));
            }
        }

        var favicon = await TryFaviconAsync(context, finalUri, result);
        if (favicon is not null)
        {
            result.Metrics["faviconMd5"] = favicon.Value.Md5;
            result.Metrics["faviconSha256"] = favicon.Value.Sha256;
            result.Metrics["faviconBytes"] = favicon.Value.Bytes.ToString();
        }

        if (orderedTechnologies.Count > 0)
        {
            result.Findings.Add(new Finding
            {
                CheckId = Id,
                Title = "Web technologies detected",
                Description =
                    "Passive and runtime fingerprinting identified the technologies below. " +
                    "This is inventory information, not a vulnerability.",
                Severity = Severity.Info,
                Confidence = Confidence.High,
                Target = context.Target.BaseUrl,
                Url = finalUri.ToString(),
                Evidence = new Dictionary<string, string>
                {
                    ["technologies"] = string.Join(", ", orderedTechnologies),
                    ["technologyDetails"] = string.Join("; ", technologyDetails.Take(50)),
                    ["pageTitle"] = scan.Title,
                    ["headless"] = capture is not null ? "true" : "false",
                    ["server"] = Header(headers, "Server"),
                    ["poweredBy"] = Header(headers, "X-Powered-By"),
                    ["cookies"] = Truncate(Header(headers, "Set-Cookie"), 500),
                    ["metaGenerator"] = hints.Generator ?? string.Empty,
                    ["ngVersion"] = hints.NgVersion ?? string.Empty,
                    ["nextData"] = hints.HasNextData ? "true" : "false",
                    ["baseHref"] = hints.BaseHref ?? string.Empty,
                    ["faviconMd5"] = favicon?.Md5 ?? string.Empty,
                    ["faviconSha256"] = favicon?.Sha256 ?? string.Empty,
                    ["faviconBytes"] = favicon?.Bytes.ToString() ?? string.Empty,
                },
            });
        }

        var databasePath = AdvisoryDatabaseStore.ResolvePath(
            context.DataDirectory,
            context.Engagement.AdvisoryDatabasePath);
        using var database = AdvisoryDatabaseStore.OpenIfExists(databasePath, context.Log);
        var repository = database?.LoadRepository();
        if (repository is null)
        {
            var repositoryUrl = context.Settings.GetString("retireRepository");
            repository = await RetireRepositoryStore.LoadAsync(
                context.ExternalHttp,
                context.Log,
                context.DataDirectory,
                repositoryUrl,
                context.Engagement.Offline,
                context.CancellationToken);
        }

        if (repository is null)
        {
            result.Notes.Add(context.Engagement.Offline
                ? "Offline mode: no advisory database or cached Retire repository; " +
                  "JavaScript library versions were not checked. Run 'aetheleye --update db' " +
                  "on a connected machine and copy the database."
                : "Retire repository was unavailable; JavaScript library versions were not checked. " +
                  "Run 'aetheleye --update db' for a local advisory database.");
            result.Summary = $"Detected {orderedTechnologies.Count} technology item(s); Retire check skipped.";
            result.Status = context.Engagement.Offline ? CheckStatus.NoRisk : CheckStatus.Partial;
            return result;
        }

        Focus.ApplyExtractors(repository);
        var focusText = context.Settings.GetString("focus");
        var focus = Focus.TryParseGroup(focusText, out var focusGroup)
            ? focusGroup
            : FocusGroup.All;

        var warnings = new ConcurrentBag<string>();
        void Warn(string message) => warnings.Add(message);

        var components = new ConcurrentDictionary<string, (RetireModel.Component Component, string File)>(
            StringComparer.OrdinalIgnoreCase);

        var maxScripts = Math.Clamp(context.Settings.GetInt("maxScripts", 40), 0, 200);
        var maxInline = Math.Clamp(context.Settings.GetInt("maxInlineScripts", 20), 0, 100);
        var deep = context.Settings.GetBool("deep", false);
        var documents = new List<(string File, string Content)>();

        if (IsHtml(headers, body))
        {
            var html = Encoding.UTF8.GetString(body);
            var document = HtmlExtractor.Parse(html, maxScripts);

            foreach (var inline in document.InlineScripts.Take(maxInline))
            {
                documents.Add(($"{finalUri}#inline-{documents.Count + 1}", inline));
            }

            var scriptUris = new List<Uri>();
            foreach (var source in document.ScriptUrls.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!Uri.TryCreate(finalUri, source, out var script))
                {
                    continue;
                }

                // CDN URLs often contain the version, so match the URL before spending a request.
                var text = script.ToString();
                var matches = RetireEngine.ScanUri(text, repository, Warn);
                foreach (var component in RetireEngine.ScanFileName(script.AbsolutePath, repository, warn: Warn))
                {
                    if (!matches.Exists(existing =>
                            existing.Name == component.Name && existing.Version == component.Version))
                    {
                        matches.Add(component);
                    }
                }

                if (matches.Count > 0)
                {
                    AddComponents(components, matches, text);
                    continue;
                }

                if (!context.Scope.IsAllowed(script))
                {
                    result.Notes.Add($"Skipped out-of-scope script: {script}");
                    continue;
                }

                scriptUris.Add(script);
            }

            await FetchAndScanScriptsAsync(context, repository, scriptUris, components, deep, Warn);
        }
        else if (finalUri.AbsolutePath.EndsWith(".js", StringComparison.OrdinalIgnoreCase))
        {
            documents.Add((finalUri.ToString(), Encoding.UTF8.GetString(body)));
        }

        if (capture is not null)
        {
            var runtimeIndex = 0;
            foreach (var script in capture.Scripts)
            {
                if (string.IsNullOrWhiteSpace(script))
                {
                    continue;
                }

                runtimeIndex++;
                ScanContent(
                    repository,
                    $"{finalUri}#runtime-{runtimeIndex}",
                    script,
                    components,
                    deep,
                    Warn);
            }

            result.Metrics["runtimeScripts"] = runtimeIndex.ToString();
        }

        foreach (var (file, content) in documents)
        {
            ScanContent(repository, file, content, components, deep, Warn);
        }

        result.Metrics["components"] = components.Count.ToString();
        foreach (var warning in warnings.Distinct(StringComparer.OrdinalIgnoreCase).Take(10))
        {
            result.Notes.Add(warning);
        }

        var vulnerable = 0;
        foreach (var (component, file) in components.Values)
        {
            var package = component.NpmName ?? component.Name;
            if (focus != FocusGroup.All && !Focus.IsFocused(package, focus))
            {
                continue;
            }

            if (database is not null)
            {
                AdvisoryDatabaseStore.MergeAdvisories(database, component, Warn);
            }

            if (component.Vulnerabilities is not { Count: > 0 })
            {
                continue;
            }

            vulnerable++;
            var severity = component.Vulnerabilities
                .Select(vulnerability => MapSeverity(vulnerability.Severity))
                .DefaultIfEmpty(Severity.Medium)
                .Max();
            var cves = component.Vulnerabilities
                .SelectMany(vulnerability => vulnerability.Identifiers?.Cve ?? [])
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var details = component.Vulnerabilities
                .Select(vulnerability => Describe(vulnerability))
                .Where(text => text.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(5)
                .ToList();
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
            var licenses = EvaluateLicenses(repository, component);

            result.Findings.Add(new Finding
            {
                CheckId = Id,
                Title = $"Vulnerable JavaScript library: {component.Name} {component.Version}",
                Description =
                    "Retire.js and the local OSV advisory database report one or more known " +
                    "vulnerabilities for this version. Confirm that the affected script is actually " +
                    "loaded and reachable.",
                Severity = severity,
                Confidence = Confidence.High,
                Target = context.Target.BaseUrl,
                Url = file,
                Evidence = new Dictionary<string, string>
                {
                    ["component"] = component.Name,
                    ["version"] = component.Version,
                    ["npm"] = component.NpmName ?? string.Empty,
                    ["detection"] = component.Detection ?? string.Empty,
                    ["file"] = file,
                    ["cves"] = string.Join(", ", cves),
                    ["details"] = string.Join(" | ", details),
                    ["licenses"] = string.Join(", ", licenses),
                    ["kev"] = kev ? "yes" : "no",
                    ["epss"] = epss > 0 ? epss.ToString("0.000") : string.Empty,
                    ["poc"] = string.Join(", ", poc),
                },
                Remediation = "Upgrade the library to a version outside the known vulnerable range.",
                References = cves
                    .Select(cve => $"https://nvd.nist.gov/vuln/detail/{cve}")
                    .Concat(poc)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
            });
        }

        result.Summary =
            $"Detected {orderedTechnologies.Count} technology item(s); checked {components.Count} " +
            $"JavaScript component(s), {vulnerable} vulnerable; " +
            $"advisory database: {(database is null ? "not found" : databasePath)}.";
        result.Status = result.RiskFindingCount > 0 ? CheckStatus.Findings : CheckStatus.NoRisk;
        return result;
    }

    private static async Task<(string Md5, string Sha256, int Bytes)?> TryFaviconAsync(
        ICheckContext context,
        Uri finalUri,
        CheckResult result)
    {
        if (!context.Settings.GetBool("favicon", true))
        {
            return null;
        }

        var uri = new Uri(finalUri.GetLeftPart(UriPartial.Authority) + "/favicon.ico");
        if (!context.Scope.IsAllowed(uri))
        {
            return null;
        }

        try
        {
            var response = await context.Http.GetAsync(uri, context.CancellationToken);
            if (!response.IsSuccess
                || response.Body.Length is 0 or > 2 * 1024 * 1024
                || response.ContentType?.Contains("html", StringComparison.OrdinalIgnoreCase) == true)
            {
                return null;
            }

            return (
                Convert.ToHexString(MD5.HashData(response.Body)).ToLowerInvariant(),
                Convert.ToHexString(SHA256.HashData(response.Body)).ToLowerInvariant(),
                response.Body.Length);
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            result.Notes.Add($"Favicon could not be read: {error.Message}");
            return null;
        }
    }

    private static string Truncate(string value, int length) =>
        Core.StringHelpers.Truncate(value, length);

    private async Task<BrowserCapture?> TryCaptureAsync(
        ICheckContext context,
        HttpResponseData? page,
        CheckResult result)
    {
        var browser = await GetBrowserAsync(context);
        if (browser is null)
        {
            result.Notes.Add("Headless browser was unavailable; only the HTTP client result was used.");
            return null;
        }

        var limit = TimeSpan.FromSeconds(
            Math.Clamp(context.Engagement.Browser.TimeoutSeconds, 5, 300));

        // Navigation, document reading and runtime collection each get their own budget. A page
        // that never fires the load event, or a body that streams forever, must not consume the
        // time needed to read the DOM and JavaScript state: the browser still has a usable page.
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(context.CancellationToken);
        lifetime.CancelAfter(limit + limit + limit + TimeSpan.FromSeconds(5));

        CdpPage? tab = null;
        try
        {
            tab = await browser.NewPageAsync(lifetime.Token);
            var headers = BrowserHeaderPolicy.Build(
                context.Engagement.Http.Headers,
                context.Engagement.Http.Evasion);
            if (headers.Count > 0)
            {
                await tab.SetExtraHeadersAsync(headers, lifetime.Token);
            }

            if (context.Engagement.Browser.SameOriginOnly)
            {
                await tab.RestrictToOriginAsync(context.Target.BaseUri, lifetime.Token);
            }

            var target = page?.FinalUri ?? context.Target.BaseUri;
            var partial = false;
            using (var load = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token))
            {
                load.CancelAfter(TimeSpan.FromMilliseconds(limit.TotalMilliseconds * 0.7));
                try
                {
                    await tab.NavigateAsync(target, load.Token);
                }
                catch (OperationCanceledException) when (!lifetime.IsCancellationRequested)
                {
                    partial = true;
                }
            }

            using var documentTimeout =
                CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
            documentTimeout.CancelAfter(limit);

            BrowserDocument? document = null;
            try
            {
                document = await tab.ReadDocumentAsync(
                    context.Engagement.Http.MaxBodyBytes,
                    documentTimeout.Token);
            }
            catch (OperationCanceledException) when (!lifetime.IsCancellationRequested)
            {
                partial = true;
            }

            // A fresh budget for collection: reading a streaming body may have used its own.
            using var collectTimeout =
                CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
            collectTimeout.CancelAfter(limit);

            var finalUri = document?.Url ?? target;
            IReadOnlyDictionary<string, string[]> finalHeaders =
                document?.Headers ?? page?.Headers ?? new Dictionary<string, string[]>();
            var body = document?.Body is { Length: > 0 } content
                ? content
                : page?.Body ?? [];

            var collector = new RuntimeCollector(tab);
            var engine = GetEngine(context);
            var rules = engine.GetRuntimeRules();
            var collection = await collector.CollectAsync(rules, collectTimeout.Token);
            var runtimeResult = await engine.FingerprintWithRuntimeAsync(
                finalHeaders,
                body,
                new RuntimeOptions
                {
                    Collector = new CachedCollector(collection),
                    Timeout = limit,
                },
                collectTimeout.Token);

            return new BrowserCapture(
                finalUri,
                document?.StatusCode ?? 0,
                finalHeaders,
                body,
                runtimeResult.Technologies,
                collection.Evidence.Scripts ?? [],
                partial,
                runtimeResult.Error?.Message ?? collection.Error?.Message);
        }
        catch (OperationCanceledException) when (!context.CancellationToken.IsCancellationRequested)
        {
            result.Notes.Add(
                $"Headless capture exceeded {limit.TotalSeconds * 3:0}s; partial results may be used.");
            return null;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            result.Notes.Add("Headless browser failed: " + error.Message);
            context.Log.Warn($"Headless browser failed: {error.Message}");
            return null;
        }
        finally
        {
            if (tab is not null)
            {
                await tab.DisposeAsync();
            }
        }
    }

    private async Task<ChromiumBrowser?> GetBrowserAsync(ICheckContext context)
    {
        if (_browser is not null)
        {
            return _browser;
        }

        if (_browserUnavailable)
        {
            return null;
        }

        await _browserGate.WaitAsync(context.CancellationToken);
        try
        {
            if (_browser is not null)
            {
                return _browser;
            }

            if (_browserUnavailable)
            {
                return null;
            }

            try
            {
                var userAgent = context.Engagement.Http.Evasion
                                || context.Engagement.Http.RandomUserAgent
                    ? EvasionProfile.NextUserAgent()
                    : context.Engagement.Browser.UserAgent;
                _browser = await ChromiumBrowser.LaunchAsync(
                    new ChromiumOptions
                    {
                        ExecutablePath = context.Engagement.Browser.ChromiumPath,
                        DisableSandbox = context.Engagement.Browser.DisableSandbox,
                        IgnoreCertificateErrors = context.Engagement.Http.Insecure,
                        ProxyServer = ProxyUrl.Normalize(context.Engagement.Http.Proxy),
                        UserAgent = userAgent,
                        StartupTimeout = TimeSpan.FromSeconds(30),
                    },
                    context.CancellationToken);
                context.Log.Info("Headless Chromium started for runtime technology detection.");
                return _browser;
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                _browserUnavailable = true;
                context.Log.Warn("Headless Chromium could not start: " + error.Message);
                return null;
            }
        }
        finally
        {
            _browserGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_browser is not null)
        {
            await _browser.DisposeAsync();
            _browser = null;
        }

        _browserGate.Dispose();
    }

    private async Task FetchAndScanScriptsAsync(
        ICheckContext context,
        RetireModel.Repository repository,
        IReadOnlyList<Uri> scriptUris,
        ConcurrentDictionary<string, (RetireModel.Component Component, string File)> components,
        bool deep,
        Action<string> warn)
    {
        var parallelism = context.Engagement.Http.Evasion ? 1 : 4;
        using var gate = new SemaphoreSlim(parallelism);
        await Task.WhenAll(scriptUris.Select(async script =>
        {
            await gate.WaitAsync(context.CancellationToken);
            try
            {
                var response = await context.Http.GetAsync(script, context.CancellationToken);
                if (!response.IsSuccess)
                {
                    warn($"{script} returned HTTP {response.StatusCode}.");
                    return;
                }

                ScanContent(repository, script.ToString(), response.Text, components, deep, warn);
            }
            catch (Exception error) when (error is not OutOfMemoryException and not OperationCanceledException)
            {
                warn($"{script} could not be read: {error.Message}");
            }
            finally
            {
                gate.Release();
            }
        }));
    }

    private static void AddComponents(
        ConcurrentDictionary<string, (RetireModel.Component Component, string File)> components,
        IEnumerable<RetireModel.Component> found,
        string file)
    {
        foreach (var component in found)
        {
            components[Key(component, file)] = (component, file);
        }
    }

    private static void ScanContent(
        RetireModel.Repository repository,
        string file,
        string content,
        ConcurrentDictionary<string, (RetireModel.Component Component, string File)> components,
        bool deep,
        Action<string> warn)
    {
        var found = RetireEngine.ScanFileContent(content, repository, warn);
        if (deep)
        {
            try
            {
                found.AddRange(DeepScanner.Scan(content, repository, TimeSpan.FromMinutes(2)));
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                warn($"Deep scan failed for {file}: {error.Message}");
            }
        }

        AddComponents(components, found, file);
    }

    private static string Key(RetireModel.Component component, string file) =>
        $"{component.Name}|{component.Version}|{file}";

    private static bool IsHtml(IReadOnlyDictionary<string, string[]> headers, byte[] body)
    {
        var contentType = Header(headers, "Content-Type");
        if (contentType.Contains("html", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var text = Encoding.UTF8.GetString(body).TrimStart();
        return text.StartsWith('<');
    }

    private static string Header(IReadOnlyDictionary<string, string[]> headers, string name) =>
        headers.TryGetValue(name, out var values) && values.Length > 0
            ? string.Join(", ", values)
            : string.Empty;

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

    private sealed record BrowserCapture(
        Uri FinalUri,
        int StatusCode,
        IReadOnlyDictionary<string, string[]> Headers,
        byte[] Body,
        HashSet<string> Technologies,
        IReadOnlyList<string> Scripts,
        bool Partial,
        string? Error);

    private sealed class CachedCollector(RuntimeCollection collection) : IRuntimeCollector
    {
        public Task<RuntimeCollection> CollectAsync(
            RuntimeRules rules,
            CancellationToken cancellationToken) =>
            Task.FromResult(collection);
    }
}
