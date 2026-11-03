using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;

namespace AethelEye.Modules.Exposure;

/// <summary>
/// Detects default management pages and interfaces that should not be reachable from the Internet:
/// Tomcat manager, Swagger/OpenAPI, Spring Actuator, API listings, debug endpoints and default
/// admin/login pages. It is a detection check only; it does not try credentials or exploit anything.
/// </summary>
public sealed class ExposureCheck : ICheck
{
    private enum Category
    {
        Admin,
        Api,
        Tomcat,
        Swagger,
        Actuator,
        Debug,
        DefaultPage,
        Config,
    }

    private sealed record Probe(
        string Path,
        string Title,
        string Description,
        Severity Severity,
        Category Category,
        Func<HttpResponseData, bool> Match,
        string Remediation);

    private static readonly Regex IndexOf = new(
        @"<title>\s*Index of",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Probe[] Probes =
    [
        // Tomcat and Java application-server defaults.
        new("manager/html", "Tomcat Web Application Manager is exposed",
            "The Tomcat manager application is reachable. It can deploy applications and read server state.",
            Severity.High, Category.Tomcat,
            response => ContainsAny(response, "Tomcat Web Application Manager", "Manager Application"),
            "Restrict /manager to trusted networks or remove the manager application."),
        new("host-manager/html", "Tomcat Host Manager is exposed",
            "The Tomcat host manager is reachable.",
            Severity.High, Category.Tomcat,
            response => ContainsAny(response, "Tomcat Virtual Host Manager", "Host Manager"),
            "Restrict /host-manager to trusted networks or remove the application."),
        new("manager/status", "Tomcat manager status is exposed",
            "The Tomcat manager status page is reachable and discloses server internals.",
            Severity.High, Category.Tomcat,
            response => ContainsAny(response, "Server Status", "Tomcat", "Free memory"),
            "Restrict /manager to trusted networks."),
        new("examples/", "Tomcat examples are deployed",
            "The Tomcat examples web application is reachable.",
            Severity.Low, Category.Tomcat,
            response => ContainsAny(response, "Apache Tomcat Examples", "Tomcat Examples"),
            "Remove the examples application from production Tomcat."),
        new("docs/", "Tomcat documentation is deployed",
            "The Tomcat documentation web application is reachable.",
            Severity.Low, Category.Tomcat,
            response => ContainsAny(response, "Apache Tomcat", "Tomcat Documentation"),
            "Remove documentation applications from production Tomcat."),
        new("WEB-INF/web.xml", "WEB-INF/web.xml is readable",
            "The Java web application descriptor is served as source. It can disclose routes, filters and security settings.",
            Severity.Critical, Category.Config,
            response => ContainsAny(response, "<web-app", "<servlet", "<security-constraint"),
            "Block /WEB-INF and /META-INF at the web server and redeploy the application correctly."),
        new("WEB-INF/", "WEB-INF directory listing is exposed",
            "The WEB-INF directory is listable.",
            Severity.High, Category.Config,
            response => IndexOf.IsMatch(response.Text) || ContainsAny(response, "WEB-INF", "web.xml"),
            "Block /WEB-INF at the web server."),
        new("META-INF/", "META-INF directory listing is exposed",
            "The META-INF directory is listable.",
            Severity.High, Category.Config,
            response => IndexOf.IsMatch(response.Text) || ContainsAny(response, "META-INF", "MANIFEST.MF"),
            "Block /META-INF at the web server."),

        // Swagger / OpenAPI.
        new("swagger-ui.html", "Swagger UI is public",
            "A Swagger UI page is reachable and exposes the API surface.",
            Severity.Medium, Category.Swagger,
            response => ContainsAny(response, "swagger-ui", "Swagger UI"),
            "Require authentication for API documentation or disable it in production."),
        new("swagger-ui/index.html", "Swagger UI is public",
            "A Swagger UI page is reachable and exposes the API surface.",
            Severity.Medium, Category.Swagger,
            response => ContainsAny(response, "swagger-ui", "Swagger UI"),
            "Require authentication for API documentation or disable it in production."),
        new("swagger.json", "OpenAPI/Swagger specification is public",
            "A machine-readable API specification is reachable.",
            Severity.Medium, Category.Swagger,
            response => JsonContains(response, "\"swagger\"", "\"openapi\"", "\"paths\""),
            "Require authentication for API specifications or disable them in production."),
        new("openapi.json", "OpenAPI specification is public",
            "A machine-readable OpenAPI specification is reachable.",
            Severity.Medium, Category.Swagger,
            response => JsonContains(response, "\"openapi\"", "\"paths\"", "\"swagger\""),
            "Require authentication for API specifications or disable them in production."),
        new("v2/api-docs", "Swagger 2 API documentation is public",
            "Springfox-style API documentation is reachable.",
            Severity.Medium, Category.Swagger,
            response => JsonContains(response, "\"swagger\"", "\"paths\"", "\"definitions\""),
            "Disable Springfox documentation in production or protect it with authentication."),
        new("v3/api-docs", "OpenAPI 3 documentation is public",
            "springdoc-style OpenAPI documentation is reachable.",
            Severity.Medium, Category.Swagger,
            response => JsonContains(response, "\"openapi\"", "\"paths\"", "\"components\""),
            "Disable springdoc documentation in production or protect it with authentication."),
        new("api-docs", "API documentation is public",
            "An API documentation endpoint is reachable.",
            Severity.Medium, Category.Swagger,
            response => JsonContains(response, "\"swagger\"", "\"openapi\"", "\"paths\"")
                        || ContainsAny(response, "swagger-ui", "Swagger UI"),
            "Require authentication for API documentation or disable it in production."),
        new("redoc", "ReDoc API documentation is public",
            "A ReDoc page is reachable and exposes the API surface.",
            Severity.Medium, Category.Swagger,
            response => ContainsAny(response, "redoc", "ReDoc"),
            "Require authentication for API documentation or disable it in production."),
        new("swagger-resources", "Swagger resource listing is public",
            "The Swagger resource listing is reachable.",
            Severity.Low, Category.Swagger,
            response => JsonContains(response, "swagger", "url", "name"),
            "Disable Swagger resources in production or protect them with authentication."),

        // Spring Boot Actuator.
        new("actuator", "Spring Actuator index is exposed",
            "The Spring Boot Actuator index is reachable and lists management endpoints.",
            Severity.Low, Category.Actuator,
            response => JsonContains(response, "_links", "self", "health"),
            "Restrict actuator endpoints to the management network and require authentication."),
        new("actuator/health", "Spring Actuator health endpoint is exposed",
            "The health endpoint is reachable.",
            Severity.Info, Category.Actuator,
            response => JsonContains(response, "\"status\"", "UP", "DOWN"),
            "Expose only a minimal health response to untrusted networks."),
        new("actuator/env", "Spring Actuator environment is exposed",
            "The environment endpoint can disclose configuration, credentials and connection strings.",
            Severity.High, Category.Actuator,
            response => JsonContains(response, "propertySources", "activeProfiles", "systemProperties"),
            "Disable /actuator/env or restrict actuator to the management network."),
        new("actuator/configprops", "Spring Actuator configuration properties are exposed",
            "The configprops endpoint can disclose configuration values.",
            Severity.High, Category.Actuator,
            response => JsonContains(response, "contexts", "properties", "configProps"),
            "Disable /actuator/configprops or restrict actuator to the management network."),
        new("actuator/heapdump", "Spring Actuator heap dump is downloadable",
            "A heap dump is downloadable. It can contain credentials, tokens and personal data.",
            Severity.Critical, Category.Actuator,
            response => response.Body.Length > 0
                        && response.ContentType?.Contains("html", StringComparison.OrdinalIgnoreCase) != true,
            "Disable /actuator/heapdump and restrict actuator to the management network."),
        new("actuator/mappings", "Spring Actuator mappings are exposed",
            "The mappings endpoint discloses routes and handler methods.",
            Severity.Medium, Category.Actuator,
            response => JsonContains(response, "contexts", "mappings", "dispatcherServlets"),
            "Disable /actuator/mappings or restrict actuator to the management network."),
        new("actuator/beans", "Spring Actuator beans are exposed",
            "The beans endpoint discloses application internals.",
            Severity.Medium, Category.Actuator,
            response => JsonContains(response, "contexts", "beans"),
            "Disable /actuator/beans or restrict actuator to the management network."),
        new("actuator/loggers", "Spring Actuator loggers are exposed",
            "The loggers endpoint discloses logger configuration and may allow runtime changes.",
            Severity.Medium, Category.Actuator,
            response => JsonContains(response, "loggers", "configuredLevel"),
            "Disable /actuator/loggers or restrict actuator to the management network."),
        new("actuator/threaddump", "Spring Actuator thread dump is exposed",
            "The threaddump endpoint discloses thread names, stack traces and request state.",
            Severity.Medium, Category.Actuator,
            response => JsonContains(response, "threads", "threadName", "stackTrace"),
            "Disable /actuator/threaddump or restrict actuator to the management network."),
        new("actuator/httptrace", "Spring Actuator HTTP trace is exposed",
            "The httptrace endpoint can disclose request paths, headers and session identifiers.",
            Severity.Medium, Category.Actuator,
            response => JsonContains(response, "traces", "request", "response"),
            "Disable /actuator/httptrace or restrict actuator to the management network."),
        new("actuator/prometheus", "Spring Actuator Prometheus metrics are exposed",
            "Prometheus metrics are reachable and disclose internal application details.",
            Severity.Medium, Category.Actuator,
            response => ContainsAny(response, "# HELP", "# TYPE"),
            "Restrict metrics to the monitoring network and require authentication."),
        new("actuator/gateway/routes", "Spring Cloud Gateway routes are exposed",
            "Gateway route definitions are reachable.",
            Severity.Medium, Category.Actuator,
            response => JsonContains(response, "routes", "predicate", "filters"),
            "Disable /actuator/gateway/routes or restrict actuator to the management network."),
        new("actuator/jolokia", "Jolokia JMX bridge is exposed",
            "The Jolokia endpoint can expose JMX operations and application state.",
            Severity.High, Category.Actuator,
            response => JsonContains(response, "jolokia", "value", "request"),
            "Disable Jolokia or restrict it to the management network with authentication."),

        // API listing and GraphQL consoles.
        new("api", "API root responds with data",
            "The API root returns a JSON document, which can reveal routes and data.",
            Severity.Info, Category.Api,
            response => JsonObjectOrArray(response),
            "Review whether the API root should be public and require authentication where needed."),
        new("api/", "API root responds with data",
            "The API root returns a JSON document, which can reveal routes and data.",
            Severity.Info, Category.Api,
            response => JsonObjectOrArray(response),
            "Review whether the API root should be public and require authentication where needed."),
        new("api/v1", "API version root responds with data",
            "A versioned API root returns a JSON document.",
            Severity.Info, Category.Api,
            response => JsonObjectOrArray(response),
            "Review whether the API root should be public and require authentication where needed."),
        new("api/v2", "API version root responds with data",
            "A versioned API root returns a JSON document.",
            Severity.Info, Category.Api,
            response => JsonObjectOrArray(response),
            "Review whether the API root should be public and require authentication where needed."),
        new("graphiql", "GraphiQL console is public",
            "A GraphiQL console is reachable.",
            Severity.Medium, Category.Api,
            response => ContainsAny(response, "GraphiQL", "graphiql"),
            "Disable GraphiQL in production or require authentication."),
        new("playground", "GraphQL Playground is public",
            "A GraphQL Playground is reachable.",
            Severity.Medium, Category.Api,
            response => ContainsAny(response, "GraphQL Playground", "graphql-playground"),
            "Disable GraphQL Playground in production or require authentication."),
        new("graphql", "GraphQL endpoint is reachable",
            "A GraphQL endpoint responds. Review whether introspection and mutations should be public.",
            Severity.Low, Category.Api,
            response => ContainsAny(response, "GraphQL", "graphql", "query"),
            "Disable introspection in production and require authentication for mutations."),

        // Debug endpoints.
        new("debug/vars", "Go expvar debug endpoint is exposed",
            "The Go expvar endpoint discloses runtime variables and memory statistics.",
            Severity.High, Category.Debug,
            response => JsonContains(response, "cmdline", "memstats", "expvar"),
            "Block /debug endpoints at the reverse proxy."),
        new("debug/pprof/", "Go pprof profiling endpoint is exposed",
            "The Go pprof index is reachable and can disclose runtime profiles.",
            Severity.High, Category.Debug,
            response => ContainsAny(response, "Types of profiles available", "goroutine", "profile"),
            "Block /debug/pprof at the reverse proxy."),
        new("debug/requests", "Debug requests endpoint is exposed",
            "A debug requests endpoint is reachable.",
            Severity.High, Category.Debug,
            response => ContainsAny(response, "debug requests", "profile", "requests"),
            "Block /debug endpoints at the reverse proxy."),
        new("debug/events", "Debug events endpoint is exposed",
            "A debug events endpoint is reachable.",
            Severity.High, Category.Debug,
            response => ContainsAny(response, "debug events", "events", "profile"),
            "Block /debug endpoints at the reverse proxy."),
        new("__debug__/", "Framework debug toolbar is exposed",
            "A framework debug interface is reachable.",
            Severity.High, Category.Debug,
            response => ContainsAny(response, "debug", "Django", "toolbar"),
            "Disable debug mode and block the debug interface in production."),
        new("h2-console", "H2 database console is exposed",
            "The H2 web console is reachable and may allow database access.",
            Severity.High, Category.Debug,
            response => ContainsAny(response, "H2 Console", "login.jsp", "H2 Database"),
            "Disable the H2 console in production or restrict it to localhost."),
        new("console", "Administration console is exposed",
            "A console page is reachable.",
            Severity.Medium, Category.Debug,
            response => ContainsAny(response, "Admin Console", "Web Console", "Console"),
            "Restrict management consoles to trusted networks and require authentication."),
        new("druid/", "Druid monitoring console is exposed",
            "The Druid console is reachable.",
            Severity.Medium, Category.Debug,
            response => ContainsAny(response, "Druid", "druid"),
            "Restrict the Druid console to the management network."),
        new("metrics", "Metrics endpoint is exposed",
            "A Prometheus-style metrics endpoint is reachable.",
            Severity.Medium, Category.Debug,
            response => ContainsAny(response, "# HELP", "# TYPE"),
            "Restrict metrics to the monitoring network and require authentication."),
        new("env", "Environment variables are exposed",
            "An environment endpoint returns process variables.",
            Severity.Critical, Category.Debug,
            response => ContainsAny(response, "PATH=", "JAVA_HOME", "PWD=", "SECRET", "TOKEN"),
            "Remove the endpoint and rotate any credentials it exposed."),
        new("heapdump", "Heap dump is downloadable",
            "A heap dump is downloadable and may contain secrets and personal data.",
            Severity.Critical, Category.Debug,
            response => response.Body.Length > 0
                        && response.ContentType?.Contains("html", StringComparison.OrdinalIgnoreCase) != true,
            "Remove the heap dump endpoint and restrict diagnostic endpoints to the management network."),
        new("threaddump", "Thread dump is exposed",
            "A thread dump endpoint is reachable.",
            Severity.Medium, Category.Debug,
            response => ContainsAny(response, "threadName", "stackTrace", "threads"),
            "Restrict diagnostic endpoints to the management network."),

        // Generic default admin/login pages. CMS-specific pages are covered by the cms check.
        new("admin", "Default admin page is exposed",
            "An administrative login page is reachable.",
            Severity.Info, Category.Admin,
            LoginForm,
            "Restrict administrative pages to trusted networks and enforce strong authentication."),
        new("admin/", "Default admin page is exposed",
            "An administrative login page is reachable.",
            Severity.Info, Category.Admin,
            LoginForm,
            "Restrict administrative pages to trusted networks and enforce strong authentication."),
        new("admin/login", "Default admin login page is exposed",
            "An administrative login page is reachable.",
            Severity.Info, Category.Admin,
            LoginForm,
            "Restrict administrative pages to trusted networks and enforce strong authentication."),
        new("login", "Login page is exposed",
            "A login page is reachable.",
            Severity.Info, Category.Admin,
            LoginForm,
            "Review whether the login page should be public and enforce rate limiting."),
        new("signin", "Login page is exposed",
            "A login page is reachable.",
            Severity.Info, Category.Admin,
            LoginForm,
            "Review whether the login page should be public and enforce rate limiting."),
        new("webadmin", "Default web administration page is exposed",
            "A web administration page is reachable.",
            Severity.Info, Category.Admin,
            LoginForm,
            "Restrict administrative pages to trusted networks and enforce strong authentication."),
        new("cpanel", "cPanel login page is exposed",
            "A cPanel login page is reachable.",
            Severity.Info, Category.Admin,
            response => ContainsAny(response, "cPanel", "cpanel"),
            "Restrict hosting control panels to trusted networks."),
    ];

    public string Id => "exposure";

    public string Name => "Default pages and exposed interfaces";

    public string Description =>
        "Checks Tomcat manager, Swagger/OpenAPI, Spring Actuator, API listings, debug endpoints " +
        "and default admin pages for Internet exposure.";

    public int Order => 28;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        var parallelism = context.Engagement.Http.Evasion
            ? 1
            : Math.Clamp(context.Settings.GetInt("parallelism", 4), 1, 10);
        var baselinePath = $".aetheleye-{Guid.NewGuid():N}";
        var findings = new ConcurrentBag<Finding>();
        var notes = new ConcurrentBag<string>();
        var baseline = await TryGetAsync(context, baselinePath, notes);
        var probed = 0;
        var exposed = 0;

        using var gate = new SemaphoreSlim(parallelism);
        await Task.WhenAll(Probes.Select(async probe =>
        {
            await gate.WaitAsync(context.CancellationToken);
            try
            {
                Interlocked.Increment(ref probed);
                var response = await TryGetAsync(context, probe.Path, notes);
                if (response is null)
                {
                    return;
                }

                if (response.StatusCode is 401 or 403)
                {
                    notes.Add($"{probe.Path}: HTTP {response.StatusCode} (protected)");
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

                if (!probe.Match(response))
                {
                    return;
                }

                Interlocked.Increment(ref exposed);
                findings.Add(new Finding
                {
                    CheckId = Id,
                    Title = probe.Title,
                    Description = probe.Description,
                    Severity = probe.Severity,
                    Confidence = probe.Severity >= Severity.High ? Confidence.High : Confidence.Medium,
                    Target = context.Target.BaseUrl,
                    Url = context.Url(probe.Path),
                    Evidence = new Dictionary<string, string>
                    {
                        ["category"] = probe.Category.ToString(),
                        ["path"] = "/" + probe.Path.TrimStart('/'),
                        ["status"] = response.StatusCode.ToString(),
                        ["contentType"] = response.ContentType ?? string.Empty,
                        ["bytes"] = response.Body.Length.ToString(),
                        ["marker"] = probe.Category is Category.Config or Category.Debug or Category.Actuator
                            ? string.Empty
                            : Marker(response),
                    },
                    Remediation = probe.Remediation,
                });
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                notes.Add($"{probe.Path}: {error.Message}");
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

        result.Metrics["probed"] = probed.ToString();
        result.Metrics["exposed"] = exposed.ToString();
        result.Metrics["highRisk"] = result.Findings.Count(finding => finding.Severity >= Severity.High).ToString();
        result.Summary =
            $"Probed {probed} interface(s); {exposed} exposed, " +
            $"{result.Findings.Count(finding => finding.Severity >= Severity.High)} high-risk.";
        result.Status = result.RiskFindingCount > 0
            ? CheckStatus.Findings
            : CheckStatus.NoRisk;
        return result;
    }

    private static async Task<HttpResponseData?> TryGetAsync(
        ICheckContext context,
        string path,
        ConcurrentBag<string> notes)
    {
        var uri = new Uri(context.Url(path), UriKind.Absolute);
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
            notes.Add($"{path}: {error.Message}");
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

    private static bool ContainsAny(HttpResponseData response, params string[] markers) =>
        markers.Any(marker => response.Text.Contains(marker, StringComparison.OrdinalIgnoreCase));

    private static bool JsonContains(HttpResponseData response, params string[] markers) =>
        IsJson(response) && ContainsAny(response, markers);

    private static bool IsJson(HttpResponseData response) =>
        response.ContentType?.Contains("json", StringComparison.OrdinalIgnoreCase) == true
        || response.Text.TrimStart().StartsWith('{')
        || response.Text.TrimStart().StartsWith('[');

    private static bool JsonObjectOrArray(HttpResponseData response) =>
        IsJson(response) && response.Text.TrimStart() is ['{' or '[', ..];

    private static bool LoginForm(HttpResponseData response) =>
        ContainsAny(response, "type=\"password\"", "type='password'", "name=\"password\"", "name='password'")
        && ContainsAny(response, "login", "sign in", "signin", "username", "user name");

    private static string Marker(HttpResponseData response)
    {
        var text = response.Text.Trim();
        if (text.Length == 0)
        {
            return string.Empty;
        }

        return text.Length <= 160 ? text : text[..160] + "...";
    }
}
