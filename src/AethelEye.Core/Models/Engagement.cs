using System.Text.Json;
using System.Text.Json.Serialization;

namespace AethelEye.Core.Models;

/// <summary>
/// The only file a typical user needs. Everything else has a safe default.
/// </summary>
public sealed class Engagement
{
    public string Name { get; set; } = "engagement";

    public string? Client { get; set; }

    /// <summary>
    /// Public brand domain used by GitHub and leak OSINT when the scan target is an internal
    /// host name such as a UAT server. Empty means the target host is used.
    /// </summary>
    public string? OsintDomain { get; set; }

    public string? AuthorizedBy { get; set; }

    public string? Notes { get; set; }

    /// <summary>
    /// Minimal mode: target checks still run, but public OSINT sources and repository downloads
    /// are skipped. Useful on an isolated assessment network.
    /// </summary>
    public bool Offline { get; set; }

    public List<string> Targets { get; set; } = [];

    /// <summary>
    /// Local source trees, JavaScript files or .zip archives. Used by the "source" check.
    /// A target URL is optional; with only sources the scan runs the source check once.
    /// </summary>
    public List<string> Sources { get; set; } = [];

    /// <summary>
    /// SQLite advisory database built by <c>aetheleye --update db</c>. When empty, the file
    /// <c>aetheleye.db</c> under the framework data directory is used.
    /// </summary>
    public string? AdvisoryDatabasePath { get; set; }

    public ScopeSettings Scope { get; set; } = new();

    public HttpSettings Http { get; set; } = new();

    /// <summary>Optional headless Chromium rendering for JavaScript-heavy technology detection.</summary>
    public BrowserSettings Browser { get; set; } = new();

    public DnsSettings Dns { get; set; } = new();

    public EngineSettings Engine { get; set; } = new();

    public Dictionary<string, CheckSettings> Checks { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    public GitHubSettings GitHub { get; set; } = new();

    public LeakSettings Leaks { get; set; } = new();

    public List<ToolSettings> Tools { get; set; } = [];

    public OutputSettings Output { get; set; } = new();

    public bool IsCheckEnabled(string checkId) =>
        !Checks.TryGetValue(checkId, out var settings) || settings.Enabled;

    public CheckSettings SettingsFor(string checkId)
    {
        if (Checks.TryGetValue(checkId, out var settings))
        {
            return settings;
        }

        settings = new CheckSettings();
        Checks[checkId] = settings;
        return settings;
    }
}

public sealed class ScopeSettings
{
    /// <summary>
    /// Hosts that may be contacted. Supports "example.com" and "*.example.com".
    /// When empty, the hosts from <see cref="Engagement.Targets"/> are used.
    /// </summary>
    public List<string> AllowedHosts { get; set; } = [];

    public List<string> ExcludedHosts { get; set; } = [];

    public bool IncludeSubdomains { get; set; } = true;

    public bool AllowPrivateAddresses { get; set; }

    public bool AllowNonStandardPorts { get; set; } = true;
}

public sealed class HttpSettings
{
    public string UserAgent { get; set; } =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
        "(KHTML, like Gecko) Chrome/132.0 Safari/537.36 AethelEye/0.1";

    public int TimeoutSeconds { get; set; } = 20;

    public int MaxBodyBytes { get; set; } = 5 * 1024 * 1024;

    public int MaxRedirects { get; set; } = 5;

    public int RequestsPerSecond { get; set; } = 5;

    public int Retries { get; set; } = 2;

    /// <summary>Short timeout for public APIs. Kept separate so a dead Internet does not stall a scan.</summary>
    public int ExternalTimeoutSeconds { get; set; } = 12;

    /// <summary>Retries for public APIs. One retry is enough; the circuit breaker handles the rest.</summary>
    public int ExternalRetries { get; set; } = 1;

    /// <summary>Hard cap on calls to public APIs per scan, so a broken network cannot stall a run.</summary>
    public int MaxExternalRequests { get; set; } = 100;

    /// <summary>Number of consecutive failures before the circuit breaker opens and blocks further requests.</summary>
    public int CircuitBreakerThreshold { get; set; } = 3;

    /// <summary>Cooldown in seconds before the circuit breaker resets after opening.</summary>
    public int CircuitBreakerCooldownSeconds { get; set; } = 60;

    public bool Insecure { get; set; }

    public string? Proxy { get; set; }

    /// <summary>
    /// Request-shaping profile for authorized WAF/IDS testing: low request rate, jitter, rotating
    /// User-Agent and browser-like headers. It does not guarantee that a device will be bypassed.
    /// </summary>
    public bool Evasion { get; set; }

    /// <summary>Maximum random delay added before a request when <see cref="Evasion"/> is on.</summary>
    public int EvasionJitterMilliseconds { get; set; } = 750;

    /// <summary>Rotate a browser User-Agent for every target request to reduce static fingerprints.</summary>
    public bool RandomUserAgent { get; set; }

    public Dictionary<string, string> Headers { get; set; } = [];
}

public sealed class BrowserSettings
{
    /// <summary>Render the page in headless Chromium before fingerprinting it.</summary>
    public bool Headless { get; set; }

    /// <summary>Chromium/Edge executable. When empty, CHROME_PATH and common locations are tried.</summary>
    public string? ChromiumPath { get; set; }

    /// <summary>Only needed when Chromium runs as root in a container.</summary>
    public bool DisableSandbox { get; set; }

    /// <summary>
    /// Block browser requests to any host other than the target. Use it for single-target
    /// engagements where the page must not contact third-party CDNs, analytics or subdomains.
    /// </summary>
    public bool SameOriginOnly { get; set; }

    /// <summary>
    /// Browser user agent. Empty keeps Chromium's own user agent, which is what a real browser
    /// sends; do not reuse the HTTP client agent because its tool token can trip a WAF.
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>Navigation and runtime-collection budget in seconds.</summary>
    public int TimeoutSeconds { get; set; } = 20;
}

public sealed class EngineSettings
{
    public int TargetConcurrency { get; set; } = 1;

    public int DefaultCheckTimeoutSeconds { get; set; } = 120;
}

public sealed class CheckSettings
{
    public bool Enabled { get; set; } = true;

    public int? TimeoutSeconds { get; set; }

    public Dictionary<string, JsonElement> Options { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Lets users put an option directly on the check object instead of under "options".</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Extra { get; set; } = [];
}

public sealed class GitHubSettings
{
    /// <summary>Falls back to the GITHUB_TOKEN environment variable.</summary>
    public string? Token { get; set; }

    public int MaxRepositories { get; set; } = 20;

    public bool CodeSearch { get; set; } = true;

    /// <summary>Clone repositories and run the gitleaks binary. Off by default because it is slow.</summary>
    public bool CloneAndScan { get; set; }

    public string? GitleaksPath { get; set; }
}

public sealed class LeakSettings
{
    /// <summary>Falls back to BREACHDIRECTORY_API_KEY.</summary>
    public string? BreachDirectoryApiKey { get; set; }

    public bool HudsonRock { get; set; } = true;

    public bool ProxyNova { get; set; } = true;

    public bool BreachDirectory { get; set; }

    public bool IncludeDorks { get; set; } = true;

    public int MaxResults { get; set; } = 20;
}

public sealed class ToolSettings
{
    public required string Name { get; set; }

    public required string Path { get; set; }
}

public sealed class DnsSettings
{
    /// <summary>
    /// Ordered list of DNS-over-HTTPS providers. Each entry is a base URL that accepts
    /// <c>?name=...&amp;type=...</c> query parameters and returns <c>application/dns-json</c>.
    /// When empty, the built-in defaults (Cloudflare, then Google) are used.
    /// </summary>
    public List<string> DohProviders { get; set; } = [];
}

public sealed class OutputSettings
{
    public string Directory { get; set; } = "results";

    public List<string> Formats { get; set; } = ["text"];

    public string FileName { get; set; } = "aetheleye-report";
}
