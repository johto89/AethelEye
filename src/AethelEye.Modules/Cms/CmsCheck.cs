using System.Text.RegularExpressions;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;
using RetireSharp.Web;

namespace AethelEye.Modules.Cms;

/// <summary>
/// CMS detection inspired by CMSeeK's header, generator, page-source, robots.txt and directory
/// methods (GPL-3.0). It identifies common CMS platforms and versions and reports exposed
/// admin/login, version-disclosure and configuration-leak endpoints. It does not exploit them.
/// </summary>
public sealed partial class CmsCheck : ICheck
{
    [GeneratedRegex(@"(?:WordPress|Joomla!?|Drupal|Magento|TYPO3|PrestaShop|OpenCart|Ghost)\s*[/ ]?\s*(?<version>\d+(?:\.\d+){0,3})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex GeneratorVersion();

    [GeneratedRegex(@"Version\s+(?<version>\d+(?:\.\d+){0,3})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex WordPressReadmeVersion();

    [GeneratedRegex(@"<version>\s*(?<version>\d+(?:\.\d+){0,3})\s*</version>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex JoomlaXmlVersion();

    [GeneratedRegex(@"Drupal\s+(?<version>\d+(?:\.\d+){0,3})\s*,", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DrupalChangelogVersion();

    public string Id => "cms";

    public string Name => "CMS detection";

    public string Description =>
        "Detects common CMS platforms and versions from headers, generator meta, page markers, " +
        "robots.txt and version/login/config files.";

    public int Order => 12;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        var candidates = new Dictionary<string, Candidate>(StringComparer.OrdinalIgnoreCase);

        var page = await context.Pages.GetAsync(context.Target.BaseUri, context.CancellationToken);
        if (page.IsSuccess)
        {
            DetectFromPage(page, candidates);
        }

        var robots = await TryGetAsync(context, "robots.txt", result);
        if (robots is { IsSuccess: true })
        {
            DetectFromRobots(robots.Text, candidates);
        }

        if (context.Settings.GetBool("activeProbe", true))
        {
            await ProbeAsync(context, candidates, result);
        }

        foreach (var candidate in candidates.Values
                     .OrderBy(candidate => candidate.Name, StringComparer.OrdinalIgnoreCase))
        {
            result.Findings.Add(new Finding
            {
                CheckId = Id,
                Title = $"CMS detected: {candidate.Name}" +
                        (candidate.Version is { Length: > 0 } ? $" {candidate.Version}" : string.Empty),
                Description =
                    "The target exposes signatures associated with this content-management system. " +
                    "This is inventory information; review the CMS version and exposed endpoints.",
                Severity = Severity.Info,
                Confidence = candidate.Confidence,
                Target = context.Target.BaseUrl,
                Url = page.FinalUri.ToString(),
                Evidence = new Dictionary<string, string>
                {
                    ["cms"] = candidate.Name,
                    ["version"] = candidate.Version ?? string.Empty,
                    ["detections"] = string.Join("; ", candidate.Evidence.Distinct(StringComparer.OrdinalIgnoreCase)),
                },
            });
        }

        result.Metrics["cms"] = candidates.Count.ToString();
        foreach (var candidate in candidates.Values)
        {
            result.Metrics[candidate.Name.ToLowerInvariant()] = candidate.Version ?? "unknown";
        }

        if (candidates.Count == 0)
        {
            result.Summary = "No CMS signature was detected.";
        }
        else
        {
            result.Summary =
                "Detected " + string.Join(", ", candidates.Values.Select(candidate =>
                    candidate.Version is { Length: > 0 }
                        ? $"{candidate.Name} {candidate.Version}"
                        : candidate.Name)) + ".";
        }

        result.Status = result.RiskFindingCount > 0 ? CheckStatus.Findings : CheckStatus.NoRisk;
        return result;
    }

    private static void DetectFromPage(HttpResponseData page, Dictionary<string, Candidate> candidates)
    {
        var html = page.Text;
        var lower = html.ToLowerInvariant();
        var hints = HtmlExtractor.Parse(html, 0);

        foreach (var header in new[]
                 {
                     "X-Generator", "X-Powered-By", "X-Drupal-Cache", "X-Drupal-Dynamic-Cache",
                     "X-Joomla-Version", "X-Magento-Cache-Debug", "X-Shopify-Stage",
                 })
        {
            var value = page.Header(header);
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            var text = header + ": " + value;
            if (value.Contains("WordPress", StringComparison.OrdinalIgnoreCase)
                || value.Contains("wp-", StringComparison.OrdinalIgnoreCase))
            {
                Add(candidates, "WordPress", VersionFrom(value), Confidence.High, text);
            }
            else if (value.Contains("Joomla", StringComparison.OrdinalIgnoreCase))
            {
                Add(candidates, "Joomla", VersionFrom(value), Confidence.High, text);
            }
            else if (value.Contains("Drupal", StringComparison.OrdinalIgnoreCase))
            {
                Add(candidates, "Drupal", VersionFrom(value), Confidence.High, text);
            }
            else if (value.Contains("Magento", StringComparison.OrdinalIgnoreCase))
            {
                Add(candidates, "Magento", VersionFrom(value), Confidence.High, text);
            }
        }

        var cookies = page.Header("Set-Cookie") ?? string.Empty;
        if (cookies.Contains("wordpress_", StringComparison.OrdinalIgnoreCase)
            || cookies.Contains("wp-settings", StringComparison.OrdinalIgnoreCase))
        {
            Add(candidates, "WordPress", null, Confidence.Medium, "WordPress cookie");
        }

        if (hints.Generator is { Length: > 0 } generator)
        {
            var version = VersionFrom(generator);
            if (generator.Contains("WordPress", StringComparison.OrdinalIgnoreCase))
            {
                Add(candidates, "WordPress", version, Confidence.High, "meta generator: " + generator);
            }
            else if (generator.Contains("Joomla", StringComparison.OrdinalIgnoreCase))
            {
                Add(candidates, "Joomla", version, Confidence.High, "meta generator: " + generator);
            }
            else if (generator.Contains("Drupal", StringComparison.OrdinalIgnoreCase))
            {
                Add(candidates, "Drupal", version, Confidence.High, "meta generator: " + generator);
            }
            else if (generator.Contains("TYPO3", StringComparison.OrdinalIgnoreCase))
            {
                Add(candidates, "TYPO3", version, Confidence.High, "meta generator: " + generator);
            }
            else if (generator.Contains("PrestaShop", StringComparison.OrdinalIgnoreCase))
            {
                Add(candidates, "PrestaShop", version, Confidence.High, "meta generator: " + generator);
            }
            else if (generator.Contains("Ghost", StringComparison.OrdinalIgnoreCase))
            {
                Add(candidates, "Ghost", version, Confidence.High, "meta generator: " + generator);
            }
        }

        if (lower.Contains("/wp-content/", StringComparison.Ordinal)
            || lower.Contains("/wp-includes/", StringComparison.Ordinal)
            || lower.Contains("wp-emoji-release", StringComparison.Ordinal)
            || lower.Contains("wp-json", StringComparison.Ordinal))
        {
            Add(candidates, "WordPress", null, Confidence.High, "WordPress asset path");
        }

        if (lower.Contains("/media/jui/", StringComparison.Ordinal)
            || lower.Contains("/components/com_", StringComparison.Ordinal))
        {
            Add(candidates, "Joomla", null, Confidence.High, "Joomla asset path");
        }

        if (lower.Contains("drupal.settings", StringComparison.Ordinal)
            || lower.Contains("/sites/default/files/", StringComparison.Ordinal)
            || lower.Contains("drupalSettings", StringComparison.Ordinal))
        {
            Add(candidates, "Drupal", null, Confidence.High, "Drupal asset path");
        }

        if (lower.Contains("/skin/frontend/", StringComparison.Ordinal)
            || lower.Contains("mage/cookies", StringComparison.Ordinal))
        {
            Add(candidates, "Magento", null, Confidence.High, "Magento asset path");
        }

        if (lower.Contains("cdn.shopify.com", StringComparison.Ordinal)
            || lower.Contains("shopify.theme", StringComparison.Ordinal))
        {
            Add(candidates, "Shopify", null, Confidence.High, "Shopify asset path");
        }

        if (lower.Contains("typo3temp", StringComparison.Ordinal)
            || lower.Contains("typo3conf", StringComparison.Ordinal))
        {
            Add(candidates, "TYPO3", null, Confidence.High, "TYPO3 asset path");
        }

        if (lower.Contains("prestashop", StringComparison.Ordinal)
            && (lower.Contains("/modules/", StringComparison.Ordinal)
                || lower.Contains("var prestashop", StringComparison.Ordinal)))
        {
            Add(candidates, "PrestaShop", null, Confidence.Medium, "PrestaShop marker");
        }

        if (lower.Contains("route=common/home", StringComparison.Ordinal)
            || lower.Contains("opencart", StringComparison.Ordinal))
        {
            Add(candidates, "OpenCart", null, Confidence.Medium, "OpenCart marker");
        }

        if (lower.Contains("/bitrix/", StringComparison.Ordinal)
            || lower.Contains("bitrix_sessid", StringComparison.Ordinal))
        {
            Add(candidates, "Bitrix", null, Confidence.High, "Bitrix asset path");
        }
    }

    private static void DetectFromRobots(string robots, Dictionary<string, Candidate> candidates)
    {
        var lower = robots.ToLowerInvariant();
        if (lower.Contains("/wp-admin/", StringComparison.Ordinal)
            || lower.Contains("/wp-content/", StringComparison.Ordinal))
        {
            Add(candidates, "WordPress", null, Confidence.Medium, "robots.txt WordPress path");
        }

        if (lower.Contains("/administrator/", StringComparison.Ordinal))
        {
            Add(candidates, "Joomla", null, Confidence.Medium, "robots.txt Joomla path");
        }

        if (lower.Contains("/sites/default/", StringComparison.Ordinal)
            || lower.Contains("/core/", StringComparison.Ordinal))
        {
            Add(candidates, "Drupal", null, Confidence.Medium, "robots.txt Drupal path");
        }
    }

    private static async Task ProbeAsync(
        ICheckContext context,
        Dictionary<string, Candidate> candidates,
        CheckResult result)
    {
        var riskKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!candidates.ContainsKey("WordPress")
            && !candidates.ContainsKey("Joomla")
            && !candidates.ContainsKey("Drupal")
            && !candidates.ContainsKey("Magento"))
        {
            var wpLogin = await TryGetAsync(context, "wp-login.php", result);
            if (wpLogin is { IsSuccess: true }
                && ContainsAny(wpLogin.Text, "wp-submit", "loginform", "WordPress"))
            {
                Add(candidates, "WordPress", null, Confidence.High, "wp-login.php");
                AddRisk(result, riskKeys, new Finding
                {
                    CheckId = "cms",
                    Title = "CMS login panel is exposed",
                    Description = "A WordPress login page is reachable.",
                    Severity = Severity.Info,
                    Confidence = Confidence.High,
                    Target = context.Target.BaseUrl,
                    Url = context.Url("wp-login.php"),
                    Evidence = new Dictionary<string, string> { ["cms"] = "WordPress" },
                });
            }

            var joomlaAdmin = await TryGetAsync(context, "administrator/", result);
            if (joomlaAdmin is { IsSuccess: true }
                && ContainsAny(joomlaAdmin.Text, "Joomla!", "com_login", "mod-login"))
            {
                Add(candidates, "Joomla", null, Confidence.High, "administrator/");
                AddRisk(result, riskKeys, LoginFinding(context, "Joomla", "administrator/"));
            }

            var drupalLogin = await TryGetAsync(context, "user/login", result);
            if (drupalLogin is { IsSuccess: true }
                && ContainsAny(drupalLogin.Text, "Drupal", "user_login_form", "form_id"))
            {
                Add(candidates, "Drupal", null, Confidence.High, "user/login");
                AddRisk(result, riskKeys, LoginFinding(context, "Drupal", "user/login"));
            }

            var magentoAdmin = await TryGetAsync(context, "admin", result);
            if (magentoAdmin is { IsSuccess: true }
                && ContainsAny(magentoAdmin.Text, "Magento", "adminhtml"))
            {
                Add(candidates, "Magento", null, Confidence.High, "admin");
                AddRisk(result, riskKeys, LoginFinding(context, "Magento", "admin"));
            }
        }

        if (candidates.ContainsKey("WordPress"))
        {
            await ProbeWordPressAsync(context, candidates, result, riskKeys);
        }

        if (candidates.ContainsKey("Joomla"))
        {
            await ProbeJoomlaAsync(context, candidates, result, riskKeys);
        }

        if (candidates.ContainsKey("Drupal"))
        {
            await ProbeDrupalAsync(context, candidates, result, riskKeys);
        }

        if (candidates.ContainsKey("Magento"))
        {
            await ProbeMagentoAsync(context, result, riskKeys);
        }
    }

    private static async Task ProbeWordPressAsync(
        ICheckContext context,
        Dictionary<string, Candidate> candidates,
        CheckResult result,
        HashSet<string> riskKeys)
    {
        var readme = await TryGetAsync(context, "readme.html", result);
        if (readme is { IsSuccess: true })
        {
            var match = WordPressReadmeVersion().Match(readme.Text);
            if (match.Success)
            {
                Add(candidates, "WordPress", match.Groups["version"].Value, Confidence.High, "readme.html");
                AddRisk(result, riskKeys, VersionDisclosureFinding(context, "WordPress", "readme.html"));
            }
        }

        var users = await TryGetAsync(context, "wp-json/wp/v2/users", result);
        if (users is { IsSuccess: true }
            && users.Text.TrimStart().StartsWith('[')
            && ContainsAny(users.Text, "\"slug\"", "\"name\""))
        {
            AddRisk(result, riskKeys, new Finding
            {
                CheckId = "cms",
                Title = "WordPress user enumeration is possible",
                Description =
                    "The WordPress REST API returned a user list without authentication. " +
                    "Usernames can support password guessing and social engineering.",
                Severity = Severity.Medium,
                Confidence = Confidence.High,
                Target = context.Target.BaseUrl,
                Url = context.Url("wp-json/wp/v2/users"),
                Evidence = new Dictionary<string, string>
                {
                    ["endpoint"] = "wp-json/wp/v2/users",
                    ["sample"] = Truncate(users.Text, 500),
                },
                Remediation =
                    "Restrict the users endpoint, disable public user enumeration and use strong " +
                    "authentication with rate limiting.",
            });
        }

        var xmlrpc = await TryGetAsync(context, "xmlrpc.php", result);
        if (xmlrpc is { IsSuccess: true }
            && ContainsAny(xmlrpc.Text, "XML-RPC server accepts POST", "XML-RPC"))
        {
            AddRisk(result, riskKeys, new Finding
            {
                CheckId = "cms",
                Title = "WordPress XML-RPC endpoint is enabled",
                Description =
                    "xmlrpc.php is reachable. XML-RPC can be used for brute-force amplification and " +
                    "pingback abuse when it is not needed.",
                Severity = Severity.Low,
                Confidence = Confidence.High,
                Target = context.Target.BaseUrl,
                Url = context.Url("xmlrpc.php"),
                Evidence = new Dictionary<string, string>
                {
                    ["endpoint"] = "xmlrpc.php",
                },
                Remediation = "Disable XML-RPC at the web server or application layer if it is not required.",
            });
        }
    }

    private static async Task ProbeJoomlaAsync(
        ICheckContext context,
        Dictionary<string, Candidate> candidates,
        CheckResult result,
        HashSet<string> riskKeys)
    {
        var manifest = await TryGetAsync(
            context,
            "administrator/manifests/files/joomla.xml",
            result);
        if (manifest is { IsSuccess: true })
        {
            var match = JoomlaXmlVersion().Match(manifest.Text);
            if (match.Success)
            {
                Add(candidates, "Joomla", match.Groups["version"].Value, Confidence.High, "joomla.xml");
                AddRisk(result, riskKeys, VersionDisclosureFinding(context, "Joomla", "joomla.xml"));
            }
        }

        var config = await TryGetAsync(context, "configuration.php-dist", result);
        if (config is { IsSuccess: true }
            && ContainsAny(config.Text, "class JConfig", "public $host"))
        {
            AddRisk(result, riskKeys, new Finding
            {
                CheckId = "cms",
                Title = "Joomla configuration template is exposed",
                Description =
                    "configuration.php-dist is reachable. It is a template rather than the live " +
                    "configuration, but it discloses deployment details and should not be public.",
                Severity = Severity.Low,
                Confidence = Confidence.Medium,
                Target = context.Target.BaseUrl,
                Url = context.Url("configuration.php-dist"),
                Evidence = new Dictionary<string, string>
                {
                    ["endpoint"] = "configuration.php-dist",
                },
                Remediation = "Block configuration templates and backup files at the web server.",
            });
        }
    }

    private static async Task ProbeDrupalAsync(
        ICheckContext context,
        Dictionary<string, Candidate> candidates,
        CheckResult result,
        HashSet<string> riskKeys)
    {
        var changelog = await TryGetAsync(context, "CHANGELOG.txt", result);
        if (changelog is { IsSuccess: true })
        {
            var match = DrupalChangelogVersion().Match(changelog.Text);
            if (match.Success)
            {
                Add(candidates, "Drupal", match.Groups["version"].Value, Confidence.High, "CHANGELOG.txt");
                AddRisk(result, riskKeys, VersionDisclosureFinding(context, "Drupal", "CHANGELOG.txt"));
            }
        }

        var settings = await TryGetAsync(context, "sites/default/settings.php", result);
        if (settings is { IsSuccess: true }
            && ContainsAny(settings.Text, "$databases", "$settings[", "database =>"))
        {
            AddRisk(result, riskKeys, new Finding
            {
                CheckId = "cms",
                Title = "Drupal settings.php source is exposed",
                Description =
                    "sites/default/settings.php is being served as source. It can contain database " +
                    "credentials and should never be readable over HTTP.",
                Severity = Severity.Critical,
                Confidence = Confidence.High,
                Target = context.Target.BaseUrl,
                Url = context.Url("sites/default/settings.php"),
                Evidence = new Dictionary<string, string>
                {
                    ["endpoint"] = "sites/default/settings.php",
                    ["marker"] = "database configuration",
                },
                Remediation =
                    "Remove the file from the web root, fix the web-server handler and rotate any " +
                    "credentials it contained.",
            });
        }
    }

    private static async Task ProbeMagentoAsync(
        ICheckContext context,
        CheckResult result,
        HashSet<string> riskKeys)
    {
        var local = await TryGetAsync(context, "app/etc/local.xml", result);
        if (local is { IsSuccess: true }
            && ContainsAny(local.Text, "<host>", "<username>", "<password>"))
        {
            AddRisk(result, riskKeys, new Finding
            {
                CheckId = "cms",
                Title = "Magento local.xml configuration is exposed",
                Description =
                    "app/etc/local.xml is being served. It can contain database credentials and " +
                    "encryption keys.",
                Severity = Severity.Critical,
                Confidence = Confidence.High,
                Target = context.Target.BaseUrl,
                Url = context.Url("app/etc/local.xml"),
                Evidence = new Dictionary<string, string>
                {
                    ["endpoint"] = "app/etc/local.xml",
                },
                Remediation =
                    "Block app/etc, remove the file from the web root and rotate database and " +
                    "encryption credentials.",
            });
        }
    }

    private static Finding LoginFinding(ICheckContext context, string cms, string path) => new()
    {
        CheckId = "cms",
        Title = "CMS login panel is exposed",
        Description = $"A {cms} login page is reachable.",
        Severity = Severity.Info,
        Confidence = Confidence.High,
        Target = context.Target.BaseUrl,
        Url = context.Url(path),
        Evidence = new Dictionary<string, string> { ["cms"] = cms, ["path"] = path },
    };

    private static Finding VersionDisclosureFinding(ICheckContext context, string cms, string path) => new()
    {
        CheckId = "cms",
        Title = "CMS version is disclosed",
        Description =
            $"{cms} exposes its exact version through {path}. Version disclosure helps an attacker " +
            "select version-specific payloads and should be removed when practical.",
        Severity = Severity.Low,
        Confidence = Confidence.High,
        Target = context.Target.BaseUrl,
        Url = context.Url(path),
        Evidence = new Dictionary<string, string> { ["cms"] = cms, ["path"] = path },
        Remediation = "Remove or block version-disclosure files and suppress generator metadata.",
    };

    private static void AddRisk(CheckResult result, HashSet<string> keys, Finding finding)
    {
        var key = finding.Title + "|" + finding.Url;
        if (keys.Add(key))
        {
            result.Findings.Add(finding);
        }
    }

    private static async Task<HttpResponseData?> TryGetAsync(
        ICheckContext context,
        string path,
        CheckResult result)
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
            result.Notes.Add($"{path}: {error.Message}");
            return null;
        }
    }

    private static void Add(
        Dictionary<string, Candidate> candidates,
        string name,
        string? version,
        Confidence confidence,
        string evidence)
    {
        if (!candidates.TryGetValue(name, out var candidate))
        {
            candidate = new Candidate(name);
            candidates[name] = candidate;
        }

        candidate.Evidence.Add(evidence);
        if (confidence > candidate.Confidence)
        {
            candidate.Confidence = confidence;
        }

        if (!string.IsNullOrWhiteSpace(version) && string.IsNullOrWhiteSpace(candidate.Version))
        {
            candidate.Version = version.Trim();
        }
    }

    private static string? VersionFrom(string value)
    {
        var match = GeneratorVersion().Match(value);
        return match.Success ? match.Groups["version"].Value : null;
    }

    private static bool ContainsAny(string text, params string[] markers) =>
        markers.Any(marker => text.Contains(marker, StringComparison.OrdinalIgnoreCase));

    private static string Truncate(string value, int length) =>
        Core.StringHelpers.Truncate(value, length);

    private sealed class Candidate(string name)
    {
        public string Name { get; } = name;

        public string? Version { get; set; }

        public Confidence Confidence { get; set; } = Confidence.Low;

        public List<string> Evidence { get; } = [];
    }
}
