namespace AethelEye.Cli;

/// <summary>
/// Human-facing mode names. "all" is context aware: a web target adds the five web checks,
/// and --src adds the source check.
/// </summary>
public static class CheckModes
{
    public const string Usage = "all, web, technology, external, source";

    private static readonly string[] DomainChecks = ["dns", "rdap", "subdomains", "social"];
    private static readonly string[] WebChecks =
        ["robots", "sitemap", "cms", "api", "waf", "technology", "security", "exposure", "hidden-paths",
            "backup", .. DomainChecks];
    private static readonly string[] ExternalChecks = ["github", "leaked-accounts"];
    private static readonly string[] AllWebChecks = [.. WebChecks, .. ExternalChecks];

    public static IReadOnlySet<string> Expand(string? mode, bool hasWebTargets, bool hasSources)
    {
        var text = string.IsNullOrWhiteSpace(mode) ? "all" : mode;
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var token = Normalize(raw);
            switch (token)
            {
                case "all":
                    if (hasWebTargets)
                    {
                        result.UnionWith(AllWebChecks);
                    }

                    if (hasSources)
                    {
                        result.Add("source");
                    }

                    if (!hasWebTargets && !hasSources)
                    {
                        throw new ArgumentException(
                            "Nothing to scan. Use --url <domain/url> and/or --src <path>.");
                    }

                    break;

                case "web":
                case "target":
                case "targets":
                    RequireWeb(token, hasWebTargets);
                    result.UnionWith(WebChecks);
                    break;

                case "external":
                case "osint":
                    RequireWeb(token, hasWebTargets);
                    result.UnionWith(ExternalChecks);
                    break;

                case "github":
                case "git":
                    RequireWeb(token, hasWebTargets);
                    result.Add("github");
                    break;

                case "leaked":
                case "leaks":
                case "leaked-account":
                case "leaked-accounts":
                case "leaked-acount":
                    RequireWeb(token, hasWebTargets);
                    result.Add("leaked-accounts");
                    break;

                case "dns":
                    RequireWeb(token, hasWebTargets);
                    result.Add("dns");
                    break;

                case "rdap":
                case "whois":
                    RequireWeb(token, hasWebTargets);
                    result.Add("rdap");
                    break;

                case "subdomain":
                case "subdomains":
                case "ct":
                    RequireWeb(token, hasWebTargets);
                    result.Add("subdomains");
                    break;

                case "social":
                case "contacts":
                    RequireWeb(token, hasWebTargets);
                    result.Add("social");
                    break;

                case "robots":
                    RequireWeb(token, hasWebTargets);
                    result.Add("robots");
                    break;

                case "waf":
                case "wafw00f":
                    RequireWeb(token, hasWebTargets);
                    result.Add("waf");
                    break;

                case "technology":
                case "tech":
                    RequireWeb(token, hasWebTargets);
                    result.Add("technology");
                    // The customer-facing "technology" workflow also covers CMS fingerprints
                    // and default management/API/debug pages.
                    result.Add("cms");
                    result.Add("exposure");
                    break;

                case "sitemap":
                    RequireWeb(token, hasWebTargets);
                    result.Add("sitemap");
                    break;

                case "api":
                case "api-recon":
                case "endpoint":
                case "endpoints":
                    RequireWeb(token, hasWebTargets);
                    result.Add("api");
                    break;

                case "backup":
                case "backups":
                case "backup-files":
                    RequireWeb(token, hasWebTargets);
                    result.Add("backup");
                    break;

                case "security":
                case "headers":
                case "cookies":
                    RequireWeb(token, hasWebTargets);
                    result.Add("security");
                    break;

                case "cms":
                case "wordpress":
                case "joomla":
                case "drupal":
                case "magento":
                    RequireWeb(token, hasWebTargets);
                    result.Add("cms");
                    break;

                case "exposure":
                case "default-pages":
                case "default":
                case "swagger":
                case "openapi":
                case "actuator":
                case "tomcat":
                case "debug":
                    RequireWeb(token, hasWebTargets);
                    result.Add("exposure");
                    break;

                case "hidden":
                case "hidden-path":
                case "hidden-paths":
                case "paths":
                    RequireWeb(token, hasWebTargets);
                    result.Add("hidden-paths");
                    break;

                case "source":
                case "src":
                case "code":
                case "deps":
                case "dependency":
                case "dependencies":
                case "dependency-check":
                case "dc":
                case "owasp":
                    if (!hasSources)
                    {
                        throw new ArgumentException(
                            "Mode 'source' requires --src <file|zip|directory> " +
                            "or a 'sources' entry in the engagement file.");
                    }

                    result.Add("source");
                    break;

                default:
                    throw new ArgumentException(
                        $"Unknown mode '{raw}'. Use: {Usage}.");
            }
        }

        return result;
    }

    private static void RequireWeb(string mode, bool hasWebTargets)
    {
        if (!hasWebTargets)
        {
            throw new ArgumentException(
                $"Mode '{mode}' needs a web target. Add --url <domain/url> " +
                "or pass a URL positionally.");
        }
    }

    private static string Normalize(string value) =>
        value.Trim().ToLowerInvariant().Replace('_', '-');
}
