using AethelEye.Core.Abstractions;
using AethelEye.Modules.Api;
using AethelEye.Modules.Backup;
using AethelEye.Modules.Cms;
using AethelEye.Modules.Exposure;
using AethelEye.Modules.GitHub;
using AethelEye.Modules.HiddenPaths;
using AethelEye.Modules.LeakedAccounts;
using AethelEye.Modules.Recon;
using AethelEye.Modules.Robots;
using AethelEye.Modules.Security;
using AethelEye.Modules.Seo;
using AethelEye.Modules.Source;
using AethelEye.Modules.Technology;
using AethelEye.Modules.Waf;

namespace AethelEye.Modules;

/// <summary>The default pipeline, in the same order as the assessment checklist.</summary>
public static class CheckCatalog
{
    public static IReadOnlyList<ICheck> CreateAll() =>
    [
        new DnsReconCheck(),
        new RdapCheck(),
        new SubdomainCheck(),
        new RobotsCheck(),
        new SitemapCheck(),
        new ApiReconCheck(),
        new CmsCheck(),
        new WafCheck(),
        new TechnologyCheck(),
        new SecurityCheck(),
        new SocialCheck(),
        new ExposureCheck(),
        new HiddenPathCheck(),
        new BackupCheck(),
        new SourceCheck(),
        new GitHubCheck(),
        new LeakedAccountsCheck(),
    ];

    public static IReadOnlyDictionary<string, string> Describe() =>
        CreateAll().ToDictionary(check => check.Id, check => check.Description, StringComparer.OrdinalIgnoreCase);
}
