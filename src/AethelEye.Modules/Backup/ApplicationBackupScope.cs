using AethelEye.Core.Abstractions;

namespace AethelEye.Modules.Backup;

internal sealed record ApplicationBackupCandidate(string UrlPath, string Token, bool SiteRoot);

/// <summary>
/// Builds the name-based backup candidates for one application automatically, without any
/// name-token option. The application stem comes from the target's last path segment; the
/// complete host is the second stem. Each is probed at fixed locations only:
/// <list type="bullet">
///   <item>application stem inside: /usertest/usertest.zip</item>
///   <item>application stem next to it: /usertest.zip</item>
///   <item>host stem inside: /usertest/192.168.1.2.zip</item>
///   <item>host stem at the web root: /192.168.1.2.zip</item>
/// </list>
/// No wrappers, joined names or sibling application names are generated. An IP address is used
/// whole and never split into octets.
/// </summary>
internal static class ApplicationBackupScope
{
    public static readonly string[] ArchiveExtensions =
    [
        ".zip", ".rar", ".tar.gz", ".tgz", ".tar", ".7z",
    ];

    public static IReadOnlyList<ApplicationBackupCandidate> Build(ICheckContext context)
    {
        var basePath = context.Target.BaseUri.AbsolutePath.TrimEnd('/');
        var parentPath = ParentPath(basePath);
        var host = Clean(context.Target.Host);
        var candidates = new List<ApplicationBackupCandidate>();

        var appStem = basePath.Split('/', StringSplitOptions.RemoveEmptyEntries).LastOrDefault();
        if (appStem is not null)
        {
            // Strip a file extension so /abc/find and /abc/find.php both use "find".
            var dot = appStem.LastIndexOf('.');
            if (dot > 0)
            {
                appStem = appStem[..dot];
            }

            appStem = Clean(appStem);
        }
        else
        {
            // Root target: the host itself is the application name.
            appStem = host;
        }

        foreach (var extension in ArchiveExtensions)
        {
            if (appStem.Length > 1)
            {
                // Inside the application: /usertest/usertest.zip
                Add(candidates, basePath + "/" + appStem + extension, appStem, siteRoot: false);

                // Next to the application: /usertest.zip, /abc/find.zip
                Add(candidates, parentPath + "/" + appStem + extension, appStem, siteRoot: basePath.Length > 0);
            }

            if (host.Length > 1)
            {
                // Host name inside the application: /usertest/192.168.1.2.zip
                Add(candidates, basePath + "/" + host + extension, host, siteRoot: false);

                // Host name at the web root: /192.168.1.2.zip
                Add(candidates, "/" + host + extension, host, siteRoot: true);
            }
        }

        return candidates
            .DistinctBy(candidate => candidate.UrlPath, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static void Add(
        List<ApplicationBackupCandidate> candidates,
        string urlPath,
        string token,
        bool siteRoot) =>
        candidates.Add(new ApplicationBackupCandidate(urlPath, token, siteRoot));

    private static string ParentPath(string basePath)
    {
        if (basePath.Length == 0)
        {
            return string.Empty;
        }

        var slash = basePath.LastIndexOf('/');
        return slash <= 0 ? string.Empty : basePath[..slash];
    }

    private static string Clean(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return new string(value.Trim()
            .Select(character =>
                char.IsLetterOrDigit(character) || character is '.' or '-' or '_'
                    ? character
                    : '-')
            .ToArray())
            .Trim('-', '.', '_');
    }
}
