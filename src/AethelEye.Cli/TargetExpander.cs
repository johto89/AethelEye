using System.Net;
using System.Net.Sockets;

namespace AethelEye.Cli;

/// <summary>
/// Expands target values so one engagement can cover a whole IPv4 range and several application
/// paths per host. Accepted forms:
/// <list type="bullet">
/// <item><c>10.0.0.0/24</c> (CIDR)</item>
/// <item><c>10.0.0.1-10.0.0.20</c> (inclusive range)</item>
/// <item><c>10.0.0.*</c> (wildcard)</item>
/// <item><c>10.0.0.5</c> (single address)</item>
/// <item><c>http://10.0.0.5/abc</c> (normal URL, left untouched)</item>
/// </list>
/// A range uses <c>http://</c> by default; prefix it with <c>https://</c> to change the scheme.
/// </summary>
public static class TargetExpander
{
    /// <summary>Safety cap so a typo such as /8 cannot launch an accidental mass scan.</summary>
    public const int MaxHostsPerRange = 4096;

    public static IReadOnlyList<string> Expand(
        IEnumerable<string> targets,
        IEnumerable<string>? paths = null)
    {
        var normalizedPaths = NormalizePaths(paths);
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string url)
        {
            if (seen.Add(url))
            {
                result.Add(url);
            }
        }

        foreach (var raw in targets)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            var value = raw.Trim();
            if (TryExpandRange(value, out var hosts))
            {
                foreach (var host in hosts)
                {
                    if (normalizedPaths.Count == 0)
                    {
                        Add(host);
                    }
                    else
                    {
                        foreach (var path in normalizedPaths)
                        {
                            Add(host + path);
                        }
                    }
                }

                continue;
            }

            var url = value.Contains("://", StringComparison.Ordinal) ? value : "https://" + value;
            if (normalizedPaths.Count > 0 && IsRootUrl(url))
            {
                var root = url.TrimEnd('/');
                foreach (var path in normalizedPaths)
                {
                    Add(root + path);
                }
            }
            else
            {
                Add(url);
            }
        }

        return result;
    }

    private static List<string> NormalizePaths(IEnumerable<string>? paths)
    {
        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in paths ?? [])
        {
            foreach (var part in raw.Split(
                         ',',
                         StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var path = part.Trim();
                if (path.Length == 0 || path == "/")
                {
                    continue;
                }

                if (!path.StartsWith('/'))
                {
                    path = "/" + path;
                }

                path = path.TrimEnd('/');
                if (path.Length > 0 && seen.Add(path))
                {
                    result.Add(path);
                }
            }
        }

        return result;
    }

    private static bool IsRootUrl(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri)
        && (uri.AbsolutePath.Length == 0 || uri.AbsolutePath == "/");

    private static bool TryExpandRange(string value, out List<string> hosts)
    {
        hosts = [];
        var scheme = "http";
        var text = value.Trim();

        if (text.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            text = text[7..];
        }
        else if (text.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            scheme = "https";
            text = text[8..];
        }

        text = text.TrimEnd('/');
        if (text.Length == 0)
        {
            return false;
        }

        // CIDR: 10.0.0.0/24. A normal URL with a numeric path is rare, but a scheme-less value is
        // unambiguous, which is the form documented for ranges.
        var slash = text.LastIndexOf('/');
        if (slash > 0
            && int.TryParse(text[(slash + 1)..], out var prefix)
            && prefix is >= 0 and <= 32
            && IPAddress.TryParse(text[..slash], out var network)
            && network.AddressFamily == AddressFamily.InterNetwork)
        {
            return ExpandCidr(network, prefix, scheme, hosts);
        }

        // Inclusive range: 10.0.0.1-10.0.0.20
        var dash = text.IndexOf('-');
        if (dash > 0
            && IPAddress.TryParse(text[..dash], out var start)
            && IPAddress.TryParse(text[(dash + 1)..], out var end)
            && start.AddressFamily == AddressFamily.InterNetwork
            && end.AddressFamily == AddressFamily.InterNetwork)
        {
            return ExpandInclusive(start, end, scheme, hosts);
        }

        // Wildcard: 10.0.0.*
        if (text.Contains('*'))
        {
            return ExpandWildcard(text, scheme, hosts);
        }

        // Single address.
        if (IPAddress.TryParse(text, out var single)
            && single.AddressFamily == AddressFamily.InterNetwork)
        {
            hosts.Add($"{scheme}://{single}");
            return true;
        }

        return false;
    }

    private static bool ExpandCidr(
        IPAddress network,
        int prefix,
        string scheme,
        List<string> hosts)
    {
        uint address = ToUInt(network);
        int hostBits = 32 - prefix;
        long size = 1L << hostBits;
        long first = address;
        long last = address + size - 1;

        // Usable hosts for a normal subnet; /31 and /32 keep every address.
        if (prefix <= 30)
        {
            first++;
            last--;
        }

        if (last < first)
        {
            return false;
        }

        var count = last - first + 1;
        if (count > MaxHostsPerRange)
        {
            throw new ArgumentException(
                $"{network}/{prefix} expands to {count} hosts, above the {MaxHostsPerRange} " +
                "host safety cap. Split it into smaller ranges.");
        }

        for (var current = first; current <= last; current++)
        {
            hosts.Add($"{scheme}://{FromUInt((uint)current)}");
        }

        return true;
    }

    private static bool ExpandInclusive(
        IPAddress start,
        IPAddress end,
        string scheme,
        List<string> hosts)
    {
        uint first = ToUInt(start);
        uint last = ToUInt(end);
        if (last < first)
        {
            throw new ArgumentException($"IP range start {start} is after its end {end}.");
        }

        var count = (long)last - first + 1;
        if (count > MaxHostsPerRange)
        {
            throw new ArgumentException(
                $"{start}-{end} expands to {count} hosts, above the {MaxHostsPerRange} host " +
                "safety cap. Split it into smaller ranges.");
        }

        for (var current = first; current <= last; current++)
        {
            hosts.Add($"{scheme}://{FromUInt(current)}");
        }

        return true;
    }

    private static bool ExpandWildcard(string value, string scheme, List<string> hosts)
    {
        var parts = value.Split('.');
        if (parts.Length != 4)
        {
            return false;
        }

        var octets = new int[4];
        for (var index = 0; index < parts.Length; index++)
        {
            if (parts[index] == "*")
            {
                octets[index] = -1;
            }
            else if (!int.TryParse(parts[index], out octets[index])
                     || octets[index] is < 0 or > 255)
            {
                return false;
            }
        }

        var candidates = new List<string>();
        for (var a = OctetStart(octets[0], 0); a <= OctetEnd(octets[0], 0); a++)
        {
            for (var b = OctetStart(octets[1], 1); b <= OctetEnd(octets[1], 1); b++)
            {
                for (var c = OctetStart(octets[2], 2); c <= OctetEnd(octets[2], 2); c++)
                {
                    for (var d = OctetStart(octets[3], 3); d <= OctetEnd(octets[3], 3); d++)
                    {
                        candidates.Add($"{scheme}://{a}.{b}.{c}.{d}");
                        if (candidates.Count > MaxHostsPerRange)
                        {
                            throw new ArgumentException(
                                $"{value} expands to more than {MaxHostsPerRange} hosts. " +
                                "Use a smaller wildcard or an explicit range.");
                        }
                    }
                }
            }
        }

        hosts.AddRange(candidates);
        return true;
    }

    // A wildcard in the last octet usually means "all usable hosts", so skip .0 and .255 there.
    private static int OctetStart(int value, int index) => value >= 0 ? value : index == 3 ? 1 : 0;

    private static int OctetEnd(int value, int index) => value >= 0 ? value : index == 3 ? 254 : 255;

    private static uint ToUInt(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    private static IPAddress FromUInt(uint value) =>
        new([(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value]);
}
