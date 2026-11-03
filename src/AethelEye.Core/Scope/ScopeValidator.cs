using System.Net;
using AethelEye.Core.Models;

namespace AethelEye.Core.Scope;

/// <summary>
/// The boundary that every target request and redirect must cross. Host allow/deny lists are the
/// primary control; private address literals and local names are denied unless explicitly enabled.
/// </summary>
public sealed class ScopeValidator
{
    private readonly ScopeSettings _settings;
    private readonly List<string> _allowedHosts;

    public ScopeValidator(ScopeSettings settings, IEnumerable<Target> targets)
    {
        _settings = settings;
        var allowed = settings.AllowedHosts ?? [];
        _allowedHosts = allowed.Count > 0
            ? allowed.Select(NormalizePattern).Where(pattern => pattern.Length > 0).ToList()
            : targets.Select(target => NormalizePattern(target.Host)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public IReadOnlyList<string> AllowedHosts => _allowedHosts;

    public bool AllowPrivateAddresses => _settings.AllowPrivateAddresses;

    public bool IsAllowed(Uri uri) => Check(uri) is null;

    public void Validate(Uri uri)
    {
        var reason = Check(uri);
        if (reason is not null)
        {
            throw new ScopeViolationException(uri, reason);
        }
    }

    public string? Check(Uri uri)
    {
        if (uri.Scheme is not ("http" or "https"))
        {
            return $"scheme '{uri.Scheme}' is outside the engagement";
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            return "URLs with embedded credentials are not allowed";
        }

        if (!_settings.AllowNonStandardPorts && uri.Port is not (80 or 443))
        {
            return $"port {uri.Port} is outside the engagement";
        }

        var host = uri.IdnHost.TrimEnd('.').ToLowerInvariant();

        if (MatchesAny(host, _settings.ExcludedHosts ?? []))
        {
            return $"host '{host}' is explicitly excluded";
        }

        if (!MatchesAny(host, _allowedHosts))
        {
            return $"host '{host}' is not in the allowed scope";
        }

        if (!_settings.AllowPrivateAddresses && IsPrivateOrLocal(host))
        {
            return $"host '{host}' resolves to a private or local address";
        }

        return null;
    }

    public static bool IsPrivateOrLocal(string host)
    {
        if (host is "localhost" or "localhost.localdomain"
            || host.EndsWith(".localhost", StringComparison.Ordinal)
            || host.EndsWith(".local", StringComparison.Ordinal)
            || host.EndsWith(".internal", StringComparison.Ordinal)
            || host.EndsWith(".lan", StringComparison.Ordinal)
            || host.EndsWith(".home", StringComparison.Ordinal)
            || host.EndsWith(".corp", StringComparison.Ordinal))
        {
            return true;
        }

        return IPAddress.TryParse(host, out var address) && IsPrivateAddress(address);
    }

    public static bool IsPrivateAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            return true;
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast)
            {
                return true;
            }

            var v6 = address.GetAddressBytes();
            return (v6[0] & 0xFE) == 0xFC; // fc00::/7 unique local
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == 0
            || bytes[0] == 10
            || bytes[0] == 127
            || (bytes[0] == 169 && bytes[1] == 254)
            || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
            || (bytes[0] == 192 && bytes[1] == 168)
            || (bytes[0] == 100 && bytes[1] is >= 64 and <= 127);
    }

    private bool MatchesAny(string host, IEnumerable<string> patterns) =>
        patterns.Any(pattern => Matches(host, pattern));

    private bool Matches(string host, string pattern)
    {
        if (pattern.StartsWith("*.", StringComparison.Ordinal))
        {
            var suffix = pattern[2..];
            return host.Equals(suffix, StringComparison.OrdinalIgnoreCase)
                || host.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase);
        }

        if (host.Equals(pattern, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return _settings.IncludeSubdomains
            && host.EndsWith("." + pattern, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePattern(string value)
    {
        var text = value.Trim().ToLowerInvariant();
        if (text.Contains("://", StringComparison.Ordinal) && Uri.TryCreate(text, UriKind.Absolute, out var uri))
        {
            text = uri.IdnHost;
        }

        return text.TrimEnd('.');
    }
}

public sealed class ScopeViolationException(Uri uri, string reason)
    : Exception($"Out of scope: {uri} ({reason})")
{
    public Uri Uri { get; } = uri;

    public string Reason { get; } = reason;
}
