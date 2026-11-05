namespace AethelEye.Core.Http;

/// <summary>
/// Normalizes proxy values. A bare <c>ipproxy:8080</c> is parsed by <see cref="Uri"/> as a scheme
/// named <c>ipproxy</c>, which breaks <see cref="System.Net.WebProxy"/>; Chromium needs a real
/// proxy URL too. Prefixing <c>http://</c> when no scheme is present keeps both clients consistent.
/// </summary>
public static class ProxyUrl
{
    public static string? Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var text = value.Trim();
        if (!text.Contains("://", StringComparison.Ordinal))
        {
            text = "http://" + text;
        }

        return text;
    }
}
