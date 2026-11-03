using AethelEye.Core.Models;

namespace AethelEye.Core.Http;

/// <summary>
/// Request shaping for authorized WAF/IDS/IPS testing. The profile lowers the request rate,
/// adds jitter and presents ordinary browser headers. It reduces obvious scanner signatures;
/// it is not a guarantee that a particular device can be bypassed.
/// </summary>
public static class EvasionProfile
{
    private static readonly string[] BrowserUserAgents =
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    ];

    private static readonly string[] Languages =
    [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9",
        "en-US,en;q=0.8,vi;q=0.6",
    ];

    public static string NextUserAgent() => BrowserUserAgents[Random.Shared.Next(BrowserUserAgents.Length)];

    public static string NextLanguage() => Languages[Random.Shared.Next(Languages.Length)];

    /// <summary>Applies the profile to settings. Values explicitly set lower by the user are kept.</summary>
    public static void Apply(HttpSettings settings)
    {
        settings.Evasion = true;
        settings.RandomUserAgent = true;
        settings.RequestsPerSecond = Math.Clamp(settings.RequestsPerSecond, 1, 2);
        settings.Retries = Math.Max(settings.Retries, 2);
        settings.Headers["Accept"] =
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
        settings.Headers["Accept-Language"] = NextLanguage();
        settings.Headers["Cache-Control"] = "no-cache";
        settings.Headers["Pragma"] = "no-cache";
        settings.Headers["Upgrade-Insecure-Requests"] = "1";
    }

    /// <summary>Headers that make a request look like a top-level browser navigation.</summary>
    public static IReadOnlyDictionary<string, string> NavigationHeaders(Uri target)
    {
        var origin = target.GetLeftPart(UriPartial.Authority);
        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            ["Accept-Language"] = NextLanguage(),
            ["Cache-Control"] = "no-cache",
            ["Pragma"] = "no-cache",
            ["Referer"] = origin + "/",
            ["Upgrade-Insecure-Requests"] = "1",
            ["Sec-Fetch-Dest"] = "document",
            ["Sec-Fetch-Mode"] = "navigate",
            ["Sec-Fetch-Site"] = "same-origin",
            ["Sec-Fetch-User"] = "?1",
        };
    }
}
