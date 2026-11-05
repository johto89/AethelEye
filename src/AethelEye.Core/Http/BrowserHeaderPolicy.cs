namespace AethelEye.Core.Http;

/// <summary>
/// Decides which engagement headers may be replayed into a headless browser. Auth material such as
/// <c>Cookie</c>, <c>Authorization</c> and custom <c>X-*</c> headers is useful; navigation headers
/// from a Burp API capture (<c>Accept: application/json</c>, <c>Referer</c>, <c>Origin</c>, ...)
/// would make the browser request the wrong representation or trip CSRF/WAF rules, so they are
/// left to Chromium.
/// </summary>
public static class BrowserHeaderPolicy
{
    private static readonly HashSet<string> NotForwarded = new(StringComparer.OrdinalIgnoreCase)
    {
        "Accept",
        "Accept-Encoding",
        "Accept-Language",
        "Cache-Control",
        "Connection",
        "DNT",
        "Host",
        "HTTP2-Settings",
        "Keep-Alive",
        "Origin",
        "Pragma",
        "Proxy-Connection",
        "Range",
        "Referer",
        "Save-Data",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Upgrade-Insecure-Requests",
        "User-Agent",
        "Via",
        "Viewport-Width",
        "Width",
    };

    /// <summary>True when <paramref name="name"/> is safe and useful for a browser navigation.</summary>
    public static bool ShouldForward(string name)
    {
        if (RequestHeaderPolicy.IsContentHeader(name) || NotForwarded.Contains(name))
        {
            return false;
        }

        // Sec-* describes the browser's own request and If-* is conditional-cache state.
        return !name.StartsWith("Sec-", StringComparison.OrdinalIgnoreCase)
               && !name.StartsWith("If-", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Builds the header list for a browser page, including the optional evasion language.</summary>
    public static List<(string Name, string Value)> Build(
        IEnumerable<KeyValuePair<string, string>> headers,
        bool evasion)
    {
        var result = new List<(string Name, string Value)>();
        foreach (var (name, value) in headers)
        {
            if (ShouldForward(name))
            {
                result.Add((name, value));
            }
        }

        if (evasion)
        {
            result.Add(("Accept-Language", EvasionProfile.NextLanguage()));
        }

        return result;
    }
}
