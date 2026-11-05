namespace AethelEye.Core.Http;

/// <summary>
/// Content headers belong on <see cref="System.Net.Http.HttpContent"/>, not on
/// <see cref="System.Net.Http.HttpRequestMessage"/>. Calling
/// <see cref="System.Net.Http.Headers.HttpHeaders.Remove(string)"/> (or <c>Add</c>) with one of
/// these names against request headers throws <see cref="InvalidOperationException"/>
/// ("Misused header name"), so any header name taken from user input — a Burp capture passed via
/// <c>--authen</c>, or an engagement/appsettings header — must be filtered through
/// <see cref="IsContentHeader"/> first.
/// </summary>
public static class RequestHeaderPolicy
{
    private static readonly HashSet<string> ContentHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Allow",
        "Content-Disposition",
        "Content-Encoding",
        "Content-Language",
        "Content-Length",
        "Content-Location",
        "Content-MD5",
        "Content-Range",
        "Content-Type",
        "Expires",
        "Last-Modified",
    };

    /// <summary>True when <paramref name="name"/> is a content header and must not be applied to a request.</summary>
    public static bool IsContentHeader(string name) => ContentHeaders.Contains(name);
}
