using System.Collections.Concurrent;

namespace AethelEye.Core.Http;

/// <summary>
/// Per-target page cache. Uses ConcurrentDictionary with Lazy to guarantee each URL is fetched
/// exactly once, even under concurrent access from multiple checks.
/// </summary>
public sealed class PageCache(IScopedHttpClient http)
{
    private readonly ConcurrentDictionary<string, Lazy<Task<HttpResponseData>>> _cache = new(StringComparer.OrdinalIgnoreCase);

    public Task<HttpResponseData> GetAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        var key = uri.ToString();
        var lazy = _cache.GetOrAdd(key, _ => new Lazy<Task<HttpResponseData>>(
            () => http.GetAsync(uri, cancellationToken)));
        return lazy.Value;
    }

    public Task<HttpResponseData> GetAsync(string url, CancellationToken cancellationToken = default) =>
        GetAsync(new Uri(url, UriKind.Absolute), cancellationToken);
}
