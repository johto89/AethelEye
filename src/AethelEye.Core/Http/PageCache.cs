using System.Collections.Concurrent;

namespace AethelEye.Core.Http;

/// <summary>
/// Per-target page cache. Uses ConcurrentDictionary with Lazy to guarantee each URL is fetched
/// exactly once, even under concurrent access from multiple checks.
/// When a browser fetcher is enabled it is tried first: a target that tarpits the plain HTTP client
/// still serves the page to Chromium. If the browser gets no document the HTTP client is used.
/// </summary>
public sealed class PageCache(IScopedHttpClient http, IBrowserPageFetcher? browser = null)
{
    private readonly ConcurrentDictionary<string, Lazy<Task<HttpResponseData>>> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    public async Task<HttpResponseData> GetAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        var key = uri.ToString();
        var lazy = _cache.GetOrAdd(
            key,
            _ => new Lazy<Task<HttpResponseData>>(() => FetchAsync(uri, cancellationToken)));

        try
        {
            return await lazy.Value.ConfigureAwait(false);
        }
        catch
        {
            // Do not poison the cache for later checks with a cancelled or failed fetch.
            _cache.TryRemove(new KeyValuePair<string, Lazy<Task<HttpResponseData>>>(key, lazy));
            throw;
        }
    }

    public Task<HttpResponseData> GetAsync(string url, CancellationToken cancellationToken = default) =>
        GetAsync(new Uri(url, UriKind.Absolute), cancellationToken);

    private async Task<HttpResponseData> FetchAsync(Uri uri, CancellationToken cancellationToken)
    {
        if (browser is { Enabled: true })
        {
            BrowserPage? page = null;
            try
            {
                page = await browser.FetchAsync(uri, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                page = null;
            }

            if (page is not null && page.StatusCode > 0)
            {
                return new HttpResponseData
                {
                    RequestUri = uri,
                    FinalUri = page.FinalUri,
                    StatusCode = page.StatusCode,
                    Headers = page.Headers,
                    Body = page.Body,
                    ContentType = HeaderValue(page.Headers, "Content-Type"),
                };
            }
        }

        return await http.GetAsync(uri, cancellationToken).ConfigureAwait(false);
    }

    private static string? HeaderValue(IReadOnlyDictionary<string, string[]> headers, string name) =>
        headers.TryGetValue(name, out var values) ? string.Join(", ", values) : null;
}
