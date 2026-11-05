using AethelEye.Core.Scope;

namespace AethelEye.Core.Http;

/// <summary>
/// Routes target GET requests through headless Chromium first and falls back to the HTTP client.
/// A UAT target can tarpit or fingerprint the .NET client while still serving a real browser; the
/// browser result is mapped back to <see cref="HttpResponseData"/> so existing checks keep working.
/// Non-GET traffic stays on the HTTP client.
/// </summary>
public sealed class BrowserFirstHttpClient(
    IScopedHttpClient inner,
    IBrowserPageFetcher browser,
    ScopeValidator scope) : IScopedHttpClient
{
    public async Task<HttpResponseData> GetAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        if (browser.Enabled && scope.IsAllowed(uri))
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

        return await inner.GetAsync(uri, cancellationToken).ConfigureAwait(false);
    }

    public Task<HttpResponseData> GetAsync(string url, CancellationToken cancellationToken = default) =>
        GetAsync(new Uri(url, UriKind.Absolute), cancellationToken);

    public Task<HttpResponseData> SendAsync(
        Uri uri,
        HttpMethod method,
        CancellationToken cancellationToken = default) =>
        inner.SendAsync(uri, method, cancellationToken);

    public void Dispose()
    {
        // The wrapped client is owned by the orchestrator, which also disposes the browser.
    }

    private static string? HeaderValue(IReadOnlyDictionary<string, string[]> headers, string name) =>
        headers.TryGetValue(name, out var values) ? string.Join(", ", values) : null;
}
