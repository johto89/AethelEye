namespace AethelEye.Core.Http;

/// <summary>A page as a real browser received it, including the post-render DOM body.</summary>
public sealed record BrowserPage(
    Uri FinalUri,
    int StatusCode,
    IReadOnlyDictionary<string, string[]> Headers,
    byte[] Body);

/// <summary>
/// Optional browser-backed content fetcher. Checks that need rendered page content use this when
/// <c>--chromium</c> is enabled, because a target may tarpit or block the plain HTTP client while
/// still serving a real browser.
/// </summary>
public interface IBrowserPageFetcher : IAsyncDisposable
{
    /// <summary>False when headless Chromium is not configured or could not start.</summary>
    bool Enabled { get; }

    /// <summary>Fetches one URL in a fresh browser page, or null when no document arrived.</summary>
    Task<BrowserPage?> FetchAsync(Uri uri, CancellationToken cancellationToken);
}
