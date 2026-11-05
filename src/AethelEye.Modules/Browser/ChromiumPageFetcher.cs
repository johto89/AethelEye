using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;
using WappalyzerSharp.Headless;

namespace AethelEye.Modules.Browser;

/// <summary>
/// Shared headless-Chromium content fetcher used by page-based checks when <c>--chromium</c> is
/// enabled. One browser is launched per scan and a fresh page is used for each URL. Navigation and
/// document reading have separate budgets so a page that never fires <c>load</c> can still be read.
/// </summary>
public sealed class ChromiumPageFetcher(Engagement engagement, ILog log) : IBrowserPageFetcher
{
    private readonly SemaphoreSlim _launchGate = new(1, 1);
    private readonly SemaphoreSlim _fetchGate =
        new(Math.Clamp(Environment.ProcessorCount, 2, 6));
    private ChromiumBrowser? _browser;
    private bool _unavailable;

    public bool Enabled => engagement.Browser.Headless && !_unavailable;

    public async Task<BrowserPage?> FetchAsync(Uri uri, CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            return null;
        }

        await _fetchGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await FetchCoreAsync(uri, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _fetchGate.Release();
        }
    }

    private async Task<BrowserPage?> FetchCoreAsync(Uri uri, CancellationToken cancellationToken)
    {
        var browser = await GetBrowserAsync(cancellationToken).ConfigureAwait(false);
        if (browser is null)
        {
            return null;
        }

        var limit = TimeSpan.FromSeconds(
            Math.Clamp(engagement.Browser.TimeoutSeconds, 5, 300));
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lifetime.CancelAfter(limit + limit + TimeSpan.FromSeconds(5));

        CdpPage? tab = null;
        try
        {
            tab = await browser.NewPageAsync(lifetime.Token).ConfigureAwait(false);
            var headers = BrowserHeaderPolicy.Build(engagement.Http.Headers, engagement.Http.Evasion);
            if (headers.Count > 0)
            {
                await tab.SetExtraHeadersAsync(headers, lifetime.Token).ConfigureAwait(false);
            }

            if (engagement.Browser.SameOriginOnly)
            {
                await tab.RestrictToOriginAsync(uri, lifetime.Token).ConfigureAwait(false);
            }

            BrowserDocument? document = null;
            try
            {
                using (var load = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token))
                {
                    load.CancelAfter(TimeSpan.FromMilliseconds(limit.TotalMilliseconds * 0.7));
                    try
                    {
                        await tab.NavigateAsync(uri, load.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (!lifetime.IsCancellationRequested)
                    {
                        // Slow assets must not discard a document the browser already has.
                    }
                }

                using var documentTimeout =
                    CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                documentTimeout.CancelAfter(limit);

                document = await tab.ReadDocumentAsync(
                    engagement.Http.MaxBodyBytes,
                    documentTimeout.Token).ConfigureAwait(false);
            }
            catch (CdpException) when (!lifetime.IsCancellationRequested)
            {
                // A download (.zip/.sql) aborts the navigation with ERR_ABORTED, and a 4xx/5xx
                // may have no document. Load the resource directly through the network stack.
            }

            if (document is null)
            {
                using var resourceTimeout =
                    CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                resourceTimeout.CancelAfter(limit);
                document = await tab.FetchResourceAsync(
                    uri,
                    engagement.Http.MaxBodyBytes,
                    resourceTimeout.Token).ConfigureAwait(false);
            }

            if (document is null)
            {
                return null;
            }

            return new BrowserPage(
                document.Url,
                document.StatusCode,
                document.Headers,
                document.Body);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            log.Warn($"Browser fetch failed for {uri}: {error.Message}");
            return null;
        }
        finally
        {
            if (tab is not null)
            {
                await tab.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task<ChromiumBrowser?> GetBrowserAsync(CancellationToken cancellationToken)
    {
        if (_browser is not null)
        {
            return _browser;
        }

        if (_unavailable)
        {
            return null;
        }

        await _launchGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_browser is not null)
            {
                return _browser;
            }

            if (_unavailable)
            {
                return null;
            }

            try
            {
                var userAgent = engagement.Http.Evasion || engagement.Http.RandomUserAgent
                    ? EvasionProfile.NextUserAgent()
                    : engagement.Browser.UserAgent;
                _browser = await ChromiumBrowser.LaunchAsync(
                    new ChromiumOptions
                    {
                        ExecutablePath = engagement.Browser.ChromiumPath,
                        DisableSandbox = engagement.Browser.DisableSandbox,
                        IgnoreCertificateErrors = engagement.Http.Insecure,
                        ProxyServer = ProxyUrl.Normalize(engagement.Http.Proxy),
                        UserAgent = userAgent,
                        StartupTimeout = TimeSpan.FromSeconds(30),
                    },
                    cancellationToken).ConfigureAwait(false);
                log.Info("Headless Chromium started for browser-backed content checks.");
                return _browser;
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                _unavailable = true;
                log.Warn("Headless Chromium could not start: " + error.Message);
                return null;
            }
        }
        finally
        {
            _launchGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_browser is not null)
        {
            await _browser.DisposeAsync().ConfigureAwait(false);
            _browser = null;
        }

        _fetchGate.Dispose();
        _launchGate.Dispose();
    }
}
