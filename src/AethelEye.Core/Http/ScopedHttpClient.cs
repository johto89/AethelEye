using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Models;
using AethelEye.Core.Scope;

namespace AethelEye.Core.Http;

/// <summary>
/// The only client used against target hosts. Redirects are followed manually so every hop is
/// checked against the engagement scope instead of trusting HttpClient's automatic behaviour.
/// </summary>
public sealed class ScopedHttpClient : IScopedHttpClient
{
    private readonly HttpClient _client;
    private readonly HttpSettings _settings;
    private readonly ScopeValidator _scope;
    private readonly ILog _log;
    private readonly AsyncRateLimiter _limiter;

    public ScopedHttpClient(HttpSettings settings, ScopeValidator scope, ILog log)
    {
        _settings = settings;
        _scope = scope;
        _log = log;
        _limiter = new AsyncRateLimiter(settings.RequestsPerSecond);

        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            // Match a real browser (and wapsharp): use the system proxy by default. A machine
            // that can only reach the UAT network through the corporate proxy works without
            // --proxy. An explicit --proxy/appsettings value overrides the system proxy.
            UseProxy = true,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(Math.Min(Math.Max(settings.TimeoutSeconds, 1), 15)),
            MaxResponseHeadersLength = 256,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        };

        if (!string.IsNullOrWhiteSpace(settings.Proxy))
        {
            handler.Proxy = new WebProxy(new Uri(ProxyUrl.Normalize(settings.Proxy)!));
        }
        else
        {
            // Resolve at connect time so a redirect or DNS change cannot reach a private address.
            handler.ConnectCallback = ConnectAsync;
        }

        if (settings.Insecure)
        {
            handler.SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            };
        }

        _client = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan,
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        };

        HttpRequestHeaders headers = _client.DefaultRequestHeaders;
        headers.TryAddWithoutValidation("User-Agent", settings.UserAgent);
        headers.TryAddWithoutValidation("Accept", "*/*");
        foreach (var (name, value) in settings.Headers ?? [])
        {
            if (RequestHeaderPolicy.IsContentHeader(name))
            {
                continue;
            }

            headers.Remove(name);
            headers.TryAddWithoutValidation(name, value);
        }
    }

    public Task<HttpResponseData> GetAsync(string url, CancellationToken cancellationToken = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException($"Not an absolute URL: {url}", nameof(url));
        }

        return GetAsync(uri, cancellationToken);
    }

    public Task<HttpResponseData> GetAsync(Uri uri, CancellationToken cancellationToken = default) =>
        SendAsync(uri, HttpMethod.Get, cancellationToken);

    public async Task<HttpResponseData> SendAsync(
        Uri uri,
        HttpMethod method,
        CancellationToken cancellationToken = default)
    {
        Exception? lastError = null;
        var attempts = Math.Max(0, _settings.Retries);

        for (var attempt = 0; attempt <= attempts; attempt++)
        {
            try
            {
                var result = await SendOnceAsync(uri, method, cancellationToken);
                if (IsTransient(result.StatusCode) && attempt < attempts)
                {
                    _log.Debug($"{method} {uri} -> HTTP {result.StatusCode}; retry {attempt + 1}/{attempts}");
                    await Task.Delay(Backoff(attempt), cancellationToken);
                    continue;
                }

                return result;
            }
            catch (ScopeViolationException)
            {
                throw;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error) when (IsTransient(error))
            {
                lastError = error;
                if (attempt >= attempts)
                {
                    break;
                }

                _log.Debug($"{method} {uri} failed ({error.Message}); retry {attempt + 1}/{attempts}");
                await Task.Delay(Backoff(attempt), cancellationToken);
            }
        }

        throw new HttpRequestException($"Request failed after {attempts + 1} attempt(s): {uri}", lastError);
    }

    private async Task<HttpResponseData> SendOnceAsync(
        Uri uri,
        HttpMethod method,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, _settings.TimeoutSeconds)));

        var started = Stopwatch.StartNew();
        var current = uri;

        for (var redirect = 0; redirect <= _settings.MaxRedirects; redirect++)
        {
            _scope.Validate(current);
            await _limiter.WaitAsync(timeout.Token);

            if (_settings.Evasion && _settings.EvasionJitterMilliseconds > 0)
            {
                var jitter = Random.Shared.Next(0, Math.Clamp(_settings.EvasionJitterMilliseconds, 0, 10_000));
                if (jitter > 0)
                {
                    await Task.Delay(jitter, timeout.Token);
                }
            }

            using var request = new HttpRequestMessage(method, current);
            if (_settings.Evasion || _settings.RandomUserAgent)
            {
                request.Headers.TryAddWithoutValidation("User-Agent", EvasionProfile.NextUserAgent());
            }

            if (_settings.Evasion)
            {
                foreach (var (name, value) in EvasionProfile.NavigationHeaders(current))
                {
                    request.Headers.TryAddWithoutValidation(name, value);
                }
            }
            else
            {
                request.Headers.TryAddWithoutValidation("Accept", "*/*");
            }

            HttpResponseMessage response;
            try
            {
                response = await _client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    timeout.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException(
                    $"Request to {current} exceeded {_settings.TimeoutSeconds}s.");
            }

            using (response)
            {
                var status = (int)response.StatusCode;
                if (IsRedirect(status) && response.Headers.Location is { } location)
                {
                    if (redirect == _settings.MaxRedirects)
                    {
                        throw new HttpRequestException($"Too many redirects starting at {uri}.");
                    }

                    var next = location.IsAbsoluteUri ? location : new Uri(current, location);
                    _scope.Validate(next);
                    current = next;
                    continue;
                }

                var body = await HttpHelpers.ReadBodyAsync(response, method, _settings.MaxBodyBytes, timeout.Token);
                var headers = HttpHelpers.CollectHeaders(response);

                return new HttpResponseData
                {
                    RequestUri = uri,
                    FinalUri = current,
                    StatusCode = status,
                    ReasonPhrase = response.ReasonPhrase,
                    ContentType = response.Content.Headers.ContentType?.ToString(),
                    Headers = headers,
                    Body = body.Body,
                    Truncated = body.Truncated,
                    Elapsed = started.Elapsed,
                };
            }
        }

        throw new HttpRequestException($"Redirect limit reached for {uri}.");
    }


    private async ValueTask<Stream> ConnectAsync(
        SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        var host = context.DnsEndPoint.Host;
        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
        }
        catch (SocketException error)
        {
            throw new HttpRequestException($"DNS resolution failed for {host}.", error);
        }

        var candidates = _scope.AllowPrivateAddresses
            ? addresses
            : addresses.Where(address => !ScopeValidator.IsPrivateAddress(address)).ToArray();

        if (candidates.Length == 0)
        {
            throw new HttpRequestException(
                $"Refusing to connect to private or local address for {host}.");
        }

        SocketException? lastError = null;
        foreach (var address in candidates)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true,
            };

            try
            {
                await socket.ConnectAsync(
                    new IPEndPoint(address, context.DnsEndPoint.Port),
                    cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException error)
            {
                lastError = error;
                socket.Dispose();
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        throw new HttpRequestException(
            $"Could not connect to {host}:{context.DnsEndPoint.Port}.", lastError);
    }

    private static bool IsRedirect(int status) => status is 301 or 302 or 303 or 307 or 308;

    private static bool IsTransient(int status) => status is 408 or 425 or 429 or 500 or 502 or 503 or 504;

    private static bool IsTransient(Exception error) =>
        error is HttpRequestException or TimeoutException or IOException;

    private static TimeSpan Backoff(int attempt) =>
        TimeSpan.FromMilliseconds(400 * Math.Pow(2, Math.Min(attempt, 4)));

    public void Dispose() => _client.Dispose();
}
