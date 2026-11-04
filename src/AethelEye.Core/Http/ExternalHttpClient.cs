using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using AethelEye.Core.Models;

namespace AethelEye.Core.Http;

/// <summary>Small client for public APIs. It is not scope bound because it never touches the target.</summary>
public sealed class ExternalHttpClient : IExternalHttpClient
{
    private readonly HttpClient _client;

    private readonly HttpSettings _settings;
    private readonly bool _offline;
    private readonly int _circuitThreshold;
    private readonly TimeSpan _circuitCooldown;
    private int _requests;
    private int _consecutiveFailures;
    private long _circuitOpenedAt;

    public ExternalHttpClient(HttpSettings settings, bool offline = false)
    {
        _settings = settings;
        _offline = offline;
        _circuitThreshold = Math.Max(1, settings.CircuitBreakerThreshold);
        _circuitCooldown = TimeSpan.FromSeconds(Math.Max(1, settings.CircuitBreakerCooldownSeconds));
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 5,
            UseCookies = false,
            UseProxy = !string.IsNullOrWhiteSpace(settings.Proxy),
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(
                Math.Clamp(settings.ExternalTimeoutSeconds, 3, 15)),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        };

        if (!string.IsNullOrWhiteSpace(settings.Proxy))
        {
            handler.Proxy = new WebProxy(settings.Proxy);
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
        headers.TryAddWithoutValidation("Accept", "application/json, text/plain, */*");
    }

    public async Task<HttpResponseData> GetAsync(
        string url,
        CancellationToken cancellationToken = default,
        IReadOnlyDictionary<string, string>? headers = null)
    {
        if (_offline)
        {
            throw new OfflineException(url);
        }

        if (Volatile.Read(ref _consecutiveFailures) >= _circuitThreshold)
        {
            var openedTicks = Volatile.Read(ref _circuitOpenedAt);
            if (openedTicks > 0)
            {
                var elapsed = System.Diagnostics.Stopwatch.GetElapsedTime(openedTicks);
                if (elapsed >= _circuitCooldown)
                {
                    // Half-open: allow one probe request through
                    Interlocked.Exchange(ref _consecutiveFailures, 0);
                    Interlocked.Exchange(ref _circuitOpenedAt, 0);
                }
                else
                {
                    throw new HttpRequestException(
                        $"External network is unavailable (circuit open, resets in " +
                        $"{(_circuitCooldown - elapsed).TotalSeconds:F0}s). " +
                        "Use --offline or restore connectivity and retry.");
                }
            }
            else
            {
                throw new HttpRequestException(
                    "External network is unavailable (circuit open). " +
                    "Use --offline or restore connectivity and retry.");
            }
        }

        if (_settings.MaxExternalRequests > 0
            && Interlocked.Increment(ref _requests) > _settings.MaxExternalRequests)
        {
            throw new InvalidOperationException(
                $"External request budget exhausted ({_settings.MaxExternalRequests}). " +
                "Use --offline for isolated runs or raise http.maxExternalRequests.");
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException($"Not an absolute URL: {url}", nameof(url));
        }

        Exception? lastError = null;
        var attempts = Math.Max(0, _settings.ExternalRetries);

        for (var attempt = 0; attempt <= attempts; attempt++)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(Math.Max(3, _settings.ExternalTimeoutSeconds)));

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                if (headers is not null)
                {
                    foreach (var (name, value) in headers)
                    {
                        request.Headers.TryAddWithoutValidation(name, value);
                    }
                }

                var started = System.Diagnostics.Stopwatch.StartNew();
                using var response = await _client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    timeout.Token);

                var status = (int)response.StatusCode;
                if (status is 429 or 500 or 502 or 503 or 504 && attempt < attempts)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(500 * Math.Pow(2, attempt)), cancellationToken);
                    continue;
                }

                if (status >= 500)
                {
                    if (Interlocked.Increment(ref _consecutiveFailures) >= _circuitThreshold)
                    {
                        Interlocked.CompareExchange(ref _circuitOpenedAt,
                            System.Diagnostics.Stopwatch.GetTimestamp(), 0);
                    }
                }
                else
                {
                    Interlocked.Exchange(ref _consecutiveFailures, 0);
                    Interlocked.Exchange(ref _circuitOpenedAt, 0);
                }

                var (body, truncated) = await HttpHelpers.ReadBodyAsync(response, HttpMethod.Get, _settings.MaxBodyBytes, timeout.Token);
                var collected = HttpHelpers.CollectHeaders(response);

                return new HttpResponseData
                {
                    RequestUri = uri,
                    FinalUri = response.RequestMessage?.RequestUri ?? uri,
                    StatusCode = status,
                    ReasonPhrase = response.ReasonPhrase,
                    ContentType = response.Content.Headers.ContentType?.ToString(),
                    Headers = collected,
                    Body = body,
                    Truncated = truncated,
                    Elapsed = started.Elapsed,
                };
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error) when (error is HttpRequestException or IOException or OperationCanceledException)
            {
                lastError = error;
                if (Interlocked.Increment(ref _consecutiveFailures) >= _circuitThreshold)
                {
                    Interlocked.CompareExchange(ref _circuitOpenedAt,
                        System.Diagnostics.Stopwatch.GetTimestamp(), 0);
                }

                if (attempt >= attempts)
                {
                    break;
                }

                await Task.Delay(TimeSpan.FromMilliseconds(500 * Math.Pow(2, attempt)), cancellationToken);
            }
        }

        throw new HttpRequestException($"External request failed after retries: {url}", lastError);
    }

    public void Dispose() => _client.Dispose();
}
