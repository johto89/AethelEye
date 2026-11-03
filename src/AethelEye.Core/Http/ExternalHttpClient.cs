using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using AethelEye.Core.Models;

namespace AethelEye.Core.Http;

/// <summary>Small client for public APIs. It is not scope bound because it never touches the target.</summary>
public sealed class ExternalHttpClient : IExternalHttpClient
{
    private readonly HttpClient _client;
    private const int CircuitThreshold = 3;

    private readonly HttpSettings _settings;
    private readonly bool _offline;
    private int _requests;
    private int _consecutiveFailures;

    public ExternalHttpClient(HttpSettings settings, bool offline = false)
    {
        _settings = settings;
        _offline = offline;
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

        if (Volatile.Read(ref _consecutiveFailures) >= CircuitThreshold)
        {
            throw new HttpRequestException(
                "External network is unavailable (circuit open). " +
                "Use --offline or restore connectivity and retry.");
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
                    Interlocked.Increment(ref _consecutiveFailures);
                }
                else
                {
                    Interlocked.Exchange(ref _consecutiveFailures, 0);
                }

                var (body, truncated) = await ReadBodyAsync(response, timeout.Token);
                var collected = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
                foreach (var header in response.Headers)
                {
                    collected[header.Key] = header.Value.ToArray();
                }

                foreach (var header in response.Content.Headers)
                {
                    collected[header.Key] = header.Value.ToArray();
                }

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
                Interlocked.Increment(ref _consecutiveFailures);
                if (attempt >= attempts)
                {
                    break;
                }

                await Task.Delay(TimeSpan.FromMilliseconds(500 * Math.Pow(2, attempt)), cancellationToken);
            }
        }

        throw new HttpRequestException($"External request failed after retries: {url}", lastError);
    }

    private async Task<(byte[] Body, bool Truncated)> ReadBodyAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var limit = _settings.MaxBodyBytes <= 0 ? int.MaxValue : _settings.MaxBodyBytes;
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        var total = 0;
        var truncated = false;

        while (true)
        {
            var read = await stream.ReadAsync(chunk.AsMemory(), cancellationToken);
            if (read == 0)
            {
                break;
            }

            if (total + read > limit)
            {
                buffer.Write(chunk, 0, Math.Max(0, limit - total));
                truncated = true;
                break;
            }

            buffer.Write(chunk, 0, read);
            total += read;
        }

        return (buffer.ToArray(), truncated);
    }

    public void Dispose() => _client.Dispose();
}
