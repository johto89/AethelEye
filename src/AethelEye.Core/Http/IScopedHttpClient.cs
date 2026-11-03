namespace AethelEye.Core.Http;

/// <summary>HTTP client for authorized targets. Enforces scope, rate limit, retry and body limits.</summary>
public interface IScopedHttpClient : IDisposable
{
    Task<HttpResponseData> GetAsync(string url, CancellationToken cancellationToken = default);

    Task<HttpResponseData> GetAsync(Uri uri, CancellationToken cancellationToken = default);

    Task<HttpResponseData> SendAsync(Uri uri, HttpMethod method, CancellationToken cancellationToken = default);
}
