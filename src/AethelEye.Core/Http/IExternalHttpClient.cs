namespace AethelEye.Core.Http;

/// <summary>HTTP client for public data sources (GitHub, HudsonRock, ProxyNova, advisory feeds).</summary>
public interface IExternalHttpClient : IDisposable
{
    Task<HttpResponseData> GetAsync(
        string url,
        CancellationToken cancellationToken = default,
        IReadOnlyDictionary<string, string>? headers = null);
}
