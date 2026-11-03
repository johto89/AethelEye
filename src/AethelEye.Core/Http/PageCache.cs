namespace AethelEye.Core.Http;

/// <summary>Per-target cache. Checks run sequentially per target, so the simple dictionary is enough.</summary>
public sealed class PageCache(IScopedHttpClient http)
{
    private readonly Dictionary<string, HttpResponseData> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<HttpResponseData> GetAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        var key = uri.ToString();
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_cache.TryGetValue(key, out var cached))
            {
                return cached;
            }
        }
        finally
        {
            _gate.Release();
        }

        var response = await http.GetAsync(uri, cancellationToken);

        await _gate.WaitAsync(cancellationToken);
        try
        {
            _cache[key] = response;
        }
        finally
        {
            _gate.Release();
        }

        return response;
    }

    public Task<HttpResponseData> GetAsync(string url, CancellationToken cancellationToken = default) =>
        GetAsync(new Uri(url, UriKind.Absolute), cancellationToken);
}
