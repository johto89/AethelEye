namespace AethelEye.Core.Http;

/// <summary>
/// Shared HTTP utilities used by both <see cref="ScopedHttpClient"/> and
/// <see cref="ExternalHttpClient"/> to avoid code duplication.
/// </summary>
internal static class HttpHelpers
{
    /// <summary>
    /// Reads the response body up to <paramref name="maxBytes"/>. Returns the body and whether
    /// the stream was truncated. A <see cref="HttpMethod.Head"/> request returns an empty body.
    /// </summary>
    internal static async Task<(byte[] Body, bool Truncated)> ReadBodyAsync(
        HttpResponseMessage response,
        HttpMethod method,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        if (method == HttpMethod.Head)
        {
            return ([], false);
        }

        var limit = maxBytes <= 0 ? int.MaxValue : maxBytes;
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

    /// <summary>
    /// Collects response headers and content headers into a single case-insensitive dictionary.
    /// </summary>
    internal static Dictionary<string, string[]> CollectHeaders(HttpResponseMessage response)
    {
        var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in response.Headers)
        {
            headers[header.Key] = header.Value.ToArray();
        }

        foreach (var header in response.Content.Headers)
        {
            headers[header.Key] = header.Value.ToArray();
        }

        return headers;
    }
}
