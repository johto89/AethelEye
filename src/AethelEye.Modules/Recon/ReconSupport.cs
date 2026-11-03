using System.Net;
using System.Text.Json;
using AethelEye.Core.Http;
using AethelEye.Core.Models;

namespace AethelEye.Modules.Recon;

/// <summary>Small helpers shared by the passive domain-recon checks.</summary>
internal static class ReconSupport
{
    public static bool IsIp(string host) => IPAddress.TryParse(host, out _);

    public static string? Domain(Target target) =>
        IsIp(target.Host) ? null : target.Host.TrimEnd('.').ToLowerInvariant();

    public static async Task<HttpResponseData?> TryGetJsonAsync(
        IExternalHttpClient http,
        string url,
        CancellationToken cancellationToken,
        IReadOnlyDictionary<string, string>? headers = null,
        Action<string>? warn = null)
    {
        try
        {
            var response = await http.GetAsync(url, cancellationToken, headers);
            if (!response.IsSuccess)
            {
                warn?.Invoke($"{url}: HTTP {response.StatusCode}");
                return null;
            }

            return response;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            warn?.Invoke($"{url}: {error.Message}");
            return null;
        }
    }

    public static string? String(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    public static IReadOnlyList<string> Strings(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(name, out var values)
            || values.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return values.EnumerateArray()
            .Where(value => value.ValueKind == JsonValueKind.String)
            .Select(value => value.GetString()!)
            .Where(value => value.Length > 0)
            .ToArray();
    }

    public static IEnumerable<JsonElement> Array(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(name, out var values)
            || values.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return values.EnumerateArray().ToArray();
    }

    public static string CleanTxt(string value) =>
        value.Trim().Trim('"').Replace("\\\"", "\"", StringComparison.Ordinal);
}
