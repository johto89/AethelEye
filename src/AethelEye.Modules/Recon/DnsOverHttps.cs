using System.Text.Json;
using AethelEye.Core.Http;

namespace AethelEye.Modules.Recon;

/// <summary>
/// Minimal DNS-over-HTTPS client. It gives MX/TXT/NS/CNAME/CAA records without adding a DNS
/// package, and honours the configured external HTTP budget. Providers are tried in order;
/// the default list is Cloudflare then Google.
/// </summary>
internal static class DnsOverHttps
{
    private static readonly (string Name, string Url)[] DefaultProviders =
    [
        ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
        ("Google", "https://dns.google/resolve"),
    ];

    public static async Task<IReadOnlyList<string>> QueryAsync(
        IExternalHttpClient http,
        string name,
        string type,
        CancellationToken cancellationToken,
        Action<string>? warn = null,
        IReadOnlyList<string>? customProviders = null)
    {
        IReadOnlyList<(string Name, string Url)> providers = customProviders is { Count: > 0 }
            ? customProviders.Select((url, i) => (Name: $"Custom-{i + 1}", Url: url)).ToArray()
            : DefaultProviders;
        foreach (var provider in providers)
        {
            try
            {
                var url =
                    $"{provider.Url}?name={Uri.EscapeDataString(name)}&type={Uri.EscapeDataString(type)}";
                var response = await http.GetAsync(
                    url,
                    cancellationToken,
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Accept"] = "application/dns-json",
                    });

                if (!response.IsSuccess)
                {
                    warn?.Invoke($"{provider.Name} DNS {type} {name}: HTTP {response.StatusCode}");
                    continue;
                }

                using var document = JsonDocument.Parse(response.Body);
                var root = document.RootElement;
                if (root.TryGetProperty("Status", out var status)
                    && status.ValueKind == JsonValueKind.Number
                    && status.GetInt32() != 0)
                {
                    return [];
                }

                if (!root.TryGetProperty("Answer", out var answers)
                    || answers.ValueKind != JsonValueKind.Array)
                {
                    return [];
                }

                var result = new List<string>();
                foreach (var answer in answers.EnumerateArray())
                {
                    if (answer.ValueKind == JsonValueKind.Object
                        && answer.TryGetProperty("data", out var data)
                        && data.ValueKind == JsonValueKind.String
                        && data.GetString() is { Length: > 0 } value)
                    {
                        result.Add(ReconSupport.CleanTxt(value));
                    }
                }

                return result;
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                warn?.Invoke($"{provider.Name} DNS {type} {name}: {error.Message}");
            }
        }

        return [];
    }
}
