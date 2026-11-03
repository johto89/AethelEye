using System.Net;
using System.Net.Security;
using WappalyzerSharp;

namespace AethelEye.Modules.Technology;

/// <summary>
/// Downloads the Wappalyzer fingerprint database through WappalyzerSharp's FingerprintUpdater and
/// stores it in the framework data directory. The next scan loads it over the embedded database.
/// </summary>
public static class WappalyzerFingerprintStore
{
    public const string DefaultFileName = "wappalyzer-fingerprints.json";

    public static string DefaultPath(string dataDirectory) =>
        Path.Combine(dataDirectory, DefaultFileName);

    public static async Task<int> UpdateAsync(
        string path,
        string? proxy,
        bool insecure,
        Action<string> log,
        Action<string> warn,
        CancellationToken cancellationToken)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(30),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        };

        if (!string.IsNullOrWhiteSpace(proxy))
        {
            handler.Proxy = new WebProxy(proxy);
            handler.UseProxy = true;
        }

        if (insecure)
        {
            handler.SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            };
        }

        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromMinutes(10),
        };
        client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "AethelEye/0.1");

        try
        {
            var fingerprints = await FingerprintUpdater.DownloadAsync(client, cancellationToken);
            var directory = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            FingerprintUpdater.Save(fingerprints, path);
            var count = fingerprints["apps"] is System.Text.Json.Nodes.JsonObject apps
                ? apps.Count
                : 0;
            log($"Wappalyzer fingerprints: {count} applications -> {Path.GetFullPath(path)}");
            return count;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            warn($"Wappalyzer fingerprint update failed, keeping the embedded data: {error.Message}");
            return 0;
        }
    }
}
