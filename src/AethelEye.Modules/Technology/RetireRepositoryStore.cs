using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using RetireSharp.Model;
using RetireSharp.Repo;

namespace AethelEye.Modules.Technology;

/// <summary>
/// Downloads the Retire.js repository once, caches it under the framework data directory and
/// reparses it only when the cache expires. The parser is RetireSharp's, so detection stays in C#.
/// </summary>
public static class RetireRepositoryStore
{
    public const string DefaultUrl =
        "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v6.json";

    private static readonly ConcurrentDictionary<string, Repository> Memory =
        new(StringComparer.OrdinalIgnoreCase);

    private static readonly SemaphoreSlim Gate = new(1, 1);

    public static async Task<Repository?> LoadAsync(
        IExternalHttpClient http,
        ILog log,
        string dataDirectory,
        string? repositoryUrl,
        bool offline,
        CancellationToken cancellationToken)
    {
        var source = string.IsNullOrWhiteSpace(repositoryUrl) ? DefaultUrl : repositoryUrl;
        if (Memory.TryGetValue(source, out var known))
        {
            return known;
        }

        await Gate.WaitAsync(cancellationToken);
        try
        {
            if (Memory.TryGetValue(source, out known))
            {
                return known;
            }

            var cacheDirectory = Path.Combine(dataDirectory, "cache");
            Directory.CreateDirectory(cacheDirectory);
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(source)))
                .ToLowerInvariant()[..12];
            var path = Path.Combine(cacheDirectory, $"retire-{hash}.json");

            Repository? repository = null;
            var cacheFresh = File.Exists(path)
                && DateTime.UtcNow - File.GetLastWriteTimeUtc(path) < TimeSpan.FromHours(24);

            if (cacheFresh || (offline && File.Exists(path)))
            {
                repository = TryParse(path, log);
            }

            if (repository is null && offline)
            {
                log.Warn(
                    "Offline mode: Retire repository is not cached; JavaScript library versions will be skipped.");
                return null;
            }

            if (repository is null)
            {
                try
                {
                    log.Info($"Refreshing Retire repository from {source}");
                    var response = await http.GetAsync(source, cancellationToken);
                    if (!response.IsSuccess || response.Body.Length == 0)
                    {
                        log.Warn($"Retire repository returned HTTP {response.StatusCode}.");
                    }
                    else
                    {
                        repository = RepositoryLoader.ParseText(response.Text, source);
                        File.WriteAllText(path, response.Text, new UTF8Encoding(false));
                    }
                }
                catch (Exception error) when (error is not OutOfMemoryException)
                {
                    log.Warn($"Could not refresh the Retire repository: {error.Message}");
                }
            }

            if (repository is null && File.Exists(path))
            {
                repository = TryParse(path, log);
            }

            if (repository is not null)
            {
                Memory[source] = repository;
            }

            return repository;
        }
        finally
        {
            Gate.Release();
        }
    }

    private static Repository? TryParse(string path, ILog log)
    {
        try
        {
            return RepositoryLoader.ParseText(File.ReadAllText(path), path);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            log.Warn($"Cached Retire repository is unusable: {error.Message}");
            return null;
        }
    }
}
