using System.Text.Json;
using System.Text.Json.Serialization;
using AethelEye.Core.Models;

namespace AethelEye.Core.Reporting;

public sealed class JsonReportWriter : IReportWriter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public string Format => "json";

    public string Extension => ".json";

    public async Task WriteAsync(
        ScanReport report,
        string path,
        CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // Project the engagement instead of serializing it directly: tokens, API keys, proxy
        // credentials and custom request headers must never reach a report file.
        var payload = new
        {
            report.Tool,
            report.Version,
            Engagement = new
            {
                report.Engagement.Name,
                report.Engagement.Client,
                report.Engagement.AuthorizedBy,
                report.Engagement.Notes,
                report.Engagement.Offline,
                report.Engagement.AdvisoryDatabasePath,
                report.Engagement.Targets,
                report.Engagement.Scope,
                Http = new
                {
                    report.Engagement.Http.UserAgent,
                    report.Engagement.Http.TimeoutSeconds,
                    report.Engagement.Http.MaxBodyBytes,
                    report.Engagement.Http.MaxRedirects,
                    report.Engagement.Http.RequestsPerSecond,
                    report.Engagement.Http.Retries,
                    report.Engagement.Http.ExternalTimeoutSeconds,
                    report.Engagement.Http.ExternalRetries,
                    report.Engagement.Http.MaxExternalRequests,
                    report.Engagement.Http.Insecure,
                    report.Engagement.Http.Evasion,
                    report.Engagement.Http.EvasionJitterMilliseconds,
                    report.Engagement.Http.RandomUserAgent,
                },
                report.Engagement.Browser,
                report.Engagement.Engine,
                GitHub = new
                {
                    report.Engagement.GitHub.MaxRepositories,
                    report.Engagement.GitHub.CodeSearch,
                    report.Engagement.GitHub.CloneAndScan,
                },
                Leaks = new
                {
                    report.Engagement.Leaks.HudsonRock,
                    report.Engagement.Leaks.ProxyNova,
                    report.Engagement.Leaks.BreachDirectory,
                    report.Engagement.Leaks.IncludeDorks,
                    report.Engagement.Leaks.MaxResults,
                },
                report.Engagement.Output,
            },
            report.StartedAt,
            report.CompletedAt,
            report.Targets,
        };

        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, payload, Options, cancellationToken);
    }
}
