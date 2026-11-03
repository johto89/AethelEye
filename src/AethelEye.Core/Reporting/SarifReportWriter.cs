using System.Text.Json;
using System.Text.Json.Serialization;
using AethelEye.Core.Models;

namespace AethelEye.Core.Reporting;

/// <summary>
/// Writes a SARIF 2.1.0 log so CI/CD systems (GitHub Code Scanning, Azure DevOps, GitLab SAST)
/// can ingest AethelEye findings as first-class alerts. Each check becomes a reporting descriptor
/// (rule); each finding becomes a result linked to that rule.
/// </summary>
public sealed class SarifReportWriter : IReportWriter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public string Format => "sarif";

    public string Extension => ".sarif";

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

        var findings = report.AllFindings.ToList();

        // Build rule index: one rule per unique CheckId
        var ruleIndex = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var rules = new List<object>();
        foreach (var finding in findings)
        {
            if (ruleIndex.ContainsKey(finding.CheckId))
            {
                continue;
            }

            ruleIndex[finding.CheckId] = rules.Count;
            rules.Add(new
            {
                id = finding.CheckId,
                shortDescription = new { text = finding.CheckId },
                defaultConfiguration = new
                {
                    level = MapLevel(finding.Severity),
                },
            });
        }

        var results = new List<object>();
        foreach (var finding in findings)
        {
            var result = new Dictionary<string, object?>
            {
                ["ruleId"] = finding.CheckId,
                ["ruleIndex"] = ruleIndex[finding.CheckId],
                ["level"] = MapLevel(finding.Severity),
                ["message"] = new { text = FormatMessage(finding) },
            };

            // SARIF requires at least one location; use the target URL as the artifact
            if (finding.Url is { Length: > 0 } url)
            {
                result["locations"] = new[]
                {
                    new
                    {
                        physicalLocation = new
                        {
                            artifactLocation = new { uri = url },
                        },
                    },
                };
            }

            // Map finding properties to SARIF property bags
            var properties = new Dictionary<string, object>
            {
                ["findingId"] = finding.Id,
                ["severity"] = finding.Severity.ToString().ToLowerInvariant(),
                ["confidence"] = finding.Confidence.ToString().ToLowerInvariant(),
                ["target"] = finding.Target,
                ["discoveredAt"] = finding.DiscoveredAt.ToString("o"),
            };

            if (finding.Evidence is { Count: > 0 })
            {
                properties["evidence"] = finding.Evidence;
            }

            result["properties"] = properties;

            if (finding.Remediation is { Length: > 0 } remediation)
            {
                result["fixes"] = new[]
                {
                    new { description = new { text = remediation } },
                };
            }

            if (finding.References is { Count: > 0 })
            {
                result["relatedLocations"] = finding.References
                    .Select((reference, index) => new
                    {
                        id = index,
                        message = new { text = reference },
                        physicalLocation = Uri.TryCreate(reference, UriKind.Absolute, out _)
                            ? new { artifactLocation = new { uri = reference } }
                            : null,
                    })
                    .ToArray();
            }

            results.Add(result);
        }

        var sarif = new
        {
            schema = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            version = "2.1.0",
            runs = new[]
            {
                new
                {
                    tool = new
                    {
                        driver = new
                        {
                            name = report.Tool,
                            semanticVersion = report.Version,
                            informationUri = "https://github.com/johto89/AethelEye",
                            rules,
                        },
                    },
                    results,
                    invocations = new[]
                    {
                        new
                        {
                            executionSuccessful = true,
                            startTimeUtc = report.StartedAt.UtcDateTime.ToString("o"),
                            endTimeUtc = report.CompletedAt.UtcDateTime.ToString("o"),
                        },
                    },
                },
            },
        };

        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, sarif, Options, cancellationToken);
    }

    /// <summary>
    /// Maps AethelEye severity to SARIF level: error (Critical/High), warning (Medium), note (Low/Info).
    /// </summary>
    private static string MapLevel(Severity severity) => severity switch
    {
        Severity.Critical => "error",
        Severity.High => "error",
        Severity.Medium => "warning",
        Severity.Low => "note",
        _ => "note",
    };

    private static string FormatMessage(Finding finding)
    {
        var text = finding.Title;
        if (finding.Description is { Length: > 0 } description)
        {
            text += " — " + description;
        }

        return text;
    }
}
