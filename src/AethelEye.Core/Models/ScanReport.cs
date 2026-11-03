using System.Text.Json.Serialization;

namespace AethelEye.Core.Models;

public sealed class TargetReport
{
    public required Target Target { get; init; }

    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.UtcNow;

    public TimeSpan Duration { get; set; }

    public string? Error { get; set; }

    public List<CheckResult> Checks { get; } = [];
}

public sealed class ScanReport
{
    public string Tool { get; init; } = "aetheleye";

    public string Version { get; init; } = "0.1.0";

    public required Engagement Engagement { get; init; }

    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.UtcNow;

    public DateTimeOffset CompletedAt { get; set; }

    public List<TargetReport> Targets { get; } = [];

    [JsonIgnore]
    public IEnumerable<Finding> AllFindings =>
        Targets.SelectMany(target => target.Checks).SelectMany(check => check.Findings);

    [JsonIgnore]
    public int FindingCount => AllFindings.Count();

    public int CountBySeverity(Severity severity) =>
        AllFindings.Count(finding => finding.Severity == severity);

    [JsonIgnore]
    public bool HasHighRisk => AllFindings.Any(finding => finding.Severity >= Severity.High);
}
