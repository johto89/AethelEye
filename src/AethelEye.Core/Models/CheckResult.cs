namespace AethelEye.Core.Models;

public enum CheckStatus
{
    Completed,
    NoRisk,
    Findings,
    Partial,
    Skipped,
    Failed,
    TimedOut,
    Cancelled,
}

/// <summary>
/// One check against one target. A check never throws out of the engine: the orchestrator turns
/// exceptions, timeouts and cancellation into a result so the rest of the scan can continue.
/// </summary>
public sealed class CheckResult
{
    public required string CheckId { get; init; }

    public required string CheckName { get; init; }

    public CheckStatus Status { get; set; } = CheckStatus.Completed;

    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.UtcNow;

    public TimeSpan Duration { get; set; }

    public List<Finding> Findings { get; } = [];

    public List<string> Notes { get; } = [];

    public Dictionary<string, string> Metrics { get; } =
        new(StringComparer.OrdinalIgnoreCase);

    public string? Summary { get; set; }

    public string? Error { get; set; }

    /// <summary>Findings above Info. An informational technology or WAF finding is not a risk by itself.</summary>
    public int RiskFindingCount => Findings.Count(finding => finding.Severity > Severity.Info);

    public string Conclusion => Status switch
    {
        CheckStatus.NoRisk => "No risk identified at the time of assessment.",
        CheckStatus.Findings => $"{RiskFindingCount} finding(s) require review at the time of assessment.",
        CheckStatus.Partial => "Part of the check did not complete; results may be incomplete.",
        CheckStatus.Skipped => "Check skipped by configuration.",
        CheckStatus.TimedOut => "Check exceeded its time limit; results may be incomplete.",
        CheckStatus.Failed => "Check failed; rerun to obtain a conclusion.",
        CheckStatus.Cancelled => "Check cancelled.",
        _ => Summary ?? "Check completed.",
    };

    public static CheckResult NoRisk(string checkId, string checkName, string summary) => new()
    {
        CheckId = checkId,
        CheckName = checkName,
        Status = CheckStatus.NoRisk,
        Summary = summary,
    };
}
