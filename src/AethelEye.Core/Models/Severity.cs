namespace AethelEye.Core.Models;

/// <summary>Ordered so higher values are more urgent.</summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// <summary>How strongly the evidence supports a finding.</summary>
public enum Confidence
{
    Low = 0,
    Medium = 1,
    High = 2,
}

public static class SeverityExtensions
{
    public static string ToLabel(this Severity severity) => severity switch
    {
        Severity.Critical => "CRITICAL",
        Severity.High => "HIGH",
        Severity.Medium => "MEDIUM",
        Severity.Low => "LOW",
        _ => "INFO",
    };
}
