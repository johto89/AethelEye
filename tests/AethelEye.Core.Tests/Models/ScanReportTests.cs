using AethelEye.Core.Models;

namespace AethelEye.Core.Tests.Models;

public sealed class ScanReportTests
{
    private static ScanReport CreateReport(params Finding[] findings)
    {
        var check = new CheckResult { CheckId = "test", CheckName = "Test" };
        check.Findings.AddRange(findings);
        var target = new TargetReport
        {
            Target = Target.Parse("https://example.com")
        };
        target.Checks.Add(check);
        var report = new ScanReport { Engagement = new Engagement() };
        report.Targets.Add(target);
        return report;
    }

    private static Finding MakeFinding(Severity severity) => new()
    {
        CheckId = "test",
        Title = $"{severity} finding",
        Target = "https://example.com",
        Severity = severity,
    };

    [Fact]
    public void FindingCount_sums_across_targets_and_checks()
    {
        var report = CreateReport(
            MakeFinding(Severity.Info),
            MakeFinding(Severity.High),
            MakeFinding(Severity.Low));

        Assert.Equal(3, report.FindingCount);
    }

    [Fact]
    public void FindingCount_is_zero_for_empty_report()
    {
        var report = new ScanReport { Engagement = new Engagement() };
        Assert.Equal(0, report.FindingCount);
    }

    [Fact]
    public void CountBySeverity_filters_correctly()
    {
        var report = CreateReport(
            MakeFinding(Severity.High),
            MakeFinding(Severity.High),
            MakeFinding(Severity.Low));

        Assert.Equal(2, report.CountBySeverity(Severity.High));
        Assert.Equal(1, report.CountBySeverity(Severity.Low));
        Assert.Equal(0, report.CountBySeverity(Severity.Critical));
    }

    [Fact]
    public void HasHighRisk_true_when_high_severity_present()
    {
        var report = CreateReport(MakeFinding(Severity.High));
        Assert.True(report.HasHighRisk);
    }

    [Fact]
    public void HasHighRisk_true_when_critical_severity_present()
    {
        var report = CreateReport(MakeFinding(Severity.Critical));
        Assert.True(report.HasHighRisk);
    }

    [Fact]
    public void HasHighRisk_false_when_only_low_and_info()
    {
        var report = CreateReport(
            MakeFinding(Severity.Info),
            MakeFinding(Severity.Low));

        Assert.False(report.HasHighRisk);
    }

    [Fact]
    public void AllFindings_enumerates_all_findings()
    {
        var report = CreateReport(
            MakeFinding(Severity.Info),
            MakeFinding(Severity.High));

        Assert.Equal(2, report.AllFindings.Count());
    }
}
