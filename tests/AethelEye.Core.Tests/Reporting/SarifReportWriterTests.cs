using System.Text.Json;
using AethelEye.Core.Models;
using AethelEye.Core.Reporting;

namespace AethelEye.Core.Tests.Reporting;

public sealed class SarifReportWriterTests
{
    private static ScanReport CreateReport(params Finding[] findings)
    {
        var report = new ScanReport
        {
            Engagement = new Engagement { Name = "test" },
            StartedAt = DateTimeOffset.Parse("2025-01-01T00:00:00Z"),
            CompletedAt = DateTimeOffset.Parse("2025-01-01T01:00:00Z"),
        };

        var target = new TargetReport
        {
            Target = Target.Parse("https://example.com"),
        };

        var check = new CheckResult { CheckId = "test-check", CheckName = "Test" };
        check.Findings.AddRange(findings);
        target.Checks.Add(check);
        report.Targets.Add(target);
        return report;
    }

    [Fact]
    public async Task Format_returns_sarif()
    {
        var writer = new SarifReportWriter();
        Assert.Equal("sarif", writer.Format);
        Assert.Equal(".sarif", writer.Extension);
    }

    [Fact]
    public async Task WriteAsync_produces_valid_sarif_structure()
    {
        var finding = new Finding
        {
            CheckId = "dns",
            Title = "DMARC missing",
            Description = "No DMARC record found.",
            Severity = Severity.Medium,
            Confidence = Confidence.High,
            Target = "https://example.com",
            Url = "https://example.com",
            Remediation = "Add a DMARC record.",
            References = ["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"],
        };

        var report = CreateReport(finding);
        var path = Path.Combine(Path.GetTempPath(), $"sarif-test-{Guid.NewGuid():N}.sarif");
        try
        {
            var writer = new SarifReportWriter();
            await writer.WriteAsync(report, path);

            var json = await File.ReadAllTextAsync(path);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            Assert.Equal("2.1.0", root.GetProperty("version").GetString());
            Assert.True(root.TryGetProperty("runs", out var runs));
            Assert.Equal(1, runs.GetArrayLength());

            var run = runs[0];
            var driver = run.GetProperty("tool").GetProperty("driver");
            Assert.Equal("aetheleye", driver.GetProperty("name").GetString());

            // Rules
            var rules = driver.GetProperty("rules");
            Assert.Equal(1, rules.GetArrayLength());
            Assert.Equal("dns", rules[0].GetProperty("id").GetString());

            // Results
            var results = run.GetProperty("results");
            Assert.Equal(1, results.GetArrayLength());
            var result = results[0];
            Assert.Equal("dns", result.GetProperty("ruleId").GetString());
            Assert.Equal("warning", result.GetProperty("level").GetString());

            // Fix
            var fixes = result.GetProperty("fixes");
            Assert.Equal(1, fixes.GetArrayLength());
            Assert.Contains("DMARC", fixes[0].GetProperty("description").GetProperty("text").GetString());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Severity_mapping_is_correct()
    {
        var findings = new[]
        {
            new Finding { CheckId = "a", Title = "Critical", Severity = Severity.Critical, Confidence = Confidence.High, Target = "t" },
            new Finding { CheckId = "b", Title = "High", Severity = Severity.High, Confidence = Confidence.High, Target = "t" },
            new Finding { CheckId = "c", Title = "Medium", Severity = Severity.Medium, Confidence = Confidence.High, Target = "t" },
            new Finding { CheckId = "d", Title = "Low", Severity = Severity.Low, Confidence = Confidence.High, Target = "t" },
            new Finding { CheckId = "e", Title = "Info", Severity = Severity.Info, Confidence = Confidence.High, Target = "t" },
        };

        var report = CreateReport(findings);
        var path = Path.Combine(Path.GetTempPath(), $"sarif-level-{Guid.NewGuid():N}.sarif");
        try
        {
            await new SarifReportWriter().WriteAsync(report, path);
            using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(path));
            var results = doc.RootElement.GetProperty("runs")[0].GetProperty("results");

            Assert.Equal("error", results[0].GetProperty("level").GetString());   // Critical
            Assert.Equal("error", results[1].GetProperty("level").GetString());   // High
            Assert.Equal("warning", results[2].GetProperty("level").GetString()); // Medium
            Assert.Equal("note", results[3].GetProperty("level").GetString());    // Low
            Assert.Equal("note", results[4].GetProperty("level").GetString());    // Info
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Empty_report_produces_empty_results()
    {
        var report = CreateReport();
        var path = Path.Combine(Path.GetTempPath(), $"sarif-empty-{Guid.NewGuid():N}.sarif");
        try
        {
            await new SarifReportWriter().WriteAsync(report, path);
            using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(path));
            var results = doc.RootElement.GetProperty("runs")[0].GetProperty("results");
            Assert.Equal(0, results.GetArrayLength());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Factory_creates_sarif_writer()
    {
        var writer = ReportWriterFactory.Create("sarif");
        Assert.IsType<SarifReportWriter>(writer);
        Assert.Equal(".sarif", ReportWriterFactory.ExtensionFor("sarif"));
    }
}
