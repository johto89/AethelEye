using System.Text;
using AethelEye.Core.Models;

namespace AethelEye.Core.Reporting;

/// <summary>Plain-text report for reading in a terminal or opening in any text editor.</summary>
public sealed class TextReportWriter : IReportWriter
{
    public string Format => "text";

    public string Extension => ".txt";

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

        await File.WriteAllTextAsync(path, Build(report), new UTF8Encoding(false), cancellationToken);
    }

    public static string Build(ScanReport report)
    {
        var text = new StringBuilder();
        var line = new string('=', 78);
        text.AppendLine("AETHELeye Web Assessment - " + Clean(report.Engagement.Name));
        text.AppendLine(line);

        if (!string.IsNullOrWhiteSpace(report.Engagement.Client))
        {
            text.AppendLine("Client:        " + Clean(report.Engagement.Client));
        }

        if (!string.IsNullOrWhiteSpace(report.Engagement.AuthorizedBy))
        {
            text.AppendLine("Authorized by: " + Clean(report.Engagement.AuthorizedBy));
        }

        text.AppendLine($"Tool:          {report.Tool} {report.Version}");
        text.AppendLine($"Started:       {report.StartedAt:yyyy-MM-dd HH:mm:ss zzz}");
        text.AppendLine($"Completed:     {report.CompletedAt:yyyy-MM-dd HH:mm:ss zzz}");
        text.AppendLine($"Targets:       {report.Targets.Count}");
        text.AppendLine(
            $"Findings:      {report.FindingCount} " +
            $"(critical {report.CountBySeverity(Severity.Critical)}, " +
            $"high {report.CountBySeverity(Severity.High)}, " +
            $"medium {report.CountBySeverity(Severity.Medium)}, " +
            $"low {report.CountBySeverity(Severity.Low)}, " +
            $"info {report.CountBySeverity(Severity.Info)})");
        text.AppendLine();

        text.AppendLine("CHECK SUMMARY");
        text.AppendLine(new string('-', 78));
        foreach (var targetReport in report.Targets)
        {
            if (targetReport.Error is not null)
            {
                text.AppendLine($"{Clean(targetReport.Target.BaseUrl)} | target | failed | 0 | {Clean(targetReport.Error)}");
            }

            foreach (var check in targetReport.Checks)
            {
                text.AppendLine(
                    $"{Clean(targetReport.Target.BaseUrl)} | {Clean(check.CheckName)} | {check.Status} | " +
                    $"{check.RiskFindingCount} | {Clean(check.Conclusion)}");
            }
        }

        text.AppendLine();

        foreach (var targetReport in report.Targets)
        {
            text.AppendLine(line);
            text.AppendLine("TARGET: " + Clean(targetReport.Target.BaseUrl));
            text.AppendLine(line);

            if (targetReport.Error is not null)
            {
                text.AppendLine("Target error: " + Clean(targetReport.Error));
                text.AppendLine();
            }

            foreach (var check in targetReport.Checks)
            {
                text.AppendLine();
                text.AppendLine($"[{check.CheckId}] {Clean(check.CheckName)}");
                text.AppendLine($"  Status:     {check.Status}");
                text.AppendLine($"  Conclusion: {Clean(check.Conclusion)}");
                text.AppendLine($"  Duration:   {check.Duration.TotalSeconds:0.0}s");

                if (!string.IsNullOrWhiteSpace(check.Summary))
                {
                    text.AppendLine("  Summary:    " + Clean(check.Summary));
                }

                if (!string.IsNullOrWhiteSpace(check.Error))
                {
                    text.AppendLine("  Error:      " + Clean(check.Error));
                }

                if (check.Metrics.Count > 0)
                {
                    text.AppendLine(
                        "  Metrics:    " +
                        string.Join(", ", check.Metrics.Select(pair => $"{pair.Key}={Clean(pair.Value)}")));
                }

                if (check.Notes.Count > 0)
                {
                    text.AppendLine("  Notes:");
                    foreach (var note in check.Notes)
                    {
                        text.AppendLine("    - " + Clean(note));
                    }
                }

                foreach (var finding in check.Findings
                             .OrderByDescending(finding => finding.Severity)
                             .ThenBy(finding => finding.Title, StringComparer.Ordinal))
                {
                    WriteFinding(text, finding);
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(report.Engagement.Notes))
        {
            text.AppendLine();
            text.AppendLine("ENGAGEMENT NOTES");
            text.AppendLine(new string('-', 78));
            text.AppendLine(Clean(report.Engagement.Notes));
        }

        text.AppendLine();
        text.AppendLine("> This report records observations only. Every finding must be verified manually");
        text.AppendLine("> before it is treated as a vulnerability or used in a remediation decision.");
        return text.ToString();
    }

    private static void WriteFinding(StringBuilder text, Finding finding)
    {
        text.AppendLine();
        text.AppendLine($"  FINDING [{finding.Severity.ToLabel()}] {Clean(finding.Title)}");
        text.AppendLine($"    Check:       {finding.CheckId}");
        text.AppendLine($"    Confidence:  {finding.Confidence}");
        if (!string.IsNullOrWhiteSpace(finding.Url))
        {
            text.AppendLine("    URL:         " + Clean(finding.Url));
        }

        if (!string.IsNullOrWhiteSpace(finding.Description))
        {
            text.AppendLine("    Description: " + Clean(finding.Description));
        }

        if (finding.Evidence.Count > 0)
        {
            text.AppendLine("    Evidence:");
            foreach (var (key, value) in finding.Evidence)
            {
                text.AppendLine($"      {key}: {Clean(value)}");
            }
        }

        if (!string.IsNullOrWhiteSpace(finding.Remediation))
        {
            text.AppendLine("    Remediation: " + Clean(finding.Remediation));
        }

        if (finding.References.Count > 0)
        {
            text.AppendLine("    References:  " + string.Join(", ", finding.References.Select(Clean)));
        }
    }

    private static string Clean(string value) =>
        value.Replace("\r", " ", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal);
}
