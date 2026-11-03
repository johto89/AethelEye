namespace AethelEye.Core.Reporting;

public static class ReportWriterFactory
{
    public static IReportWriter Create(string format) => format.Trim().ToLowerInvariant() switch
    {
        "json" => new JsonReportWriter(),
        "sarif" => new SarifReportWriter(),
        "text" or "txt" => new TextReportWriter(),
        _ => throw new ArgumentException($"Unsupported report format: {format}. Use text, json or sarif."),
    };

    public static string ExtensionFor(string format) => Create(format).Extension;
}
