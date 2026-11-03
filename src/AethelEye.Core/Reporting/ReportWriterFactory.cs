namespace AethelEye.Core.Reporting;

public static class ReportWriterFactory
{
    public static IReportWriter Create(string format) => format.Trim().ToLowerInvariant() switch
    {
        "json" => new JsonReportWriter(),
        "text" or "txt" => new TextReportWriter(),
        _ => throw new ArgumentException($"Unsupported report format: {format}. Use text or json."),
    };

    public static string ExtensionFor(string format) => Create(format).Extension;
}
