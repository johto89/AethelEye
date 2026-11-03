using AethelEye.Core.Models;

namespace AethelEye.Core.Reporting;

public interface IReportWriter
{
    string Format { get; }

    string Extension { get; }

    Task WriteAsync(ScanReport report, string path, CancellationToken cancellationToken = default);
}
