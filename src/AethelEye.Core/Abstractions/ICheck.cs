using AethelEye.Core.Models;

namespace AethelEye.Core.Abstractions;

/// <summary>
/// One OSINT check. Implementations should treat the network as hostile, keep secrets out of the
/// report, and return a <see cref="CheckResult"/> instead of throwing for expected failures.
/// </summary>
public interface ICheck
{
    string Id { get; }

    string Name { get; }

    string Description { get; }

    /// <summary>Lower runs first. Gives the report a stable, explainable order.</summary>
    int Order { get; }

    /// <summary>
    /// True for scan-wide checks such as local source analysis. The orchestrator runs these only
    /// once, on the first target, instead of once per web application.
    /// </summary>
    bool RunsOncePerScan => false;

    Task<CheckResult> RunAsync(ICheckContext context);
}
