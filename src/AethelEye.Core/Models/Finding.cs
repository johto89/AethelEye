namespace AethelEye.Core.Models;

/// <summary>A single reviewable observation. Secrets must be masked before they reach this object.</summary>
public sealed class Finding
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..12];

    public required string CheckId { get; init; }

    public required string Title { get; init; }

    public string? Description { get; init; }

    public Severity Severity { get; init; } = Severity.Info;

    public Confidence Confidence { get; init; } = Confidence.Medium;

    public required string Target { get; init; }

    public string? Url { get; init; }

    public IReadOnlyDictionary<string, string> Evidence { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public string? Remediation { get; init; }

    public IReadOnlyList<string> References { get; init; } = [];

    public DateTimeOffset DiscoveredAt { get; init; } = DateTimeOffset.UtcNow;
}
