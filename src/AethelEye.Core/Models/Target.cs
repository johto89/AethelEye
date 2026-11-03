using System.Text.Json.Serialization;

namespace AethelEye.Core.Models;

/// <summary>One authorized web target. Parsing is deliberately strict: only http and https.</summary>
public sealed record Target
{
    public required string BaseUrl { get; init; }
    public required string Host { get; init; }
    public string? Label { get; init; }

    /// <summary>True when this pseudo-target only carries a local source tree (no HTTP target).</summary>
    public bool IsSource { get; init; }

    [JsonIgnore]
    public Uri BaseUri => new(BaseUrl, UriKind.Absolute);

    /// <summary>Scheme and authority only, used for root-relative checks such as /.git/HEAD.</summary>
    [JsonIgnore]
    public string RootUrl => BaseUri.GetLeftPart(UriPartial.Authority);

    /// <summary>Pseudo-target for a scan that only has local source code.</summary>
    public static Target ForSource(string path, string? label = null)
    {
        var full = Path.GetFullPath(path);
        return new Target
        {
            BaseUrl = new Uri(full).AbsoluteUri,
            Host = "local-source",
            Label = label ?? "local source",
            IsSource = true,
        };
    }

    /// <summary>Pseudo-target for a scan that only imports Dependency-Check reports.</summary>
    public static Target ForReport() => new()
    {
        BaseUrl = "dependency-check://report",
        Host = "dependency-check",
        Label = "dependency-check report",
        IsSource = true,
    };

    public static Target Parse(string value, string? label = null)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Target must not be empty.", nameof(value));
        }

        var text = value.Trim();
        if (!text.Contains("://", StringComparison.Ordinal))
        {
            text = "https://" + text;
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri)
            || uri.Scheme is not ("http" or "https")
            || string.IsNullOrWhiteSpace(uri.Host))
        {
            throw new ArgumentException($"Target must be an http or https URL: {value}", nameof(value));
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new ArgumentException(
                "Targets with embedded credentials are not allowed; configure headers instead.",
                nameof(value));
        }

        var root = uri.GetLeftPart(UriPartial.Authority);
        var path = uri.AbsolutePath.TrimEnd('/');
        var baseUrl = path.Length == 0 ? root : root + path;

        return new Target
        {
            BaseUrl = baseUrl,
            Host = uri.IdnHost.ToLowerInvariant(),
            Label = label ?? uri.IdnHost,
        };
    }

    public override string ToString() => BaseUrl;
}
