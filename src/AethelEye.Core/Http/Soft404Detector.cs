using System.Text.RegularExpressions;

namespace AethelEye.Core.Http;

/// <summary>
/// Detects soft-404 responses by comparing a candidate page against a known-404 baseline.
/// Shared by BackupCheck, ExposureCheck and HiddenPathCheck to avoid duplicated logic.
/// </summary>
public static partial class Soft404Detector
{
    [GeneratedRegex(@"<title[^>]*>(?<title>[^<]+)</title>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TitlePattern();

    /// <summary>
    /// Returns true when <paramref name="candidate"/> is probably a custom error page that matches
    /// the <paramref name="baseline"/> 404 response.
    /// </summary>
    public static bool LooksLikeSoftNotFound(
        HttpResponseData candidate,
        HttpResponseData baseline)
    {
        if (candidate.StatusCode != baseline.StatusCode)
        {
            return false;
        }

        if (candidate.Body.Length == baseline.Body.Length
            && candidate.Text.Equals(baseline.Text, StringComparison.Ordinal))
        {
            return true;
        }

        return baseline.Body.Length > 0
            && candidate.ContentType?.Contains("html", StringComparison.OrdinalIgnoreCase) == true
            && Math.Abs(candidate.Body.Length - baseline.Body.Length) <= Math.Max(64, baseline.Body.Length / 20);
    }

    /// <summary>
    /// Extended soft-404 check that also compares page titles and normalises embedded path strings.
    /// Used by HiddenPathCheck where custom error pages often echo the requested path.
    /// </summary>
    public static bool LooksLikeSoftNotFound(
        HttpResponseData candidate,
        HttpResponseData baseline,
        string baselinePath,
        string candidatePath)
    {
        if (LooksLikeSoftNotFound(candidate, baseline))
        {
            return true;
        }

        if (candidate.StatusCode != baseline.StatusCode)
        {
            return false;
        }

        var candidateTitle = ExtractTitle(candidate.Text);
        var baselineTitle = ExtractTitle(baseline.Text);
        if (candidateTitle.Length > 0 && candidateTitle == baselineTitle)
        {
            return true;
        }

        var normalizedCandidate = candidate.Text
            .Replace(candidatePath, baselinePath, StringComparison.OrdinalIgnoreCase);
        var normalizedBaseline = baseline.Text
            .Replace(baselinePath, baselinePath, StringComparison.OrdinalIgnoreCase);
        return normalizedCandidate.Equals(normalizedBaseline, StringComparison.Ordinal);
    }

    private static string ExtractTitle(string html)
    {
        var match = TitlePattern().Match(html);
        return match.Success ? match.Groups["title"].Value.Trim() : string.Empty;
    }
}
