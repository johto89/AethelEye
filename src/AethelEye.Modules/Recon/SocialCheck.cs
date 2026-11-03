using System.Text.RegularExpressions;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Models;

namespace AethelEye.Modules.Recon;

/// <summary>
/// Extracts public social profiles and email addresses from the target page, inspired by
/// omnisci3nt's social-media module (MIT). It only reads the page that other checks already fetch.
/// </summary>
public sealed class SocialCheck : ICheck
{
    private static readonly Regex HrefPattern = new(
        @"href\s*=\s*[""'](?<url>[^""']+)[""']",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex EmailPattern = new(
        @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        RegexOptions.CultureInvariant);

    private static readonly string[] SocialHosts =
    [
        "facebook.com", "fb.com", "twitter.com", "x.com", "instagram.com", "linkedin.com",
        "youtube.com", "youtu.be", "tiktok.com", "github.com", "t.me", "telegram.me",
        "discord.gg", "discord.com", "threads.net", "mastodon.social",
    ];

    public string Id => "social";

    public string Name => "Public contact surface";

    public string Description =>
        "Finds public email addresses and social-media profiles linked from the target page.";

    public int Order => 25;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        var page = await context.Pages.GetAsync(context.Target.BaseUri, context.CancellationToken);
        if (!page.IsSuccess)
        {
            result.Status = CheckStatus.NoRisk;
            result.Summary = $"Base page returned HTTP {page.StatusCode}; no public contact data was read.";
            return result;
        }

        var maxResults = Math.Clamp(context.Settings.GetInt("maxResults", 100), 1, 1000);
        var emails = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var social = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (Match match in EmailPattern.Matches(page.Text))
        {
            emails.Add(match.Value.Trim().TrimEnd('.'));
            if (emails.Count >= maxResults)
            {
                break;
            }
        }

        foreach (Match match in HrefPattern.Matches(page.Text))
        {
            var value = match.Groups["url"].Value.Trim();
            if (value.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
            {
                var address = value[7..].Split('?')[0].Trim();
                if (address.Length > 0)
                {
                    emails.Add(address);
                }

                continue;
            }

            if (!Uri.TryCreate(page.FinalUri, value, out var uri)
                || uri.Scheme is not ("http" or "https"))
            {
                continue;
            }

            var host = uri.IdnHost.ToLowerInvariant();
            if (SocialHosts.Any(socialHost =>
                    host.Equals(socialHost, StringComparison.OrdinalIgnoreCase)
                    || host.EndsWith("." + socialHost, StringComparison.OrdinalIgnoreCase)))
            {
                social.Add(uri.GetLeftPart(UriPartial.Path));
            }

            if (social.Count >= maxResults)
            {
                break;
            }
        }

        result.Metrics["emails"] = emails.Count.ToString();
        result.Metrics["socialProfiles"] = social.Count.ToString();
        if (emails.Count == 0 && social.Count == 0)
        {
            result.Status = CheckStatus.NoRisk;
            result.Summary = "No public email addresses or social profiles were linked from the page.";
            return result;
        }

        result.Findings.Add(new Finding
        {
            CheckId = Id,
            Title = "Public contact and social profiles",
            Description =
                "Contact details published on the target page. Review them for unnecessary exposure " +
                "and for use in phishing or social-engineering attempts.",
            Severity = Severity.Info,
            Confidence = Confidence.Medium,
            Target = context.Target.BaseUrl,
            Url = page.FinalUri.ToString(),
            Evidence = new Dictionary<string, string>
            {
                ["emails"] = string.Join(", ", emails.Take(maxResults)),
                ["socialProfiles"] = string.Join(", ", social.Take(maxResults)),
            },
        });

        result.Status = CheckStatus.NoRisk;
        result.Summary =
            $"Found {emails.Count} public email address(es) and {social.Count} social profile(s).";
        return result;
    }
}
