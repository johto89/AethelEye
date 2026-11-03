// SPDX-License-Identifier: GPL-3.0-or-later
// Domain-leak logic adapted from gosearch (https://github.com/ibnaleem/gosearch), GPL-3.0.
// See THIRD-PARTY-NOTICES.md for the full attribution.

using System.Text.Json;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;

namespace AethelEye.Modules.LeakedAccounts;

/// <summary>
/// Port of the domain-leak parts of gosearch: HudsonRock info-stealer intelligence, ProxyNova COMB
/// and optional BreachDirectory. Only one request per provider; no credentials are written to the
/// report. In offline mode the providers are skipped and only manual dorks are generated.
/// </summary>
public sealed class LeakedAccountsCheck : ICheck
{
    private static readonly Dictionary<string, string> JsonHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Accept"] = "application/json",
    };

    public string Id => "leaked-accounts";

    public string Name => "Leaked accounts and credentials";

    public string Description =>
        "Checks HudsonRock, ProxyNova COMB and optionally BreachDirectory for accounts tied to the target.";

    public int Order => 50;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        var settings = context.Engagement.Leaks;
        var domain = context.Target.Host;

        if (settings.IncludeDorks)
        {
            foreach (var dork in DorkBuilder.Build(domain))
            {
                result.Notes.Add($"{dork.Engine} - {dork.Title}: {dork.Url}");
            }
        }

        if (context.Engagement.Offline)
        {
            result.Status = CheckStatus.Skipped;
            result.Summary =
                "Offline mode: leak providers were not contacted. Manual dorks were generated for later review.";
            result.Notes.Add("Run without --offline to query HudsonRock, ProxyNova and BreachDirectory.");
            return result;
        }

        var max = Math.Clamp(settings.MaxResults, 1, 100);
        var failures = 0;

        if (settings.HudsonRock)
        {
            failures += await HudsonRockAsync(context, domain, result, context.CancellationToken);
        }

        if (settings.ProxyNova)
        {
            failures += await ProxyNovaAsync(context, domain, result, max, context.CancellationToken);
        }

        if (settings.BreachDirectory)
        {
            failures += await BreachDirectoryAsync(context, domain, result, max, context.CancellationToken);
        }

        var risk = result.RiskFindingCount;
        result.Summary =
            $"{risk} risk finding(s); HudsonRock/ProxyNova/BreachDirectory request failures: {failures}.";
        result.Status = risk > 0
            ? CheckStatus.Findings
            : failures > 0 ? CheckStatus.Partial : CheckStatus.NoRisk;
        return result;
    }

    private static async Task<int> HudsonRockAsync(
        ICheckContext context,
        string domain,
        CheckResult result,
        CancellationToken cancellationToken)
    {
        var url =
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=" +
            Uri.EscapeDataString(domain);

        try
        {
            var response = await context.ExternalHttp.GetAsync(url, cancellationToken, JsonHeaders);
            if (response.StatusCode is 400 or 404)
            {
                result.Notes.Add(
                    "HudsonRock search-by-domain is not available via API; verify manually: " +
                    $"https://hudsonrock.com/search?domain={Uri.EscapeDataString(domain)}");
                return 1;
            }

            if (!response.IsSuccess)
            {
                result.Notes.Add($"HudsonRock returned HTTP {response.StatusCode}.");
                return 1;
            }

            using var document = JsonDocument.Parse(response.Text);
            var root = document.RootElement;
            var message = root.TryGetProperty("message", out var messageValue)
                ? messageValue.GetString()
                : null;
            var stealers = root.TryGetProperty("stealers", out var stealerValue)
                && stealerValue.ValueKind == JsonValueKind.Array
                ? stealerValue
                : default;

            var count = stealers.ValueKind == JsonValueKind.Array ? stealers.GetArrayLength() : 0;
            result.Metrics["hudsonRockMachines"] = count.ToString();

            if (count == 0 || message?.Contains("not associated", StringComparison.OrdinalIgnoreCase) == true)
            {
                result.Notes.Add("HudsonRock: no info-stealer association found.");
                return 0;
            }

            var families = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var dates = new List<DateTimeOffset>();

            foreach (var stealer in stealers.EnumerateArray())
            {
                if (stealer.TryGetProperty("stealer_family", out var family)
                    && family.GetString() is { Length: > 0 } familyName)
                {
                    families.Add(familyName);
                }

                if (stealer.TryGetProperty("date_compromised", out var date)
                    && DateTimeOffset.TryParse(date.GetString(), out var parsed))
                {
                    dates.Add(parsed);
                }
            }

            result.Findings.Add(new Finding
            {
                CheckId = Id,
                Title = "Info-stealer compromised machines associated with domain",
                Description =
                    $"HudsonRock reports {count} machine(s) infected by an info-stealer that " +
                    "referenced the target domain. Credentials stored on those machines should be " +
                    "treated as exposed until proven otherwise.",
                Severity = Severity.High,
                Confidence = Confidence.Medium,
                Target = context.Target.BaseUrl,
                Url = "https://hudsonrock.com/",
                Evidence = new Dictionary<string, string>
                {
                    ["machines"] = count.ToString(),
                    ["stealerFamilies"] = string.Join(", ", families),
                    ["earliestCompromise"] = dates.Count > 0
                        ? dates.Min().ToString("yyyy-MM-dd")
                        : string.Empty,
                    ["latestCompromise"] = dates.Count > 0
                        ? dates.Max().ToString("yyyy-MM-dd")
                        : string.Empty,
                    ["source"] = "HudsonRock Cavalier API (domain search)",
                },
                Remediation =
                    "Force password resets for affected accounts, revoke active sessions and API tokens, " +
                    "require MFA, and review authentication logs for anomalous access.",
            });
            return 0;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            result.Notes.Add($"HudsonRock failed: {error.Message}");
            return 1;
        }
    }

    private static async Task<int> ProxyNovaAsync(
        ICheckContext context,
        string domain,
        CheckResult result,
        int max,
        CancellationToken cancellationToken)
    {
        var url = "https://api.proxynova.com/comb?query=" + Uri.EscapeDataString(domain);

        try
        {
            var response = await context.ExternalHttp.GetAsync(url, cancellationToken, JsonHeaders);
            if (!response.IsSuccess)
            {
                result.Notes.Add($"ProxyNova returned HTTP {response.StatusCode}.");
                return 1;
            }

            using var document = JsonDocument.Parse(response.Text);
            var root = document.RootElement;
            var count = root.TryGetProperty("count", out var countValue) ? countValue.GetInt32() : 0;
            result.Metrics["proxyNovaLines"] = count.ToString();

            if (count == 0)
            {
                result.Notes.Add("ProxyNova COMB: no compromised credentials contain the domain.");
                return 0;
            }

            var samples = new List<string>();
            if (root.TryGetProperty("lines", out var lines) && lines.ValueKind == JsonValueKind.Array)
            {
                foreach (var line in lines.EnumerateArray().Take(max))
                {
                    if (line.GetString() is { Length: > 0 } value)
                    {
                        samples.Add(MaskLogin(value));
                    }
                }
            }

            result.Findings.Add(new Finding
            {
                CheckId = Id,
                Title = "Compromised credentials containing domain found in public COMB dataset",
                Description =
                    $"ProxyNova reports {count} line(s) containing the target domain in the " +
                    "Combination Of Many Breaches dataset. Passwords are never copied into this report.",
                Severity = Severity.High,
                Confidence = Confidence.Medium,
                Target = context.Target.BaseUrl,
                Url = "https://www.proxynova.com/tools/comb/",
                Evidence = new Dictionary<string, string>
                {
                    ["count"] = count.ToString(),
                    ["sampleLogins"] = string.Join(", ", samples.Distinct(StringComparer.OrdinalIgnoreCase)),
                    ["source"] = "ProxyNova COMB API (domain query)",
                },
                Remediation =
                    "Notify affected users, force password resets, block breached passwords, and enable MFA.",
            });
            return 0;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            result.Notes.Add($"ProxyNova failed: {error.Message}");
            return 1;
        }
    }

    private static async Task<int> BreachDirectoryAsync(
        ICheckContext context,
        string domain,
        CheckResult result,
        int max,
        CancellationToken cancellationToken)
    {
        var settings = context.Engagement.Leaks;
        var key = settings.BreachDirectoryApiKey
            ?? Environment.GetEnvironmentVariable("BREACHDIRECTORY_API_KEY");

        if (string.IsNullOrWhiteSpace(key))
        {
            result.Notes.Add(
                "BreachDirectory is enabled but no API key is configured " +
                "(appsettings.json or BREACHDIRECTORY_API_KEY).");
            return 1;
        }

        var url = "https://breachdirectory.p.rapidapi.com/?func=auto&term=" + Uri.EscapeDataString(domain);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["X-RapidAPI-Key"] = key,
            ["X-RapidAPI-Host"] = "breachdirectory.p.rapidapi.com",
            ["Accept"] = "application/json",
        };

        try
        {
            var response = await context.ExternalHttp.GetAsync(url, cancellationToken, headers);
            if (!response.IsSuccess)
            {
                result.Notes.Add($"BreachDirectory returned HTTP {response.StatusCode}.");
                return 1;
            }

            using var document = JsonDocument.Parse(response.Text);
            var root = document.RootElement;
            var found = root.TryGetProperty("found", out var foundValue) ? foundValue.GetInt32() : 0;
            result.Metrics["breachDirectoryFound"] = found.ToString();

            if (found == 0)
            {
                result.Notes.Add("BreachDirectory: no breach records found.");
                return 0;
            }

            var sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (root.TryGetProperty("result", out var entries) && entries.ValueKind == JsonValueKind.Array)
            {
                foreach (var entry in entries.EnumerateArray().Take(max))
                {
                    if (entry.TryGetProperty("sources", out var sourceValue))
                    {
                        if (sourceValue.ValueKind == JsonValueKind.String)
                        {
                            sources.Add(sourceValue.GetString()!);
                        }
                        else if (sourceValue.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var source in sourceValue.EnumerateArray())
                            {
                                if (source.GetString() is { Length: > 0 } name)
                                {
                                    sources.Add(name);
                                }
                            }
                        }
                    }
                }
            }

            result.Findings.Add(new Finding
            {
                CheckId = Id,
                Title = "Breach records associated with domain",
                Description =
                    $"BreachDirectory reports {found} record(s) for the target domain. " +
                    "Passwords and hashes are intentionally not copied into this report.",
                Severity = Severity.High,
                Confidence = Confidence.Medium,
                Target = context.Target.BaseUrl,
                Url = "https://breachdirectory.org/",
                Evidence = new Dictionary<string, string>
                {
                    ["found"] = found.ToString(),
                    ["sources"] = string.Join(", ", sources),
                    ["source"] = "BreachDirectory API",
                },
                Remediation =
                    "Notify affected users, force password resets, and review the listed breaches for " +
                    "reuse of corporate credentials.",
            });
            return 0;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            result.Notes.Add($"BreachDirectory failed: {error.Message}");
            return 1;
        }
    }

    private static string MaskLogin(string line)
    {
        var value = line.Split(':', 2)[0].Trim();
        var at = value.IndexOf('@');
        if (at > 1)
        {
            var local = value[..at];
            var masked = local.Length <= 2 ? local[..1] + "***" : local[..2] + "***";
            return masked + value[at..];
        }

        return value.Length <= 2 ? "***" : value[..2] + "***";
    }
}
