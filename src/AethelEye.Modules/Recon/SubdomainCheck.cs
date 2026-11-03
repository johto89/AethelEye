using System.Text.Json;
using System.Text.RegularExpressions;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;

namespace AethelEye.Modules.Recon;

/// <summary>
/// Certificate Transparency subdomain discovery through crt.sh, with a Hackertarget hostsearch
/// fallback. This is the passive part of omnisci3nt's subdomain module (MIT); no DNS brute force.
/// </summary>
public sealed partial class SubdomainCheck : ICheck
{
    [GeneratedRegex(@"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ValidHost();

    public string Id => "subdomains";

    public string Name => "Subdomain discovery (CT)";

    public string Description =>
        "Collects subdomains from Certificate Transparency logs (crt.sh) with a hostsearch fallback.";

    public int Order => 8;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        var domain = ReconSupport.Domain(context.Target);
        if (domain is null)
        {
            result.Status = CheckStatus.Skipped;
            result.Summary = "Subdomain discovery needs a domain target, not an IP address.";
            return result;
        }

        if (context.Engagement.Offline)
        {
            result.Status = CheckStatus.Skipped;
            result.Summary = "Certificate Transparency needs Internet access and was skipped in offline mode.";
            return result;
        }

        var maxResults = Math.Clamp(context.Settings.GetInt("maxResults", 500), 1, 5000);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var url = $"https://crt.sh/?q={Uri.EscapeDataString("%." + domain)}&output=json";
        var response = await ReconSupport.TryGetJsonAsync(
            context.ExternalHttp,
            url,
            context.CancellationToken,
            warn: message => result.Notes.Add(message));

        var fromCrt = response is not null && TryParseCrt(response.Body, domain, names);
        if (!fromCrt)
        {
            result.Notes.Add("crt.sh did not return usable JSON; trying Hackertarget hostsearch.");
            await AddHackertargetAsync(context, domain, names, result);
        }

        var ordered = names
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var shown = ordered.Take(maxResults).ToArray();

        result.Metrics["subdomains"] = ordered.Length.ToString();
        result.Metrics["returned"] = shown.Length.ToString();
        if (ordered.Length > shown.Length)
        {
            result.Notes.Add(
                $"Result list truncated to {shown.Length} of {ordered.Length} unique names.");
        }

        if (shown.Length == 0)
        {
            result.Status = CheckStatus.Partial;
            result.Summary = "No subdomains could be collected from Certificate Transparency or hostsearch.";
            return result;
        }

        result.Findings.Add(new Finding
        {
            CheckId = Id,
            Title = $"Public sources expose {ordered.Length} subdomain(s)",
            Description =
                "Hostnames observed in public Certificate Transparency or hostsearch data. " +
                "This expands the known attack surface and should be reviewed against the authorized scope.",
            Severity = Severity.Info,
            Confidence = fromCrt ? Confidence.High : Confidence.Medium,
            Target = context.Target.BaseUrl,
            Url = url,
            Evidence = new Dictionary<string, string>
            {
                ["domain"] = domain,
                ["count"] = ordered.Length.ToString(),
                ["source"] = fromCrt ? "crt.sh" : "hackertarget hostsearch",
                ["subdomains"] = string.Join(", ", shown),
            },
        });

        result.Status = CheckStatus.NoRisk;
        result.Summary =
            $"Found {ordered.Length} unique subdomain(s) from " +
            (fromCrt ? "Certificate Transparency." : "Hackertarget hostsearch.");
        return result;
    }

    private static bool TryParseCrt(byte[] body, string domain, HashSet<string> names)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                return false;
            }

            foreach (var entry in document.RootElement.EnumerateArray())
            {
                if (entry.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                AddNames(names, ReconSupport.String(entry, "name_value"), domain);
                AddNames(names, ReconSupport.String(entry, "common_name"), domain);
            }

            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static async Task AddHackertargetAsync(
        ICheckContext context,
        string domain,
        HashSet<string> names,
        CheckResult result)
    {
        var url = $"https://api.hackertarget.com/hostsearch/?q={Uri.EscapeDataString(domain)}";
        HttpResponseData? response;
        try
        {
            response = await context.ExternalHttp.GetAsync(url, context.CancellationToken);
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            result.Notes.Add($"{url}: {error.Message}");
            return;
        }

        if (!response.IsSuccess)
        {
            result.Notes.Add($"{url}: HTTP {response.StatusCode}");
            return;
        }

        foreach (var line in response.Text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var host = line.Split(',')[0].Trim();
            AddNames(names, host, domain);
        }
    }

    private static void AddNames(HashSet<string> names, string? value, string domain)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        foreach (var raw in value.Split(['\n', '\r', ','], StringSplitOptions.RemoveEmptyEntries))
        {
            var name = raw.Trim().TrimEnd('.').ToLowerInvariant();
            if (name.StartsWith("*.", StringComparison.Ordinal))
            {
                name = name[2..];
            }

            if (name.Length == 0
                || name.Length > 253
                || !ValidHost().IsMatch(name)
                || !(name.Equals(domain, StringComparison.OrdinalIgnoreCase)
                     || name.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            names.Add(name);
        }
    }
}
