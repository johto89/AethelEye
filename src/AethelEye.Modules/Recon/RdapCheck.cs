using System.Globalization;
using System.Text.Json;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Models;

namespace AethelEye.Modules.Recon;

/// <summary>
/// Registration data through RDAP, a structured WHOIS replacement. The module mirrors the
/// domain-registration part of omnisci3nt's WHOIS lookup (MIT) without a WHOIS text parser.
/// </summary>
public sealed class RdapCheck : ICheck
{
    public string Id => "rdap";

    public string Name => "Domain registration (RDAP)";

    public string Description =>
        "Retrieves registrar, registration dates, status and nameservers through RDAP.";

    public int Order => 7;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        if (context.Engagement.Offline)
        {
            result.Status = CheckStatus.Skipped;
            result.Summary = "RDAP needs Internet access and was skipped in offline mode.";
            return result;
        }

        var host = context.Target.Host;
        var isIp = ReconSupport.IsIp(host);
        var url = isIp
            ? $"https://rdap.org/ip/{Uri.EscapeDataString(host)}"
            : $"https://rdap.org/domain/{Uri.EscapeDataString(host)}";
        var response = await ReconSupport.TryGetJsonAsync(
            context.ExternalHttp,
            url,
            context.CancellationToken,
            warn: message => result.Notes.Add(message));
        if (response is null)
        {
            result.Status = CheckStatus.Partial;
            result.Summary = "RDAP data was unavailable.";
            return result;
        }

        try
        {
            using var document = JsonDocument.Parse(response.Body);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                result.Status = CheckStatus.Partial;
                result.Summary = "RDAP returned an unexpected document.";
                return result;
            }

            var name = ReconSupport.String(root, "ldhName")
                ?? ReconSupport.String(root, "name")
                ?? ReconSupport.String(root, "handle")
                ?? host;
            var statuses = ReconSupport.Strings(root, "status");
            var nameservers = ReconSupport.Array(root, "nameservers")
                .Select(server => ReconSupport.String(server, "ldhName"))
                .OfType<string>()
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var events = ReconSupport.Array(root, "events")
                .Select(item => new
                {
                    Action = ReconSupport.String(item, "eventAction") ?? string.Empty,
                    Date = ReconSupport.String(item, "eventDate") ?? string.Empty,
                })
                .Where(item => item.Action.Length > 0)
                .ToArray();
            var registrar = RegistrarName(root);
            var startAddress = ReconSupport.String(root, "startAddress");
            var endAddress = ReconSupport.String(root, "endAddress");
            var country = ReconSupport.String(root, "country");

            var evidence = new Dictionary<string, string>
            {
                ["name"] = name,
                ["registrar"] = registrar ?? string.Empty,
                ["status"] = string.Join(", ", statuses),
                ["nameservers"] = string.Join(", ", nameservers),
                ["startAddress"] = startAddress ?? string.Empty,
                ["endAddress"] = endAddress ?? string.Empty,
                ["country"] = country ?? string.Empty,
                ["source"] = url,
            };
            foreach (var item in events)
            {
                evidence[item.Action] = item.Date;
            }

            result.Findings.Add(new Finding
            {
                CheckId = Id,
                Title = isIp ? "IP registration data" : "Domain registration data",
                Description =
                    "Registration data obtained from RDAP. This is inventory information; " +
                    "expiry and deletion status are reported separately.",
                Severity = Severity.Info,
                Confidence = Confidence.High,
                Target = context.Target.BaseUrl,
                Url = url,
                Evidence = evidence,
            });

            var expiry = events
                .Where(item => item.Action.Equals("expiration", StringComparison.OrdinalIgnoreCase))
                .Select(item => ParseDate(item.Date))
                .FirstOrDefault(date => date is not null);
            if (expiry is { } expires)
            {
                var days = (expires - DateTimeOffset.UtcNow).TotalDays;
                result.Metrics["daysToExpiry"] = days.ToString("0");
                if (days < 0)
                {
                    result.Findings.Add(new Finding
                    {
                        CheckId = Id,
                        Title = "Domain registration has expired",
                        Description = $"RDAP reports that the registration expired on {expires:u}.",
                        Severity = Severity.High,
                        Confidence = Confidence.High,
                        Target = context.Target.BaseUrl,
                        Url = url,
                        Evidence = new Dictionary<string, string> { ["expiration"] = expires.ToString("u") },
                        Remediation = "Renew the domain immediately; an expired domain can be re-registered by a third party.",
                    });
                }
                else if (days <= 30)
                {
                    result.Findings.Add(new Finding
                    {
                        CheckId = Id,
                        Title = "Domain registration expires soon",
                        Description = $"The domain expires in {days:0} day(s), on {expires:u}.",
                        Severity = Severity.Medium,
                        Confidence = Confidence.High,
                        Target = context.Target.BaseUrl,
                        Url = url,
                        Evidence = new Dictionary<string, string>
                        {
                            ["expiration"] = expires.ToString("u"),
                            ["daysRemaining"] = days.ToString("0"),
                        },
                        Remediation = "Renew the domain and verify auto-renew and registrar contact details.",
                    });
                }
            }

            if (statuses.Any(status =>
                    status.Contains("pending delete", StringComparison.OrdinalIgnoreCase)
                    || status.Contains("redemption", StringComparison.OrdinalIgnoreCase)))
            {
                result.Findings.Add(new Finding
                {
                    CheckId = Id,
                    Title = "Domain is in a deletion or redemption period",
                    Description =
                        "The registry status indicates that the domain is being deleted or is in " +
                        "redemption. Service and ownership may be lost.",
                    Severity = Severity.High,
                    Confidence = Confidence.High,
                    Target = context.Target.BaseUrl,
                    Url = url,
                    Evidence = new Dictionary<string, string>
                    {
                        ["status"] = string.Join(", ", statuses),
                    },
                    Remediation = "Contact the registrar and restore or renew the registration immediately.",
                });
            }

            result.Metrics["nameservers"] = nameservers.Length.ToString();
            result.Metrics["statuses"] = statuses.Count.ToString();
            result.Summary =
                $"RDAP data for {name}" +
                (registrar is null ? string.Empty : $"; registrar {registrar}") +
                (expiry is null ? string.Empty : $"; expires {expiry:yyyy-MM-dd}") + ".";
            result.Status = result.RiskFindingCount > 0 ? CheckStatus.Findings : CheckStatus.NoRisk;
            return result;
        }
        catch (JsonException error)
        {
            result.Status = CheckStatus.Partial;
            result.Summary = "RDAP response could not be parsed: " + error.Message;
            return result;
        }
    }

    private static string? RegistrarName(JsonElement root)
    {
        foreach (var entity in ReconSupport.Array(root, "entities"))
        {
            var roles = ReconSupport.Strings(entity, "roles");
            if (!roles.Any(role => role.Equals("registrar", StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (!entity.TryGetProperty("vcardArray", out var vcard)
                || vcard.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var item in vcard.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var field in item.EnumerateArray())
                {
                    if (field.ValueKind == JsonValueKind.Array
                        && field.GetArrayLength() >= 4
                        && field[0].ValueKind == JsonValueKind.String
                        && field[0].GetString()?.Equals("fn", StringComparison.OrdinalIgnoreCase) == true
                        && field[3].ValueKind == JsonValueKind.String)
                    {
                        return field[3].GetString();
                    }
                }
            }
        }

        return null;
    }

    private static DateTimeOffset? ParseDate(string value) =>
        DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,
            out var parsed)
            ? parsed
            : null;
}
