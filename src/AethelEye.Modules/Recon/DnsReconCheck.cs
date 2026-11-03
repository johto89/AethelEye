using System.Net;
using System.Text.RegularExpressions;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Models;

namespace AethelEye.Modules.Recon;

/// <summary>
/// Passive DNS and email-authentication inventory inspired by omnisci3nt's dns and DMARC modules
/// (MIT). It records A/AAAA/MX/NS/TXT/CNAME/CAA data and flags missing or weak SPF/DMARC records.
/// </summary>
public sealed class DnsReconCheck : ICheck
{
    private static readonly string[] RecordTypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA"];

    private static readonly Regex DmarcPolicy = new(
        @"(?:^|;)\s*p\s*=\s*(?<value>[^;]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex DmarcSpPolicy = new(
        @"(?:^|;)\s*sp\s*=\s*(?<value>[^;]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex DmarcPercent = new(
        @"(?:^|;)\s*pct\s*=\s*(?<value>[^;]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public string Id => "dns";

    public string Name => "DNS and email authentication";

    public string Description =>
        "Collects DNS records and reports missing or weak SPF and DMARC policies.";

    public int Order => 5;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        var domain = ReconSupport.Domain(context.Target);
        if (domain is null)
        {
            result.Status = CheckStatus.Skipped;
            result.Summary = "DNS recon needs a domain target, not an IP address.";
            return result;
        }

        var records = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        if (context.Engagement.Offline)
        {
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(domain, context.CancellationToken);
                records["A"] = addresses
                    .Where(address => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(address => address.ToString())
                    .ToList();
                records["AAAA"] = addresses
                    .Where(address => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    .Select(address => address.ToString())
                    .ToList();
                result.Notes.Add(
                    "Offline mode: only local A/AAAA records were resolved; " +
                    "MX/TXT/NS/CAA and DMARC require the online DNS-over-HTTPS query.");
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                result.Notes.Add($"Local DNS resolution failed: {error.Message}");
            }
        }
        else
        {
            foreach (var type in RecordTypes)
            {
                var values = await DnsOverHttps.QueryAsync(
                    context.ExternalHttp,
                    domain,
                    type,
                    context.CancellationToken,
                    message => result.Notes.Add(message));
                if (values.Count > 0)
                {
                    records[type] = values.ToList();
                }
            }
        }

        IReadOnlyList<string> dmarcRecords = context.Engagement.Offline
            ? []
            : await DnsOverHttps.QueryAsync(
                context.ExternalHttp,
                "_dmarc." + domain,
                "TXT",
                context.CancellationToken,
                message => result.Notes.Add(message));
        IReadOnlyList<string> dnskey = context.Engagement.Offline
            ? []
            : await DnsOverHttps.QueryAsync(
                context.ExternalHttp,
                domain,
                "DNSKEY",
                context.CancellationToken,
                message => result.Notes.Add(message));
        IReadOnlyList<string> ds = context.Engagement.Offline
            ? []
            : await DnsOverHttps.QueryAsync(
                context.ExternalHttp,
                domain,
                "DS",
                context.CancellationToken,
                message => result.Notes.Add(message));
        var dnssec = dnskey.Count > 0 || ds.Count > 0;

        var txtRecords = records.TryGetValue("TXT", out var txt) ? txt : [];
        var allTxt = txtRecords.Concat(dmarcRecords).ToList();
        var spf = allTxt.FirstOrDefault(value =>
            value.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase));
        var dmarc = allTxt.FirstOrDefault(value =>
            value.Contains("v=DMARC1", StringComparison.OrdinalIgnoreCase)
            && (value.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)
                || value.Contains("v=DMARC1", StringComparison.OrdinalIgnoreCase)));

        foreach (var (type, values) in records.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            result.Metrics[type.ToLowerInvariant()] = values.Count.ToString();
        }

        if (records.Count == 0 && spf is null && dmarc is null)
        {
            result.Status = CheckStatus.Partial;
            result.Summary = "No DNS records could be collected.";
            return result;
        }

        var evidence = new Dictionary<string, string>
        {
            ["domain"] = domain,
            ["spf"] = context.Engagement.Offline ? "not checked" : spf ?? string.Empty,
            ["dmarc"] = context.Engagement.Offline ? "not checked" : dmarc ?? string.Empty,
            ["dnssec"] = context.Engagement.Offline ? "not checked" : dnssec ? "present" : "missing",
            ["dnskey"] = context.Engagement.Offline ? "not checked" : dnskey.Count.ToString(),
            ["ds"] = context.Engagement.Offline ? "not checked" : ds.Count.ToString(),
        };
        foreach (var (type, values) in records)
        {
            evidence[type.ToLowerInvariant()] = string.Join(" | ", values.Take(20));
        }

        result.Findings.Add(new Finding
        {
            CheckId = Id,
            Title = "DNS and email-authentication records",
            Description =
                "Public DNS records observed for the target domain. " +
                "This is inventory information; missing records are reported separately.",
            Severity = Severity.Info,
            Confidence = Confidence.High,
            Target = context.Target.BaseUrl,
            Url = context.Target.BaseUrl,
            Evidence = evidence,
        });

        var hasMail = records.TryGetValue("MX", out var mx) && mx.Count > 0;
        AddEmailAuthFindings(context, result, domain, dmarc, spf, hasMail);

        result.Metrics["records"] = records.Count.ToString();
        result.Metrics["mx"] = hasMail ? "yes" : "no";
        result.Metrics["dmarc"] = dmarc is null ? "missing" : "present";
        result.Metrics["spf"] = spf is null ? "missing" : "present";
        result.Metrics["dnssec"] = dnssec ? "present" : "missing";

        if (!context.Engagement.Offline && !dnssec)
        {
            result.Findings.Add(new Finding
            {
                CheckId = Id,
                Title = "DNSSEC is not enabled",
                Description =
                    "No DNSKEY or DS records were observed. DNSSEC lets resolvers detect forged " +
                    "or tampered DNS answers for this domain.",
                Severity = Severity.Low,
                Confidence = Confidence.Medium,
                Target = context.Target.BaseUrl,
                Url = context.Target.BaseUrl,
                Evidence = new Dictionary<string, string>
                {
                    ["domain"] = domain,
                    ["dnskey"] = dnskey.Count.ToString(),
                    ["ds"] = ds.Count.ToString(),
                },
                Remediation =
                    "Enable DNSSEC at the registrar and DNS provider after confirming that the " +
                    "authoritative DNS platform supports it.",
            });
        }
        result.Summary =
            $"Collected {records.Count} DNS record type(s); " +
            $"SPF {(spf is null ? "missing" : "present")}, " +
            $"DMARC {(dmarc is null ? "missing" : "present")}.";
        result.Status = result.RiskFindingCount > 0 ? CheckStatus.Findings : CheckStatus.NoRisk;
        return result;
    }

    private static void AddEmailAuthFindings(
        ICheckContext context,
        CheckResult result,
        string domain,
        string? dmarc,
        string? spf,
        bool hasMail)
    {
        if (dmarc is null)
        {
            result.Findings.Add(new Finding
            {
                CheckId = "dns",
                Title = "DMARC record is missing",
                Description =
                    "No _dmarc TXT record with v=DMARC1 was found. Without DMARC, receivers have no " +
                    "policy for messages that fail SPF or DKIM, so the domain is easier to spoof.",
                Severity = hasMail ? Severity.Medium : Severity.Low,
                Confidence = Confidence.High,
                Target = context.Target.BaseUrl,
                Url = context.Target.BaseUrl,
                Evidence = new Dictionary<string, string>
                {
                    ["query"] = "_dmarc." + domain,
                    ["mx"] = hasMail ? "present" : "absent",
                },
                Remediation =
                    "Publish a DMARC record, start with p=none for monitoring, then move to " +
                    "p=quarantine or p=reject after reviewing reports.",
            });
        }
        else
        {
            var policy = DmarcPolicy.Match(dmarc).Groups["value"].Value.Trim().ToLowerInvariant();
            var spPolicy = DmarcSpPolicy.Match(dmarc).Groups["value"].Value.Trim().ToLowerInvariant();
            var percent = DmarcPercent.Match(dmarc).Groups["value"].Value.Trim();
            if (policy is "none" or "")
            {
                result.Findings.Add(new Finding
                {
                    CheckId = "dns",
                    Title = "DMARC policy is monitor-only",
                    Description =
                        "The DMARC record exists but p is none or absent, so failing messages are " +
                        "not quarantined or rejected. Spoofed mail can still be delivered.",
                    Severity = Severity.Medium,
                    Confidence = Confidence.High,
                    Target = context.Target.BaseUrl,
                    Url = context.Target.BaseUrl,
                    Evidence = new Dictionary<string, string>
                    {
                        ["record"] = dmarc,
                        ["policy"] = policy,
                        ["subdomainPolicy"] = spPolicy,
                        ["percent"] = percent,
                    },
                    Remediation =
                        "Review DMARC reports, then raise the policy to quarantine or reject.",
                });
            }
        }

        if (spf is null)
        {
            result.Findings.Add(new Finding
            {
                CheckId = "dns",
                Title = "SPF record is missing",
                Description =
                    "No v=spf1 TXT record was found. Receivers cannot use SPF to reject forged " +
                    "envelope senders for this domain.",
                Severity = hasMail ? Severity.Medium : Severity.Low,
                Confidence = Confidence.High,
                Target = context.Target.BaseUrl,
                Url = context.Target.BaseUrl,
                Evidence = new Dictionary<string, string>
                {
                    ["domain"] = domain,
                },
                Remediation =
                    "Publish an SPF record listing only the systems that are allowed to send mail.",
            });
            return;
        }

        var lower = spf.ToLowerInvariant();
        if (lower.Contains("+all", StringComparison.Ordinal)
            || lower.Contains("?all", StringComparison.Ordinal))
        {
            result.Findings.Add(new Finding
            {
                CheckId = "dns",
                Title = "SPF allows every sender",
                Description =
                    "The SPF record ends with +all or ?all. This defeats the purpose of SPF and " +
                    "makes sender spoofing easier.",
                Severity = Severity.High,
                Confidence = Confidence.High,
                Target = context.Target.BaseUrl,
                Url = context.Target.BaseUrl,
                Evidence = new Dictionary<string, string>
                {
                    ["record"] = spf,
                },
                Remediation = "Replace the all mechanism with ~all or -all after listing authorized senders.",
            });
        }
    }
}
