using System.Text.RegularExpressions;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;

namespace AethelEye.Modules.Security;

/// <summary>
/// Reviews HTTP security headers, HSTS, cookie flags and security.txt. The checks are inspired by
/// recon-web's http-security, hsts, cookies and security-txt handlers.
/// </summary>
public sealed class SecurityCheck : ICheck
{
    private static readonly Regex HstsMaxAge = new(
        @"max-age\s*=\s*(?<value>\d+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex CookieName = new(
        @"^\s*(?<name>[^=;,\s]+)\s*=",
        RegexOptions.CultureInvariant);

    public string Id => "security";

    public string Name => "HTTP security posture";

    public string Description =>
        "Reviews security headers, HSTS, cookie flags, CORS headers and security.txt.";

    public int Order => 22;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        var page = await context.Pages.GetAsync(context.Target.BaseUri, context.CancellationToken);
        if (!page.IsSuccess)
        {
            result.Status = CheckStatus.NoRisk;
            result.Summary = $"Base page returned HTTP {page.StatusCode}; security headers were not reviewed.";
            return result;
        }

        var headers = page.Headers;
        var hsts = Header(headers, "Strict-Transport-Security");
        var csp = Header(headers, "Content-Security-Policy");
        var xfo = Header(headers, "X-Frame-Options");
        var xcto = Header(headers, "X-Content-Type-Options");
        var referrer = Header(headers, "Referrer-Policy");
        var permissions = Header(headers, "Permissions-Policy");
        var coop = Header(headers, "Cross-Origin-Opener-Policy");
        var coep = Header(headers, "Cross-Origin-Embedder-Policy");
        var corp = Header(headers, "Cross-Origin-Resource-Policy");
        var acao = Header(headers, "Access-Control-Allow-Origin");
        var server = Header(headers, "Server");
        var poweredBy = Header(headers, "X-Powered-By");
        var isHttps = page.FinalUri.Scheme == Uri.UriSchemeHttps;

        result.Metrics["hsts"] = hsts.Length > 0 ? "present" : "missing";
        result.Metrics["csp"] = csp.Length > 0 ? "present" : "missing";
        result.Metrics["xFrameOptions"] = xfo.Length > 0 ? "present" : "missing";
        result.Metrics["xContentTypeOptions"] = xcto.Length > 0 ? "present" : "missing";
        result.Metrics["referrerPolicy"] = referrer.Length > 0 ? "present" : "missing";
        result.Metrics["server"] = server.Length > 0 ? server : "not disclosed";

        if (isHttps && hsts.Length == 0)
        {
            Add(result, context, Severity.Medium, "HSTS is not enabled",
                "The HTTPS response does not include Strict-Transport-Security. " +
                "A user can be downgraded to HTTP on the first request.",
                "Add Strict-Transport-Security with a max-age of at least 15552000 seconds, " +
                "includeSubDomains, and preload once the domain is ready.");
        }
        else if (hsts.Length > 0)
        {
            var match = HstsMaxAge.Match(hsts);
            var maxAge = match.Success && long.TryParse(match.Groups["value"].Value, out var value)
                ? value
                : 0;
            if (maxAge < 15_552_000)
            {
                Add(result, context, Severity.Low, "HSTS max-age is short",
                    "The HSTS max-age is below 180 days, so browsers forget the policy quickly.",
                    "Raise max-age to at least 15552000 seconds and consider includeSubDomains.",
                    new Dictionary<string, string> { ["header"] = hsts });
            }

            if (!hsts.Contains("includeSubDomains", StringComparison.OrdinalIgnoreCase))
            {
                Add(result, context, Severity.Low, "HSTS does not include subdomains",
                    "Strict-Transport-Security does not cover subdomains.",
                    "Add includeSubDomains after confirming every subdomain supports HTTPS.",
                    new Dictionary<string, string> { ["header"] = hsts });
            }
        }

        if (csp.Length == 0)
        {
            Add(result, context, Severity.Low, "Content-Security-Policy is missing",
                "No Content-Security-Policy header was observed. CSP is a defence-in-depth control " +
                "against script injection.",
                "Deploy a restrictive CSP after inventorying required script and style sources.");
        }
        else if (xfo.Length == 0
                 && !csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase))
        {
            Add(result, context, Severity.Medium, "Clickjacking protection is missing",
                "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
                "Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors.");
        }

        if (xfo.Length == 0 && csp.Length == 0)
        {
            Add(result, context, Severity.Medium, "X-Frame-Options is missing",
                "The response can be framed by another site, which enables clickjacking.",
                "Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors.");
        }

        if (xcto.Length == 0)
        {
            Add(result, context, Severity.Low, "X-Content-Type-Options is missing",
                "Browsers may MIME-sniff responses when X-Content-Type-Options is absent.",
                "Add X-Content-Type-Options: nosniff.");
        }

        if (referrer.Length == 0)
        {
            Add(result, context, Severity.Low, "Referrer-Policy is missing",
                "The default referrer policy can leak full URLs to third-party sites.",
                "Add Referrer-Policy: strict-origin-when-cross-origin or a stricter policy.");
        }

        if (permissions.Length == 0)
        {
            Add(result, context, Severity.Info, "Permissions-Policy is not set",
                "No Permissions-Policy header was observed. Browser features are not explicitly restricted.",
                "Restrict camera, microphone, geolocation and other features that the site does not use.");
        }

        if (coop.Length == 0 && coep.Length == 0 && corp.Length == 0)
        {
            Add(result, context, Severity.Info, "Cross-origin isolation headers are not set",
                "COOP, COEP and CORP were not observed. This is not always required, but it limits " +
                "cross-origin attacks such as Spectre-style leaks.",
                "Add COOP/COEP/CORP where the application does not depend on cross-origin embedding.");
        }

        if (acao == "*")
        {
            Add(result, context, Severity.Low, "CORS allows any origin",
                "Access-Control-Allow-Origin is *. Public read-only APIs may need this, but " +
                "authenticated endpoints must not use a wildcard.",
                "Restrict Access-Control-Allow-Origin to trusted origins for authenticated endpoints.");
        }

        if (server.Length > 0 || poweredBy.Length > 0)
        {
            result.Notes.Add(
                "Server banners: " +
                string.Join(", ", new[] { server, poweredBy }.Where(value => value.Length > 0)));
        }

        AnalyzeCookies(context, result, headers, isHttps);
        await AnalyzeSecurityTxtAsync(context, result);

        result.Summary =
            $"HSTS {(hsts.Length > 0 ? "present" : "missing")}, " +
            $"CSP {(csp.Length > 0 ? "present" : "missing")}, " +
            $"X-Frame-Options {(xfo.Length > 0 ? "present" : "missing")}, " +
            $"X-Content-Type-Options {(xcto.Length > 0 ? "present" : "missing")}.";
        result.Status = result.RiskFindingCount > 0 ? CheckStatus.Findings : CheckStatus.NoRisk;
        return result;
    }

    private static void AnalyzeCookies(
        ICheckContext context,
        CheckResult result,
        IReadOnlyDictionary<string, string[]> headers,
        bool isHttps)
    {
        if (!headers.TryGetValue("Set-Cookie", out var cookies) || cookies.Length == 0)
        {
            result.Metrics["cookies"] = "0";
            return;
        }

        var names = new List<string>();
        var missingSecure = new List<string>();
        var missingHttpOnly = new List<string>();
        var missingSameSite = new List<string>();
        var sameSiteNoneWithoutSecure = new List<string>();

        foreach (var cookie in cookies)
        {
            var match = CookieName.Match(cookie);
            var name = match.Success ? match.Groups["name"].Value : "cookie";
            names.Add(name);
            var lower = cookie.ToLowerInvariant();
            if (isHttps && !lower.Contains("; secure", StringComparison.Ordinal)
                && !lower.StartsWith("secure;", StringComparison.Ordinal))
            {
                missingSecure.Add(name);
            }

            if (!lower.Contains("httponly", StringComparison.Ordinal))
            {
                missingHttpOnly.Add(name);
            }

            if (!lower.Contains("samesite", StringComparison.Ordinal))
            {
                missingSameSite.Add(name);
            }
            else if (lower.Contains("samesite=none", StringComparison.Ordinal)
                     && !lower.Contains("; secure", StringComparison.Ordinal))
            {
                sameSiteNoneWithoutSecure.Add(name);
            }
        }

        result.Metrics["cookies"] = names.Count.ToString();
        result.Metrics["cookiesMissingSecure"] = missingSecure.Count.ToString();
        result.Metrics["cookiesMissingHttpOnly"] = missingHttpOnly.Count.ToString();
        result.Metrics["cookiesMissingSameSite"] = missingSameSite.Count.ToString();

        if (missingSecure.Count > 0)
        {
            Add(result, context, Severity.Medium, "Cookies are missing the Secure flag",
                "Cookies without Secure can be sent over HTTP if the site is ever reachable over " +
                "plain HTTP.",
                "Set Secure on every cookie, especially session and authentication cookies.",
                new Dictionary<string, string> { ["cookies"] = string.Join(", ", missingSecure.Take(20)) });
        }

        if (missingHttpOnly.Count > 0)
        {
            Add(result, context, Severity.Low, "Cookies are missing the HttpOnly flag",
                "Cookies without HttpOnly are readable by JavaScript and can be stolen through XSS.",
                "Set HttpOnly on session and authentication cookies.",
                new Dictionary<string, string> { ["cookies"] = string.Join(", ", missingHttpOnly.Take(20)) });
        }

        if (missingSameSite.Count > 0)
        {
            Add(result, context, Severity.Low, "Cookies are missing the SameSite attribute",
                "Cookies without SameSite may be sent on cross-site requests, which increases CSRF risk.",
                "Set SameSite=Lax or SameSite=Strict on session cookies.",
                new Dictionary<string, string> { ["cookies"] = string.Join(", ", missingSameSite.Take(20)) });
        }

        if (sameSiteNoneWithoutSecure.Count > 0)
        {
            Add(result, context, Severity.Medium, "SameSite=None cookies are missing Secure",
                "Browsers reject SameSite=None cookies that are not also marked Secure.",
                "Add Secure to every cookie that uses SameSite=None.",
                new Dictionary<string, string>
                {
                    ["cookies"] = string.Join(", ", sameSiteNoneWithoutSecure.Take(20)),
                });
        }
    }

    private static async Task AnalyzeSecurityTxtAsync(ICheckContext context, CheckResult result)
    {
        var root = context.Target.RootUrl.TrimEnd('/');
        foreach (var path in new[] { "/.well-known/security.txt", "/security.txt" })
        {
            var uri = new Uri(root + path, UriKind.Absolute);
            if (!context.Scope.IsAllowed(uri))
            {
                continue;
            }

            HttpResponseData response;
            try
            {
                response = await context.Http.GetAsync(uri, context.CancellationToken);
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                result.Notes.Add($"{path}: {error.Message}");
                continue;
            }

            if (!response.IsSuccess
                || response.Text.TrimStart().StartsWith('<')
                || !response.Text.Contains("Contact:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            result.Metrics["securityTxt"] = path;
            result.Findings.Add(new Finding
            {
                CheckId = "security",
                Title = "security.txt is published",
                Description =
                    "A security.txt file tells researchers how to report vulnerabilities. " +
                    "This is good practice; verify that the contact details are current.",
                Severity = Severity.Info,
                Confidence = Confidence.High,
                Target = context.Target.BaseUrl,
                Url = uri.ToString(),
                Evidence = new Dictionary<string, string>
                {
                    ["path"] = path,
                    ["content"] = Truncate(response.Text, 1500),
                    ["pgpSigned"] = response.Text.Contains(
                        "-----BEGIN PGP SIGNED MESSAGE-----",
                        StringComparison.Ordinal)
                        ? "true"
                        : "false",
                },
            });
            return;
        }

        result.Metrics["securityTxt"] = "missing";
        result.Notes.Add("security.txt was not found at /.well-known/security.txt or /security.txt.");
    }

    private static void Add(
        CheckResult result,
        ICheckContext context,
        Severity severity,
        string title,
        string description,
        string remediation,
        Dictionary<string, string>? evidence = null)
    {
        result.Findings.Add(new Finding
        {
            CheckId = "security",
            Title = title,
            Description = description,
            Severity = severity,
            Confidence = Confidence.High,
            Target = context.Target.BaseUrl,
            Url = context.Target.BaseUrl,
            Evidence = evidence ?? [],
            Remediation = remediation,
        });
    }

    private static string Header(IReadOnlyDictionary<string, string[]> headers, string name) =>
        headers.TryGetValue(name, out var values) && values.Length > 0
            ? string.Join(", ", values)
            : string.Empty;

    private static string Truncate(string value, int length) =>
        value.Length <= length ? value : value[..length] + "...";
}
