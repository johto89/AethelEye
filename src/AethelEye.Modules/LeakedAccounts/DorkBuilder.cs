// SPDX-License-Identifier: GPL-3.0-or-later
// Ported from gosearch (https://github.com/ibnaleem/gosearch), GPL-3.0.
// See THIRD-PARTY-NOTICES.md for the full attribution.

namespace AethelEye.Modules.LeakedAccounts;

public sealed record Dork(string Engine, string Title, string Query, string Url);

/// <summary>
/// Port of the manual dork set from gosearch's domain-leak module. These are evidence links for a
/// human reviewer, not findings. They are generated offline because they need no network.
/// </summary>
public static class DorkBuilder
{
    public static IReadOnlyList<Dork> Build(string domain)
    {
        var at = "@" + domain;
        var credentials =
            $"\"{domain}\" (\"password\" OR \"passwd\" OR \"pwd\" OR \"matkhau\" OR \"mat_khau\" " +
            "OR \"tai_khoan\" OR \"secret\" OR \"api_key\" OR \"apikey\" OR \"api_secret\" " +
            "OR \"token\" OR \"access_token\" OR \"credentials\" OR \"authorization\" " +
            "OR \"bearer\" OR \"private_key\")";
        var infrastructure =
            $"\"{domain}\" (\"jdbc\" OR \"smtp\" OR \"ftp\" OR \"ssh\" OR \"mysql\" " +
            "OR \"connectionstring\" OR \"mongodb://\" OR \"Server=\" OR \"aws_secret_access_key\" " +
            "OR \"BEGIN RSA PRIVATE KEY\" OR \"BEGIN OPENSSH PRIVATE KEY\")";
        var dump =
            $"\"{domain}\" (\"password:\" OR \"pass:\" OR \"pwd:\" OR \"email:password\" " +
            "OR \"user:pass\" OR \"username:password\" OR \"matkhau:\")";
        var files =
            $"\"{domain}\" (ext:sql OR ext:env OR ext:log OR ext:bak OR ext:old " +
            "OR ext:xls OR ext:xlsx OR ext:csv OR ext:txt)";
        var paste =
            $"\"{domain}\" (site:pastebin.com OR site:paste.rs OR site:controlc.com " +
            "OR site:rentry.co OR site:ghostbin.com OR site:paste.ee OR site:github.com)";
        var githubCode = $"\"{domain}\" password OR passwd OR secret OR api_key";
        var githubKeys =
            $"\"{domain}\" \"BEGIN RSA PRIVATE KEY\" OR \"BEGIN OPENSSH PRIVATE KEY\" " +
            "OR \"aws_secret_access_key\"";
        var sourcegraph =
            $"context:global \"{domain}\" (password OR secret OR api_key OR passwd)";

        return
        [
            G("Google", "Accounts + generic secrets", credentials, "https://www.google.com/search?q="),
            G("Google", "Infrastructure / connection strings / private keys", infrastructure,
                "https://www.google.com/search?q="),
            G("Google", "Email:pass dumps with @domain", dump,
                "https://www.google.com/search?q="),
            G("Google", "Exposed files sql/env/log/bak/xls/csv", files,
                "https://www.google.com/search?q="),
            G("Google", "Paste sites", paste,
                "https://www.google.com/search?q="),
            G("Bing", "Accounts + secrets (cross-check Google)", credentials,
                "https://www.bing.com/search?q="),
            G("Bing", "Email:pass dumps (cross-check Google)", dump,
                "https://www.bing.com/search?q="),
            new("GitHub", "Code search: credentials", githubCode,
                "https://github.com/search?q=" + Uri.EscapeDataString(githubCode) + "&type=code"),
            new("GitHub", "Code search: private keys", githubKeys,
                "https://github.com/search?q=" + Uri.EscapeDataString(githubKeys) + "&type=code"),
            new("Sourcegraph", "Global code search", sourcegraph,
                "https://sourcegraph.com/search?q=" + Uri.EscapeDataString(sourcegraph) +
                "&patternType=keyword"),
            new("GrayHat", "Open S3 buckets with domain", domain,
                "https://buckets.grayhatwarfare.com/search?q=" + Uri.EscapeDataString(domain)),
            new("urlscan", "URLs / artifacts related to domain", domain,
                "https://urlscan.io/search/#" + Uri.EscapeDataString(domain)),
        ];

        static Dork G(string engine, string title, string query, string prefix) =>
            new(engine, title, query, prefix + Uri.EscapeDataString(query));
    }
}
