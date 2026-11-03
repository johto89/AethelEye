using System.Text.Json;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;
using AethelEye.Core.Tools;

namespace AethelEye.Modules.GitHub;

/// <summary>
/// Searches public GitHub repositories and code, then optionally clones repositories and runs the
/// gitleaks binary through the external tool runner. No secret value is copied into the report.
/// </summary>
public sealed class GitHubCheck : ICheck
{
    private sealed record Repository(string FullName, string Url, string CloneUrl, string? Description);

    public string Id => "github";

    public string Name => "GitHub exposure";

    public string Description =>
        "Searches GitHub for repositories and code related to the target domain; optional gitleaks pass.";

    public int Order => 40;

    public async Task<CheckResult> RunAsync(ICheckContext context)
    {
        var result = new CheckResult { CheckId = Id, CheckName = Name };
        if (context.Engagement.Offline)
        {
            result.Status = CheckStatus.Skipped;
            result.Summary = "Offline mode: GitHub requires Internet and was not contacted.";
            result.Notes.Add("Run without --offline to enable GitHub repository and code search.");
            return result;
        }

        var settings = context.Engagement.GitHub;
        var token = settings.Token ?? Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        var domain = context.Target.Host;

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Accept"] = "application/vnd.github+json",
            ["X-GitHub-Api-Version"] = "2022-11-28",
        };
        if (!string.IsNullOrWhiteSpace(token))
        {
            headers["Authorization"] = "Bearer " + token;
        }

        var repositories = new List<Repository>();
        var query = $"{domain} in:name,description,readme";
        var repositoryUrl =
            "https://api.github.com/search/repositories?q=" + Uri.EscapeDataString(query) +
            $"&per_page={Math.Clamp(settings.MaxRepositories, 1, 100)}";
        var repositoryResponse = await TryGetAsync(
            context.ExternalHttp, repositoryUrl, headers, result, context.CancellationToken, "repository search");
        var hadError = repositoryResponse is null;

        if (repositoryResponse is not null)
        {
            ParseRepositories(repositoryResponse, repositories, result);
        }

        result.Metrics["repositories"] = repositories.Count.ToString();
        foreach (var repository in repositories)
        {
            result.Findings.Add(new Finding
            {
                CheckId = Id,
                Title = "Public GitHub repository references target",
                Description =
                    "A public repository mentions the target host in its name, description or readme. " +
                    "Review it for copied code, credentials or internal documentation.",
                Severity = Severity.Info,
                Confidence = Confidence.Medium,
                Target = context.Target.BaseUrl,
                Url = repository.Url,
                Evidence = new Dictionary<string, string>
                {
                    ["repository"] = repository.FullName,
                    ["description"] = repository.Description ?? string.Empty,
                },
                Remediation = "Confirm ownership and remove sensitive material from public repositories.",
            });
        }

        if (settings.CodeSearch)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                hadError = true;
            }

            hadError |= await SearchCodeAsync(context, domain, token, headers, result) > 0;
        }

        if (settings.CloneAndScan && repositories.Count > 0)
        {
            hadError |= await ScanRepositoriesAsync(context, repositories, result) > 0;
        }
        else if (settings.CloneAndScan)
        {
            result.Notes.Add("Clone-and-scan was enabled but no repository was found.");
            hadError = true;
        }

        result.Summary =
            $"{repositories.Count} repository reference(s); {result.RiskFindingCount} risk finding(s).";
        result.Status = result.RiskFindingCount > 0
            ? CheckStatus.Findings
            : hadError ? CheckStatus.Partial : CheckStatus.NoRisk;
        return result;
    }

    private static async Task<HttpResponseData?> TryGetAsync(
        IExternalHttpClient http,
        string url,
        IReadOnlyDictionary<string, string> headers,
        CheckResult result,
        CancellationToken cancellationToken,
        string label)
    {
        try
        {
            var response = await http.GetAsync(url, cancellationToken, headers);
            if (response.IsSuccess)
            {
                return response;
            }

            var reset = response.Header("X-RateLimit-Reset");
            var detail = string.IsNullOrWhiteSpace(reset) ? string.Empty : $" (rate limit reset {reset})";
            result.Notes.Add($"GitHub {label} returned HTTP {response.StatusCode}{detail}.");
            return null;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            result.Notes.Add($"GitHub {label} failed: {error.Message}");
            return null;
        }
    }

    private static void ParseRepositories(
        HttpResponseData response,
        List<Repository> repositories,
        CheckResult result)
    {
        try
        {
            using var document = JsonDocument.Parse(response.Text);
            if (!document.RootElement.TryGetProperty("items", out var items)
                || items.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            foreach (var item in items.EnumerateArray())
            {
                var fullName = item.TryGetProperty("full_name", out var name)
                    ? name.GetString()
                    : null;
                var url = item.TryGetProperty("html_url", out var html) ? html.GetString() : null;
                var clone = item.TryGetProperty("clone_url", out var cloneUrl) ? cloneUrl.GetString() : null;
                var description = item.TryGetProperty("description", out var text) ? text.GetString() : null;
                if (string.IsNullOrWhiteSpace(fullName) || string.IsNullOrWhiteSpace(url))
                {
                    continue;
                }

                repositories.Add(new Repository(fullName, url, clone ?? url, description));
            }
        }
        catch (JsonException error)
        {
            result.Notes.Add($"GitHub repository response could not be parsed: {error.Message}");
        }
    }

    private static async Task<int> SearchCodeAsync(
        ICheckContext context,
        string domain,
        string? token,
        IReadOnlyDictionary<string, string> headers,
        CheckResult result)
    {
        var failures = 0;
        var queries = new (string Query, Severity Severity, string Label)[]
        {
            ($"\"{domain}\" password", Severity.Medium, "password"),
            ($"\"{domain}\" (api_key OR api_secret OR passwd)", Severity.Medium, "api key"),
            ($"\"{domain}\" \"BEGIN RSA PRIVATE KEY\"", Severity.High, "private key"),
        };

        if (string.IsNullOrWhiteSpace(token))
        {
            result.Notes.Add(
                "GitHub code search needs GITHUB_TOKEN. Manual queries are listed below.");
            foreach (var (query, _, _) in queries)
            {
                result.Notes.Add(
                    "https://github.com/search?q=" + Uri.EscapeDataString(query) + "&type=code");
            }

            return 0;
        }

        foreach (var (query, severity, label) in queries)
        {
            var url =
                "https://api.github.com/search/code?q=" + Uri.EscapeDataString(query) +
                $"&per_page={Math.Clamp(context.Engagement.GitHub.MaxRepositories, 1, 100)}";
            var response = await TryGetAsync(
                context.ExternalHttp, url, headers, result, context.CancellationToken, $"code search ({label})");
            if (response is null)
            {
                failures++;
                continue;
            }

            try
            {
                using var document = JsonDocument.Parse(response.Text);
                var total = document.RootElement.TryGetProperty("total_count", out var totalValue)
                    ? totalValue.GetInt32()
                    : 0;
                result.Metrics[$"codeSearch:{label}"] = total.ToString();

                if (total == 0
                    || !document.RootElement.TryGetProperty("items", out var items)
                    || items.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var item in items.EnumerateArray())
                {
                    var path = item.TryGetProperty("path", out var pathValue) ? pathValue.GetString() : null;
                    var html = item.TryGetProperty("html_url", out var htmlValue) ? htmlValue.GetString() : null;
                    var repository = item.TryGetProperty("repository", out var repoValue)
                        && repoValue.TryGetProperty("full_name", out var nameValue)
                        ? nameValue.GetString()
                        : null;
                    if (string.IsNullOrWhiteSpace(html))
                    {
                        continue;
                    }

                    result.Findings.Add(new Finding
                    {
                        CheckId = Id,
                        Title = "Potential secret in public GitHub code",
                        Description =
                            "GitHub code search matched a credential-related query. " +
                            "The result must be opened manually and confirmed before reporting.",
                        Severity = severity,
                        Confidence = Confidence.Low,
                        Target = context.Target.BaseUrl,
                        Url = html,
                        Evidence = new Dictionary<string, string>
                        {
                            ["repository"] = repository ?? string.Empty,
                            ["path"] = path ?? string.Empty,
                            ["query"] = query,
                        },
                        Remediation =
                            "Remove the secret, rotate it, and purge it from git history. " +
                            "Enable GitHub secret scanning.",
                    });
                }
            }
            catch (JsonException error)
            {
                result.Notes.Add($"GitHub code search response could not be parsed: {error.Message}");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(1500), context.CancellationToken);
        }

        return failures;
    }

    private static async Task<int> ScanRepositoriesAsync(
        ICheckContext context,
        IReadOnlyList<Repository> repositories,
        CheckResult result)
    {
        var failures = 0;
        if (context.Tools.Resolve("git") is null)
        {
            result.Notes.Add("git was not found; clone-and-scan was skipped.");
            return 1;
        }

        var runner = context.Tools;
        var configured = context.Engagement.GitHub.GitleaksPath;
        if (!string.IsNullOrWhiteSpace(configured))
        {
            runner = new ExternalToolRunner(
                [new ToolSettings { Name = "gitleaks", Path = configured }],
                context.Log);
        }

        if (runner.Resolve("gitleaks") is null)
        {
            result.Notes.Add(
                "gitleaks was not found. Set tools[].path or GITLEAKS_PATH; clone-and-scan was skipped.");
            return 1;
        }

        foreach (var repository in repositories.Take(5))
        {
            var tempRoot = Path.Combine(
                Path.GetTempPath(),
                "aetheleye-gitleaks",
                Guid.NewGuid().ToString("N"));
            var checkout = Path.Combine(tempRoot, "repo");
            var report = Path.Combine(tempRoot, "gitleaks.json");

            try
            {
                Directory.CreateDirectory(tempRoot);
                var clone = await context.Tools.RunAsync(
                    "git",
                    ["-c", "credential.helper=", "clone", "--depth", "1", "--quiet", repository.CloneUrl, checkout],
                    TimeSpan.FromMinutes(2),
                    environment: new Dictionary<string, string>
                    {
                        ["GIT_TERMINAL_PROMPT"] = "0",
                    },
                    cancellationToken: context.CancellationToken);

                if (!clone.Succeeded)
                {
                    failures++;
                    result.Notes.Add($"git clone failed for {repository.FullName}: {Truncate(clone.StandardError, 200)}");
                    continue;
                }

                var scan = await runner.RunAsync(
                    "gitleaks",
                    [
                        "detect",
                        "--source", checkout,
                        "--report-format", "json",
                        "--report-path", report,
                        "--no-banner",
                        "--exit-code", "0",
                    ],
                    TimeSpan.FromMinutes(4),
                    cancellationToken: context.CancellationToken);

                if (!File.Exists(report))
                {
                    failures++;
                    result.Notes.Add(
                        $"gitleaks produced no report for {repository.FullName}: {Truncate(scan.StandardError, 200)}");
                    continue;
                }

                ParseGitleaksReport(report, repository, context, result);
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                failures++;
                result.Notes.Add($"gitleaks failed for {repository.FullName}: {error.Message}");
            }
            finally
            {
                try
                {
                    if (Directory.Exists(tempRoot))
                    {
                        Directory.Delete(tempRoot, recursive: true);
                    }
                }
                catch (IOException)
                {
                    // Temporary files are best effort.
                }
            }
        }

        return failures;
    }

    private static void ParseGitleaksReport(
        string path,
        Repository repository,
        ICheckContext context,
        CheckResult result)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            foreach (var item in document.RootElement.EnumerateArray())
            {
                var rule = item.TryGetProperty("RuleID", out var ruleValue) ? ruleValue.GetString() : null;
                var description = item.TryGetProperty("Description", out var descriptionValue)
                    ? descriptionValue.GetString()
                    : null;
                var file = item.TryGetProperty("File", out var fileValue) ? fileValue.GetString() : null;
                var line = item.TryGetProperty("StartLine", out var lineValue) ? lineValue.ToString() : null;
                var secret = item.TryGetProperty("Secret", out var secretValue) ? secretValue.GetString() : null;
                var commit = item.TryGetProperty("Commit", out var commitValue) ? commitValue.GetString() : null;

                var severity = rule?.Contains("private-key", StringComparison.OrdinalIgnoreCase) == true
                    ? Severity.Critical
                    : Severity.High;

                result.Findings.Add(new Finding
                {
                    CheckId = Id,
                    Title = "Secret found by gitleaks in a cloned repository",
                    Description = description ?? "gitleaks matched a credential rule.",
                    Severity = severity,
                    Confidence = Confidence.High,
                    Target = context.Target.BaseUrl,
                    Url = repository.Url,
                    Evidence = new Dictionary<string, string>
                    {
                        ["repository"] = repository.FullName,
                        ["rule"] = rule ?? string.Empty,
                        ["file"] = file ?? string.Empty,
                        ["line"] = line ?? string.Empty,
                        ["commit"] = commit ?? string.Empty,
                        ["secret"] = Mask(secret),
                    },
                    Remediation =
                        "Treat the secret as compromised: rotate it, remove it from history, " +
                        "and review access logs for use.",
                });
            }
        }
        catch (JsonException error)
        {
            result.Notes.Add($"gitleaks report could not be parsed: {error.Message}");
        }
    }

    private static string Mask(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        return value.Length <= 8 ? "***" : value[..4] + "..." + value[^2..];
    }

    private static string Truncate(string? value, int length) =>
        Core.StringHelpers.Truncate(value, length);
}
