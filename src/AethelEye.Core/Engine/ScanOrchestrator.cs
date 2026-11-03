using System.Diagnostics;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;
using AethelEye.Core.Scope;
using AethelEye.Core.Tools;

namespace AethelEye.Core.Engine;

/// <summary>
/// Runs checks in deterministic order, with one timeout and one failure boundary per check. A crash
/// or timeout in a module is recorded and the scan continues, which is the property ad-hoc scripts lack.
/// </summary>
public sealed class ScanOrchestrator : IAsyncDisposable
{
    private sealed record CheckPlan(ICheck Check, CheckSettings Settings, bool Enabled, TimeSpan Timeout);

    private readonly IReadOnlyList<ICheck> _checks;
    private readonly ILog _log;
    private readonly Action<CheckEvent>? _onCheckCompleted;

    public ScanOrchestrator(
        IEnumerable<ICheck> checks,
        ILog? log = null,
        Action<CheckEvent>? onCheckCompleted = null)
    {
        _log = log ?? NullLog.Instance;
        _onCheckCompleted = onCheckCompleted;
        _checks = checks
            .GroupBy(check => check.Id, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(check => check.Order)
            .ThenBy(check => check.Id, StringComparer.Ordinal)
            .ToArray();
    }

    public IReadOnlyList<ICheck> Checks => _checks;

    public async Task<ScanReport> RunAsync(
        Engagement engagement,
        string dataDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(engagement);

        var targets = engagement.Targets.Count > 0
            ? engagement.Targets
                .Select((value, index) => Target.Parse(value, $"target-{index + 1}"))
                .ToArray()
            : engagement.Sources.Count > 0
                ? [Target.ForSource(engagement.Sources[0], "local source")]
                : [Target.ForReport()];

        Directory.CreateDirectory(dataDirectory);

        var scope = new ScopeValidator(engagement.Scope, targets);
        var report = new ScanReport
        {
            Engagement = engagement,
            StartedAt = DateTimeOffset.UtcNow,
        };

        using var scopedHttp = new ScopedHttpClient(engagement.Http, scope, _log);
        using var externalHttp = new ExternalHttpClient(engagement.Http, engagement.Offline);
        var tools = new ExternalToolRunner(engagement.Tools, _log);

        // Resolve settings once: Dictionary is not thread-safe when targets run in parallel.
        var plans = _checks.Select(check =>
        {
            var settings = engagement.SettingsFor(check.Id);
            var timeout = TimeSpan.FromSeconds(
                Math.Max(1, settings.TimeoutSeconds ?? engagement.Engine.DefaultCheckTimeoutSeconds));
            return new CheckPlan(check, settings, engagement.IsCheckEnabled(check.Id), timeout);
        }).ToArray();

        var targetReports = new TargetReport?[targets.Length];
        var concurrency = Math.Max(1, engagement.Engine.TargetConcurrency);

        await Parallel.ForEachAsync(
            Enumerable.Range(0, targets.Length),
            new ParallelOptions
            {
                MaxDegreeOfParallelism = concurrency,
                CancellationToken = cancellationToken,
            },
            async (index, token) =>
            {
                var target = targets[index];
                var started = DateTimeOffset.UtcNow;
                var stopwatch = Stopwatch.StartNew();
                var targetReport = new TargetReport { Target = target, StartedAt = started };

                try
                {
                    if (!target.IsSource)
                    {
                        scope.Validate(target.BaseUri);
                    }
                }
                catch (Exception error)
                {
                    targetReport.Error = error.Message;
                    targetReport.Duration = stopwatch.Elapsed;
                    targetReports[index] = targetReport;
                    _log.Error($"{target.BaseUrl}: {error.Message}");
                    return;
                }

                var pages = new PageCache(scopedHttp);

                foreach (var plan in plans)
                {
                    var check = plan.Check;
                    if (check.RunsOncePerScan && index > 0)
                    {
                        continue;
                    }

                    if (!plan.Enabled)
                    {
                        var skipped = new CheckResult
                        {
                            CheckId = check.Id,
                            CheckName = check.Name,
                            Status = CheckStatus.Skipped,
                            Summary = "Disabled in the engagement configuration.",
                        };
                        targetReport.Checks.Add(skipped);
                        continue;
                    }

                    token.ThrowIfCancellationRequested();
                    using var checkTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                    checkTimeout.CancelAfter(plan.Timeout);

                    var context = new CheckContext(
                        target,
                        engagement,
                        scope,
                        scopedHttp,
                        externalHttp,
                        pages,
                        tools,
                        _log,
                        dataDirectory,
                        plan.Settings,
                        checkTimeout.Token);

                    var checkWatch = Stopwatch.StartNew();
                    CheckResult result;
                    try
                    {
                        result = await check.RunAsync(context);
                    }
                    catch (OperationCanceledException) when (
                        checkTimeout.IsCancellationRequested && !token.IsCancellationRequested)
                    {
                        result = new CheckResult
                        {
                            CheckId = check.Id,
                            CheckName = check.Name,
                            Status = CheckStatus.TimedOut,
                            Error = $"Check exceeded {plan.Timeout.TotalSeconds:0}s.",
                        };
                    }
                    catch (OperationCanceledException) when (token.IsCancellationRequested)
                    {
                        result = new CheckResult
                        {
                            CheckId = check.Id,
                            CheckName = check.Name,
                            Status = CheckStatus.Cancelled,
                            Error = "Scan cancelled.",
                        };
                    }
                    catch (Exception error)
                    {
                        result = new CheckResult
                        {
                            CheckId = check.Id,
                            CheckName = check.Name,
                            Status = CheckStatus.Failed,
                            Error = error.Message,
                        };
                        _log.Error($"{target.BaseUrl} / {check.Id}: {error.Message}");
                    }

                    result.Duration = checkWatch.Elapsed;

                    if (result.Status == CheckStatus.Completed)
                    {
                        result.Status = result.RiskFindingCount > 0
                            ? CheckStatus.Findings
                            : CheckStatus.NoRisk;
                    }
                    else if (result.RiskFindingCount > 0 && result.Status == CheckStatus.NoRisk)
                    {
                        result.Status = CheckStatus.Findings;
                    }

                    targetReport.Checks.Add(result);
                    _log.Info(
                        $"{target.Host} / {check.Id}: {result.Status} " +
                        $"({result.Findings.Count} finding(s), {result.Duration.TotalSeconds:0.0}s)");

                    _onCheckCompleted?.Invoke(new CheckEvent(
                        target,
                        check.Id,
                        check.Name,
                        result.Status,
                        result.Findings.Count,
                        result.Duration,
                        result.Error));

                    if (result.Status == CheckStatus.Cancelled)
                    {
                        break;
                    }
                }

                targetReport.Duration = stopwatch.Elapsed;
                targetReports[index] = targetReport;
            });

        foreach (var targetReport in targetReports)
        {
            if (targetReport is not null)
            {
                report.Targets.Add(targetReport);
            }
        }

        report.CompletedAt = DateTimeOffset.UtcNow;
        return report;
    }

    /// <summary>Releases check-owned resources such as a headless browser.</summary>
    public async ValueTask DisposeAsync()
    {
        foreach (var check in _checks)
        {
            if (check is IAsyncDisposable asyncDisposable)
            {
                await asyncDisposable.DisposeAsync();
            }
            else if (check is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }
}
