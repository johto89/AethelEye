using System.Diagnostics;
using AethelEye.Core.Abstractions;
using AethelEye.Core.Models;

namespace AethelEye.Core.Tools;

public sealed record ToolResult(
    string Tool,
    string Command,
    int ExitCode,
    string StandardOutput,
    string StandardError,
    TimeSpan Duration,
    bool TimedOut)
{
    public bool Succeeded => !TimedOut && ExitCode == 0;
}

/// <summary>
/// Runs Go/Python/native tools without a shell, with a hard timeout and captured output. This is
/// the bridge for tools that are not worth porting, such as gitleaks.
/// </summary>
public sealed class ExternalToolRunner
{
    private readonly Dictionary<string, string> _configured;
    private readonly ILog _log;

    public ExternalToolRunner(IEnumerable<ToolSettings>? tools, ILog log)
    {
        _log = log;
        _configured = (tools ?? [])
            .Where(tool => !string.IsNullOrWhiteSpace(tool.Name) && !string.IsNullOrWhiteSpace(tool.Path))
            .GroupBy(tool => tool.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.Last().Path, StringComparer.OrdinalIgnoreCase);
    }

    public string? Resolve(string name)
    {
        if (_configured.TryGetValue(name, out var configured))
        {
            var full = Path.GetFullPath(configured);
            return File.Exists(full) ? full : null;
        }

        var env = Environment.GetEnvironmentVariable(name.ToUpperInvariant() + "_PATH");
        if (!string.IsNullOrWhiteSpace(env) && File.Exists(env))
        {
            return Path.GetFullPath(env);
        }

        var path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var extensions = (Environment.GetEnvironmentVariable("PATHEXT") ?? ".EXE;.CMD;.BAT")
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Prepend(string.Empty);

        foreach (var directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            foreach (var extension in extensions)
            {
                try
                {
                    var candidate = Path.Combine(directory, name + extension);
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }
                catch (ArgumentException)
                {
                    // An invalid PATH entry should not stop discovery.
                }
            }
        }

        return null;
    }

    public async Task<ToolResult> RunAsync(
        string tool,
        IEnumerable<string> arguments,
        TimeSpan timeout,
        string? workingDirectory = null,
        IReadOnlyDictionary<string, string>? environment = null,
        CancellationToken cancellationToken = default)
    {
        var executable = Resolve(tool)
            ?? throw new FileNotFoundException(
                $"Tool '{tool}' was not found. Configure it under 'tools' in the engagement file.");

        var argumentList = arguments.ToArray();
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory ?? Environment.CurrentDirectory,
        };

        foreach (var argument in argumentList)
        {
            startInfo.ArgumentList.Add(argument);
        }

        if (environment is not null)
        {
            foreach (var (name, value) in environment)
            {
                startInfo.Environment[name] = value;
            }
        }

        _log.Debug($"Running {executable} {string.Join(' ', argumentList)}");
        var started = Stopwatch.StartNew();

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        var timedOut = false;
        var cancelled = false;
        try
        {
            await process.WaitForExitAsync(timeoutSource.Token);
        }
        catch (OperationCanceledException)
        {
            cancelled = cancellationToken.IsCancellationRequested;
            timedOut = !cancelled;
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (Exception killError) when (killError is InvalidOperationException
                                                   or System.ComponentModel.Win32Exception
                                                   or NotSupportedException)
            {
                // Process already exited or cannot be killed; the timeout still stands.
            }
        }

        var output = await standardOutput;
        var error = await standardError;
        if (cancelled)
        {
            throw new OperationCanceledException(cancellationToken);
        }

        return new ToolResult(
            tool,
            $"{executable} {string.Join(' ', argumentList)}",
            timedOut ? -1 : process.ExitCode,
            output,
            error,
            started.Elapsed,
            timedOut);
    }
}
