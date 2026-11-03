using System.Text.Json;
using System.Text.Json.Serialization;

namespace AethelEye.Core.Abstractions;

public enum LogSeverity
{
    Debug,
    Info,
    Warning,
    Error,
}

/// <summary>
/// Structured log entry for SIEM ingestion. Each entry carries severity, module, target and
/// an optional payload of key-value pairs so security operations teams can filter and correlate.
/// </summary>
public sealed class LogEntry
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public LogSeverity Severity { get; init; }

    public string? Module { get; init; }

    public string? Target { get; init; }

    public required string Message { get; init; }

    public IReadOnlyDictionary<string, string>? Data { get; init; }
}

public interface ILog
{
    void Debug(string message);

    void Info(string message);

    void Warn(string message);

    void Error(string message);

    /// <summary>Emits a structured log entry for SIEM / JSON log pipelines.</summary>
    void Emit(LogEntry entry) => Emit(entry, entry.Severity switch
    {
        LogSeverity.Debug => "dbg",
        LogSeverity.Warning => "warn",
        LogSeverity.Error => "error",
        _ => "info",
    });

    /// <summary>Default implementation falls back to unstructured text.</summary>
    private void Emit(LogEntry entry, string level)
    {
        var text = entry.Module is not null
            ? $"[{entry.Module}] {entry.Message}"
            : entry.Message;
        switch (entry.Severity)
        {
            case LogSeverity.Debug: Debug(text); break;
            case LogSeverity.Warning: Warn(text); break;
            case LogSeverity.Error: Error(text); break;
            default: Info(text); break;
        }
    }
}

public sealed class ConsoleLog(bool verbose = false, bool jsonOutput = false) : ILog
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    };

    private readonly object _gate = new();

    public void Debug(string message)
    {
        if (verbose)
        {
            Write("dbg", message);
        }
    }

    public void Info(string message) => Write("info", message);

    public void Warn(string message) => Write("warn", message);

    public void Error(string message) => Write("error", message);

    public void Emit(LogEntry entry)
    {
        if (entry.Severity == LogSeverity.Debug && !verbose)
        {
            return;
        }

        if (jsonOutput)
        {
            var json = JsonSerializer.Serialize(entry, JsonOptions);
            lock (_gate)
            {
                Console.Error.WriteLine(json);
            }
        }
        else
        {
            var prefix = entry.Module is not null ? $"[{entry.Module}] " : "";
            var level = entry.Severity switch
            {
                LogSeverity.Debug => "dbg",
                LogSeverity.Warning => "warn",
                LogSeverity.Error => "error",
                _ => "info",
            };
            Write(level, $"{prefix}{entry.Message}");
        }
    }

    private void Write(string level, string message)
    {
        lock (_gate)
        {
            Console.Error.WriteLine($"[{DateTimeOffset.Now:HH:mm:ss}] {level,-5} {message}");
        }
    }
}

public sealed class NullLog : ILog
{
    public static readonly NullLog Instance = new();

    public void Debug(string message) { }

    public void Info(string message) { }

    public void Warn(string message) { }

    public void Error(string message) { }
}
