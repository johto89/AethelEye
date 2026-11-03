namespace AethelEye.Core.Abstractions;

public interface ILog
{
    void Debug(string message);

    void Info(string message);

    void Warn(string message);

    void Error(string message);
}

public sealed class ConsoleLog(bool verbose = false) : ILog
{
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
