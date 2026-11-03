using System.Diagnostics;

namespace AethelEye.Core.Http;

/// <summary>Spaces requests evenly. Zero or negative requests per second disables limiting.</summary>
public sealed class AsyncRateLimiter
{
    private readonly long _intervalTicks;
    private readonly object _gate = new();
    private long _nextAvailable;

    public AsyncRateLimiter(double requestsPerSecond)
    {
        _intervalTicks = requestsPerSecond <= 0
            ? 0
            : (long)(Stopwatch.Frequency / requestsPerSecond);
    }

    public async Task WaitAsync(CancellationToken cancellationToken = default)
    {
        if (_intervalTicks <= 0)
        {
            return;
        }

        TimeSpan delay;
        lock (_gate)
        {
            var now = Stopwatch.GetTimestamp();
            var next = Math.Max(now, _nextAvailable);
            _nextAvailable = next + _intervalTicks;
            delay = TimeSpan.FromSeconds((next - now) / (double)Stopwatch.Frequency);
        }

        if (delay > TimeSpan.Zero)
        {
            await Task.Delay(delay, cancellationToken);
        }
    }
}
