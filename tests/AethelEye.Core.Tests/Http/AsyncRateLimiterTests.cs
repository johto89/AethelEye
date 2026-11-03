using System.Diagnostics;
using AethelEye.Core.Http;

namespace AethelEye.Core.Tests.Http;

public sealed class AsyncRateLimiterTests
{
    [Fact]
    public async Task Zero_rps_returns_immediately()
    {
        var limiter = new AsyncRateLimiter(0);
        var sw = Stopwatch.StartNew();

        for (var i = 0; i < 5; i++)
            await limiter.WaitAsync();

        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < 100,
            $"Zero-RPS limiter should be instant, took {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    public async Task Negative_rps_disables_limiting()
    {
        var limiter = new AsyncRateLimiter(-5);
        var sw = Stopwatch.StartNew();

        for (var i = 0; i < 5; i++)
            await limiter.WaitAsync();

        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < 100,
            $"Negative-RPS limiter should be instant, took {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    public async Task Respects_cancellation_token()
    {
        var limiter = new AsyncRateLimiter(1); // 1 RPS = 1 second between calls
        await limiter.WaitAsync(); // first call is immediate

        using var cts = new CancellationTokenSource(50);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => limiter.WaitAsync(cts.Token));
    }

    [Fact]
    public async Task Spaces_requests_at_configured_rate()
    {
        // 20 RPS = 50ms between requests
        var limiter = new AsyncRateLimiter(20);
        var sw = Stopwatch.StartNew();

        // First call is immediate; subsequent calls are spaced
        for (var i = 0; i < 4; i++)
            await limiter.WaitAsync();

        sw.Stop();
        // 3 intervals of ~50ms = ~150ms minimum; allow generous tolerance for CI
        Assert.True(sw.ElapsedMilliseconds >= 100,
            $"Expected at least 100ms for 4 calls at 20 RPS, got {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    public async Task First_call_returns_without_delay()
    {
        var limiter = new AsyncRateLimiter(2); // 2 RPS = 500ms
        var sw = Stopwatch.StartNew();

        await limiter.WaitAsync();

        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < 100,
            $"First call should be immediate, took {sw.ElapsedMilliseconds}ms");
    }
}
