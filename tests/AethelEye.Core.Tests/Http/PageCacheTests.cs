using AethelEye.Core.Http;
using NSubstitute;

namespace AethelEye.Core.Tests.Http;

public sealed class PageCacheTests
{
    private static HttpResponseData Ok(Uri uri) => new()
    {
        RequestUri = uri,
        FinalUri = uri,
        StatusCode = 200,
        Body = "ok"u8.ToArray(),
    };

    [Fact]
    public async Task Returns_response_for_uri()
    {
        var uri = new Uri("https://example.com/page");
        var http = Substitute.For<IScopedHttpClient>();
        http.GetAsync(uri, Arg.Any<CancellationToken>()).Returns(Ok(uri));

        var cache = new PageCache(http);
        var result = await cache.GetAsync(uri);

        Assert.Equal(200, result.StatusCode);
    }

    [Fact]
    public async Task Same_url_fetched_only_once()
    {
        var uri = new Uri("https://example.com/page");
        var http = Substitute.For<IScopedHttpClient>();
        http.GetAsync(uri, Arg.Any<CancellationToken>()).Returns(Ok(uri));

        var cache = new PageCache(http);
        var r1 = await cache.GetAsync(uri);
        var r2 = await cache.GetAsync(uri);

        Assert.Same(r1, r2);
        await http.Received(1).GetAsync(uri, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Different_urls_fetched_separately()
    {
        var uri1 = new Uri("https://example.com/a");
        var uri2 = new Uri("https://example.com/b");
        var http = Substitute.For<IScopedHttpClient>();
        http.GetAsync(uri1, Arg.Any<CancellationToken>()).Returns(Ok(uri1));
        http.GetAsync(uri2, Arg.Any<CancellationToken>()).Returns(Ok(uri2));

        var cache = new PageCache(http);
        await cache.GetAsync(uri1);
        await cache.GetAsync(uri2);

        await http.Received(1).GetAsync(uri1, Arg.Any<CancellationToken>());
        await http.Received(1).GetAsync(uri2, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Case_insensitive_url_dedup()
    {
        var lower = new Uri("https://example.com/page");
        var upper = new Uri("https://EXAMPLE.COM/PAGE");
        var http = Substitute.For<IScopedHttpClient>();
        http.GetAsync(lower, Arg.Any<CancellationToken>()).Returns(Ok(lower));

        var cache = new PageCache(http);
        var r1 = await cache.GetAsync(lower);
        var r2 = await cache.GetAsync(upper);

        Assert.Same(r1, r2);
    }

    [Fact]
    public async Task String_overload_works()
    {
        var uri = new Uri("https://example.com/str");
        var http = Substitute.For<IScopedHttpClient>();
        http.GetAsync(uri, Arg.Any<CancellationToken>()).Returns(Ok(uri));

        var cache = new PageCache(http);
        var result = await cache.GetAsync("https://example.com/str");

        Assert.Equal(200, result.StatusCode);
    }

    [Fact]
    public async Task Concurrent_access_fetches_only_once()
    {
        var uri = new Uri("https://example.com/concurrent");
        var callCount = 0;
        var http = Substitute.For<IScopedHttpClient>();
        http.GetAsync(uri, Arg.Any<CancellationToken>())
            .Returns(async callInfo =>
            {
                Interlocked.Increment(ref callCount);
                await Task.Delay(50);
                return Ok(uri);
            });

        var cache = new PageCache(http);
        var tasks = Enumerable.Range(0, 10).Select(_ => cache.GetAsync(uri)).ToArray();
        var results = await Task.WhenAll(tasks);

        Assert.Equal(1, callCount);
        Assert.All(results, r => Assert.Same(results[0], r));
    }
}
