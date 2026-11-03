using AethelEye.Core.Models;

namespace AethelEye.Core.Tests.Models;

public sealed class TargetTests
{
    [Fact]
    public void Parse_adds_https_scheme_when_missing()
    {
        var target = Target.Parse("example.com");
        Assert.StartsWith("https://", target.BaseUrl);
        Assert.Equal("example.com", target.Host);
    }

    [Fact]
    public void Parse_preserves_existing_scheme()
    {
        var target = Target.Parse("http://example.com");
        Assert.StartsWith("http://", target.BaseUrl);
    }

    [Fact]
    public void Parse_strips_trailing_slash_from_path()
    {
        var target = Target.Parse("https://example.com/app/");
        Assert.Equal("https://example.com/app", target.BaseUrl);
    }

    [Fact]
    public void Parse_lowercases_host()
    {
        var target = Target.Parse("https://EXAMPLE.COM");
        Assert.Equal("example.com", target.Host);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Parse_rejects_empty_input(string input)
    {
        Assert.Throws<ArgumentException>(() => Target.Parse(input));
    }

    [Fact]
    public void Parse_rejects_embedded_credentials()
    {
        Assert.Throws<ArgumentException>(
            () => Target.Parse("https://user:pass@example.com"));
    }

    [Theory]
    [InlineData("ftp://example.com")]
    [InlineData("file:///etc/passwd")]
    public void Parse_rejects_non_http_scheme(string input)
    {
        Assert.Throws<ArgumentException>(() => Target.Parse(input));
    }

    [Fact]
    public void RootUrl_returns_scheme_and_authority()
    {
        var target = Target.Parse("https://example.com/deep/path");
        Assert.Equal("https://example.com", target.RootUrl);
    }

    [Fact]
    public void ForSource_creates_file_uri_with_source_flag()
    {
        var target = Target.ForSource("/tmp/code");
        Assert.True(target.IsSource);
        Assert.Equal("local-source", target.Host);
    }

    [Fact]
    public void ForReport_creates_dependency_check_pseudo_target()
    {
        var target = Target.ForReport();
        Assert.True(target.IsSource);
        Assert.Equal("dependency-check", target.Host);
    }

    [Fact]
    public void ToString_returns_base_url()
    {
        var target = Target.Parse("https://example.com/app");
        Assert.Equal("https://example.com/app", target.ToString());
    }
}
