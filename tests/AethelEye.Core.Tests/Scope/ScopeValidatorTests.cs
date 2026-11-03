using AethelEye.Core.Models;
using AethelEye.Core.Scope;

namespace AethelEye.Core.Tests.Scope;

public sealed class ScopeValidatorTests
{
    private static ScopeValidator Create(
        ScopeSettings? settings = null,
        params string[] targetUrls)
    {
        settings ??= new ScopeSettings();
        var targets = targetUrls.Length > 0
            ? targetUrls.Select(Target.Parse).ToArray()
            : [Target.Parse("https://example.com")];
        return new ScopeValidator(settings, targets);
    }

    // ─── Scheme ───

    [Fact]
    public void Allows_https_uri()
    {
        var sut = Create();
        Assert.True(sut.IsAllowed(new Uri("https://example.com/page")));
    }

    [Fact]
    public void Allows_http_uri()
    {
        var sut = Create();
        Assert.True(sut.IsAllowed(new Uri("http://example.com/page")));
    }

    [Theory]
    [InlineData("ftp://example.com/file")]
    [InlineData("file:///etc/passwd")]
    [InlineData("javascript:alert(1)")]
    public void Rejects_non_http_schemes(string url)
    {
        var sut = Create();
        Assert.False(sut.IsAllowed(new Uri(url)));
    }

    // ─── Embedded credentials ───

    [Fact]
    public void Rejects_urls_with_embedded_credentials()
    {
        var sut = Create();
        Assert.False(sut.IsAllowed(new Uri("https://admin:pass@example.com/")));
    }

    // ─── Port rules ───

    [Fact]
    public void Allows_non_standard_ports_by_default()
    {
        var sut = Create();
        Assert.True(sut.IsAllowed(new Uri("https://example.com:8443/")));
    }

    [Fact]
    public void Rejects_non_standard_port_when_disabled()
    {
        var settings = new ScopeSettings { AllowNonStandardPorts = false };
        var sut = Create(settings, "https://example.com");
        Assert.False(sut.IsAllowed(new Uri("https://example.com:8443/")));
    }

    [Fact]
    public void Allows_port_443_when_non_standard_disabled()
    {
        var settings = new ScopeSettings { AllowNonStandardPorts = false };
        var sut = Create(settings, "https://example.com");
        Assert.True(sut.IsAllowed(new Uri("https://example.com/")));
    }

    // ─── Host allow list ───

    [Fact]
    public void Derives_allowed_hosts_from_targets_when_empty()
    {
        var sut = Create(null, "https://example.com", "https://other.org");
        Assert.True(sut.IsAllowed(new Uri("https://example.com/a")));
        Assert.True(sut.IsAllowed(new Uri("https://other.org/b")));
    }

    [Fact]
    public void Rejects_host_not_in_target_list()
    {
        var sut = Create(null, "https://example.com");
        Assert.False(sut.IsAllowed(new Uri("https://evil.com/")));
    }

    [Fact]
    public void Explicit_allowed_hosts_override_targets()
    {
        var settings = new ScopeSettings
        {
            AllowedHosts = ["allowed.com"]
        };
        var sut = Create(settings, "https://example.com");
        Assert.True(sut.IsAllowed(new Uri("https://allowed.com/")));
        Assert.False(sut.IsAllowed(new Uri("https://example.com/")));
    }

    // ─── Wildcard patterns ───

    [Fact]
    public void Wildcard_allows_subdomains()
    {
        var settings = new ScopeSettings
        {
            AllowedHosts = ["*.example.com"]
        };
        var sut = Create(settings, "https://example.com");
        Assert.True(sut.IsAllowed(new Uri("https://sub.example.com/")));
        Assert.True(sut.IsAllowed(new Uri("https://deep.sub.example.com/")));
    }

    [Fact]
    public void Wildcard_also_matches_apex_domain()
    {
        var settings = new ScopeSettings
        {
            AllowedHosts = ["*.example.com"]
        };
        var sut = Create(settings, "https://example.com");
        Assert.True(sut.IsAllowed(new Uri("https://example.com/")));
    }

    // ─── IncludeSubdomains ───

    [Fact]
    public void Includes_subdomains_by_default()
    {
        var sut = Create(null, "https://example.com");
        Assert.True(sut.IsAllowed(new Uri("https://sub.example.com/")));
    }

    [Fact]
    public void Rejects_subdomains_when_disabled()
    {
        var settings = new ScopeSettings { IncludeSubdomains = false };
        var sut = Create(settings, "https://example.com");
        Assert.False(sut.IsAllowed(new Uri("https://sub.example.com/")));
    }

    // ─── Excluded hosts ───

    [Fact]
    public void Excluded_hosts_take_precedence_over_allowed()
    {
        var settings = new ScopeSettings
        {
            ExcludedHosts = ["admin.example.com"]
        };
        var sut = Create(settings, "https://example.com");
        Assert.False(sut.IsAllowed(new Uri("https://admin.example.com/")));
        Assert.True(sut.IsAllowed(new Uri("https://example.com/")));
    }

    // ─── Private addresses ───

    [Theory]
    [InlineData("localhost")]
    [InlineData("localhost.localdomain")]
    [InlineData("app.localhost")]
    [InlineData("server.local")]
    [InlineData("db.internal")]
    [InlineData("nas.lan")]
    [InlineData("pi.home")]
    [InlineData("ad.corp")]
    public void Detects_local_hostnames(string host)
    {
        Assert.True(ScopeValidator.IsPrivateOrLocal(host));
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.1")]
    [InlineData("192.168.1.1")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("169.254.1.1")]
    [InlineData("100.64.0.1")]
    [InlineData("0.0.0.0")]
    public void Detects_private_ipv4_addresses(string ip)
    {
        Assert.True(ScopeValidator.IsPrivateOrLocal(ip));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("93.184.216.34")]
    public void Rejects_public_ipv4(string ip)
    {
        Assert.False(ScopeValidator.IsPrivateOrLocal(ip));
    }

    [Fact]
    public void Detects_ipv6_loopback()
    {
        Assert.True(ScopeValidator.IsPrivateOrLocal("::1"));
    }

    [Fact]
    public void Rejects_private_host_by_default()
    {
        var settings = new ScopeSettings
        {
            AllowedHosts = ["*.localhost"]
        };
        var sut = Create(settings, "https://example.com");
        Assert.False(sut.IsAllowed(new Uri("https://app.localhost/")));
    }

    [Fact]
    public void Allows_private_host_when_enabled()
    {
        var settings = new ScopeSettings
        {
            AllowPrivateAddresses = true,
            AllowedHosts = ["*.localhost"]
        };
        var sut = Create(settings, "https://example.com");
        Assert.True(sut.IsAllowed(new Uri("https://app.localhost/")));
    }

    // ─── Validate throws ───

    [Fact]
    public void Validate_throws_for_out_of_scope_uri()
    {
        var sut = Create(null, "https://example.com");
        var ex = Assert.Throws<ScopeViolationException>(
            () => sut.Validate(new Uri("https://evil.com/")));
        Assert.Contains("evil.com", ex.Message);
        Assert.Equal("https://evil.com/", ex.Uri.ToString());
    }

    [Fact]
    public void Validate_does_not_throw_for_allowed_uri()
    {
        var sut = Create(null, "https://example.com");
        sut.Validate(new Uri("https://example.com/page")); // no exception
    }

    // ─── URL normalization ───

    [Fact]
    public void Normalizes_url_in_allowed_hosts()
    {
        var settings = new ScopeSettings
        {
            AllowedHosts = ["https://EXAMPLE.COM/path"]
        };
        var sut = Create(settings, "https://other.com");
        Assert.True(sut.IsAllowed(new Uri("https://example.com/")));
    }

    [Fact]
    public void Strips_trailing_dot_from_host()
    {
        var settings = new ScopeSettings
        {
            AllowedHosts = ["example.com."]
        };
        var sut = Create(settings, "https://other.com");
        Assert.True(sut.IsAllowed(new Uri("https://example.com/")));
    }
}
