namespace AethelEye.Core.Tests;

public sealed class StringHelpersTests
{
    [Fact]
    public void Returns_value_unchanged_when_within_limit()
    {
        Assert.Equal("hello", StringHelpers.Truncate("hello", 10));
    }

    [Fact]
    public void Truncates_and_appends_ellipsis()
    {
        Assert.Equal("hel...", StringHelpers.Truncate("hello world", 3));
    }

    [Fact]
    public void Returns_empty_for_null()
    {
        Assert.Equal(string.Empty, StringHelpers.Truncate(null, 10));
    }

    [Fact]
    public void Returns_empty_for_empty_string()
    {
        Assert.Equal(string.Empty, StringHelpers.Truncate("", 10));
    }

    [Fact]
    public void Exact_length_not_truncated()
    {
        Assert.Equal("abc", StringHelpers.Truncate("abc", 3));
    }
}
