using System.Text;
using AethelEye.Core.Http;

namespace AethelEye.Core.Tests.Http;

public sealed class Soft404DetectorTests
{
    private static HttpResponseData MakeResponse(
        int statusCode,
        string body,
        string contentType = "text/html")
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        return new HttpResponseData
        {
            RequestUri = new Uri("https://example.com/test"),
            FinalUri = new Uri("https://example.com/test"),
            StatusCode = statusCode,
            ContentType = contentType,
            Body = bytes,
        };
    }

    // ─── Basic two-argument overload ───

    [Fact]
    public void Exact_match_detected_as_soft_404()
    {
        var baseline = MakeResponse(200, "<html>Not Found</html>");
        var candidate = MakeResponse(200, "<html>Not Found</html>");

        Assert.True(Soft404Detector.LooksLikeSoftNotFound(candidate, baseline));
    }

    [Fact]
    public void Different_status_codes_are_not_soft_404()
    {
        var baseline = MakeResponse(200, "<html>Not Found</html>");
        var candidate = MakeResponse(301, "<html>Not Found</html>");

        Assert.False(Soft404Detector.LooksLikeSoftNotFound(candidate, baseline));
    }

    [Fact]
    public void Similar_body_length_html_is_soft_404()
    {
        var body = new string('x', 1000);
        var baseline = MakeResponse(200, body);
        // Within 5% threshold (1000 / 20 = 50, max(64, 50) = 64)
        var candidate = MakeResponse(200, body + new string('y', 60));

        Assert.True(Soft404Detector.LooksLikeSoftNotFound(candidate, baseline));
    }

    [Fact]
    public void Very_different_body_length_is_not_soft_404()
    {
        var baseline = MakeResponse(200, new string('x', 1000));
        var candidate = MakeResponse(200, new string('y', 2000));

        Assert.False(Soft404Detector.LooksLikeSoftNotFound(candidate, baseline));
    }

    [Fact]
    public void Non_html_content_type_skips_length_similarity()
    {
        var body = new string('x', 1000);
        var baseline = MakeResponse(200, body, "text/html");
        var candidate = MakeResponse(200, body + new string('y', 10), "application/json");

        // Same status, different text, non-HTML content type → not detected
        Assert.False(Soft404Detector.LooksLikeSoftNotFound(candidate, baseline));
    }

    [Fact]
    public void Empty_baseline_body_skips_length_similarity()
    {
        var baseline = MakeResponse(200, "");
        var candidate = MakeResponse(200, "<html>real page</html>");

        Assert.False(Soft404Detector.LooksLikeSoftNotFound(candidate, baseline));
    }

    // ─── Four-argument overload with title and path normalization ───

    [Fact]
    public void Same_title_different_path_detected_as_soft_404()
    {
        var baseline = MakeResponse(404,
            "<html><title>Page Not Found</title><body>/nonexistent-baseline</body></html>");
        var candidate = MakeResponse(404,
            "<html><title>Page Not Found</title><body>/other-path</body></html>");

        Assert.True(Soft404Detector.LooksLikeSoftNotFound(
            candidate, baseline, "/nonexistent-baseline", "/other-path"));
    }

    [Fact]
    public void Path_normalized_bodies_match_detected_as_soft_404()
    {
        var baseline = MakeResponse(404,
            "<html><title>Error A</title><body>Cannot find /baseline-path</body></html>");
        var candidate = MakeResponse(404,
            "<html><title>Error B</title><body>Cannot find /candidate-path</body></html>");

        Assert.True(Soft404Detector.LooksLikeSoftNotFound(
            candidate, baseline, "/baseline-path", "/candidate-path"));
    }

    [Fact]
    public void Different_titles_and_bodies_not_soft_404()
    {
        var baseline = MakeResponse(404,
            "<html><title>Not Found</title><body>Error page</body></html>");
        var candidate = MakeResponse(404,
            "<html><title>Admin Panel</title><body>Login required</body></html>");

        Assert.False(Soft404Detector.LooksLikeSoftNotFound(
            candidate, baseline, "/baseline", "/candidate"));
    }

    [Fact]
    public void Different_status_codes_fail_extended_check_too()
    {
        var baseline = MakeResponse(200, "<html><title>X</title></html>");
        var candidate = MakeResponse(404, "<html><title>X</title></html>");

        Assert.False(Soft404Detector.LooksLikeSoftNotFound(
            candidate, baseline, "/a", "/b"));
    }
}
