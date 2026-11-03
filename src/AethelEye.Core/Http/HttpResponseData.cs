using System.Text;

namespace AethelEye.Core.Http;

/// <summary>A bounded HTTP response. Body size is capped by the shared client.</summary>
public sealed class HttpResponseData
{
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false);

    public required Uri RequestUri { get; init; }

    public required Uri FinalUri { get; init; }

    public int StatusCode { get; init; }

    public string? ReasonPhrase { get; init; }

    public string? ContentType { get; init; }

    public IReadOnlyDictionary<string, string[]> Headers { get; init; } =
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

    public byte[] Body { get; init; } = [];

    public bool Truncated { get; init; }

    public TimeSpan Elapsed { get; init; }

    public bool IsSuccess => StatusCode is >= 200 and <= 299;

    public string Text => Utf8.GetString(Body);

    public string? Header(string name) =>
        Headers.TryGetValue(name, out var values) ? string.Join(", ", values) : null;
}
