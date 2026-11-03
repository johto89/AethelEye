using System.Text;

namespace AethelEye.Core.Http;

/// <summary>
/// Reads a raw HTTP request-header block copied from Burp or a browser. Cookie and Authorization
/// values are applied to target requests only. The file is never written to a report.
/// </summary>
public static class AuthHeaderFile
{
    private const long MaxFileBytes = 1024 * 1024;

    private static readonly HashSet<string> Ignored = new(StringComparer.OrdinalIgnoreCase)
    {
        "Host",
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "Proxy-Connection",
        "Keep-Alive",
        "Upgrade",
        "HTTP2-Settings",
        "TE",
        "Trailer",
    };

    public static IReadOnlyDictionary<string, string> Load(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
        {
            throw new FileNotFoundException($"Authentication header file not found: {path}", path);
        }

        if (new FileInfo(full).Length > MaxFileBytes)
        {
            throw new InvalidDataException(
                $"Authentication header file is larger than {MaxFileBytes / 1024} KB: {path}");
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? name = null;
        var value = new StringBuilder();

        void Commit()
        {
            if (name is null)
            {
                return;
            }

            var text = value.ToString().Trim();
            if (text.Length > 0 && !Ignored.Contains(name))
            {
                headers[name] = text;
            }

            name = null;
            value.Clear();
        }

        foreach (var raw in File.ReadLines(full))
        {
            var line = raw.TrimEnd();
            if (line.Length == 0)
            {
                if (headers.Count > 0 || name is not null)
                {
                    break;
                }

                continue;
            }

            // Header folding: a line starting with whitespace continues the previous value.
            if (line[0] is ' ' or '\t')
            {
                if (name is not null)
                {
                    value.Append(' ').Append(line.Trim());
                }

                continue;
            }

            // Burp includes the request line, for example: GET /abc HTTP/1.1
            if (IsRequestLine(line))
            {
                continue;
            }

            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            Commit();
            name = line[..separator].Trim();
            value.Append(line[(separator + 1)..].Trim());
        }

        Commit();

        if (headers.Count == 0)
        {
            throw new InvalidDataException(
                "No HTTP headers were found in the authentication file. " +
                "Paste the request headers from Burp, including Cookie or Authorization.");
        }

        return headers;
    }

    private static bool IsRequestLine(string line) =>
        line.Contains(" HTTP/", StringComparison.OrdinalIgnoreCase)
        && line.IndexOf(' ') > 0;
}
