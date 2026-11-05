using System.Text;

namespace AethelEye.Core.Http;

/// <summary>
/// Binary signatures for archive and database files. A 200 response is not proof that a backup
/// exists: servers often return an HTML soft-404 with an archive content type. These signatures
/// let a check confirm the bytes really are an archive or database before reporting it.
/// </summary>
public static class FileSignatures
{
    public static string? Identify(byte[] body)
    {
        if (body.Length == 0)
        {
            return null;
        }

        if (StartsWith(body, [0x50, 0x4B, 0x03, 0x04])
            || StartsWith(body, [0x50, 0x4B, 0x05, 0x06])
            || StartsWith(body, [0x50, 0x4B, 0x07, 0x08]))
        {
            return "ZIP archive";
        }

        if (StartsWith(body, [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]))
        {
            return "RAR archive";
        }

        if (StartsWith(body, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]))
        {
            return "7-Zip archive";
        }

        if (StartsWith(body, [0x1F, 0x8B]))
        {
            return "GZIP archive";
        }

        if (StartsWith(body, [0x42, 0x5A, 0x68]))
        {
            return "BZIP2 archive";
        }

        if (StartsWith(body, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]))
        {
            return "XZ archive";
        }

        if (body.Length > 262
            && body[257] == (byte)'u'
            && body[258] == (byte)'s'
            && body[259] == (byte)'t'
            && body[260] == (byte)'a'
            && body[261] == (byte)'r')
        {
            return "TAR archive";
        }

        if (StartsWith(body, Encoding.ASCII.GetBytes("SQLite format 3\0")))
        {
            return "SQLite database";
        }

        return null;
    }

    private static bool StartsWith(byte[] body, byte[] signature) =>
        body.Length >= signature.Length && body.AsSpan(0, signature.Length).SequenceEqual(signature);
}
