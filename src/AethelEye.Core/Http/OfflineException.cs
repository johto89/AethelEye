namespace AethelEye.Core.Http;

/// <summary>Thrown when a module tries to reach a public source while offline mode is active.</summary>
public sealed class OfflineException(string url)
    : InvalidOperationException($"Offline mode is active; external request blocked: {url}")
{
    public string Url { get; } = url;
}
