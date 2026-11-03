namespace AethelEye.Core;

/// <summary>Small text utilities shared across modules.</summary>
public static class StringHelpers
{
    /// <summary>Returns the first <paramref name="maxLength"/> characters followed by "..." when the
    /// value is longer, or the value unchanged when it fits. Null and empty map to empty.</summary>
    public static string Truncate(string? value, int maxLength) =>
        string.IsNullOrEmpty(value) ? string.Empty
        : value.Length <= maxLength ? value
        : value[..maxLength] + "...";
}
