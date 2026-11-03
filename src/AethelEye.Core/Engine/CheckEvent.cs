using AethelEye.Core.Models;

namespace AethelEye.Core.Engine;

public sealed record CheckEvent(
    Target Target,
    string CheckId,
    string CheckName,
    CheckStatus Status,
    int Findings,
    TimeSpan Duration,
    string? Error);
