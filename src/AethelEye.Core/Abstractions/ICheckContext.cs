using AethelEye.Core.Http;
using AethelEye.Core.Models;
using AethelEye.Core.Scope;
using AethelEye.Core.Tools;

namespace AethelEye.Core.Abstractions;

/// <summary>Everything a check is allowed to use. Shared clients keep rate limits and scope in one place.</summary>
public interface ICheckContext
{
    Target Target { get; }

    Engagement Engagement { get; }

    ScopeValidator Scope { get; }

    /// <summary>HTTP to the authorized target; every request and redirect is scope validated.</summary>
    IScopedHttpClient Http { get; }

    /// <summary>HTTP to public OSINT sources such as GitHub or HudsonRock (not scope validated).</summary>
    IExternalHttpClient ExternalHttp { get; }

    /// <summary>Per-target page cache, so several checks do not fetch the home page twice.</summary>
    PageCache Pages { get; }

    ExternalToolRunner Tools { get; }

    ILog Log { get; }

    string DataDirectory { get; }

    CheckSettings Settings { get; }

    CancellationToken CancellationToken { get; }

    /// <summary>Resolves a root-relative path against the target authority.</summary>
    string Url(string pathOrAbsoluteUrl);
}
