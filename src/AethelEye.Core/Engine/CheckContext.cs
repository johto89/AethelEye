using AethelEye.Core.Abstractions;
using AethelEye.Core.Http;
using AethelEye.Core.Models;
using AethelEye.Core.Scope;
using AethelEye.Core.Tools;

namespace AethelEye.Core.Engine;

internal sealed class CheckContext(
    Target target,
    Engagement engagement,
    ScopeValidator scope,
    IScopedHttpClient http,
    IExternalHttpClient externalHttp,
    PageCache pages,
    ExternalToolRunner tools,
    ILog log,
    string dataDirectory,
    CheckSettings settings,
    CancellationToken cancellationToken) : ICheckContext
{
    public Target Target { get; } = target;

    public Engagement Engagement { get; } = engagement;

    public ScopeValidator Scope { get; } = scope;

    public IScopedHttpClient Http { get; } = http;

    public IExternalHttpClient ExternalHttp { get; } = externalHttp;

    public PageCache Pages { get; } = pages;

    public ExternalToolRunner Tools { get; } = tools;

    public ILog Log { get; } = log;

    public string DataDirectory { get; } = dataDirectory;

    public CheckSettings Settings { get; } = settings;

    public CancellationToken CancellationToken { get; } = cancellationToken;

    public string Url(string pathOrAbsoluteUrl)
    {
        if (Uri.TryCreate(pathOrAbsoluteUrl, UriKind.Absolute, out var absolute)
            && absolute.Scheme is "http" or "https")
        {
            return absolute.ToString();
        }

        // App-relative, not root-relative: http://host/abc and /xyz are separate applications.
        var root = new Uri(Target.BaseUrl.TrimEnd('/') + "/", UriKind.Absolute);
        return new Uri(root, pathOrAbsoluteUrl.TrimStart('/')).ToString();
    }
}
