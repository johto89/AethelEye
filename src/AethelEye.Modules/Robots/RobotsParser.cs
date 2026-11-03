namespace AethelEye.Modules.Robots;

public sealed record RobotsRule(string Directive, string Value);

public sealed class RobotsGroup
{
    public List<string> UserAgents { get; } = [];

    public List<RobotsRule> Rules { get; } = [];
}

public sealed class RobotsDocument
{
    public List<RobotsGroup> Groups { get; } = [];

    public List<string> Sitemaps { get; } = [];

    public List<RobotsRule> Rules => Groups.SelectMany(group => group.Rules).ToList();

    public static RobotsDocument Parse(string text)
    {
        var document = new RobotsDocument();
        RobotsGroup? current = null;

        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            var comment = line.IndexOf('#');
            if (comment >= 0)
            {
                line = line[..comment].Trim();
            }

            if (line.Length == 0)
            {
                continue;
            }

            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            var directive = line[..separator].Trim().ToLowerInvariant();
            var value = line[(separator + 1)..].Trim();

            if (directive == "user-agent")
            {
                if (current is null || current.Rules.Count > 0)
                {
                    current = new RobotsGroup();
                    document.Groups.Add(current);
                }

                current.UserAgents.Add(value);
                continue;
            }

            if (directive == "sitemap")
            {
                if (value.Length > 0)
                {
                    document.Sitemaps.Add(value);
                }

                continue;
            }

            if (directive is "allow" or "disallow" or "crawl-delay" or "host")
            {
                current ??= AddGroup(document);
                current.Rules.Add(new RobotsRule(directive, value));
            }
        }

        return document;
    }

    private static RobotsGroup AddGroup(RobotsDocument document)
    {
        var group = new RobotsGroup();
        document.Groups.Add(group);
        return group;
    }
}
