namespace AethelEye.Cli;

public sealed class CliOptions
{
    public string Command { get; set; } = "scan";

    public List<string> Inputs { get; } = [];

    /// <summary>Explicit web targets. Keeps source scans and web scans unambiguous.</summary>
    public List<string> Urls { get; } = [];

    /// <summary>Explicit local source paths (directory, .js/.json file or .zip).</summary>
    public List<string> Sources { get; } = [];

    /// <summary>Database target for <c>--update</c>; only "db" is supported.</summary>
    public string? UpdateTarget { get; set; }

    /// <summary>SQLite advisory database path. Default: &lt;data dir&gt;/aetheleye.db.</summary>
    public string? DatabasePath { get; set; }

    public string? Mode { get; set; }

    /// <summary>Offline is opt-in. No flag means online.</summary>
    public bool Offline { get; set; }

    /// <summary>Enables headless Chromium; an optional executable path may follow.</summary>
    public bool Headless { get; set; }

    public string? ChromiumPath { get; set; }

    public int? TimeoutSeconds { get; set; }

    /// <summary>Low-and-slow, browser-like request profile for authorized WAF/IDS testing.</summary>
    public bool Evasion { get; set; }

    /// <summary>Rotate a browser User-Agent for every target request.</summary>
    public bool RandomAgent { get; set; }

    /// <summary>Keep only High/Critical findings in the report.</summary>
    public bool Exploited { get; set; }

    /// <summary>Enable RetireSharp AST-based deep JavaScript detection.</summary>
    public bool Deep { get; set; }

    /// <summary>Raw HTTP header block from Burp, applied to target requests for authenticated scans.</summary>
    public string? AuthFile { get; set; }

    /// <summary>Extra filename stems for the backup check, for example the application name.</summary>
    public List<string> NameTokens { get; } = [];

    /// <summary>UAT/lab preset: allow private hosts, self-signed TLS and non-standard ports.</summary>
    public bool AllowUat { get; set; }

    public bool Verbose { get; set; }

    public bool NoBanner { get; set; }

    public bool Help { get; set; }

    public string? OutputDirectory { get; set; }

    public string? Format { get; set; }

    public int? Concurrency { get; set; }

    public static CliOptions Parse(string[] args)
    {
        var options = new CliOptions();
        var index = 0;

        if (args.Length > 0 && !args[0].StartsWith('-') && IsCommand(args[0]))
        {
            options.Command = args[0].ToLowerInvariant();
            index = 1;
        }

        for (; index < args.Length; index++)
        {
            var argument = args[index];
            switch (argument)
            {
                case "--offline":
                case "-offline":
                    options.Offline = true;
                    break;
                case "--allow-uat":
                case "-allow-uat":
                case "--uat":
                    options.AllowUat = true;
                    break;
                case "--chromium":
                case "-chromium":
                    options.Headless = true;
                    if (index + 1 < args.Length && !args[index + 1].StartsWith('-'))
                    {
                        options.ChromiumPath = args[++index];
                    }

                    break;
                case "--evasion":
                case "-evasion":
                    options.Evasion = true;
                    break;
                case "--random-agent":
                case "-random-agent":
                case "-r":
                    options.RandomAgent = true;
                    break;
                case "--exploited":
                case "-exploited":
                    options.Exploited = true;
                    break;
                case "--deep":
                case "-deep":
                    options.Deep = true;
                    break;
                case "--authen":
                case "-authen":
                case "--auth":
                case "-auth":
                    options.AuthFile = NextValue(args, ref index, argument);
                    break;
                case "--name-token":
                case "-name-token":
                case "-n":
                    AddUrlSet(options.NameTokens, NextValue(args, ref index, argument));
                    break;
                case "--timeout":
                case "-timeout":
                    options.TimeoutSeconds = ParsePositive(
                        NextValue(args, ref index, argument),
                        argument,
                        1,
                        3600);
                    break;
                case "--concurrency":
                case "-concurrency":
                case "-c":
                    options.Concurrency = ParsePositive(
                        NextValue(args, ref index, argument),
                        argument,
                        1,
                        256);
                    break;
                case "--verbose":
                case "-verbose":
                    options.Verbose = true;
                    break;
                case "--no-banner":
                case "-no-banner":
                    options.NoBanner = true;
                    break;
                case "--version":
                case "-version":
                    options.Command = "version";
                    break;
                case "--help":
                case "-h":
                case "-help":
                    options.Help = true;
                    break;
                case "--url":
                case "-url":
                    AddUrlSet(options.Urls, NextValue(args, ref index, argument));
                    break;
                case "--src":
                case "-src":
                    options.Sources.Add(NextValue(args, ref index, argument));
                    break;
                case "--update":
                case "-update":
                    options.UpdateTarget = NextValue(args, ref index, argument);
                    break;
                case "--db":
                case "-db":
                    options.DatabasePath = NextValue(args, ref index, argument);
                    break;
                case "--mode":
                case "-mode":
                    options.Mode = NextValue(args, ref index, argument);
                    break;
                case "--out":
                case "-out":
                    options.OutputDirectory = NextValue(args, ref index, argument);
                    break;
                case "--format":
                case "-format":
                    options.Format = NextValue(args, ref index, argument);
                    break;
                default:
                    if (argument.StartsWith('-'))
                    {
                        throw new ArgumentException($"Unknown option: {argument}");
                    }

                    options.Inputs.Add(argument);
                    break;
            }
        }

        // "aetheleye update db" is accepted as an alternative to "--update db".
        if (options.Command == "update" && options.UpdateTarget is null && options.Inputs.Count > 0)
        {
            options.UpdateTarget = options.Inputs[0];
            options.Inputs.RemoveAt(0);
        }

        if (options.Command == "scan"
            && options.Inputs.Count == 0
            && options.Urls.Count == 0
            && options.Sources.Count == 0)
        {
            var fallback = Path.Combine(Directory.GetCurrentDirectory(), "engagement.json");
            if (File.Exists(fallback))
            {
                options.Inputs.Add(fallback);
            }
        }

        return options;
    }

    private static bool IsCommand(string value) =>
        value is "scan" or "init" or "checks" or "help" or "version" or "banner" or "about" or "update";

    private static string NextValue(string[] args, ref int index, string option)
    {
        index++;
        if (index >= args.Length)
        {
            throw new ArgumentException($"Option {option} requires a value.");
        }

        return args[index];
    }

    private static int ParsePositive(string value, string option, int min, int max)
    {
        if (!int.TryParse(value, out var number) || number < min || number > max)
        {
            throw new ArgumentException($"{option} must be between {min} and {max}.");
        }

        return number;
    }

    private static void AddUrlSet(List<string> urls, string value)
    {
        foreach (var item in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            urls.Add(item);
        }
    }
}
