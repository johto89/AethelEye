using AethelEye.Core.Models;

namespace AethelEye.Modules.HiddenPaths;

public enum HiddenPathValidation
{
    None,
    Contains,
    Regex,
    EnvFile,
    SqlDump,
    Archive,
}

public sealed record HiddenPath(
    string Path,
    Severity Severity,
    HiddenPathValidation Validation,
    string? Marker,
    string Description,
    bool AllowHtml = false,
    bool SiteRoot = false);

/// <summary>
/// Built-in word list for exposed source control, configuration, keys, backups, dumps, logs and
/// debug interfaces. Markers are what turn a 200 response into high confidence instead of a guess;
/// archive entries are confirmed from their magic bytes, not from the response headers.
/// </summary>
public static class HiddenPathCatalog
{
    // Generic backup basenames from backup_finder.py. These are combined with the archive
    // extensions below, independent of the target name.
    private static readonly string[] BackupStems =
    [
        "backup", "backups", "bak", "bkp", "full_backup", "fullbackup",
        "site", "sitebackup", "site_backup", "web", "webbackup", "web_backup",
        "www", "wwwroot", "html", "htdocs", "public_html", "public",
        "data", "database", "db", "dbbackup", "db_backup", "dump", "dbdump",
        "sql", "mysql", "dump_all", "alldb", "all",
        "old", "new", "temp", "tmp", "test", "prod", "production", "staging",
        "release", "latest", "final", "copy", "archive", "export", "dump_backup",
        "wordpress", "wp", "app", "application", "source", "src", "code", "project",
        "admin", "config", "conf", "settings",
    ];

    private static readonly string[] BackupExtensions =
    [
        ".zip", ".tar.gz", ".tgz", ".tar", ".rar", ".7z",
    ];

    // Stems that admins most often wrap: backup_<name>.zip, <name>_backup.zip, <name>_old.zip.
    private static readonly string[] WrappedBackupStems =
    [
        "backup", "backups", "site", "www", "web", "database",
        "db", "dump", "data", "source", "app", "config",
    ];

    private static readonly string[] BackupWrappers =
    [
        "{name}_backup{ext}",
        "backup_{name}{ext}",
        "{name}-backup{ext}",
        "{name}_old{ext}",
    ];

    private static readonly string[] DumpStems =
    [
        "backup", "backups", "bak", "bkp", "full_backup", "fullbackup",
        "data", "database", "db", "dbbackup", "db_backup", "dump", "dbdump",
        "sql", "mysql", "dump_all", "alldb", "all", "dump_backup",
        "wordpress", "wp", "app", "application", "source", "src", "code",
        "project", "admin", "config", "conf", "settings",
    ];

    private static readonly string[] DumpExtensions = [".sql", ".dump"];


    public static IReadOnlyList<HiddenPath> All { get; } = Build();

    private static IReadOnlyList<HiddenPath> Build()
    {
        var entries = new List<HiddenPath>
        {
            // Source control metadata.
            new("/.git/HEAD", Severity.High, HiddenPathValidation.Regex,
                @"^(ref:\s*refs/|[0-9a-f]{40})", "Git metadata is exposed."),
            new("/.git/config", Severity.High, HiddenPathValidation.Contains,
                "[core]", "Git configuration is exposed."),
            new("/.git/index", Severity.High, HiddenPathValidation.Contains,
                "DIRC", "Git index is exposed."),
            new("/.git/logs/HEAD", Severity.High, HiddenPathValidation.Contains,
                "commit", "Git reflog is exposed."),
            new("/.git/packed-refs", Severity.Medium, HiddenPathValidation.Contains,
                "refs/", "Git packed refs are exposed."),
            new("/.git/refs/heads/main", Severity.High, HiddenPathValidation.Regex,
                @"^[0-9a-f]{40}", "Git branch ref is exposed."),
            new("/.git/refs/heads/master", Severity.High, HiddenPathValidation.Regex,
                @"^[0-9a-f]{40}", "Git branch ref is exposed."),
            new("/.git/description", Severity.Low, HiddenPathValidation.Contains,
                "Unnamed repository", "Git repository description is exposed."),
            new("/.git/", Severity.High, HiddenPathValidation.Contains,
                "Index of", "Git directory listing is exposed.", AllowHtml: true),
            new("/.gitignore", Severity.Low, HiddenPathValidation.None,
                null, "Repository ignore file is exposed."),
            new("/.gitattributes", Severity.Low, HiddenPathValidation.Contains,
                "text=", "Repository attributes file is exposed."),
            new("/.gitmodules", Severity.Low, HiddenPathValidation.Contains,
                "[submodule", "Repository submodule configuration is exposed."),
            new("/.svn/entries", Severity.Medium, HiddenPathValidation.Regex,
                @"^\s*(<?xml|\d+)", "Subversion metadata is exposed."),
            new("/.svn/wc.db", Severity.High, HiddenPathValidation.Archive,
                null, "Subversion working-copy database is exposed."),
            new("/.svn/", Severity.Medium, HiddenPathValidation.Contains,
                "Index of", "Subversion directory listing is exposed.", AllowHtml: true),
            new("/.hg/requires", Severity.Medium, HiddenPathValidation.Regex,
                @"(revlog|store)", "Mercurial metadata is exposed."),
            new("/.hg/hgrc", Severity.Medium, HiddenPathValidation.Contains,
                "[paths]", "Mercurial configuration is exposed."),
            new("/.hg/store/", Severity.Medium, HiddenPathValidation.Contains,
                "Index of", "Mercurial store listing is exposed.", AllowHtml: true),
            new("/.bzr/branch/format", Severity.Medium, HiddenPathValidation.Contains,
                "Bazaar", "Bazaar metadata is exposed."),
            new("/.bzr/README", Severity.Low, HiddenPathValidation.Contains,
                "Bazaar", "Bazaar repository metadata is exposed."),

            // Environment and application configuration.
            new("/.env", Severity.Critical, HiddenPathValidation.EnvFile,
                null, "Environment file is exposed and may contain credentials."),
            new("/.env.local", Severity.Critical, HiddenPathValidation.EnvFile,
                null, "Local environment file is exposed and may contain credentials."),
            new("/.env.production", Severity.Critical, HiddenPathValidation.EnvFile,
                null, "Production environment file is exposed and may contain credentials."),
            new("/.env.backup", Severity.Critical, HiddenPathValidation.EnvFile,
                null, "Environment backup is exposed and may contain credentials."),
            new("/.env.dev", Severity.Critical, HiddenPathValidation.EnvFile,
                null, "Development environment file is exposed."),
            new("/.env.development", Severity.Critical, HiddenPathValidation.EnvFile,
                null, "Development environment file is exposed."),
            new("/.env.staging", Severity.Critical, HiddenPathValidation.EnvFile,
                null, "Staging environment file is exposed."),
            new("/.env.test", Severity.Critical, HiddenPathValidation.EnvFile,
                null, "Test environment file is exposed."),
            new("/.env.uat", Severity.Critical, HiddenPathValidation.EnvFile,
                null, "UAT environment file is exposed."),
            new("/.env.example", Severity.Low, HiddenPathValidation.EnvFile,
                null, "Environment example file is exposed."),
            new("/.env.bak", Severity.Critical, HiddenPathValidation.EnvFile,
                null, "Environment backup is exposed."),
            new("/.env.old", Severity.Critical, HiddenPathValidation.EnvFile,
                null, "Old environment file is exposed."),
            new("/.env.save", Severity.Critical, HiddenPathValidation.EnvFile,
                null, "Saved environment file is exposed."),
            new("/.env.swp", Severity.Critical, HiddenPathValidation.EnvFile,
                null, "Editor swap file for the environment is exposed."),
            new("/.htaccess", Severity.Medium, HiddenPathValidation.Regex,
                @"(?i)(RewriteRule|AuthType|Options\s+[-+])", "Apache access rules are exposed."),
            new("/.htpasswd", Severity.Critical, HiddenPathValidation.Regex,
                @"^[^:\r\n]+:\$", "Apache password file is exposed."),
            new("/.htaccess.bak", Severity.Medium, HiddenPathValidation.Regex,
                @"(?i)(RewriteRule|AuthType|Options\s+[-+])", "Apache access-rule backup is exposed."),
            new("/.htpasswd.bak", Severity.Critical, HiddenPathValidation.Regex,
                @"^[^:\r\n]+:\$", "Apache password-file backup is exposed."),
            new("/web.config", Severity.High, HiddenPathValidation.Contains,
                "<configuration", "ASP.NET configuration is exposed."),
            new("/web.config.bak", Severity.High, HiddenPathValidation.Contains,
                "<configuration", "ASP.NET configuration backup is exposed."),
            new("/web.config.old", Severity.High, HiddenPathValidation.Contains,
                "<configuration", "Old ASP.NET configuration is exposed."),
            new("/wp-config.php", Severity.Critical, HiddenPathValidation.Contains,
                "DB_PASSWORD", "WordPress configuration is exposed."),
            new("/wp-config.php.bak", Severity.Critical, HiddenPathValidation.Contains,
                "DB_PASSWORD", "WordPress configuration backup is exposed."),
            new("/wp-config.php.old", Severity.Critical, HiddenPathValidation.Contains,
                "DB_PASSWORD", "Old WordPress configuration is exposed."),
            new("/wp-config.php~", Severity.Critical, HiddenPathValidation.Contains,
                "DB_PASSWORD", "WordPress configuration editor backup is exposed."),
            new("/wp-config.php.save", Severity.Critical, HiddenPathValidation.Contains,
                "DB_PASSWORD", "Saved WordPress configuration is exposed."),
            new("/wp-config.php.swp", Severity.Critical, HiddenPathValidation.Contains,
                "DB_PASSWORD", "WordPress configuration swap file is exposed."),
            new("/config.php", Severity.High, HiddenPathValidation.Regex,
                @"(?i)(DB_PASSWORD|DB_HOST|<\?php)", "PHP configuration is exposed."),
            new("/config.php.bak", Severity.High, HiddenPathValidation.Regex,
                @"(?i)(DB_PASSWORD|DB_HOST|<\?php)", "PHP configuration backup is exposed."),
            new("/config.php.old", Severity.High, HiddenPathValidation.Regex,
                @"(?i)(DB_PASSWORD|DB_HOST|<\?php)", "Old PHP configuration is exposed."),
            new("/config.php~", Severity.High, HiddenPathValidation.Regex,
                @"(?i)(DB_PASSWORD|DB_HOST|<\?php)", "PHP configuration editor backup is exposed."),
            new("/config.php.save", Severity.High, HiddenPathValidation.Regex,
                @"(?i)(DB_PASSWORD|DB_HOST|<\?php)", "Saved PHP configuration is exposed."),
            new("/configuration.php", Severity.High, HiddenPathValidation.Contains,
                "class JConfig", "Joomla configuration is exposed."),
            new("/settings.php", Severity.High, HiddenPathValidation.Regex,
                @"(?i)(<\?php|database|dbname)", "Application settings are exposed."),
            new("/config.inc.php", Severity.High, HiddenPathValidation.Contains,
                "<?php", "PHP include configuration is exposed."),
            new("/config.yml", Severity.High, HiddenPathValidation.Regex,
                @"(?i)(password|secret|token|database|datasource)", "YAML configuration is exposed."),
            new("/config.yaml", Severity.High, HiddenPathValidation.Regex,
                @"(?i)(password|secret|token|database|datasource)", "YAML configuration is exposed."),
            new("/config.json", Severity.High, HiddenPathValidation.Regex,
                @"(?i)(password|secret|token|database|datasource)", "JSON configuration is exposed."),
            new("/application.properties", Severity.High, HiddenPathValidation.Regex,
                @"(?i)(spring\.datasource|password|secret)", "Spring configuration is exposed."),
            new("/application.yml", Severity.High, HiddenPathValidation.Regex,
                @"(?i)(spring\.datasource|password|secret)", "Spring configuration is exposed."),
            new("/application.yaml", Severity.High, HiddenPathValidation.Regex,
                @"(?i)(spring\.datasource|password|secret)", "Spring configuration is exposed."),
            new("/appsettings.json", Severity.High, HiddenPathValidation.Contains,
                "ConnectionStrings", "ASP.NET application settings are exposed."),
            new("/appsettings.Development.json", Severity.High, HiddenPathValidation.Contains,
                "ConnectionStrings", "ASP.NET development settings are exposed."),
            new("/appsettings.Production.json", Severity.High, HiddenPathValidation.Contains,
                "ConnectionStrings", "ASP.NET production settings are exposed."),
            new("/.npmrc", Severity.High, HiddenPathValidation.Contains,
                "_authToken", "npm authentication configuration is exposed."),
            new("/.pypirc", Severity.High, HiddenPathValidation.Regex,
                @"(?i)(password|username)", "Python package authentication is exposed."),
            new("/.dockercfg", Severity.High, HiddenPathValidation.Contains,
                "auth", "Docker registry credentials are exposed."),
            new("/.docker/config.json", Severity.High, HiddenPathValidation.Contains,
                "auths", "Docker registry credentials are exposed."),
            new("/docker-compose.yml", Severity.Medium, HiddenPathValidation.Contains,
                "services:", "Container configuration is exposed."),
            new("/docker-compose.yaml", Severity.Medium, HiddenPathValidation.Contains,
                "services:", "Container configuration is exposed."),
            new("/Dockerfile", Severity.Low, HiddenPathValidation.Contains,
                "FROM ", "Build configuration is exposed."),
            new("/composer.json", Severity.Low, HiddenPathValidation.Contains,
                "\"require\"", "PHP dependency manifest is exposed."),
            new("/composer.lock", Severity.Low, HiddenPathValidation.Contains,
                "packages", "PHP dependency lock file is exposed."),
            new("/package.json", Severity.Low, HiddenPathValidation.Contains,
                "\"dependencies\"", "Node.js dependency manifest is exposed."),
            new("/package-lock.json", Severity.Low, HiddenPathValidation.Contains,
                "lockfileVersion", "npm dependency lock file is exposed."),

            // Private keys and cloud credentials.
            new("/.aws/credentials", Severity.Critical, HiddenPathValidation.Contains,
                "aws_access_key_id", "AWS credential file is exposed."),
            new("/.aws/config", Severity.High, HiddenPathValidation.Contains,
                "[default]", "AWS configuration is exposed."),
            new("/.ssh/id_rsa", Severity.Critical, HiddenPathValidation.Contains,
                "PRIVATE KEY", "SSH private key is exposed."),
            new("/.ssh/id_dsa", Severity.Critical, HiddenPathValidation.Contains,
                "PRIVATE KEY", "SSH private key is exposed."),
            new("/.ssh/id_ecdsa", Severity.Critical, HiddenPathValidation.Contains,
                "PRIVATE KEY", "SSH private key is exposed."),
            new("/.ssh/id_ed25519", Severity.Critical, HiddenPathValidation.Contains,
                "PRIVATE KEY", "SSH private key is exposed."),
            new("/id_rsa", Severity.Critical, HiddenPathValidation.Contains,
                "PRIVATE KEY", "SSH private key is exposed."),
            new("/id_dsa", Severity.Critical, HiddenPathValidation.Contains,
                "PRIVATE KEY", "SSH private key is exposed."),
            new("/id_ecdsa", Severity.Critical, HiddenPathValidation.Contains,
                "PRIVATE KEY", "SSH private key is exposed."),
            new("/id_ed25519", Severity.Critical, HiddenPathValidation.Contains,
                "PRIVATE KEY", "SSH private key is exposed."),
            new("/id_rsa.bak", Severity.Critical, HiddenPathValidation.Contains,
                "PRIVATE KEY", "SSH private key backup is exposed."),
            new("/id_dsa.bak", Severity.Critical, HiddenPathValidation.Contains,
                "PRIVATE KEY", "SSH private key backup is exposed."),
            new("/id_ecdsa.bak", Severity.Critical, HiddenPathValidation.Contains,
                "PRIVATE KEY", "SSH private key backup is exposed."),
            new("/id_ed25519.bak", Severity.Critical, HiddenPathValidation.Contains,
                "PRIVATE KEY", "SSH private key backup is exposed."),
            new("/.ssh/authorized_keys", Severity.High, HiddenPathValidation.Regex,
                @"(ssh-rsa|ssh-ed25519|ecdsa-sha2)", "SSH authorized keys are exposed."),
            new("/.ssh/known_hosts", Severity.Medium, HiddenPathValidation.Regex,
                @"(ssh-rsa|ssh-ed25519|ecdsa-sha2)", "SSH known hosts are exposed."),
            new("/.ssh/config", Severity.Medium, HiddenPathValidation.Contains,
                "Host ", "SSH client configuration is exposed."),

            // Logs and editor artefacts.
            new("/debug.log", Severity.Medium, HiddenPathValidation.None,
                null, "Debug log is exposed."),
            new("/error.log", Severity.Medium, HiddenPathValidation.None,
                null, "Error log is exposed."),
            new("/access.log", Severity.Medium, HiddenPathValidation.None,
                null, "Access log is exposed."),
            new("/app.log", Severity.Medium, HiddenPathValidation.None,
                null, "Application log is exposed."),
            new("/application.log", Severity.Medium, HiddenPathValidation.None,
                null, "Application log is exposed."),
            new("/php_errors.log", Severity.Medium, HiddenPathValidation.None,
                null, "PHP error log is exposed."),
            new("/laravel.log", Severity.Medium, HiddenPathValidation.None,
                null, "Laravel log is exposed."),
            new("/storage/logs/laravel.log", Severity.Medium, HiddenPathValidation.None,
                null, "Laravel log is exposed."),
            new("/logs/", Severity.Low, HiddenPathValidation.Contains,
                "Index of", "Log directory listing is exposed.", AllowHtml: true),
            new("/.DS_Store", Severity.Low, HiddenPathValidation.Contains,
                "Bud1", "macOS metadata file is exposed."),
            new("/Thumbs.db", Severity.Low, HiddenPathValidation.Contains,
                "Thumbs", "Windows thumbnail cache is exposed."),
            new("/desktop.ini", Severity.Low, HiddenPathValidation.Contains,
                "[.ShellClassInfo]", "Windows desktop configuration is exposed."),

            // Server, admin and debug interfaces.
            new("/phpinfo.php", Severity.High, HiddenPathValidation.Contains,
                "PHP Version", "phpinfo() exposes server and configuration details."),
            new("/info.php", Severity.High, HiddenPathValidation.Contains,
                "PHP Version", "phpinfo() exposes server and configuration details."),
            new("/adminer.php", Severity.High, HiddenPathValidation.Contains,
                "adminer", "Adminer database console is exposed."),
            new("/adminer/", Severity.High, HiddenPathValidation.Contains,
                "adminer", "Adminer database console is exposed.", AllowHtml: true),
            new("/phpmyadmin/", Severity.High, HiddenPathValidation.Contains,
                "phpMyAdmin", "phpMyAdmin is exposed.", AllowHtml: true),
            new("/pma/", Severity.High, HiddenPathValidation.Contains,
                "phpMyAdmin", "phpMyAdmin is exposed.", AllowHtml: true),
            new("/myadmin/", Severity.High, HiddenPathValidation.Contains,
                "phpMyAdmin", "phpMyAdmin is exposed.", AllowHtml: true),
            new("/server-status", Severity.Medium, HiddenPathValidation.Contains,
                "Apache Server Status", "Apache server-status is exposed.", AllowHtml: true),
            new("/server-info", Severity.Medium, HiddenPathValidation.Contains,
                "Apache Server Information", "Apache server-info is exposed.", AllowHtml: true),
            new("/.well-known/security.txt", Severity.Info, HiddenPathValidation.Contains,
                "Contact:", "security.txt is published."),
            new("/crossdomain.xml", Severity.Low, HiddenPathValidation.Contains,
                "<cross-domain-policy", "Cross-domain policy is exposed."),
            new("/clientaccesspolicy.xml", Severity.Low, HiddenPathValidation.Contains,
                "<access-policy", "Silverlight access policy is exposed."),
            new("/manager/html", Severity.High, HiddenPathValidation.Contains,
                "Tomcat Web Application Manager", "Tomcat manager is exposed."),
            new("/host-manager/html", Severity.High, HiddenPathValidation.Contains,
                "Tomcat Virtual Host Manager", "Tomcat host manager is exposed."),
            new("/manager/status", Severity.High, HiddenPathValidation.Contains,
                "Server Status", "Tomcat manager status is exposed."),
            new("/examples/", Severity.Low, HiddenPathValidation.Contains,
                "Tomcat Examples", "Tomcat examples are deployed.", AllowHtml: true),
            new("/docs/", Severity.Low, HiddenPathValidation.Contains,
                "Tomcat Documentation", "Tomcat documentation is deployed.", AllowHtml: true),
            new("/WEB-INF/web.xml", Severity.Critical, HiddenPathValidation.Contains,
                "<web-app", "Java web application descriptor is exposed."),
            new("/WEB-INF/", Severity.High, HiddenPathValidation.Contains,
                "Index of", "WEB-INF directory listing is exposed.", AllowHtml: true),
            new("/META-INF/", Severity.High, HiddenPathValidation.Contains,
                "Index of", "META-INF directory listing is exposed.", AllowHtml: true),
            new("/META-INF/MANIFEST.MF", Severity.Low, HiddenPathValidation.Contains,
                "Manifest-Version", "JAR manifest is exposed."),

            // Spring Actuator and API documentation.
            new("/actuator", Severity.Medium, HiddenPathValidation.Contains,
                "_links", "Spring Boot Actuator index is exposed."),
            new("/actuator/env", Severity.High, HiddenPathValidation.Contains,
                "propertySources", "Spring Boot Actuator environment is exposed."),
            new("/actuator/health", Severity.Low, HiddenPathValidation.Contains,
                "\"status\"", "Spring Boot Actuator health endpoint is exposed."),
            new("/actuator/configprops", Severity.High, HiddenPathValidation.Contains,
                "configProps", "Spring Boot Actuator configuration is exposed."),
            new("/actuator/heapdump", Severity.Critical, HiddenPathValidation.Archive,
                null, "Spring Boot heap dump is downloadable."),
            new("/actuator/mappings", Severity.Medium, HiddenPathValidation.Contains,
                "dispatcherServlets", "Spring Boot Actuator mappings are exposed."),
            new("/actuator/beans", Severity.Medium, HiddenPathValidation.Contains,
                "beans", "Spring Boot Actuator beans are exposed."),
            new("/actuator/loggers", Severity.Medium, HiddenPathValidation.Contains,
                "configuredLevel", "Spring Boot Actuator loggers are exposed."),
            new("/actuator/threaddump", Severity.Medium, HiddenPathValidation.Contains,
                "threadName", "Spring Boot Actuator thread dump is exposed."),
            new("/actuator/httptrace", Severity.Medium, HiddenPathValidation.Contains,
                "traces", "Spring Boot Actuator HTTP trace is exposed."),
            new("/actuator/jolokia", Severity.High, HiddenPathValidation.Contains,
                "jolokia", "Jolokia JMX bridge is exposed."),
            new("/actuator/gateway/routes", Severity.Medium, HiddenPathValidation.Contains,
                "predicate", "Spring Cloud Gateway routes are exposed."),
            new("/swagger-ui.html", Severity.Medium, HiddenPathValidation.Contains,
                "swagger-ui", "Swagger UI is exposed."),
            new("/swagger-ui/index.html", Severity.Medium, HiddenPathValidation.Contains,
                "swagger-ui", "Swagger UI is exposed."),
            new("/swagger.json", Severity.Medium, HiddenPathValidation.Regex,
                @"(?i)(""swagger""|""openapi""|""paths"")", "Swagger specification is exposed."),
            new("/openapi.json", Severity.Medium, HiddenPathValidation.Regex,
                @"(?i)(""swagger""|""openapi""|""paths"")", "OpenAPI specification is exposed."),
            new("/v2/api-docs", Severity.Medium, HiddenPathValidation.Contains,
                "swagger", "Swagger 2 documentation is exposed."),
            new("/v3/api-docs", Severity.Medium, HiddenPathValidation.Contains,
                "openapi", "OpenAPI 3 documentation is exposed."),
            new("/api-docs", Severity.Medium, HiddenPathValidation.Regex,
                @"(?i)(""swagger""|""openapi""|""paths"")", "API documentation is exposed."),
            new("/redoc", Severity.Medium, HiddenPathValidation.Contains,
                "redoc", "ReDoc API documentation is exposed."),
            new("/swagger-resources", Severity.Low, HiddenPathValidation.Contains,
                "swagger", "Swagger resource listing is exposed."),
            new("/graphiql", Severity.Medium, HiddenPathValidation.Contains,
                "GraphiQL", "GraphiQL console is exposed."),
            new("/graphql", Severity.Low, HiddenPathValidation.Contains,
                "GraphQL", "GraphQL endpoint is reachable."),
            new("/playground", Severity.Medium, HiddenPathValidation.Contains,
                "GraphQL Playground", "GraphQL Playground is exposed."),
            new("/debug/vars", Severity.High, HiddenPathValidation.Contains,
                "memstats", "Go expvar debug endpoint is exposed."),
            new("/debug/pprof/", Severity.High, HiddenPathValidation.Contains,
                "Types of profiles available", "Go pprof endpoint is exposed."),
            new("/debug/requests", Severity.High, HiddenPathValidation.Contains,
                "debug requests", "Debug requests endpoint is exposed."),
            new("/debug/events", Severity.High, HiddenPathValidation.Contains,
                "debug events", "Debug events endpoint is exposed."),
            new("/__debug__/", Severity.High, HiddenPathValidation.Contains,
                "debug", "Framework debug interface is exposed."),
            new("/h2-console", Severity.High, HiddenPathValidation.Contains,
                "H2 Console", "H2 database console is exposed."),
            new("/console", Severity.Medium, HiddenPathValidation.Contains,
                "Admin Console", "Administration console is exposed."),
            new("/druid/", Severity.Medium, HiddenPathValidation.Contains,
                "Druid", "Druid monitoring console is exposed.", AllowHtml: true),
            new("/metrics", Severity.Medium, HiddenPathValidation.Contains,
                "# HELP", "Prometheus metrics are exposed."),
            new("/env", Severity.Critical, HiddenPathValidation.Contains,
                "PATH=", "Environment variables are exposed."),
            new("/heapdump", Severity.Critical, HiddenPathValidation.Archive,
                null, "Heap dump is downloadable."),
            new("/threaddump", Severity.Medium, HiddenPathValidation.Contains,
                "threadName", "Thread dump is exposed."),
        };

        foreach (var stem in BackupStems)
        {
            foreach (var extension in BackupExtensions)
            {
                entries.Add(Archive($"/{stem}{extension}", "Backup archive is exposed."));
            }
        }

        foreach (var stem in WrappedBackupStems)
        {
            foreach (var extension in new[] { ".zip", ".tar.gz" })
            {
                foreach (var wrapper in BackupWrappers)
                {
                    var name = wrapper
                        .Replace("{name}", stem, StringComparison.Ordinal)
                        .Replace("{ext}", extension, StringComparison.Ordinal);
                    entries.Add(Archive($"/{name}", "Backup archive is exposed."));
                }
            }
        }

        foreach (var stem in DumpStems)
        {
            foreach (var extension in DumpExtensions)
            {
                entries.Add(Dump($"/{stem}{extension}", "Database dump is exposed."));
            }

            entries.Add(Archive($"/{stem}.sql.gz", "Compressed database dump is exposed."));
        }

        // Backup directories that admins leave browsable.
        foreach (var directory in new[]
                 {
                     "backup", "backups", "bk", "bkp", "old", "temp", "tmp",
                     "dump", "sql", "db", "database", "archive", "archives",
                 })
        {
            entries.Add(new HiddenPath(
                $"/{directory}/",
                Severity.Medium,
                HiddenPathValidation.Contains,
                "Index of",
                "Backup directory listing is exposed.",
                AllowHtml: true));
        }

        // Source-control repository archives.
        foreach (var path in new[] { "/.git.zip", "/.git.tar.gz", "/.svn.zip", "/.svn.tar.gz" })
        {
            entries.Add(Archive(path, "Version-control archive is exposed."));
        }

        // High-value generic backups that do not follow the stem/extension matrix.
        foreach (var path in new[]
                 {
                     "/backup.tar", "/backup.tgz", "/backup.gz", "/backup.bz2", "/backup.xz",
                     "/backups.tar", "/backups.tgz", "/backups.gz", "/backups.bz2", "/backups.xz",
                     "/site.tar", "/site.tgz", "/site.gz", "/www.tar", "/www.tgz", "/www.gz",
                     "/web.zip", "/html.zip", "/htdocs.zip", "/public_html.zip", "/wwwroot.zip",
                     "/full_backup.zip", "/fullbackup.zip", "/latest.zip", "/final.zip",
                     "/release.zip", "/prod.zip", "/production.zip", "/staging.zip",
                     "/test.zip", "/old.zip", "/new.zip", "/copy.zip", "/export.zip",
                     "/archive.zip", "/archives.zip",
                 })
        {
            entries.Add(Archive(path, "Backup archive is exposed."));
        }

        return entries
            .DistinctBy(entry => entry.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static HiddenPath Archive(string path, string description) =>
        new(path, Severity.High, HiddenPathValidation.Archive, null, description);

    private static HiddenPath Dump(string path, string description) =>
        new(path, Severity.High, HiddenPathValidation.SqlDump, null, description);
}
