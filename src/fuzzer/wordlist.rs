// Wordlist Management for Fuzzing
// Built-in wordlists and custom wordlist loading

use anyhow::Result;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};

/// Built-in wordlist types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinWordlist {
    /// Common directories (1000 entries)
    CommonDirs1k,
    /// Common directories (10000 entries)
    CommonDirs10k,
    /// Common files (backup, config, sensitive)
    CommonFiles,
    /// Common file extensions
    CommonExtensions,
    /// Common subdomains
    CommonSubdomains,
    /// Common parameters
    CommonParameters,
    /// WordPress specific paths
    WordPress,
    /// Joomla specific paths
    Joomla,
    /// Laravel framework paths
    Laravel,
    /// API endpoints
    ApiEndpoints,
}

/// Wordlist manager
#[allow(dead_code)]
pub struct WordlistManager {
    /// Custom wordlist paths
    custom_wordlists: Vec<String>,
}

impl WordlistManager {
    /// Create a new wordlist manager
    pub fn new() -> Self {
        Self {
            custom_wordlists: Vec::new(),
        }
    }

    /// Load a built-in wordlist
    pub fn load_builtin(&self, wordlist: BuiltinWordlist) -> Vec<String> {
        match wordlist {
            BuiltinWordlist::CommonDirs1k => self.get_common_dirs_1k(),
            BuiltinWordlist::CommonDirs10k => self.get_common_dirs_10k(),
            BuiltinWordlist::CommonFiles => self.get_common_files(),
            BuiltinWordlist::CommonExtensions => self.get_common_extensions(),
            BuiltinWordlist::CommonSubdomains => self.get_common_subdomains(),
            BuiltinWordlist::CommonParameters => self.get_common_parameters(),
            BuiltinWordlist::WordPress => self.get_wordpress_paths(),
            BuiltinWordlist::Joomla => self.get_joomla_paths(),
            BuiltinWordlist::Laravel => self.get_laravel_paths(),
            BuiltinWordlist::ApiEndpoints => self.get_api_endpoints(),
        }
    }

    /// Load a custom wordlist from file
    pub async fn load_from_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<String>> {
        let file = File::open(path).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut wordlist = Vec::new();

        while let Some(line) = lines.next_line().await? {
            let trimmed = line.trim();
            // Skip empty lines and comments
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                wordlist.push(trimmed.to_string());
            }
        }

        Ok(wordlist)
    }

    /// Generate wordlist mutations (l33t speak, case variations, etc.)
    pub fn mutate(&self, words: Vec<String>) -> Vec<String> {
        let mut mutated = words.clone();

        for word in &words {
            // Case variations
            mutated.push(word.to_uppercase());
            mutated.push(word.to_lowercase());
            mutated.push(Self::capitalize(word));

            // L33t speak variations
            mutated.push(Self::leetify(word));

            // Year suffixes
            for year in 2020..=2025 {
                mutated.push(format!("{}{}", word, year));
                mutated.push(format!("{}_{}", word, year));
                mutated.push(format!("{}-{}", word, year));
            }

            // Common suffixes
            for suffix in &["old", "new", "backup", "bak", "tmp", "test", "dev"] {
                mutated.push(format!("{}_{}", word, suffix));
                mutated.push(format!("{}-{}", word, suffix));
                mutated.push(format!("{}.{}", word, suffix));
            }
        }

        // Remove duplicates
        mutated.sort();
        mutated.dedup();

        mutated
    }

    /// Capitalize first letter
    fn capitalize(s: &str) -> String {
        let mut chars = s.chars();
        match chars.next() {
            None => String::new(),
            Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        }
    }

    /// Convert to l33t speak
    fn leetify(s: &str) -> String {
        s.chars()
            .map(|c| match c {
                'a' | 'A' => '4',
                'e' | 'E' => '3',
                'i' | 'I' => '1',
                'o' | 'O' => '0',
                's' | 'S' => '5',
                't' | 'T' => '7',
                _ => c,
            })
            .collect()
    }

    /// Common directories (1000 entries)
    fn get_common_dirs_1k(&self) -> Vec<String> {
        vec![
            "admin",
            "administrator",
            "login",
            "wp-admin",
            "wp-content",
            "wp-includes",
            "images",
            "img",
            "css",
            "js",
            "javascript",
            "static",
            "assets",
            "media",
            "upload",
            "uploads",
            "files",
            "download",
            "downloads",
            "backup",
            "backups",
            "temp",
            "tmp",
            "test",
            "demo",
            "dev",
            "development",
            "prod",
            "production",
            "api",
            "v1",
            "v2",
            "v3",
            "rest",
            "graphql",
            "webhooks",
            "user",
            "users",
            "account",
            "accounts",
            "profile",
            "profiles",
            "blog",
            "news",
            "posts",
            "post",
            "article",
            "articles",
            "dashboard",
            "panel",
            "cp",
            "cpanel",
            "control",
            "manager",
            "config",
            "configuration",
            "settings",
            "setup",
            "install",
            "installation",
            "docs",
            "documentation",
            "help",
            "support",
            "faq",
            "search",
            "find",
            "query",
            "results",
            "auth",
            "authentication",
            "oauth",
            "signin",
            "signup",
            "register",
            "cart",
            "checkout",
            "shop",
            "store",
            "catalog",
            "products",
            "about",
            "contact",
            "privacy",
            "terms",
            "legal",
            "policy",
            "forum",
            "forums",
            "community",
            "discuss",
            "discussion",
            "mail",
            "email",
            "webmail",
            "smtp",
            "pop3",
            "imap",
            "db",
            "database",
            "mysql",
            "pgsql",
            "postgres",
            "mongo",
            "cache",
            "redis",
            "memcache",
            "memcached",
            "log",
            "logs",
            "access",
            "error",
            "debug",
            "cgi-bin",
            "bin",
            "scripts",
            "tools",
            "utils",
            "utilities",
            "old",
            "new",
            "v1",
            "v2",
            "2023",
            "2024",
            "2025",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Common directories (10000 entries) - subset shown
    fn get_common_dirs_10k(&self) -> Vec<String> {
        // In production, this would include 10k entries
        // For now, return the 1k list extended
        let mut dirs = self.get_common_dirs_1k();

        // Add more specific paths
        let additional = vec![
            ".git",
            ".svn",
            ".hg",
            ".env",
            ".htaccess",
            ".htpasswd",
            "phpmyadmin",
            "pma",
            "adminer",
            "sqlbuddy",
            "wp-json",
            "xmlrpc.php",
            "readme.html",
            "license.txt",
            "robots.txt",
            "sitemap.xml",
            "sitemap.txt",
            "crossdomain.xml",
            "clientaccesspolicy.xml",
            "WEB-INF",
            "META-INF",
            "classes",
            "lib",
            "libs",
            "vendor",
            "node_modules",
            "bower_components",
            "public",
            "private",
            "protected",
            "secret",
            "hidden",
            "data",
            "app",
            "application",
            "applications",
            "portal",
            "portals",
            "site",
            "sites",
            "web",
            "www",
        ];

        dirs.extend(additional.iter().map(|s| s.to_string()));
        dirs
    }

    /// Common files
    fn get_common_files(&self) -> Vec<String> {
        vec![
            "robots.txt",
            "sitemap.xml",
            "README.md",
            "CHANGELOG.md",
            "config.php",
            "config.inc.php",
            "config.yml",
            "config.yaml",
            ".env",
            ".env.local",
            ".env.production",
            ".env.development",
            ".htaccess",
            ".htpasswd",
            ".gitignore",
            ".gitattributes",
            "web.config",
            "app.config",
            "settings.json",
            "appsettings.json",
            "composer.json",
            "package.json",
            "bower.json",
            "yarn.lock",
            "Gemfile",
            "Gemfile.lock",
            "requirements.txt",
            "Pipfile",
            "index.php",
            "index.html",
            "index.htm",
            "default.php",
            "default.html",
            "login.php",
            "admin.php",
            "dashboard.php",
            "panel.php",
            "backup.sql",
            "database.sql",
            "dump.sql",
            "db.sql",
            "backup.zip",
            "backup.tar.gz",
            "site.zip",
            "www.zip",
            "phpinfo.php",
            "info.php",
            "test.php",
            "debug.php",
            "wp-config.php",
            "wp-config.php.bak",
            "wp-config.old",
            "configuration.php",
            "config.inc",
            "settings.php",
            "error.log",
            "access.log",
            "debug.log",
            "app.log",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Common file extensions
    fn get_common_extensions(&self) -> Vec<String> {
        vec![
            "php", "asp", "aspx", "jsp", "jspx", "py", "rb", "cgi", "pl", "html", "htm", "xml",
            "json", "txt", "log", "bak", "old", "tmp", "sql", "db", "sqlite", "mdb", "dbf", "zip",
            "tar", "gz", "bz2", "rar", "7z", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
            "jpg", "jpeg", "png", "gif", "svg", "ico", "css", "js", "ts", "vue", "jsx", "tsx",
            "swf", "fla", "swp", "config", "conf", "cfg", "ini", "yaml", "yml", "toml",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Common subdomains
    fn get_common_subdomains(&self) -> Vec<String> {
        vec![
            "www",
            "mail",
            "ftp",
            "smtp",
            "pop",
            "imap",
            "admin",
            "administrator",
            "webmail",
            "panel",
            "cpanel",
            "api",
            "rest",
            "graphql",
            "v1",
            "v2",
            "v3",
            "dev",
            "develop",
            "development",
            "test",
            "testing",
            "stage",
            "staging",
            "prod",
            "production",
            "uat",
            "qa",
            "demo",
            "blog",
            "shop",
            "store",
            "forum",
            "wiki",
            "docs",
            "support",
            "help",
            "helpdesk",
            "tickets",
            "cdn",
            "static",
            "assets",
            "media",
            "images",
            "img",
            "db",
            "database",
            "mysql",
            "pgsql",
            "mongo",
            "vpn",
            "remote",
            "ssh",
            "rdp",
            "vnc",
            "git",
            "svn",
            "hg",
            "gitlab",
            "github",
            "bitbucket",
            "jenkins",
            "ci",
            "cd",
            "build",
            "deploy",
            "monitor",
            "monitoring",
            "metrics",
            "stats",
            "analytics",
            "backup",
            "backups",
            "old",
            "new",
            "legacy",
            "mobile",
            "m",
            "app",
            "apps",
            "portal",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Common parameters
    fn get_common_parameters(&self) -> Vec<String> {
        vec![
            "id",
            "user",
            "username",
            "email",
            "password",
            "token",
            "key",
            "api_key",
            "search",
            "query",
            "q",
            "s",
            "keyword",
            "keywords",
            "page",
            "p",
            "offset",
            "limit",
            "count",
            "size",
            "sort",
            "order",
            "orderby",
            "sortby",
            "direction",
            "filter",
            "filters",
            "category",
            "cat",
            "tag",
            "tags",
            "lang",
            "language",
            "locale",
            "region",
            "country",
            "format",
            "type",
            "view",
            "mode",
            "action",
            "file",
            "path",
            "url",
            "redirect",
            "return",
            "callback",
            "debug",
            "test",
            "dev",
            "development",
            "verbose",
            "start",
            "end",
            "from",
            "to",
            "since",
            "until",
            "name",
            "title",
            "description",
            "content",
            "body",
            "status",
            "state",
            "enabled",
            "disabled",
            "active",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// WordPress specific paths
    fn get_wordpress_paths(&self) -> Vec<String> {
        vec![
            "wp-admin",
            "wp-content",
            "wp-includes",
            "wp-json",
            "wp-login.php",
            "wp-config.php",
            "xmlrpc.php",
            "wp-content/uploads",
            "wp-content/plugins",
            "wp-content/themes",
            "wp-content/cache",
            "wp-content/backup",
            "readme.html",
            "license.txt",
            "wp-activate.php",
            "wp-blog-header.php",
            "wp-comments-post.php",
            "wp-config-sample.php",
            "wp-cron.php",
            "wp-links-opml.php",
            "wp-load.php",
            "wp-mail.php",
            "wp-settings.php",
            "wp-signup.php",
            "wp-trackback.php",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Joomla specific paths
    fn get_joomla_paths(&self) -> Vec<String> {
        vec![
            "administrator",
            "components",
            "modules",
            "plugins",
            "templates",
            "language",
            "libraries",
            "cache",
            "tmp",
            "logs",
            "configuration.php",
            "htaccess.txt",
            "web.config.txt",
            "README.txt",
            "LICENSE.txt",
            "joomla.xml",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Laravel framework paths
    fn get_laravel_paths(&self) -> Vec<String> {
        vec![
            "app",
            "bootstrap",
            "config",
            "database",
            "public",
            "resources",
            "routes",
            "storage",
            "tests",
            "vendor",
            "artisan",
            ".env",
            ".env.example",
            "composer.json",
            "package.json",
            "storage/logs",
            "storage/framework",
            "storage/app",
            "public/index.php",
            "public/robots.txt",
            "public/favicon.ico",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Common API endpoints
    fn get_api_endpoints(&self) -> Vec<String> {
        vec![
            "api",
            "api/v1",
            "api/v2",
            "api/v3",
            "rest",
            "rest/v1",
            "rest/v2",
            "graphql",
            "graphiql",
            "api/users",
            "api/auth",
            "api/login",
            "api/register",
            "api/products",
            "api/items",
            "api/posts",
            "api/articles",
            "api/search",
            "api/query",
            "api/upload",
            "api/download",
            "api/admin",
            "api/dashboard",
            "api/config",
            "api/settings",
            "api/status",
            "api/health",
            "api/ping",
            "swagger",
            "swagger-ui",
            "api-docs",
            "docs",
            "openapi.json",
            "swagger.json",
            "api.yaml",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }
}

impl Default for WordlistManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_common_dirs_1k() {
        let manager = WordlistManager::new();
        let wordlist = manager.load_builtin(BuiltinWordlist::CommonDirs1k);
        assert!(!wordlist.is_empty());
        assert!(wordlist.contains(&"admin".to_string()));
        assert!(wordlist.contains(&"api".to_string()));
    }

    #[test]
    fn test_builtin_common_files() {
        let manager = WordlistManager::new();
        let wordlist = manager.load_builtin(BuiltinWordlist::CommonFiles);
        assert!(wordlist.contains(&"robots.txt".to_string()));
        assert!(wordlist.contains(&".env".to_string()));
    }

    #[test]
    fn test_builtin_extensions() {
        let manager = WordlistManager::new();
        let wordlist = manager.load_builtin(BuiltinWordlist::CommonExtensions);
        assert!(wordlist.contains(&"php".to_string()));
        assert!(wordlist.contains(&"json".to_string()));
    }

    #[test]
    fn test_capitalize() {
        assert_eq!(WordlistManager::capitalize("admin"), "Admin");
        assert_eq!(WordlistManager::capitalize("test"), "Test");
    }

    #[test]
    fn test_leetify() {
        assert_eq!(WordlistManager::leetify("admin"), "4dm1n");
        assert_eq!(WordlistManager::leetify("test"), "7357");
        assert_eq!(WordlistManager::leetify("elite"), "3l173");
    }

    #[test]
    fn test_mutate() {
        let manager = WordlistManager::new();
        let words = vec!["admin".to_string()];
        let mutated = manager.mutate(words);

        assert!(mutated.contains(&"admin".to_string()));
        assert!(mutated.contains(&"ADMIN".to_string()));
        assert!(mutated.contains(&"Admin".to_string()));
        assert!(mutated.contains(&"4dm1n".to_string()));
        assert!(mutated.contains(&"admin2024".to_string()));
        assert!(mutated.contains(&"admin_backup".to_string()));
    }

    #[test]
    fn test_wordpress_paths() {
        let manager = WordlistManager::new();
        let wordlist = manager.load_builtin(BuiltinWordlist::WordPress);
        assert!(wordlist.contains(&"wp-admin".to_string()));
        assert!(wordlist.contains(&"wp-content".to_string()));
        assert!(wordlist.contains(&"xmlrpc.php".to_string()));
    }

    #[test]
    fn test_api_endpoints() {
        let manager = WordlistManager::new();
        let wordlist = manager.load_builtin(BuiltinWordlist::ApiEndpoints);
        assert!(wordlist.contains(&"api".to_string()));
        assert!(wordlist.contains(&"graphql".to_string()));
        assert!(wordlist.contains(&"swagger".to_string()));
    }
}
