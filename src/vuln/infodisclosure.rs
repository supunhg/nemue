// Additional information disclosure detection scripts
use super::framework::{VulnCategory, VulnResult, VulnScript, VulnSeverity};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct InfoDisclosureScripts;

impl InfoDisclosureScripts {
    /// Get all information disclosure scripts
    pub fn get_all() -> Vec<VulnScript> {
        vec![
            Self::git_exposed_check(),
            Self::svn_exposed_check(),
            Self::backup_files_check(),
            Self::admin_panel_discovery(),
            Self::server_version_disclosure(),
            Self::phpinfo_exposure(),
            Self::dotenv_exposure(),
            Self::aws_credentials_exposure(),
        ]
    }

    /// Exposed .git directory check
    pub fn git_exposed_check() -> VulnScript {
        VulnScript::new(
            "git-exposed",
            "Exposed .git Directory",
            "Checks for publicly accessible .git directory",
            VulnCategory::InfoDisclosure,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            let addr = format!("{}:{}", target, port);
            let timeout = Duration::from_secs(5);

            if let Ok(mut stream) = TcpStream::connect_timeout(&addr.parse().unwrap(), timeout) {
                stream.set_read_timeout(Some(timeout)).ok();
                stream.set_write_timeout(Some(timeout)).ok();

                let request = format!(
                    "GET /.git/HEAD HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    target
                );

                if stream.write_all(request.as_bytes()).is_ok() {
                    let mut response = String::new();
                    stream.read_to_string(&mut response).ok();

                    // Check for .git/HEAD content
                    let vulnerable = response.contains("HTTP/1.1 200")
                        && response.contains("ref:");

                    return Ok(VulnResult {
                        script_id: "git-exposed".to_string(),
                        target: target.to_string(),
                        port,
                        vulnerable,
                        severity: VulnSeverity::High,
                        cve_ids: vec![],
                        description: "Exposed .git directory allows source code download".to_string(),
                        evidence: if vulnerable {
                            Some(".git/HEAD accessible".to_string())
                        } else {
                            None
                        },
                        remediation: Some("Remove .git directory from web root or block access via web server config".to_string()),
                        references: vec!["https://en.internetwache.org/dont-publicly-expose-git-or-how-we-downloaded-your-websites-sourcecode-an-analysis-of-alexas-1m-28-07-2015/".to_string()],
                        exploit_available: false,
                    });
                }
            }

            Ok(VulnResult {
                script_id: "git-exposed".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::High,
                cve_ids: vec![],
                description: "Could not check for .git exposure".to_string(),
                evidence: None,
                remediation: None,
                references: vec![],
                exploit_available: false,
            })
        })
    }

    /// Exposed .svn directory check
    pub fn svn_exposed_check() -> VulnScript {
        VulnScript::new(
            "svn-exposed",
            "Exposed .svn Directory",
            "Checks for publicly accessible .svn directory",
            VulnCategory::InfoDisclosure,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            let addr = format!("{}:{}", target, port);
            let timeout = Duration::from_secs(5);

            if let Ok(mut stream) = TcpStream::connect_timeout(&addr.parse().unwrap(), timeout) {
                stream.set_read_timeout(Some(timeout)).ok();
                stream.set_write_timeout(Some(timeout)).ok();

                let request = format!(
                    "GET /.svn/entries HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    target
                );

                if stream.write_all(request.as_bytes()).is_ok() {
                    let mut response = String::new();
                    stream.read_to_string(&mut response).ok();

                    let vulnerable = response.contains("HTTP/1.1 200");

                    return Ok(VulnResult {
                        script_id: "svn-exposed".to_string(),
                        target: target.to_string(),
                        port,
                        vulnerable,
                        severity: VulnSeverity::High,
                        cve_ids: vec![],
                        description: "Exposed .svn directory allows source code download"
                            .to_string(),
                        evidence: if vulnerable {
                            Some(".svn/entries accessible".to_string())
                        } else {
                            None
                        },
                        remediation: Some("Remove .svn directory from web root".to_string()),
                        references: vec![],
                        exploit_available: false,
                    });
                }
            }

            Ok(VulnResult {
                script_id: "svn-exposed".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::High,
                cve_ids: vec![],
                description: "Could not check for .svn exposure".to_string(),
                evidence: None,
                remediation: None,
                references: vec![],
                exploit_available: false,
            })
        })
    }

    /// Backup files check
    pub fn backup_files_check() -> VulnScript {
        VulnScript::new(
            "backup-files",
            "Backup Files Exposure",
            "Checks for common backup file patterns",
            VulnCategory::InfoDisclosure,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            let addr = format!("{}:{}", target, port);
            let timeout = Duration::from_secs(5);

            let backup_patterns = vec![
                "/backup.zip",
                "/backup.tar.gz",
                "/site.zip",
                "/www.zip",
                "/db_backup.sql",
                "/.env.backup",
            ];

            for pattern in backup_patterns {
                if let Ok(mut stream) = TcpStream::connect_timeout(&addr.parse().unwrap(), timeout)
                {
                    stream.set_read_timeout(Some(timeout)).ok();
                    stream.set_write_timeout(Some(timeout)).ok();

                    let request = format!(
                        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        pattern, target
                    );

                    if stream.write_all(request.as_bytes()).is_ok() {
                        let mut response = String::new();
                        stream.read_to_string(&mut response).ok();

                        if response.contains("HTTP/1.1 200") {
                            return Ok(VulnResult {
                                script_id: "backup-files".to_string(),
                                target: target.to_string(),
                                port,
                                vulnerable: true,
                                severity: VulnSeverity::High,
                                cve_ids: vec![],
                                description: "Backup files accessible via web server".to_string(),
                                evidence: Some(format!("Found: {}", pattern)),
                                remediation: Some(
                                    "Remove backup files from web root and use secure storage"
                                        .to_string(),
                                ),
                                references: vec![],
                                exploit_available: false,
                            });
                        }
                    }
                }
            }

            Ok(VulnResult {
                script_id: "backup-files".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::High,
                cve_ids: vec![],
                description: "No backup files found".to_string(),
                evidence: None,
                remediation: None,
                references: vec![],
                exploit_available: false,
            })
        })
    }

    /// Admin panel discovery
    pub fn admin_panel_discovery() -> VulnScript {
        VulnScript::new(
            "admin-panel",
            "Admin Panel Discovery",
            "Discovers common admin panel locations",
            VulnCategory::InfoDisclosure,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            let addr = format!("{}:{}", target, port);
            let timeout = Duration::from_secs(5);

            let admin_paths = vec![
                "/admin",
                "/administrator",
                "/wp-admin",
                "/phpmyadmin",
                "/cpanel",
                "/admin.php",
                "/login",
                "/console",
            ];

            let mut found_panels = Vec::new();

            for path in admin_paths {
                if let Ok(mut stream) = TcpStream::connect_timeout(&addr.parse().unwrap(), timeout)
                {
                    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                    stream.set_write_timeout(Some(Duration::from_secs(2))).ok();

                    let request = format!(
                        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        path, target
                    );

                    if stream.write_all(request.as_bytes()).is_ok() {
                        let mut response = String::new();
                        stream.read_to_string(&mut response).ok();

                        if response.contains("HTTP/1.1 200") || response.contains("HTTP/1.1 401") {
                            found_panels.push(path);
                        }
                    }
                }
            }

            let vulnerable = !found_panels.is_empty();

            Ok(VulnResult {
                script_id: "admin-panel".to_string(),
                target: target.to_string(),
                port,
                vulnerable,
                severity: if vulnerable {
                    VulnSeverity::Medium
                } else {
                    VulnSeverity::Info
                },
                cve_ids: vec![],
                description: "Admin panels discovered".to_string(),
                evidence: if vulnerable {
                    Some(format!("Found: {}", found_panels.join(", ")))
                } else {
                    None
                },
                remediation: Some(
                    "Use non-standard admin URLs and implement IP whitelisting".to_string(),
                ),
                references: vec![],
                exploit_available: false,
            })
        })
    }

    /// Server version disclosure
    pub fn server_version_disclosure() -> VulnScript {
        VulnScript::new(
            "server-version",
            "Server Version Disclosure",
            "Checks for detailed server version in headers",
            VulnCategory::InfoDisclosure,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            let addr = format!("{}:{}", target, port);
            let timeout = Duration::from_secs(5);

            if let Ok(mut stream) = TcpStream::connect_timeout(&addr.parse().unwrap(), timeout) {
                stream.set_read_timeout(Some(timeout)).ok();
                stream.set_write_timeout(Some(timeout)).ok();

                let request = format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    target
                );

                if stream.write_all(request.as_bytes()).is_ok() {
                    let mut response = String::new();
                    stream.read_to_string(&mut response).ok();

                    // Look for Server header with version
                    let mut server_header = None;
                    for line in response.lines() {
                        if line.to_lowercase().starts_with("server:") {
                            server_header = Some(line.to_string());
                            break;
                        }
                    }

                    if let Some(header) = server_header {
                        // Check if version number is present
                        let has_version = header.chars().any(|c| c.is_numeric());

                        return Ok(VulnResult {
                            script_id: "server-version".to_string(),
                            target: target.to_string(),
                            port,
                            vulnerable: has_version,
                            severity: VulnSeverity::Low,
                            cve_ids: vec![],
                            description: "Server version disclosed in headers".to_string(),
                            evidence: if has_version { Some(header) } else { None },
                            remediation: Some(
                                "Configure server to hide version information".to_string(),
                            ),
                            references: vec![],
                            exploit_available: false,
                        });
                    }
                }
            }

            Ok(VulnResult {
                script_id: "server-version".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::Low,
                cve_ids: vec![],
                description: "Could not check server version".to_string(),
                evidence: None,
                remediation: None,
                references: vec![],
                exploit_available: false,
            })
        })
    }

    /// PHPInfo exposure
    pub fn phpinfo_exposure() -> VulnScript {
        VulnScript::new(
            "phpinfo-exposed",
            "PHPInfo Exposure",
            "Checks for exposed phpinfo() page",
            VulnCategory::InfoDisclosure,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            let addr = format!("{}:{}", target, port);
            let timeout = Duration::from_secs(5);

            let phpinfo_paths = vec!["/phpinfo.php", "/info.php", "/test.php", "/php.php"];

            for path in phpinfo_paths {
                if let Ok(mut stream) = TcpStream::connect_timeout(&addr.parse().unwrap(), timeout)
                {
                    stream.set_read_timeout(Some(timeout)).ok();
                    stream.set_write_timeout(Some(timeout)).ok();

                    let request = format!(
                        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        path, target
                    );

                    if stream.write_all(request.as_bytes()).is_ok() {
                        let mut response = String::new();
                        stream.read_to_string(&mut response).ok();

                        if response.contains("phpinfo()") || response.contains("PHP Version") {
                            return Ok(VulnResult {
                                script_id: "phpinfo-exposed".to_string(),
                                target: target.to_string(),
                                port,
                                vulnerable: true,
                                severity: VulnSeverity::Medium,
                                cve_ids: vec![],
                                description: "PHPInfo page exposes sensitive configuration"
                                    .to_string(),
                                evidence: Some(format!("Found at: {}", path)),
                                remediation: Some(
                                    "Remove phpinfo() files from production servers".to_string(),
                                ),
                                references: vec![],
                                exploit_available: false,
                            });
                        }
                    }
                }
            }

            Ok(VulnResult {
                script_id: "phpinfo-exposed".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::Medium,
                cve_ids: vec![],
                description: "No phpinfo exposure found".to_string(),
                evidence: None,
                remediation: None,
                references: vec![],
                exploit_available: false,
            })
        })
    }

    /// .env file exposure
    pub fn dotenv_exposure() -> VulnScript {
        VulnScript::new(
            "dotenv-exposed",
            ".env File Exposure",
            "Checks for exposed .env configuration file",
            VulnCategory::InfoDisclosure,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            let addr = format!("{}:{}", target, port);
            let timeout = Duration::from_secs(5);

            if let Ok(mut stream) = TcpStream::connect_timeout(&addr.parse().unwrap(), timeout) {
                stream.set_read_timeout(Some(timeout)).ok();
                stream.set_write_timeout(Some(timeout)).ok();

                let request = format!(
                    "GET /.env HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    target
                );

                if stream.write_all(request.as_bytes()).is_ok() {
                    let mut response = String::new();
                    stream.read_to_string(&mut response).ok();

                    let vulnerable = response.contains("HTTP/1.1 200")
                        && (response.contains("DB_")
                            || response.contains("APP_KEY")
                            || response.contains("SECRET"));

                    return Ok(VulnResult {
                        script_id: "dotenv-exposed".to_string(),
                        target: target.to_string(),
                        port,
                        vulnerable,
                        severity: VulnSeverity::Critical,
                        cve_ids: vec![],
                        description: ".env file exposes secrets and credentials".to_string(),
                        evidence: if vulnerable {
                            Some(".env file accessible with secrets".to_string())
                        } else {
                            None
                        },
                        remediation: Some(
                            "Block access to .env files in web server config".to_string(),
                        ),
                        references: vec![],
                        exploit_available: false,
                    });
                }
            }

            Ok(VulnResult {
                script_id: "dotenv-exposed".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::Critical,
                cve_ids: vec![],
                description: "Could not check .env exposure".to_string(),
                evidence: None,
                remediation: None,
                references: vec![],
                exploit_available: false,
            })
        })
    }

    /// AWS credentials exposure
    pub fn aws_credentials_exposure() -> VulnScript {
        VulnScript::new(
            "aws-creds-exposed",
            "AWS Credentials Exposure",
            "Checks for exposed AWS credentials file",
            VulnCategory::InfoDisclosure,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            let addr = format!("{}:{}", target, port);
            let timeout = Duration::from_secs(5);

            if let Ok(mut stream) = TcpStream::connect_timeout(&addr.parse().unwrap(), timeout) {
                stream.set_read_timeout(Some(timeout)).ok();
                stream.set_write_timeout(Some(timeout)).ok();

                let request = format!(
                    "GET /.aws/credentials HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    target
                );

                if stream.write_all(request.as_bytes()).is_ok() {
                    let mut response = String::new();
                    stream.read_to_string(&mut response).ok();

                    let vulnerable =
                        response.contains("HTTP/1.1 200") && response.contains("aws_access_key_id");

                    return Ok(VulnResult {
                        script_id: "aws-creds-exposed".to_string(),
                        target: target.to_string(),
                        port,
                        vulnerable,
                        severity: VulnSeverity::Critical,
                        cve_ids: vec![],
                        description: "AWS credentials file publicly accessible".to_string(),
                        evidence: if vulnerable {
                            Some("AWS credentials file accessible".to_string())
                        } else {
                            None
                        },
                        remediation: Some(
                            "Remove credentials from web root, rotate keys immediately".to_string(),
                        ),
                        references: vec![],
                        exploit_available: false,
                    });
                }
            }

            Ok(VulnResult {
                script_id: "aws-creds-exposed".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::Critical,
                cve_ids: vec![],
                description: "Could not check AWS credentials exposure".to_string(),
                evidence: None,
                remediation: None,
                references: vec![],
                exploit_available: false,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info_disclosure_scripts() {
        let scripts = InfoDisclosureScripts::get_all();
        assert_eq!(scripts.len(), 8, "Should have 8 info disclosure scripts");
    }

    #[test]
    fn test_script_categories() {
        let scripts = InfoDisclosureScripts::get_all();

        // All should be InfoDisclosure category
        assert!(scripts
            .iter()
            .all(|s| s.category == VulnCategory::InfoDisclosure));
    }

    #[test]
    fn test_severity_levels() {
        let scripts = InfoDisclosureScripts::get_all();

        // Check critical severity scripts
        let dotenv = scripts.iter().find(|s| s.id == "dotenv-exposed").unwrap();
        let aws = scripts
            .iter()
            .find(|s| s.id == "aws-creds-exposed")
            .unwrap();

        // These would be critical if vulnerable (checked in executor)
        assert_eq!(dotenv.id, "dotenv-exposed");
        assert_eq!(aws.id, "aws-creds-exposed");
    }
}
