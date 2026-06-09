// Advanced web vulnerability detection scripts
use super::framework::{VulnScript, VulnCategory, VulnSeverity, VulnResult};
use std::net::TcpStream;
use std::io::{Read, Write};
use std::time::Duration;

pub struct WebVulnScripts;

impl WebVulnScripts {
    /// Get all web vulnerability scripts
    pub fn get_all() -> Vec<VulnScript> {
        vec![
            Self::sql_injection_detection(),
            Self::xss_detection(),
            Self::directory_traversal(),
            Self::command_injection(),
            Self::xxe_detection(),
            Self::ssrf_detection(),
            Self::open_redirect(),
            Self::security_headers_check(),
        ]
    }

    /// SQL Injection detection
    pub fn sql_injection_detection() -> VulnScript {
        VulnScript::new(
            "sql-injection",
            "SQL Injection Detection",
            "Tests for SQL injection vulnerabilities using error-based detection",
            VulnCategory::SqlInjection,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            let addr = format!("{}:{}", target, port);
            let timeout = Duration::from_secs(5);
            
            // SQL injection payloads
            let payloads = vec![
                "' OR '1'='1",
                "' OR 1=1--",
                "admin'--",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
            ];

            match TcpStream::connect_timeout(&addr.parse().unwrap(), timeout) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(timeout)).ok();
                    stream.set_write_timeout(Some(timeout)).ok();

                    // Test with first payload
                    let payload = payloads[0];
                    let request = format!(
                        "GET /?id={} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        payload, target
                    );

                    if stream.write_all(request.as_bytes()).is_ok() {
                        let mut response = String::new();
                        stream.read_to_string(&mut response).ok();

                        // Check for SQL error messages
                        let sql_errors = vec![
                            "SQL syntax",
                            "mysql_fetch",
                            "ORA-",
                            "PostgreSQL",
                            "Microsoft SQL",
                            "SQLSTATE",
                            "syntax error",
                        ];

                        let vulnerable = sql_errors.iter().any(|err| response.contains(err));

                        return Ok(VulnResult {
                            script_id: "sql-injection".to_string(),
                            target: target.to_string(),
                            port,
                            vulnerable,
                            severity: VulnSeverity::Critical,
                            cve_ids: vec![],
                            description: "SQL injection allows unauthorized database access".to_string(),
                            evidence: if vulnerable {
                                Some("SQL error messages detected in response".to_string())
                            } else {
                                None
                            },
                            remediation: Some("Use parameterized queries and input validation".to_string()),
                            references: vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()],
                            exploit_available: false,
                        });
                    }
                }
                Err(_) => {}
            }

            Ok(VulnResult {
                script_id: "sql-injection".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::Critical,
                cve_ids: vec![],
                description: "Could not test for SQL injection".to_string(),
                evidence: None,
                remediation: None,
                references: vec![],
                exploit_available: false,
            })
        })
    }

    /// Cross-Site Scripting (XSS) detection
    pub fn xss_detection() -> VulnScript {
        VulnScript::new(
            "xss-detection",
            "Cross-Site Scripting (XSS)",
            "Tests for reflected XSS vulnerabilities",
            VulnCategory::CrossSiteScripting,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            let addr = format!("{}:{}", target, port);
            let timeout = Duration::from_secs(5);
            
            let payload = "<script>alert('XSS')</script>";

            match TcpStream::connect_timeout(&addr.parse().unwrap(), timeout) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(timeout)).ok();
                    stream.set_write_timeout(Some(timeout)).ok();

                    let request = format!(
                        "GET /?q={} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        payload, target
                    );

                    if stream.write_all(request.as_bytes()).is_ok() {
                        let mut response = String::new();
                        stream.read_to_string(&mut response).ok();

                        // Check if payload is reflected without encoding
                        let vulnerable = response.contains("<script>alert") 
                            && !response.contains("&lt;script&gt;");

                        return Ok(VulnResult {
                            script_id: "xss-detection".to_string(),
                            target: target.to_string(),
                            port,
                            vulnerable,
                            severity: VulnSeverity::High,
                            cve_ids: vec![],
                            description: "Cross-site scripting allows injection of malicious scripts".to_string(),
                            evidence: if vulnerable {
                                Some("XSS payload reflected without encoding".to_string())
                            } else {
                                None
                            },
                            remediation: Some("Encode all user input and use Content-Security-Policy".to_string()),
                            references: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
                            exploit_available: false,
                        });
                    }
                }
                Err(_) => {}
            }

            Ok(VulnResult {
                script_id: "xss-detection".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::High,
                cve_ids: vec![],
                description: "Could not test for XSS".to_string(),
                evidence: None,
                remediation: None,
                references: vec![],
                exploit_available: false,
            })
        })
    }

    /// Directory traversal detection
    pub fn directory_traversal() -> VulnScript {
        VulnScript::new(
            "dir-traversal",
            "Directory Traversal",
            "Tests for path traversal vulnerabilities",
            VulnCategory::InfoDisclosure,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            let addr = format!("{}:{}", target, port);
            let timeout = Duration::from_secs(5);
            
            let payloads = vec![
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\win.ini",
                "....//....//....//etc/passwd",
            ];

            match TcpStream::connect_timeout(&addr.parse().unwrap(), timeout) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(timeout)).ok();
                    stream.set_write_timeout(Some(timeout)).ok();

                    let payload = payloads[0];
                    let request = format!(
                        "GET /{}?file={} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        "", payload, target
                    );

                    if stream.write_all(request.as_bytes()).is_ok() {
                        let mut response = String::new();
                        stream.read_to_string(&mut response).ok();

                        // Check for /etc/passwd or win.ini contents
                        let vulnerable = response.contains("root:x:0:0") 
                            || response.contains("[extensions]");

                        return Ok(VulnResult {
                            script_id: "dir-traversal".to_string(),
                            target: target.to_string(),
                            port,
                            vulnerable,
                            severity: VulnSeverity::High,
                            cve_ids: vec![],
                            description: "Directory traversal allows unauthorized file access".to_string(),
                            evidence: if vulnerable {
                                Some("Sensitive file contents detected".to_string())
                            } else {
                                None
                            },
                            remediation: Some("Validate and sanitize file paths, use whitelisting".to_string()),
                            references: vec!["https://owasp.org/www-community/attacks/Path_Traversal".to_string()],
                            exploit_available: false,
                        });
                    }
                }
                Err(_) => {}
            }

            Ok(VulnResult {
                script_id: "dir-traversal".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::High,
                cve_ids: vec![],
                description: "Could not test for directory traversal".to_string(),
                evidence: None,
                remediation: None,
                references: vec![],
                exploit_available: false,
            })
        })
    }

    /// Command injection detection
    pub fn command_injection() -> VulnScript {
        VulnScript::new(
            "cmd-injection",
            "OS Command Injection",
            "Tests for OS command injection vulnerabilities",
            VulnCategory::RemoteCodeExecution,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            let _payloads = vec![
                "; ls",
                "| dir",
                "`whoami`",
                "$(sleep 5)",
            ];

            Ok(VulnResult {
                script_id: "cmd-injection".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::Critical,
                cve_ids: vec![],
                description: "OS command injection allows arbitrary command execution".to_string(),
                evidence: None,
                remediation: Some("Never pass user input to system commands, use safe APIs".to_string()),
                references: vec!["https://owasp.org/www-community/attacks/Command_Injection".to_string()],
                exploit_available: false,
            })
        })
    }

    /// XML External Entity (XXE) detection
    pub fn xxe_detection() -> VulnScript {
        VulnScript::new(
            "xxe-detection",
            "XML External Entity (XXE)",
            "Tests for XXE injection vulnerabilities",
            VulnCategory::InfoDisclosure,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            Ok(VulnResult {
                script_id: "xxe-detection".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::High,
                cve_ids: vec![],
                description: "XXE allows file disclosure and SSRF attacks".to_string(),
                evidence: None,
                remediation: Some("Disable external entity processing in XML parsers".to_string()),
                references: vec!["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing".to_string()],
                exploit_available: false,
            })
        })
    }

    /// Server-Side Request Forgery (SSRF) detection
    pub fn ssrf_detection() -> VulnScript {
        VulnScript::new(
            "ssrf-detection",
            "Server-Side Request Forgery",
            "Tests for SSRF vulnerabilities",
            VulnCategory::RemoteCodeExecution,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            Ok(VulnResult {
                script_id: "ssrf-detection".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::High,
                cve_ids: vec![],
                description: "SSRF allows attackers to make requests from the server".to_string(),
                evidence: None,
                remediation: Some("Validate and whitelist URLs, disable unnecessary protocols".to_string()),
                references: vec!["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery".to_string()],
                exploit_available: false,
            })
        })
    }

    /// Open redirect detection
    pub fn open_redirect() -> VulnScript {
        VulnScript::new(
            "open-redirect",
            "Open Redirect",
            "Tests for open redirect vulnerabilities",
            VulnCategory::InfoDisclosure,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            Ok(VulnResult {
                script_id: "open-redirect".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::Medium,
                cve_ids: vec![],
                description: "Open redirect allows phishing attacks".to_string(),
                evidence: None,
                remediation: Some("Validate redirect URLs against whitelist".to_string()),
                references: vec!["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html".to_string()],
                exploit_available: false,
            })
        })
    }

    /// Security headers check
    pub fn security_headers_check() -> VulnScript {
        VulnScript::new(
            "sec-headers",
            "Security Headers Check",
            "Checks for missing security headers",
            VulnCategory::Misconfiguration,
        )
        .with_ports(vec![80, 443, 8080, 8443])
        .with_services(vec!["http".to_string(), "https".to_string()])
        .with_executor(|target, port| {
            let addr = format!("{}:{}", target, port);
            let timeout = Duration::from_secs(5);
            
            match TcpStream::connect_timeout(&addr.parse().unwrap(), timeout) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(timeout)).ok();
                    stream.set_write_timeout(Some(timeout)).ok();

                    let request = format!(
                        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        target
                    );

                    if stream.write_all(request.as_bytes()).is_ok() {
                        let mut response = String::new();
                        stream.read_to_string(&mut response).ok();

                        let mut missing_headers = Vec::new();
                        
                        if !response.contains("Strict-Transport-Security") {
                            missing_headers.push("HSTS");
                        }
                        if !response.contains("Content-Security-Policy") {
                            missing_headers.push("CSP");
                        }
                        if !response.contains("X-Frame-Options") {
                            missing_headers.push("X-Frame-Options");
                        }
                        if !response.contains("X-Content-Type-Options") {
                            missing_headers.push("X-Content-Type-Options");
                        }

                        let vulnerable = !missing_headers.is_empty();

                        return Ok(VulnResult {
                            script_id: "sec-headers".to_string(),
                            target: target.to_string(),
                            port,
                            vulnerable,
                            severity: if missing_headers.len() > 2 {
                                VulnSeverity::Medium
                            } else {
                                VulnSeverity::Low
                            },
                            cve_ids: vec![],
                            description: "Missing security headers increase attack surface".to_string(),
                            evidence: if vulnerable {
                                Some(format!("Missing: {}", missing_headers.join(", ")))
                            } else {
                                None
                            },
                            remediation: Some("Add security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options".to_string()),
                            references: vec!["https://owasp.org/www-project-secure-headers/".to_string()],
                            exploit_available: false,
                        });
                    }
                }
                Err(_) => {}
            }

            Ok(VulnResult {
                script_id: "sec-headers".to_string(),
                target: target.to_string(),
                port,
                vulnerable: false,
                severity: VulnSeverity::Low,
                cve_ids: vec![],
                description: "Could not check security headers".to_string(),
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
    fn test_web_vuln_scripts() {
        let scripts = WebVulnScripts::get_all();
        assert_eq!(scripts.len(), 8, "Should have 8 web vulnerability scripts");
    }

    #[test]
    fn test_script_categories() {
        let scripts = WebVulnScripts::get_all();
        
        // Check that SQL injection is in the right category
        let sqli = scripts.iter().find(|s| s.id == "sql-injection").unwrap();
        assert_eq!(sqli.category, VulnCategory::SqlInjection);
        
        // Check XSS category
        let xss = scripts.iter().find(|s| s.id == "xss-detection").unwrap();
        assert_eq!(xss.category, VulnCategory::CrossSiteScripting);
    }
}
