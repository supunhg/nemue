use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Entity extracted from text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    /// Entity type (ip, domain, port, service, version, etc.)
    pub entity_type: String,
    /// Entity value
    pub value: String,
    /// Start position in text
    pub start: usize,
    /// End position in text
    pub end: usize,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
}

/// Service classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceClassification {
    /// Service name
    pub service: String,
    /// Service category
    pub category: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Subcategories
    pub subcategories: Vec<String>,
    /// Risk level
    pub risk_level: String,
}

/// NLP-generated report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NlpReport {
    /// Report title
    pub title: String,
    /// Executive summary
    pub summary: String,
    /// Key findings
    pub findings: Vec<String>,
    /// Recommendations
    pub recommendations: Vec<String>,
    /// Risk assessment
    pub risk_assessment: String,
    /// Detailed sections
    pub sections: Vec<ReportSection>,
}

/// Report section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSection {
    /// Section title
    pub title: String,
    /// Section content
    pub content: String,
    /// Section severity
    pub severity: String,
}

/// NLP engine for processing scan results
pub struct NlpEngine {
    /// Service patterns for classification
    service_patterns: HashMap<String, ServicePattern>,
    /// Entity patterns
    entity_patterns: Vec<EntityPattern>,
    /// Report templates
    report_templates: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct ServicePattern {
    keywords: Vec<String>,
    category: String,
    risk_level: String,
    subcategories: Vec<String>,
}

#[derive(Debug, Clone)]
struct EntityPattern {
    pattern: String,
    entity_type: String,
    confidence_base: f64,
}

impl NlpEngine {
    /// Create a new NLP engine
    pub fn new() -> Self {
        let mut service_patterns = HashMap::new();

        // Web server patterns
        service_patterns.insert(
            "web".to_string(),
            ServicePattern {
                keywords: vec![
                    "http".to_string(),
                    "https".to_string(),
                    "apache".to_string(),
                    "nginx".to_string(),
                    "iis".to_string(),
                    "web server".to_string(),
                ],
                category: "Web Server".to_string(),
                risk_level: "Medium".to_string(),
                subcategories: vec!["HTTP".to_string(), "HTTPS".to_string()],
            },
        );

        // Database patterns
        service_patterns.insert(
            "database".to_string(),
            ServicePattern {
                keywords: vec![
                    "mysql".to_string(),
                    "postgresql".to_string(),
                    "mongodb".to_string(),
                    "redis".to_string(),
                    "mssql".to_string(),
                    "oracle".to_string(),
                    "database".to_string(),
                ],
                category: "Database".to_string(),
                risk_level: "High".to_string(),
                subcategories: vec![
                    "SQL".to_string(),
                    "NoSQL".to_string(),
                    "Key-Value".to_string(),
                ],
            },
        );

        // Remote access patterns
        service_patterns.insert(
            "remote_access".to_string(),
            ServicePattern {
                keywords: vec![
                    "ssh".to_string(),
                    "rdp".to_string(),
                    "telnet".to_string(),
                    "vnc".to_string(),
                    "remote".to_string(),
                ],
                category: "Remote Access".to_string(),
                risk_level: "High".to_string(),
                subcategories: vec![
                    "Encrypted".to_string(),
                    "Cleartext".to_string(),
                ],
            },
        );

        // Email patterns
        service_patterns.insert(
            "email".to_string(),
            ServicePattern {
                keywords: vec![
                    "smtp".to_string(),
                    "imap".to_string(),
                    "pop3".to_string(),
                    "mail".to_string(),
                    "exchange".to_string(),
                ],
                category: "Email".to_string(),
                risk_level: "Medium".to_string(),
                subcategories: vec![
                    "SMTP".to_string(),
                    "IMAP".to_string(),
                    "POP3".to_string(),
                ],
            },
        );

        // File transfer patterns
        service_patterns.insert(
            "file_transfer".to_string(),
            ServicePattern {
                keywords: vec![
                    "ftp".to_string(),
                    "sftp".to_string(),
                    "smb".to_string(),
                    "cifs".to_string(),
                    "nfs".to_string(),
                    "file".to_string(),
                ],
                category: "File Transfer".to_string(),
                risk_level: "Medium".to_string(),
                subcategories: vec![
                    "FTP".to_string(),
                    "SMB".to_string(),
                    "NFS".to_string(),
                ],
            },
        );

        // DNS patterns
        service_patterns.insert(
            "dns".to_string(),
            ServicePattern {
                keywords: vec!["dns".to_string(), "domain".to_string(), "named".to_string()],
                category: "DNS".to_string(),
                risk_level: "Low".to_string(),
                subcategories: vec!["Authoritative".to_string(), "Recursive".to_string()],
            },
        );

        let entity_patterns = vec![
            EntityPattern {
                pattern: r"\b(?:\d{1,3}\.){3}\d{1,3}\b".to_string(),
                entity_type: "ip".to_string(),
                confidence_base: 0.95,
            },
            EntityPattern {
                pattern: r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b".to_string(),
                entity_type: "domain".to_string(),
                confidence_base: 0.8,
            },
            EntityPattern {
                pattern: r"\b(?:port|Port)\s+(\d+)\b".to_string(),
                entity_type: "port".to_string(),
                confidence_base: 0.9,
            },
            EntityPattern {
                pattern: r"\b(?:version|v)\s*[\d.]+\b".to_string(),
                entity_type: "version".to_string(),
                confidence_base: 0.85,
            },
            EntityPattern {
                pattern: r"\bCVE-\d{4}-\d{4,}\b".to_string(),
                entity_type: "cve".to_string(),
                confidence_base: 0.98,
            },
        ];

        let mut report_templates = HashMap::new();
        report_templates.insert(
            "executive_summary".to_string(),
            "Security scan identified {total_findings} findings across {total_hosts} hosts. \
             {critical_count} critical, {high_count} high, {medium_count} medium, and \
             {low_count} low severity issues were detected."
                .to_string(),
        );
        report_templates.insert(
            "risk_assessment".to_string(),
            "Overall risk level: {risk_level}. {risk_description}".to_string(),
        );

        Self {
            service_patterns,
            entity_patterns,
            report_templates,
        }
    }

    /// Parse scan results and extract entities
    pub fn extract_entities(&self, text: &str) -> Vec<Entity> {
        let mut entities = Vec::new();

        // Extract IPs using regex-like pattern matching
        let chars = text.chars().collect::<Vec<char>>();
        let mut i = 0;
        while i < chars.len() {
            if chars[i].is_ascii_digit() {
                let mut j = i;
                let mut dots = 0;
                while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '.') {
                    if chars[j] == '.' {
                        dots += 1;
                    }
                    j += 1;
                }
                if dots == 3 {
                    let ip_str: String = chars[i..j].iter().collect();
                    let parts: Vec<&str> = ip_str.split('.').collect();
                    if parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                        entities.push(Entity {
                            entity_type: "ip".to_string(),
                            value: ip_str,
                            start: i,
                            end: j,
                            confidence: 0.95,
                        });
                    }
                }
                i = j;
            } else {
                i += 1;
            }
        }

        // Extract ports
        for (idx, matched) in text.match_indices("port ") {
            let after = &text[idx + matched.len()..];
            if let Some(port_str) = after.split_whitespace().next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    entities.push(Entity {
                        entity_type: "port".to_string(),
                        value: port.to_string(),
                        start: idx,
                        end: idx + matched.len() + port_str.len(),
                        confidence: 0.9,
                    });
                }
            }
        }

        // Extract CVEs
        for (idx, _matched) in text.match_indices("CVE-") {
            let after = &text[idx..];
            let end = after
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                .unwrap_or(after.len());
            if end > 8 {
                entities.push(Entity {
                    entity_type: "cve".to_string(),
                    value: after[..end].to_string(),
                    start: idx,
                    end: idx + end,
                    confidence: 0.98,
                });
            }
        }

        // Extract domains
        let domain_chars: Vec<char> = text.chars().collect();
        let mut i = 0;
        while i < domain_chars.len() {
            if domain_chars[i].is_ascii_alphanumeric() {
                let mut j = i;
                let mut has_dot = false;
                while j < domain_chars.len()
                    && (domain_chars[j].is_ascii_alphanumeric()
                        || domain_chars[j] == '.'
                        || domain_chars[j] == '-')
                {
                    if domain_chars[j] == '.' {
                        has_dot = true;
                    }
                    j += 1;
                }
                if has_dot && j - i > 3 {
                    let domain: String = domain_chars[i..j].iter().collect();
                    if !domain.starts_with('.') && !domain.ends_with('.') {
                        entities.push(Entity {
                            entity_type: "domain".to_string(),
                            value: domain,
                            start: i,
                            end: j,
                            confidence: 0.8,
                        });
                    }
                }
                i = j;
            } else {
                i += 1;
            }
        }

        entities
    }

    /// Generate a natural language report from scan findings
    pub fn generate_report(
        &self,
        title: &str,
        hosts_scanned: usize,
        findings: &[Finding],
    ) -> NlpReport {
        let total_findings = findings.len();
        let critical_count = findings
            .iter()
            .filter(|f| f.severity == "Critical")
            .count();
        let high_count = findings
            .iter()
            .filter(|f| f.severity == "High")
            .count();
        let medium_count = findings
            .iter()
            .filter(|f| f.severity == "Medium")
            .count();
        let low_count = findings
            .iter()
            .filter(|f| f.severity == "Low")
            .count();

        let risk_level = if critical_count > 0 {
            "Critical"
        } else if high_count > 0 {
            "High"
        } else if medium_count > 0 {
            "Medium"
        } else {
            "Low"
        };

        let summary = format!(
            "Security scan identified {} findings across {} hosts. {} critical, {} high, {} medium, and {} low severity issues were detected.",
            total_findings, hosts_scanned, critical_count, high_count, medium_count, low_count
        );

        let risk_assessment = format!(
            "Overall risk level: {}. {}",
            risk_level,
            match risk_level {
                "Critical" => "Immediate action required to address critical vulnerabilities.",
                "High" => "Urgent remediation needed for high-severity issues.",
                "Medium" => "Schedule remediation for medium-severity findings.",
                _ => "Low-risk findings can be addressed in regular maintenance.",
            }
        );

        let mut key_findings = Vec::new();
        for finding in findings.iter().take(5) {
            key_findings.push(format!(
                "{}: {} ({})",
                finding.severity, finding.title, finding.target
            ));
        }

        let mut recommendations = Vec::new();
        if critical_count > 0 {
            recommendations
                .push("Address critical vulnerabilities immediately.".to_string());
        }
        if high_count > 0 {
            recommendations.push("Schedule urgent remediation for high-severity issues.".to_string());
        }
        recommendations.push("Implement regular security scanning schedule.".to_string());
        recommendations.push("Review and update security policies.".to_string());

        let sections = vec![
            ReportSection {
                title: "Findings Summary".to_string(),
                content: format!(
                    "Total: {} | Critical: {} | High: {} | Medium: {} | Low: {}",
                    total_findings, critical_count, high_count, medium_count, low_count
                ),
                severity: risk_level.to_string(),
            },
            ReportSection {
                title: "Affected Hosts".to_string(),
                content: format!("{} hosts were scanned", hosts_scanned),
                severity: "Info".to_string(),
            },
        ];

        NlpReport {
            title: title.to_string(),
            summary,
            findings: key_findings,
            recommendations,
            risk_assessment,
            sections,
        }
    }

    /// Extract service information from banner
    pub fn extract_service_from_banner(&self, banner: &str) -> Option<ServiceClassification> {
        let banner_lower = banner.to_lowercase();

        for (_key, pattern) in &self.service_patterns {
            for keyword in &pattern.keywords {
                if banner_lower.contains(&keyword.to_lowercase()) {
                    return Some(ServiceClassification {
                        service: keyword.clone(),
                        category: pattern.category.clone(),
                        confidence: 0.8,
                        subcategories: pattern.subcategories.clone(),
                        risk_level: pattern.risk_level.clone(),
                    });
                }
            }
        }

        None
    }

    /// Classify a service based on name and port
    pub fn classify_service(&self, service: &str, port: u16) -> ServiceClassification {
        let service_lower = service.to_lowercase();

        // Check known patterns
        for (_, pattern) in &self.service_patterns {
            for keyword in &pattern.keywords {
                if service_lower.contains(&keyword.to_lowercase()) {
                    return ServiceClassification {
                        service: service.to_string(),
                        category: pattern.category.clone(),
                        confidence: 0.9,
                        subcategories: pattern.subcategories.clone(),
                        risk_level: pattern.risk_level.clone(),
                    };
                }
            }
        }

        // Default classification based on port
        let (category, risk_level) = match port {
            80 | 443 | 8080 | 8443 => ("Web Server", "Medium"),
            22 => ("Remote Access", "High"),
            21 => ("File Transfer", "Medium"),
            25 | 587 => ("Email", "Medium"),
            53 => ("DNS", "Low"),
            3306 | 5432 | 27017 => ("Database", "High"),
            3389 => ("Remote Access", "High"),
            _ => ("Unknown", "Medium"),
        };

        ServiceClassification {
            service: service.to_string(),
            category: category.to_string(),
            confidence: 0.6,
            subcategories: vec![],
            risk_level: risk_level.to_string(),
        }
    }
}

/// Finding for report generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Finding title
    pub title: String,
    /// Target host/service
    pub target: String,
    /// Severity level
    pub severity: String,
    /// Description
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_entities_ips() {
        let engine = NlpEngine::new();
        let text = "Host 192.168.1.1 has port 80 open";
        let entities = engine.extract_entities(text);

        assert!(entities.iter().any(|e| e.entity_type == "ip" && e.value == "192.168.1.1"));
    }

    #[test]
    fn test_extract_entities_ports() {
        let engine = NlpEngine::new();
        let text = "Found port 443 open on host";
        let entities = engine.extract_entities(text);

        assert!(entities.iter().any(|e| e.entity_type == "port" && e.value == "443"));
    }

    #[test]
    fn test_extract_entities_cves() {
        let engine = NlpEngine::new();
        let text = "Vulnerability CVE-2024-12345 found";
        let entities = engine.extract_entities(text);

        assert!(entities.iter().any(|e| e.entity_type == "cve" && e.value == "CVE-2024-12345"));
    }

    #[test]
    fn test_generate_report() {
        let engine = NlpEngine::new();
        let findings = vec![
            Finding {
                title: "SQL Injection".to_string(),
                target: "192.168.1.1:80".to_string(),
                severity: "Critical".to_string(),
                description: "SQL injection vulnerability".to_string(),
            },
            Finding {
                title: "Weak SSH Key".to_string(),
                target: "192.168.1.2:22".to_string(),
                severity: "High".to_string(),
                description: "Weak SSH key detected".to_string(),
            },
        ];

        let report = engine.generate_report("Security Scan Report", 10, &findings);

        assert_eq!(report.title, "Security Scan Report");
        assert!(report.summary.contains("2 findings"));
        assert!(report.summary.contains("10 hosts"));
        assert!(report.risk_assessment.contains("Critical"));
    }

    #[test]
    fn test_extract_service_from_banner() {
        let engine = NlpEngine::new();

        let classification = engine.extract_service_from_banner("Apache/2.4.54 (Ubuntu)");
        assert!(classification.is_some());
        let c = classification.unwrap();
        assert_eq!(c.category, "Web Server");
    }

    #[test]
    fn test_extract_service_from_banner_database() {
        let engine = NlpEngine::new();

        let classification = engine.extract_service_from_banner("MySQL 8.0.31");
        assert!(classification.is_some());
        let c = classification.unwrap();
        assert_eq!(c.category, "Database");
    }

    #[test]
    fn test_classify_service_ssh() {
        let engine = NlpEngine::new();
        let classification = engine.classify_service("ssh", 22);

        assert_eq!(classification.category, "Remote Access");
        assert_eq!(classification.risk_level, "High");
    }

    #[test]
    fn test_classify_service_http() {
        let engine = NlpEngine::new();
        let classification = engine.classify_service("http", 80);

        assert_eq!(classification.category, "Web Server");
        assert_eq!(classification.risk_level, "Medium");
    }

    #[test]
    fn test_classify_service_unknown() {
        let engine = NlpEngine::new();
        let classification = engine.classify_service("custom", 9999);

        assert_eq!(classification.category, "Unknown");
    }

    #[test]
    fn test_report_risk_levels() {
        let engine = NlpEngine::new();

        // Critical
        let findings = vec![Finding {
            title: "Test".to_string(),
            target: "host".to_string(),
            severity: "Critical".to_string(),
            description: "desc".to_string(),
        }];
        let report = engine.generate_report("Test", 1, &findings);
        assert!(report.risk_assessment.contains("Critical"));

        // Low
        let findings = vec![Finding {
            title: "Test".to_string(),
            target: "host".to_string(),
            severity: "Low".to_string(),
            description: "desc".to_string(),
        }];
        let report = engine.generate_report("Test", 1, &findings);
        assert!(report.risk_assessment.contains("Low"));
    }
}
