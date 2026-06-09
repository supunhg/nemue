use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// IP reputation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputation {
    /// IP address
    pub ip: String,
    /// Reputation score (0-100, higher = more malicious)
    pub score: u8,
    /// Threat categories
    pub categories: Vec<String>,
    /// Number of reports
    pub report_count: u32,
    /// Last reported timestamp
    pub last_reported: Option<String>,
    /// Confidence level (0-100)
    pub confidence: u8,
    /// Country code
    pub country: Option<String>,
    /// ASN information
    pub asn: Option<String>,
}

/// Domain reputation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainReputation {
    /// Domain name
    pub domain: String,
    /// Reputation score (0-100, higher = more malicious)
    pub score: u8,
    /// Threat categories
    pub categories: Vec<String>,
    /// Domain age in days
    pub age_days: Option<u32>,
    /// Whether domain is parked
    pub is_parked: bool,
    /// Whether domain uses privacy protection
    pub has_privacy: bool,
    /// Confidence level (0-100)
    pub confidence: u8,
}

/// Service risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRisk {
    /// Service name
    pub service: String,
    /// Risk score (0-100)
    pub risk_score: u8,
    /// Risk factors
    pub risk_factors: Vec<RiskFactor>,
    /// Recommended actions
    pub recommendations: Vec<String>,
    /// Whether service is known to be vulnerable
    pub known_vulnerable: bool,
    /// Common attack vectors
    pub attack_vectors: Vec<String>,
}

/// Risk factor for a service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Factor name
    pub name: String,
    /// Impact score (0-100)
    pub impact: u8,
    /// Likelihood score (0-100)
    pub likelihood: u8,
    /// Description
    pub description: String,
}

/// Vulnerability prioritization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnPriority {
    /// CVE identifier
    pub cve_id: String,
    /// Priority score (0-100)
    pub priority_score: u8,
    /// CVSS score
    pub cvss_score: Option<f32>,
    /// Whether exploit is available
    pub exploit_available: bool,
    /// Whether vulnerability is actively exploited
    pub actively_exploited: bool,
    /// Affected assets count
    pub affected_assets: u32,
    /// Recommended remediation
    pub remediation: String,
    /// Time to remediate (hours)
    pub estimated_remediation_hours: u32,
}

/// ML-based threat scorer
pub struct MlThreatScorer {
    /// Known malicious IP ranges (simplified)
    ip_threat_db: HashMap<String, u8>,
    /// Known malicious domains
    domain_threat_db: HashMap<String, u8>,
    /// Service risk profiles
    service_risk_profiles: HashMap<String, ServiceRiskProfile>,
    /// CVE priority cache
    cve_priority_cache: HashMap<String, VulnPriority>,
}

#[derive(Debug, Clone)]
struct ServiceRiskProfile {
    base_risk: u8,
    common_attacks: Vec<String>,
    recommendations: Vec<String>,
}

impl MlThreatScorer {
    /// Create a new threat scorer with default profiles
    pub fn new() -> Self {
        let mut service_risk_profiles = HashMap::new();

        // SSH risk profile
        service_risk_profiles.insert("ssh".to_string(), ServiceRiskProfile {
            base_risk: 30,
            common_attacks: vec![
                "Brute force".to_string(),
                "Key-based authentication bypass".to_string(),
                "Version-specific exploits".to_string(),
            ],
            recommendations: vec![
                "Use key-based authentication".to_string(),
                "Disable root login".to_string(),
                "Use non-standard port".to_string(),
            ],
        });

        // HTTP/HTTPS risk profile
        service_risk_profiles.insert("http".to_string(), ServiceRiskProfile {
            base_risk: 50,
            common_attacks: vec![
                "SQL injection".to_string(),
                "XSS".to_string(),
                "CSRF".to_string(),
                "Directory traversal".to_string(),
            ],
            recommendations: vec![
                "Use HTTPS only".to_string(),
                "Implement WAF".to_string(),
                "Regular security audits".to_string(),
            ],
        });

        // FTP risk profile
        service_risk_profiles.insert("ftp".to_string(), ServiceRiskProfile {
            base_risk: 70,
            common_attacks: vec![
                "Anonymous access".to_string(),
                "Brute force".to_string(),
                "Directory traversal".to_string(),
            ],
            recommendations: vec![
                "Use SFTP instead".to_string(),
                "Disable anonymous access".to_string(),
                "Restrict access by IP".to_string(),
            ],
        });

        // Telnet risk profile
        service_risk_profiles.insert("telnet".to_string(), ServiceRiskProfile {
            base_risk: 90,
            common_attacks: vec![
                "Cleartext credentials".to_string(),
                "Session hijacking".to_string(),
                "Man-in-the-middle".to_string(),
            ],
            recommendations: vec![
                "Replace with SSH immediately".to_string(),
                "Disable Telnet service".to_string(),
            ],
        });

        // RDP risk profile
        service_risk_profiles.insert("rdp".to_string(), ServiceRiskProfile {
            base_risk: 65,
            common_attacks: vec![
                "BlueKeep (CVE-2019-0708)".to_string(),
                "Brute force".to_string(),
                "Session hijacking".to_string(),
            ],
            recommendations: vec![
                "Use NLA (Network Level Authentication)".to_string(),
                "Restrict access by IP".to_string(),
                "Use VPN for remote access".to_string(),
            ],
        });

        // SMB risk profile
        service_risk_profiles.insert("smb".to_string(), ServiceRiskProfile {
            base_risk: 75,
            common_attacks: vec![
                "EternalBlue".to_string(),
                "Pass-the-hash".to_string(),
                "SMB signing bypass".to_string(),
            ],
            recommendations: vec![
                "Disable SMBv1".to_string(),
                "Enable SMB signing".to_string(),
                "Restrict access by firewall".to_string(),
            ],
        });

        // MySQL risk profile
        service_risk_profiles.insert("mysql".to_string(), ServiceRiskProfile {
            base_risk: 55,
            common_attacks: vec![
                "SQL injection".to_string(),
                "Brute force".to_string(),
                "UDF exploitation".to_string(),
            ],
            recommendations: vec![
                "Restrict network access".to_string(),
                "Use strong passwords".to_string(),
                "Regular updates".to_string(),
            ],
        });

        // Redis risk profile
        service_risk_profiles.insert("redis".to_string(), ServiceRiskProfile {
            base_risk: 80,
            common_attacks: vec![
                "Unauthorized access".to_string(),
                "RCE via EVAL".to_string(),
                "Data exfiltration".to_string(),
            ],
            recommendations: vec![
                "Enable authentication".to_string(),
                "Bind to localhost only".to_string(),
                "Disable dangerous commands".to_string(),
            ],
        });

        Self {
            ip_threat_db: HashMap::new(),
            domain_threat_db: HashMap::new(),
            service_risk_profiles,
            cve_priority_cache: HashMap::new(),
        }
    }

    /// Score an IP address for threats
    pub fn score_ip(&self, ip: &str) -> IpReputation {
        // Check if IP is in threat database
        let score = self.ip_threat_db.get(ip).copied().unwrap_or(0);

        // Determine categories based on score
        let categories = if score > 80 {
            vec!["malware".to_string(), "botnet".to_string()]
        } else if score > 50 {
            vec!["suspicious".to_string()]
        } else {
            vec![]
        };

        IpReputation {
            ip: ip.to_string(),
            score,
            categories,
            report_count: if score > 0 { 1 } else { 0 },
            last_reported: None,
            confidence: if score > 0 { 75 } else { 50 },
            country: None,
            asn: None,
        }
    }

    /// Score a domain for threats
    pub fn score_domain(&self, domain: &str) -> DomainReputation {
        // Check if domain is in threat database
        let score = self.domain_threat_db.get(domain).copied().unwrap_or(0);

        // Determine categories based on score
        let categories = if score > 80 {
            vec!["phishing".to_string(), "malware".to_string()]
        } else if score > 50 {
            vec!["suspicious".to_string()]
        } else {
            vec![]
        };

        DomainReputation {
            domain: domain.to_string(),
            score,
            categories,
            age_days: None,
            is_parked: false,
            has_privacy: false,
            confidence: if score > 0 { 70 } else { 50 },
        }
    }

    /// Assess risk for a service
    pub fn assess_service_risk(&self, service: &str, version: Option<&str>) -> ServiceRisk {
        let service_lower = service.to_lowercase();

        // Get base risk profile
        let profile = self.service_risk_profiles.get(&service_lower);

        let (base_risk, attack_vectors, recommendations) = if let Some(p) = profile {
            (p.base_risk, p.common_attacks.clone(), p.recommendations.clone())
        } else {
            // Default risk for unknown services
            (40, vec!["Unknown service - potential attack surface".to_string()], vec![
                "Research service security".to_string(),
                "Restrict network access".to_string(),
            ])
        };

        // Adjust risk based on version if provided
        let mut risk_score = base_risk;
        let mut risk_factors = Vec::new();

        if let Some(ver) = version {
            // Older versions typically have higher risk
            if ver.contains("1.0") || ver.contains("2.0") || ver.starts_with("0.") {
                risk_score = (risk_score + 20).min(100);
                risk_factors.push(RiskFactor {
                    name: "Outdated version".to_string(),
                    impact: 70,
                    likelihood: 80,
                    description: format!("Version {} may have known vulnerabilities", ver),
                });
            }
        }

        // Add base risk factor
        risk_factors.push(RiskFactor {
            name: "Service exposure".to_string(),
            impact: base_risk,
            likelihood: 60,
            description: format!("{} service exposed to network", service),
        });

        ServiceRisk {
            service: service.to_string(),
            risk_score,
            risk_factors,
            recommendations,
            known_vulnerable: risk_score > 60,
            attack_vectors,
        }
    }

    /// Prioritize vulnerabilities
    pub fn prioritize_vulnerabilities(&self, vulns: &[VulnInput]) -> Vec<VulnPriority> {
        let mut priorities: Vec<VulnPriority> = vulns
            .iter()
            .map(|v| {
                let mut priority_score = 50u8;

                // Factor in CVSS score
                if let Some(cvss) = v.cvss_score {
                    priority_score = (cvss * 10.0) as u8;
                }

                // Factor in exploit availability
                if v.exploit_available {
                    priority_score = (priority_score + 20).min(100);
                }

                // Factor in active exploitation
                if v.actively_exploited {
                    priority_score = (priority_score + 30).min(100);
                }

                // Factor in affected assets
                if v.affected_assets > 100 {
                    priority_score = (priority_score + 15).min(100);
                } else if v.affected_assets > 10 {
                    priority_score = (priority_score + 10).min(100);
                }

                VulnPriority {
                    cve_id: v.cve_id.clone(),
                    priority_score,
                    cvss_score: v.cvss_score,
                    exploit_available: v.exploit_available,
                    actively_exploited: v.actively_exploited,
                    affected_assets: v.affected_assets,
                    remediation: self.generate_remediation(v),
                    estimated_remediation_hours: self.estimate_remediation_time(v),
                }
            })
            .collect();

        // Sort by priority score (highest first)
        priorities.sort_by(|a, b| b.priority_score.cmp(&a.priority_score));

        priorities
    }

    /// Generate remediation advice
    fn generate_remediation(&self, vuln: &VulnInput) -> String {
        if vuln.actively_exploited {
            "URGENT: Patch immediately. Vulnerability is being actively exploited in the wild.".to_string()
        } else if vuln.exploit_available {
            "HIGH: Patch as soon as possible. Public exploit is available.".to_string()
        } else if vuln.cvss_score.map_or(false, |s| s >= 7.0) {
            "MEDIUM: Schedule patching within next maintenance window.".to_string()
        } else {
            "LOW: Include in regular patching cycle.".to_string()
        }
    }

    /// Estimate remediation time in hours
    fn estimate_remediation_time(&self, vuln: &VulnInput) -> u32 {
        if vuln.actively_exploited {
            4 // Urgent - 4 hours
        } else if vuln.exploit_available {
            24 // High priority - 24 hours
        } else if vuln.cvss_score.map_or(false, |s| s >= 7.0) {
            72 // Medium priority - 72 hours
        } else {
            168 // Low priority - 1 week
        }
    }

    /// Add known malicious IP to database
    pub fn add_malicious_ip(&mut self, ip: &str, score: u8) {
        self.ip_threat_db.insert(ip.to_string(), score);
    }

    /// Add known malicious domain to database
    pub fn add_malicious_domain(&mut self, domain: &str, score: u8) {
        self.domain_threat_db.insert(domain.to_string(), score);
    }
}

/// Input for vulnerability prioritization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnInput {
    /// CVE identifier
    pub cve_id: String,
    /// CVSS score (0.0 - 10.0)
    pub cvss_score: Option<f32>,
    /// Whether exploit is available
    pub exploit_available: bool,
    /// Whether vulnerability is actively exploited
    pub actively_exploited: bool,
    /// Number of affected assets
    pub affected_assets: u32,
    /// Vulnerability description
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_reputation_clean() {
        let scorer = MlThreatScorer::new();
        let rep = scorer.score_ip("192.168.1.1");

        assert_eq!(rep.score, 0);
        assert!(rep.categories.is_empty());
    }

    #[test]
    fn test_ip_reputation_malicious() {
        let mut scorer = MlThreatScorer::new();
        scorer.add_malicious_ip("10.0.0.1", 85);

        let rep = scorer.score_ip("10.0.0.1");
        assert_eq!(rep.score, 85);
        assert!(rep.categories.contains(&"malware".to_string()));
    }

    #[test]
    fn test_domain_reputation_clean() {
        let scorer = MlThreatScorer::new();
        let rep = scorer.score_domain("example.com");

        assert_eq!(rep.score, 0);
        assert!(rep.categories.is_empty());
    }

    #[test]
    fn test_domain_reputation_malicious() {
        let mut scorer = MlThreatScorer::new();
        scorer.add_malicious_domain("evil.com", 90);

        let rep = scorer.score_domain("evil.com");
        assert_eq!(rep.score, 90);
        assert!(rep.categories.contains(&"phishing".to_string()));
    }

    #[test]
    fn test_service_risk_ssh() {
        let scorer = MlThreatScorer::new();
        let risk = scorer.assess_service_risk("ssh", None);

        assert_eq!(risk.service, "ssh");
        assert_eq!(risk.risk_score, 30);
        assert!(!risk.attack_vectors.is_empty());
    }

    #[test]
    fn test_service_risk_telnet() {
        let scorer = MlThreatScorer::new();
        let risk = scorer.assess_service_risk("telnet", None);

        assert_eq!(risk.risk_score, 90);
        assert!(risk.known_vulnerable);
    }

    #[test]
    fn test_service_risk_with_old_version() {
        let scorer = MlThreatScorer::new();
        let risk = scorer.assess_service_risk("http", Some("1.0"));

        assert!(risk.risk_score > 50); // Base 50 + 20 for old version
    }

    #[test]
    fn test_vulnerability_prioritization() {
        let scorer = MlThreatScorer::new();
        let vulns = vec![
            VulnInput {
                cve_id: "CVE-2024-0001".to_string(),
                cvss_score: Some(5.0),
                exploit_available: false,
                actively_exploited: false,
                affected_assets: 5,
                description: "Low severity".to_string(),
            },
            VulnInput {
                cve_id: "CVE-2024-0002".to_string(),
                cvss_score: Some(9.0),
                exploit_available: true,
                actively_exploited: true,
                affected_assets: 100,
                description: "Critical severity".to_string(),
            },
        ];

        let priorities = scorer.prioritize_vulnerabilities(&vulns);

        // Critical vulnerability should be first
        assert_eq!(priorities[0].cve_id, "CVE-2024-0002");
        assert!(priorities[0].priority_score > priorities[1].priority_score);
    }

    #[test]
    fn test_remediation_time_estimates() {
        let scorer = MlThreatScorer::new();

        let urgent = VulnInput {
            cve_id: "CVE-2024-0001".to_string(),
            cvss_score: Some(9.0),
            exploit_available: true,
            actively_exploited: true,
            affected_assets: 100,
            description: "Critical".to_string(),
        };

        let low = VulnInput {
            cve_id: "CVE-2024-0002".to_string(),
            cvss_score: Some(3.0),
            exploit_available: false,
            actively_exploited: false,
            affected_assets: 1,
            description: "Low".to_string(),
        };

        let priorities = scorer.prioritize_vulnerabilities(&[urgent, low]);
        assert!(priorities[0].estimated_remediation_hours < priorities[1].estimated_remediation_hours);
    }
}
