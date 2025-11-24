use crate::intel::cve::{CveInfo, CveSeverity};
use crate::intel::threat::{ThreatInfo, ThreatLevel};
use serde::{Deserialize, Serialize};

/// Overall risk assessment for a scanned target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub target: String,
    pub overall_score: u8, // 0-100
    pub risk_level: RiskLevel,
    pub findings: Vec<RiskFinding>,
    pub recommendations: Vec<String>,
}

/// Risk severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Critical => "CRITICAL",
            RiskLevel::High => "HIGH",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::Low => "LOW",
            RiskLevel::Info => "INFO",
        }
    }

    pub fn from_score(score: u8) -> Self {
        match score {
            s if s >= 90 => RiskLevel::Critical,
            s if s >= 70 => RiskLevel::High,
            s if s >= 40 => RiskLevel::Medium,
            s if s >= 20 => RiskLevel::Low,
            _ => RiskLevel::Info,
        }
    }
}

/// Individual risk finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFinding {
    pub category: RiskCategory,
    pub severity: RiskLevel,
    pub title: String,
    pub description: String,
    pub affected_ports: Vec<u16>,
    pub score: u8,
}

/// Categories of risk findings
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskCategory {
    Vulnerability,
    ThreatIntelligence,
    ServiceExposure,
    Configuration,
    Compliance,
}

/// Risk scoring engine
pub struct RiskEngine;

impl RiskEngine {
    pub fn new() -> Self {
        Self
    }

    /// Calculate comprehensive risk assessment
    pub fn assess_risk(
        &self,
        target: &str,
        open_ports: &[(u16, String)],
        vulnerabilities: &[CveInfo],
        threat_info: Option<&ThreatInfo>,
    ) -> RiskAssessment {
        let mut findings = Vec::new();
        let mut total_score = 0u8;

        // Assess vulnerabilities
        for vuln in vulnerabilities {
            let (score, finding) = self.assess_vulnerability(vuln);
            total_score = total_score.saturating_add(score);
            findings.push(finding);
        }

        // Assess threat intelligence
        if let Some(threat) = threat_info {
            let (score, finding) = self.assess_threat(threat);
            total_score = total_score.saturating_add(score);
            findings.push(finding);
        }

        // Assess service exposure
        let (score, exposure_findings) = self.assess_service_exposure(open_ports);
        total_score = total_score.saturating_add(score);
        findings.extend(exposure_findings);

        // Cap score at 100
        let overall_score = total_score.min(100);
        let risk_level = RiskLevel::from_score(overall_score);

        // Generate recommendations
        let recommendations = self.generate_recommendations(&findings);

        RiskAssessment {
            target: target.to_string(),
            overall_score,
            risk_level,
            findings,
            recommendations,
        }
    }

    /// Assess CVE vulnerability risk
    fn assess_vulnerability(&self, vuln: &CveInfo) -> (u8, RiskFinding) {
        let score = match vuln.severity {
            CveSeverity::Critical => 30,
            CveSeverity::High => 20,
            CveSeverity::Medium => 10,
            CveSeverity::Low => 5,
            CveSeverity::None => 0,
        };

        let severity = match vuln.severity {
            CveSeverity::Critical => RiskLevel::Critical,
            CveSeverity::High => RiskLevel::High,
            CveSeverity::Medium => RiskLevel::Medium,
            CveSeverity::Low => RiskLevel::Low,
            CveSeverity::None => RiskLevel::Info,
        };

        let finding = RiskFinding {
            category: RiskCategory::Vulnerability,
            severity,
            title: format!("{}: {}", vuln.cve_id, vuln.severity.as_str()),
            description: vuln.description.clone(),
            affected_ports: Vec::new(),
            score,
        };

        (score, finding)
    }

    /// Assess threat intelligence risk
    fn assess_threat(&self, threat: &ThreatInfo) -> (u8, RiskFinding) {
        let score = if threat.is_malicious {
            match threat.threat_level {
                ThreatLevel::Critical => 40,
                ThreatLevel::High => 25,
                ThreatLevel::Medium => 15,
                ThreatLevel::Low => 5,
                ThreatLevel::None => 0,
            }
        } else {
            0
        };

        let severity = match threat.threat_level {
            ThreatLevel::Critical => RiskLevel::Critical,
            ThreatLevel::High => RiskLevel::High,
            ThreatLevel::Medium => RiskLevel::Medium,
            ThreatLevel::Low => RiskLevel::Low,
            ThreatLevel::None => RiskLevel::Info,
        };

        let description = if threat.is_malicious {
            format!(
                "Target flagged as malicious. Categories: {}. Confidence: {}%",
                threat.categories.join(", "),
                threat.confidence_score
            )
        } else {
            "No threat intelligence findings".to_string()
        };

        let finding = RiskFinding {
            category: RiskCategory::ThreatIntelligence,
            severity,
            title: format!("Threat Level: {}", threat.threat_level.as_str()),
            description,
            affected_ports: Vec::new(),
            score,
        };

        (score, finding)
    }

    /// Assess service exposure risk
    fn assess_service_exposure(&self, open_ports: &[(u16, String)]) -> (u8, Vec<RiskFinding>) {
        let mut findings = Vec::new();
        let mut total_score = 0u8;

        // High-risk services
        let high_risk_ports: Vec<(u16, &str, &str)> = vec![
            (23, "Telnet", "Unencrypted remote access protocol"),
            (21, "FTP", "Unencrypted file transfer - consider SFTP/FTPS"),
            (445, "SMB", "High-value target for ransomware"),
            (3389, "RDP", "Common target for brute force attacks"),
            (1433, "MSSQL", "Database exposed to internet"),
            (3306, "MySQL", "Database exposed to internet"),
            (5432, "PostgreSQL", "Database exposed to internet"),
            (27017, "MongoDB", "NoSQL database exposed to internet"),
            (6379, "Redis", "In-memory database exposed to internet"),
        ];

        for (port, service) in open_ports {
            // Check against high-risk ports
            if let Some((_, svc_name, reason)) = high_risk_ports.iter().find(|(p, _, _)| p == port) {
                let score = 15u8;
                total_score = total_score.saturating_add(score);

                findings.push(RiskFinding {
                    category: RiskCategory::ServiceExposure,
                    severity: RiskLevel::High,
                    title: format!("High-risk service exposed: {} (port {})", svc_name, port),
                    description: reason.to_string(),
                    affected_ports: vec![*port],
                    score,
                });
            }

            // Check for administrative interfaces
            if *port == 8080 || *port == 8443 || *port == 9090 {
                let score = 10u8;
                total_score = total_score.saturating_add(score);

                findings.push(RiskFinding {
                    category: RiskCategory::ServiceExposure,
                    severity: RiskLevel::Medium,
                    title: format!("Administrative interface exposed on port {}", port),
                    description: "Management interfaces should not be exposed to the internet".to_string(),
                    affected_ports: vec![*port],
                    score,
                });
            }

            // Check for development services
            if *port == 3000 || *port == 4000 || *port == 5000 || *port == 8000 {
                let score = 8u8;
                total_score = total_score.saturating_add(score);

                findings.push(RiskFinding {
                    category: RiskCategory::ServiceExposure,
                    severity: RiskLevel::Medium,
                    title: format!("Potential development service on port {}", port),
                    description: "Development servers may have debug features enabled".to_string(),
                    affected_ports: vec![*port],
                    score,
                });
            }
        }

        // Too many open ports is suspicious
        if open_ports.len() > 20 {
            let score = 12u8;
            total_score = total_score.saturating_add(score);

            findings.push(RiskFinding {
                category: RiskCategory::Configuration,
                severity: RiskLevel::Medium,
                title: format!("{} ports open - excessive exposure", open_ports.len()),
                description: "Minimize attack surface by closing unnecessary ports".to_string(),
                affected_ports: Vec::new(),
                score,
            });
        }

        (total_score, findings)
    }

    /// Generate actionable recommendations
    fn generate_recommendations(&self, findings: &[RiskFinding]) -> Vec<String> {
        let mut recommendations = Vec::new();

        let critical_count = findings.iter().filter(|f| f.severity == RiskLevel::Critical).count();
        let high_count = findings.iter().filter(|f| f.severity == RiskLevel::High).count();

        if critical_count > 0 {
            recommendations.push(format!(
                "🚨 URGENT: {} critical vulnerabilities require immediate patching",
                critical_count
            ));
        }

        if high_count > 0 {
            recommendations.push(format!(
                "⚠️  {} high-severity findings should be addressed within 24-48 hours",
                high_count
            ));
        }

        // Check for specific vulnerability types
        if findings.iter().any(|f| matches!(f.category, RiskCategory::ThreatIntelligence)) {
            recommendations.push("🛡️  Consider blocking traffic from flagged threat IPs".to_string());
        }

        if findings.iter().any(|f| f.title.contains("Telnet") || f.title.contains("FTP")) {
            recommendations.push("🔐 Replace unencrypted protocols (Telnet, FTP) with secure alternatives (SSH, SFTP)".to_string());
        }

        if findings.iter().any(|f| f.title.contains("database")) {
            recommendations.push("🗄️  Restrict database access to internal networks only".to_string());
        }

        if findings.iter().any(|f| f.title.contains("Administrative")) {
            recommendations.push("🔧 Move administrative interfaces behind VPN or IP whitelist".to_string());
        }

        if recommendations.is_empty() {
            recommendations.push("✅ No critical issues detected - maintain current security posture".to_string());
        } else {
            recommendations.push("📊 Conduct regular vulnerability assessments to stay secure".to_string());
        }

        recommendations
    }

    /// Prioritize findings by severity and impact
    pub fn prioritize_findings(findings: &mut [RiskFinding]) {
        findings.sort_by(|a, b| {
            // First by severity
            let sev_cmp = b.score.cmp(&a.score);
            if sev_cmp != std::cmp::Ordering::Equal {
                return sev_cmp;
            }
            // Then by category (vulnerabilities first)
            match (&a.category, &b.category) {
                (RiskCategory::Vulnerability, _) => std::cmp::Ordering::Less,
                (_, RiskCategory::Vulnerability) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            }
        });
    }
}

impl Default for RiskEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(95), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(75), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(50), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(25), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(5), RiskLevel::Info);
    }

    #[test]
    fn test_service_exposure_assessment() {
        let engine = RiskEngine::new();
        let open_ports = vec![
            (23, "Telnet".to_string()),
            (445, "SMB".to_string()),
            (3389, "RDP".to_string()),
        ];

        let (score, findings) = engine.assess_service_exposure(&open_ports);
        assert!(score > 0);
        assert_eq!(findings.len(), 3); // All three are high-risk
        assert!(findings.iter().all(|f| f.severity == RiskLevel::High));
    }

    #[test]
    fn test_vulnerability_assessment() {
        let engine = RiskEngine::new();
        let vuln = CveInfo {
            cve_id: "CVE-2021-44228".to_string(),
            description: "Log4Shell RCE vulnerability".to_string(),
            severity: CveSeverity::Critical,
            cvss_score: 10.0,
            published_date: "2021-12-10".to_string(),
            references: vec![],
        };

        let (score, finding) = engine.assess_vulnerability(&vuln);
        assert_eq!(score, 30); // Critical = 30 points
        assert_eq!(finding.severity, RiskLevel::Critical);
    }

    #[test]
    fn test_threat_assessment() {
        let engine = RiskEngine::new();
        let threat = ThreatInfo {
            ip: "192.168.1.1".to_string(),
            is_malicious: true,
            threat_level: ThreatLevel::High,
            categories: vec!["C2".to_string()],
            last_seen: None,
            confidence_score: 85,
            sources: vec!["Test".to_string()],
        };

        let (score, finding) = engine.assess_threat(&threat);
        assert_eq!(score, 25); // High threat = 25 points
        assert_eq!(finding.severity, RiskLevel::High);
    }

    #[test]
    fn test_comprehensive_risk_assessment() {
        let engine = RiskEngine::new();
        let open_ports = vec![(23, "Telnet".to_string()), (80, "HTTP".to_string())];
        
        let vulnerabilities = vec![CveInfo {
            cve_id: "CVE-2021-44228".to_string(),
            description: "Critical RCE".to_string(),
            severity: CveSeverity::Critical,
            cvss_score: 10.0,
            published_date: "2021-12-10".to_string(),
            references: vec![],
        }];

        let threat = ThreatInfo {
            ip: "1.2.3.4".to_string(),
            is_malicious: true,
            threat_level: ThreatLevel::High,
            categories: vec!["Botnet".to_string()],
            last_seen: None,
            confidence_score: 90,
            sources: vec!["Test".to_string()],
        };

        let assessment = engine.assess_risk("1.2.3.4", &open_ports, &vulnerabilities, Some(&threat));
        
        assert!(assessment.overall_score > 50);
        assert_eq!(assessment.risk_level, RiskLevel::from_score(assessment.overall_score));
        assert!(!assessment.findings.is_empty());
        assert!(!assessment.recommendations.is_empty());
    }

    #[test]
    fn test_finding_prioritization() {
        let mut findings = vec![
            RiskFinding {
                category: RiskCategory::ServiceExposure,
                severity: RiskLevel::Medium,
                title: "Test 1".to_string(),
                description: "Test".to_string(),
                affected_ports: vec![],
                score: 10,
            },
            RiskFinding {
                category: RiskCategory::Vulnerability,
                severity: RiskLevel::Critical,
                title: "Test 2".to_string(),
                description: "Test".to_string(),
                affected_ports: vec![],
                score: 30,
            },
            RiskFinding {
                category: RiskCategory::ThreatIntelligence,
                severity: RiskLevel::High,
                title: "Test 3".to_string(),
                description: "Test".to_string(),
                affected_ports: vec![],
                score: 20,
            },
        ];

        RiskEngine::prioritize_findings(&mut findings);
        
        // Critical vulnerability should be first
        assert_eq!(findings[0].severity, RiskLevel::Critical);
        assert_eq!(findings[0].score, 30);
    }
}
