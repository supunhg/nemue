// Executive summary report - focused high-level overview for leadership
use crate::reporting::{ScanReport, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveReport {
    pub title: String,
    pub overall_status: RiskLevel,
    pub risk_score: f64,
    pub compliance_score: f64,
    pub key_findings: Vec<KeyFinding>,
    pub risk_breakdown: RiskBreakdown,
    pub top_recommendations: Vec<String>,
    pub trend_summary: Option<String>,
    pub business_impact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFinding {
    pub severity: Severity,
    pub title: String,
    pub affected_count: usize,
    pub business_risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskBreakdown {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub total_hosts_scanned: usize,
    pub hosts_with_critical: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Acceptable,
}

impl ExecutiveReport {
    pub fn from_scan_report(report: &ScanReport) -> Self {
        let overall_status = Self::determine_risk_level(report.executive_summary.risk_score);

        let mut key_findings: Vec<KeyFinding> = report
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
            .map(|f| KeyFinding {
                severity: f.severity,
                title: f.title.clone(),
                affected_count: f.affected_hosts.len(),
                business_risk: Self::assess_business_risk(&f.severity, f.cvss_score),
            })
            .collect();
        key_findings.sort_by(|a, b| b.severity_order().cmp(&a.severity_order()));

        let top_recommendations: Vec<String> = report
            .recommendations
            .iter()
            .filter(|r| {
                matches!(
                    r.priority,
                    crate::reporting::Priority::Critical | crate::reporting::Priority::High
                )
            })
            .take(5)
            .map(|r| format!("[{:?}] {}", r.priority, r.title))
            .collect();

        let vuln = &report.executive_summary.vulnerabilities;
        let business_impact = Self::generate_business_impact(report);

        Self {
            title: format!("Executive Security Summary - {}", report.metadata.report_id),
            overall_status,
            risk_score: report.executive_summary.risk_score,
            compliance_score: report.executive_summary.compliance_score,
            key_findings,
            risk_breakdown: RiskBreakdown {
                critical: vuln.critical,
                high: vuln.high,
                medium: vuln.medium,
                low: vuln.low,
                total_hosts_scanned: report.executive_summary.total_hosts,
                hosts_with_critical: Self::count_hosts_with_critical(report),
            },
            top_recommendations,
            trend_summary: None,
            business_impact,
        }
    }

    fn determine_risk_level(score: f64) -> RiskLevel {
        if score >= 9.0 {
            RiskLevel::Critical
        } else if score >= 7.0 {
            RiskLevel::High
        } else if score >= 4.0 {
            RiskLevel::Medium
        } else if score >= 1.0 {
            RiskLevel::Low
        } else {
            RiskLevel::Acceptable
        }
    }

    fn assess_business_risk(severity: &Severity, cvss: Option<f64>) -> String {
        match severity {
            Severity::Critical => {
                let score = cvss.unwrap_or(9.0);
                if score >= 9.5 {
                    "Immediate action required - active exploitation risk".to_string()
                } else {
                    "Urgent remediation needed within 24-48 hours".to_string()
                }
            }
            Severity::High => "Remediation required within 1-2 weeks".to_string(),
            Severity::Medium => "Schedule remediation within 30 days".to_string(),
            Severity::Low => "Address during regular maintenance window".to_string(),
            Severity::Info => "Informational - no immediate action needed".to_string(),
        }
    }

    fn count_hosts_with_critical(report: &ScanReport) -> usize {
        let mut hosts: std::collections::HashSet<String> = std::collections::HashSet::new();
        for finding in &report.findings {
            if matches!(finding.severity, Severity::Critical) {
                for host in &finding.affected_hosts {
                    hosts.insert(host.clone());
                }
            }
        }
        hosts.len()
    }

    fn generate_business_impact(report: &ScanReport) -> String {
        let vuln = &report.executive_summary.vulnerabilities;
        let risk = report.executive_summary.risk_score;

        let mut impact = String::new();

        if vuln.critical > 0 {
            impact.push_str(&format!("CRITICAL: {} critical vulnerabilities pose immediate risk of data breach or system compromise. ", vuln.critical));
        }
        if vuln.high > 0 {
            impact.push_str(&format!(
                "{} high-severity issues could lead to unauthorized access. ",
                vuln.high
            ));
        }
        if risk >= 7.0 {
            impact.push_str("Overall risk posture is HIGH - executive attention recommended. ");
        }
        if report.compliance.overall_score < 70.0 {
            impact.push_str(&format!(
                "Compliance at {:.0}% may impact regulatory standing. ",
                report.compliance.overall_score
            ));
        }
        if impact.is_empty() {
            impact = "Security posture is within acceptable parameters. Continue monitoring."
                .to_string();
        }
        impact
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str("╔══════════════════════════════════════════════════════════════╗\n");
        output.push_str("║              EXECUTIVE SECURITY SUMMARY                     ║\n");
        output.push_str("╚══════════════════════════════════════════════════════════════╝\n\n");

        output.push_str(&format!("Overall Status: {:?}\n", self.overall_status));
        output.push_str(&format!("Risk Score:     {:.1}/10\n", self.risk_score));
        output.push_str(&format!(
            "Compliance:     {:.1}%\n\n",
            self.compliance_score
        ));

        output.push_str("RISK BREAKDOWN\n");
        output.push_str("──────────────\n");
        output.push_str(&format!(
            "  Critical:  {:>3}    Hosts Scanned:    {}\n",
            self.risk_breakdown.critical, self.risk_breakdown.total_hosts_scanned
        ));
        output.push_str(&format!(
            "  High:      {:>3}    Hosts w/Critical: {}\n",
            self.risk_breakdown.high, self.risk_breakdown.hosts_with_critical
        ));
        output.push_str(&format!("  Medium:    {:>3}\n", self.risk_breakdown.medium));
        output.push_str(&format!("  Low:       {:>3}\n\n", self.risk_breakdown.low));

        if !self.key_findings.is_empty() {
            output.push_str("KEY FINDINGS\n");
            output.push_str("────────────\n");
            for (i, finding) in self.key_findings.iter().enumerate() {
                output.push_str(&format!(
                    "  {}. [{:?}] {} ({} hosts)\n",
                    i + 1,
                    finding.severity,
                    finding.title,
                    finding.affected_count
                ));
                output.push_str(&format!("     Business Risk: {}\n", finding.business_risk));
            }
            output.push('\n');
        }

        if !self.top_recommendations.is_empty() {
            output.push_str("TOP RECOMMENDATIONS\n");
            output.push_str("───────────────────\n");
            for (i, rec) in self.top_recommendations.iter().enumerate() {
                output.push_str(&format!("  {}. {}\n", i + 1, rec));
            }
            output.push('\n');
        }

        output.push_str("BUSINESS IMPACT\n");
        output.push_str("───────────────\n");
        output.push_str(&format!("{}\n\n", self.business_impact));

        if let Some(trend) = &self.trend_summary {
            output.push_str("TREND\n");
            output.push_str("─────\n");
            output.push_str(&format!("{}\n\n", trend));
        }

        output.push_str("────────────────────────────────────────────────────────────\n");
        output.push_str("Generated by Nemue Security Scanner\n");
        output
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl KeyFinding {
    fn severity_order(&self) -> u8 {
        match self.severity {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::*;
    use chrono::Utc;

    fn sample_report() -> ScanReport {
        ReportBuilder::new()
            .metadata(ReportMetadata {
                scan_id: "scan-001".to_string(),
                report_id: "report-001".to_string(),
                generated_at: Utc::now(),
                scan_start: Utc::now(),
                scan_end: Utc::now(),
                target_count: 10,
                version: "0.1.0".to_string(),
            })
            .summary(ExecutiveSummary {
                total_hosts: 10,
                hosts_up: 8,
                total_ports: 1000,
                open_ports: 45,
                vulnerabilities: VulnerabilitySummary {
                    critical: 2,
                    high: 5,
                    medium: 10,
                    low: 8,
                    info: 3,
                },
                risk_score: 7.5,
                compliance_score: 75.0,
            })
            .compliance(ComplianceStatus {
                frameworks: vec![],
                overall_score: 75.0,
            })
            .add_finding(Finding {
                id: "f-001".to_string(),
                severity: Severity::Critical,
                title: "SQL Injection".to_string(),
                description: "SQL injection in login".to_string(),
                affected_hosts: vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()],
                cvss_score: Some(9.8),
                cve_ids: vec!["CVE-2021-1234".to_string()],
                remediation: "Fix it".to_string(),
            })
            .add_finding(Finding {
                id: "f-002".to_string(),
                severity: Severity::High,
                title: "XSS Vulnerability".to_string(),
                description: "Reflected XSS".to_string(),
                affected_hosts: vec!["192.168.1.1".to_string()],
                cvss_score: Some(7.5),
                cve_ids: vec![],
                remediation: "Sanitize inputs".to_string(),
            })
            .add_recommendation(Recommendation {
                priority: Priority::Critical,
                category: "App".to_string(),
                title: "Fix SQL Injection".to_string(),
                description: "Fix it".to_string(),
                impact: "Critical".to_string(),
                effort: "Medium".to_string(),
            })
            .build()
            .unwrap()
    }

    #[test]
    fn test_executive_report_from_scan_report() {
        let report = sample_report();
        let exec = ExecutiveReport::from_scan_report(&report);

        assert_eq!(exec.overall_status, RiskLevel::High);
        assert_eq!(exec.risk_score, 7.5);
        assert_eq!(exec.compliance_score, 75.0);
        assert!(!exec.key_findings.is_empty());
    }

    #[test]
    fn test_risk_level_determination() {
        assert_eq!(
            ExecutiveReport::determine_risk_level(9.5),
            RiskLevel::Critical
        );
        assert_eq!(ExecutiveReport::determine_risk_level(7.0), RiskLevel::High);
        assert_eq!(
            ExecutiveReport::determine_risk_level(4.0),
            RiskLevel::Medium
        );
        assert_eq!(ExecutiveReport::determine_risk_level(1.0), RiskLevel::Low);
        assert_eq!(
            ExecutiveReport::determine_risk_level(0.5),
            RiskLevel::Acceptable
        );
    }

    #[test]
    fn test_key_findings_sorted() {
        let report = sample_report();
        let exec = ExecutiveReport::from_scan_report(&report);

        assert_eq!(exec.key_findings.len(), 2);
        assert_eq!(exec.key_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_business_risk_assessment() {
        let risk = ExecutiveReport::assess_business_risk(&Severity::Critical, Some(9.8));
        assert!(risk.contains("Immediate"));

        let risk = ExecutiveReport::assess_business_risk(&Severity::High, None);
        assert!(risk.contains("1-2 weeks"));
    }

    #[test]
    fn test_hosts_with_critical() {
        let report = sample_report();
        let count = ExecutiveReport::count_hosts_with_critical(&report);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_business_impact_generation() {
        let report = sample_report();
        let impact = ExecutiveReport::generate_business_impact(&report);
        assert!(impact.contains("CRITICAL"));
        assert!(impact.contains("HIGH"));
    }

    #[test]
    fn test_to_text() {
        let report = sample_report();
        let exec = ExecutiveReport::from_scan_report(&report);
        let text = exec.to_text();

        assert!(text.contains("EXECUTIVE SECURITY SUMMARY"));
        assert!(text.contains("Risk Score"));
        assert!(text.contains("KEY FINDINGS"));
        assert!(text.contains("TOP RECOMMENDATIONS"));
        assert!(text.contains("BUSINESS IMPACT"));
    }

    #[test]
    fn test_to_json() {
        let report = sample_report();
        let exec = ExecutiveReport::from_scan_report(&report);
        let json = exec.to_json().unwrap();

        assert!(json.contains("overall_status"));
        assert!(json.contains("key_findings"));
    }

    #[test]
    fn test_top_recommendations() {
        let report = sample_report();
        let exec = ExecutiveReport::from_scan_report(&report);
        assert!(!exec.top_recommendations.is_empty());
        assert!(exec.top_recommendations[0].contains("Fix SQL Injection"));
    }

    #[test]
    fn test_risk_breakdown() {
        let report = sample_report();
        let exec = ExecutiveReport::from_scan_report(&report);

        assert_eq!(exec.risk_breakdown.critical, 2);
        assert_eq!(exec.risk_breakdown.high, 5);
        assert_eq!(exec.risk_breakdown.total_hosts_scanned, 10);
        assert_eq!(exec.risk_breakdown.hosts_with_critical, 2);
    }

    #[test]
    fn test_acceptable_risk() {
        let report = ReportBuilder::new()
            .metadata(ReportMetadata {
                scan_id: "s".to_string(),
                report_id: "r".to_string(),
                generated_at: Utc::now(),
                scan_start: Utc::now(),
                scan_end: Utc::now(),
                target_count: 5,
                version: "0.1.0".to_string(),
            })
            .summary(ExecutiveSummary {
                total_hosts: 5,
                hosts_up: 5,
                total_ports: 500,
                open_ports: 10,
                vulnerabilities: VulnerabilitySummary {
                    critical: 0,
                    high: 0,
                    medium: 1,
                    low: 2,
                    info: 0,
                },
                risk_score: 0.5,
                compliance_score: 98.0,
            })
            .compliance(ComplianceStatus {
                frameworks: vec![],
                overall_score: 98.0,
            })
            .build()
            .unwrap();

        let exec = ExecutiveReport::from_scan_report(&report);
        assert_eq!(exec.overall_status, RiskLevel::Acceptable);
        assert!(exec.business_impact.contains("acceptable"));
    }
}
