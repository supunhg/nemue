use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Report generator for scan results
pub struct ReportGenerator {
    template: ReportTemplate,
}

#[derive(Debug, Clone, Copy)]
pub enum ReportTemplate {
    Executive,  // High-level summary for management
    Technical,  // Detailed findings for security teams
    Compliance, // Compliance-focused (PCI-DSS, NIST, etc.)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub metadata: ReportMetadata,
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
    pub recommendations: Vec<Recommendation>,
    pub appendix: Option<Appendix>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub title: String,
    pub generated_at: DateTime<Utc>,
    pub scan_period: DateRange,
    pub targets: Vec<String>,
    pub scanner_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub targets_scanned: usize,
    pub total_ports_scanned: usize,
    pub open_ports_found: usize,
    pub services_identified: usize,
    pub vulnerabilities_found: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub overall_risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub description: String,
    pub affected_hosts: Vec<String>,
    pub affected_ports: Vec<u16>,
    pub cve_ids: Vec<String>,
    pub cvss_score: Option<f32>,
    pub remediation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: Priority,
    pub title: String,
    pub description: String,
    pub expected_impact: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    Immediate,
    Short,
    Medium,
    Long,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Appendix {
    pub methodology: String,
    pub tools_used: Vec<String>,
    pub scan_configuration: HashMap<String, String>,
}

impl ReportGenerator {
    pub fn new(template: ReportTemplate) -> Self {
        Self { template }
    }

    /// Generate a report from scan data
    pub fn generate(&self, report: &ScanReport) -> Result<String> {
        match self.template {
            ReportTemplate::Executive => self.generate_executive(report),
            ReportTemplate::Technical => self.generate_technical(report),
            ReportTemplate::Compliance => self.generate_compliance(report),
        }
    }

    /// Generate executive summary (Markdown)
    fn generate_executive(&self, report: &ScanReport) -> Result<String> {
        let mut output = String::new();

        // Title
        output.push_str(&format!("# {}\n\n", report.metadata.title));
        output.push_str(&format!(
            "**Generated:** {}\n\n",
            report.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Executive Summary
        output.push_str("## Executive Summary\n\n");
        output.push_str(&format!(
            "This security assessment scanned **{} target(s)** and identified **{} finding(s)** requiring attention.\n\n",
            report.summary.targets_scanned,
            report.findings.len()
        ));

        output.push_str(&format!(
            "**Overall Risk Score:** {}/100 ({})\n\n",
            report.summary.overall_risk_score,
            self.risk_rating(report.summary.overall_risk_score)
        ));

        // Risk Breakdown
        output.push_str("### Risk Breakdown\n\n");
        output.push_str("| Severity | Count |\n");
        output.push_str("|----------|-------|\n");
        output.push_str(&format!("| 🔴 Critical | {} |\n", report.summary.critical_findings));
        output.push_str(&format!("| 🟠 High | {} |\n", report.summary.high_findings));
        output.push_str(&format!("| 🟡 Medium | {} |\n", report.summary.medium_findings));
        output.push_str(&format!("| 🟢 Low | {} |\n\n", report.summary.low_findings));

        // Key Findings
        output.push_str("## Key Findings\n\n");
        for finding in report.findings.iter().take(5) {
            output.push_str(&format!("### {} {}\n\n", 
                self.severity_emoji(finding.severity),
                finding.title
            ));
            output.push_str(&format!("{}\n\n", finding.description));
            if !finding.affected_hosts.is_empty() {
                output.push_str(&format!("**Affected Hosts:** {}\n\n", 
                    finding.affected_hosts.join(", ")
                ));
            }
        }

        // Recommendations
        output.push_str("## Priority Recommendations\n\n");
        for (i, rec) in report.recommendations.iter().enumerate() {
            output.push_str(&format!("{}. **{}**\n", i + 1, rec.title));
            output.push_str(&format!("   - {}\n", rec.description));
            output.push_str(&format!("   - Expected Impact: {}\n\n", rec.expected_impact));
        }

        Ok(output)
    }

    /// Generate technical report (detailed Markdown)
    fn generate_technical(&self, report: &ScanReport) -> Result<String> {
        let mut output = String::new();

        // Title and metadata
        output.push_str(&format!("# {} - Technical Report\n\n", report.metadata.title));
        output.push_str(&format!(
            "**Scan Period:** {} to {}\n\n",
            report.metadata.scan_period.start.format("%Y-%m-%d %H:%M:%S"),
            report.metadata.scan_period.end.format("%Y-%m-%d %H:%M:%S")
        ));
        output.push_str(&format!("**Targets:** {}\n\n", report.metadata.targets.join(", ")));

        // Scan Statistics
        output.push_str("## Scan Statistics\n\n");
        output.push_str("| Metric | Value |\n");
        output.push_str("|--------|-------|\n");
        output.push_str(&format!("| Targets Scanned | {} |\n", report.summary.targets_scanned));
        output.push_str(&format!("| Ports Scanned | {} |\n", report.summary.total_ports_scanned));
        output.push_str(&format!("| Open Ports Found | {} |\n", report.summary.open_ports_found));
        output.push_str(&format!("| Services Identified | {} |\n", report.summary.services_identified));
        output.push_str(&format!("| Vulnerabilities Found | {} |\n\n", report.summary.vulnerabilities_found));

        // All Findings
        output.push_str("## Detailed Findings\n\n");
        for (i, finding) in report.findings.iter().enumerate() {
            output.push_str(&format!("### Finding #{}: {} {}\n\n", 
                i + 1,
                self.severity_emoji(finding.severity),
                finding.title
            ));
            
            output.push_str(&format!("**Severity:** {}\n\n", finding.severity.as_str()));
            output.push_str(&format!("**Category:** {}\n\n", finding.category));
            output.push_str(&format!("**Description:**\n{}\n\n", finding.description));
            
            if !finding.affected_hosts.is_empty() {
                output.push_str(&format!("**Affected Hosts:**\n"));
                for host in &finding.affected_hosts {
                    output.push_str(&format!("- {}\n", host));
                }
                output.push_str("\n");
            }
            
            if !finding.affected_ports.is_empty() {
                output.push_str(&format!("**Affected Ports:** {}\n\n", 
                    finding.affected_ports.iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            
            if !finding.cve_ids.is_empty() {
                output.push_str(&format!("**CVE IDs:** {}\n\n", finding.cve_ids.join(", ")));
            }
            
            if let Some(cvss) = finding.cvss_score {
                output.push_str(&format!("**CVSS Score:** {}\n\n", cvss));
            }
            
            output.push_str(&format!("**Remediation:**\n{}\n\n", finding.remediation));
            output.push_str("---\n\n");
        }

        // Recommendations
        output.push_str("## Remediation Roadmap\n\n");
        for rec in &report.recommendations {
            output.push_str(&format!("### {} - {}\n\n", 
                self.priority_label(rec.priority),
                rec.title
            ));
            output.push_str(&format!("{}\n\n", rec.description));
            output.push_str(&format!("**Expected Impact:** {}\n\n", rec.expected_impact));
        }

        // Appendix
        if let Some(appendix) = &report.appendix {
            output.push_str("## Appendix\n\n");
            output.push_str("### Methodology\n\n");
            output.push_str(&format!("{}\n\n", appendix.methodology));
            
            output.push_str("### Tools Used\n\n");
            for tool in &appendix.tools_used {
                output.push_str(&format!("- {}\n", tool));
            }
            output.push_str("\n");
            
            output.push_str("### Scan Configuration\n\n");
            output.push_str("| Parameter | Value |\n");
            output.push_str("|-----------|-------|\n");
            for (key, value) in &appendix.scan_configuration {
                output.push_str(&format!("| {} | {} |\n", key, value));
            }
        }

        Ok(output)
    }

    /// Generate compliance report
    fn generate_compliance(&self, report: &ScanReport) -> Result<String> {
        let mut output = String::new();

        output.push_str(&format!("# {} - Compliance Report\n\n", report.metadata.title));
        
        // Compliance Overview
        output.push_str("## Compliance Status\n\n");
        output.push_str("This report maps security findings to common compliance frameworks.\n\n");

        // Map findings to compliance requirements
        output.push_str("### PCI-DSS v4.0 Findings\n\n");
        for finding in &report.findings {
            if self.is_pci_relevant(finding) {
                output.push_str(&format!("- **Requirement 1.1:** {}\n", finding.title));
            }
        }
        output.push_str("\n");

        output.push_str("### NIST CSF Findings\n\n");
        for finding in &report.findings {
            output.push_str(&format!("- **Identify (ID.RA):** {}\n", finding.title));
        }
        output.push_str("\n");

        output.push_str("### CIS Controls\n\n");
        output.push_str("| Control | Status | Findings |\n");
        output.push_str("|---------|--------|----------|\n");
        output.push_str(&format!("| CIS Control 1 | ⚠️ Needs Attention | {} |\n", 
            report.summary.critical_findings + report.summary.high_findings
        ));

        Ok(output)
    }

    fn severity_emoji(&self, severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🟢",
            Severity::Info => "ℹ️",
        }
    }

    fn priority_label(&self, priority: Priority) -> &'static str {
        match priority {
            Priority::Immediate => "🚨 IMMEDIATE",
            Priority::Short => "⏰ SHORT-TERM (1-30 days)",
            Priority::Medium => "📅 MEDIUM-TERM (1-3 months)",
            Priority::Long => "📆 LONG-TERM (3+ months)",
        }
    }

    fn risk_rating(&self, score: u8) -> &'static str {
        match score {
            90..=100 => "CRITICAL",
            70..=89 => "HIGH",
            40..=69 => "MEDIUM",
            20..=39 => "LOW",
            _ => "MINIMAL",
        }
    }

    fn is_pci_relevant(&self, _finding: &Finding) -> bool {
        // In production, this would map findings to PCI-DSS requirements
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_report() -> ScanReport {
        ScanReport {
            metadata: ReportMetadata {
                title: "Security Assessment".to_string(),
                generated_at: Utc::now(),
                scan_period: DateRange {
                    start: Utc::now(),
                    end: Utc::now(),
                },
                targets: vec!["192.168.1.1".to_string()],
                scanner_version: "1.0.0".to_string(),
            },
            summary: ScanSummary {
                targets_scanned: 1,
                total_ports_scanned: 100,
                open_ports_found: 5,
                services_identified: 3,
                vulnerabilities_found: 2,
                critical_findings: 1,
                high_findings: 1,
                medium_findings: 0,
                low_findings: 0,
                overall_risk_score: 75,
            },
            findings: vec![
                Finding {
                    severity: Severity::Critical,
                    category: "Vulnerability".to_string(),
                    title: "Critical RCE Vulnerability".to_string(),
                    description: "Remote code execution found".to_string(),
                    affected_hosts: vec!["192.168.1.1".to_string()],
                    affected_ports: vec![22],
                    cve_ids: vec!["CVE-2021-12345".to_string()],
                    cvss_score: Some(9.8),
                    remediation: "Update to latest version".to_string(),
                },
            ],
            recommendations: vec![
                Recommendation {
                    priority: Priority::Immediate,
                    title: "Patch critical vulnerabilities".to_string(),
                    description: "Apply security updates immediately".to_string(),
                    expected_impact: "Eliminates critical risk".to_string(),
                },
            ],
            appendix: Some(Appendix {
                methodology: "Network scanning".to_string(),
                tools_used: vec!["Nemue".to_string()],
                scan_configuration: HashMap::new(),
            }),
        }
    }

    #[test]
    fn test_executive_report() {
        let generator = ReportGenerator::new(ReportTemplate::Executive);
        let report = create_test_report();
        
        let output = generator.generate(&report).unwrap();
        assert!(output.contains("Executive Summary"));
        assert!(output.contains("Critical RCE Vulnerability"));
    }

    #[test]
    fn test_technical_report() {
        let generator = ReportGenerator::new(ReportTemplate::Technical);
        let report = create_test_report();
        
        let output = generator.generate(&report).unwrap();
        assert!(output.contains("Technical Report"));
        assert!(output.contains("Detailed Findings"));
        assert!(output.contains("CVE-2021-12345"));
    }

    #[test]
    fn test_compliance_report() {
        let generator = ReportGenerator::new(ReportTemplate::Compliance);
        let report = create_test_report();
        
        let output = generator.generate(&report).unwrap();
        assert!(output.contains("Compliance"));
        assert!(output.contains("PCI-DSS"));
    }

    #[test]
    fn test_severity_levels() {
        assert_eq!(Severity::Critical.as_str(), "CRITICAL");
        assert_eq!(Severity::High.as_str(), "HIGH");
        assert_eq!(Severity::Medium.as_str(), "MEDIUM");
        assert_eq!(Severity::Low.as_str(), "LOW");
    }
}
