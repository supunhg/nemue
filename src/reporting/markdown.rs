// Markdown report generation
use crate::reporting::{ScanReport, Severity, Priority};

pub struct MarkdownReportGenerator;

impl MarkdownReportGenerator {
    pub fn generate(report: &ScanReport) -> String {
        let mut md = String::new();

        md.push_str(&Self::header(report));
        md.push_str(&Self::executive_summary(report));
        md.push_str(&Self::vulnerability_summary(report));
        md.push_str(&Self::findings(report));
        md.push_str(&Self::compliance(report));
        md.push_str(&Self::recommendations(report));
        md.push_str(&Self::footer());

        md
    }

    fn header(report: &ScanReport) -> String {
        format!(
            "# Security Scan Report\n\n\
             | Field | Value |\n\
             |-------|-------|\n\
             | Report ID | `{}` |\n\
             | Scan ID | `{}` |\n\
             | Generated | {} |\n\
             | Scan Period | {} to {} |\n\
             | Targets | {} |\n\n",
            report.metadata.report_id,
            report.metadata.scan_id,
            report.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            report.metadata.scan_start.format("%Y-%m-%d %H:%M"),
            report.metadata.scan_end.format("%Y-%m-%d %H:%M"),
            report.metadata.target_count
        )
    }

    fn executive_summary(report: &ScanReport) -> String {
        let s = &report.executive_summary;
        format!(
            "## Executive Summary\n\n\
             | Metric | Value |\n\
             |--------|-------|\n\
             | Total Hosts | {} |\n\
             | Hosts Up | {} |\n\
             | Open Ports | {}/{} |\n\
             | Risk Score | {:.1}/10 |\n\
             | Compliance Score | {:.1}% |\n\n",
            s.total_hosts, s.hosts_up, s.open_ports, s.total_ports,
            s.risk_score, s.compliance_score
        )
    }

    fn vulnerability_summary(report: &ScanReport) -> String {
        let v = &report.executive_summary.vulnerabilities;
        let total = v.critical + v.high + v.medium + v.low + v.info;
        format!(
            "## Vulnerability Summary\n\n\
             **Total Vulnerabilities:** {}\n\n\
             | Severity | Count | Percentage |\n\
             |----------|-------|------------|\n\
             | {} Critical | {} | {:.1}% |\n\
             | {} High | {} | {:.1}% |\n\
             | {} Medium | {} | {:.1}% |\n\
             | {} Low | {} | {:.1}% |\n\
             | {} Info | {} | {:.1}% |\n\n",
            total,
            Self::severity_icon(&Severity::Critical), v.critical, Self::pct(v.critical, total),
            Self::severity_icon(&Severity::High), v.high, Self::pct(v.high, total),
            Self::severity_icon(&Severity::Medium), v.medium, Self::pct(v.medium, total),
            Self::severity_icon(&Severity::Low), v.low, Self::pct(v.low, total),
            Self::severity_icon(&Severity::Info), v.info, Self::pct(v.info, total),
        )
    }

    fn findings(report: &ScanReport) -> String {
        if report.findings.is_empty() {
            return "## Findings\n\nNo findings to report.\n\n".to_string();
        }

        let mut md = String::from("## Findings\n\n");
        md.push_str("| # | Severity | Title | Hosts | CVSS | CVE IDs |\n");
        md.push_str("|---|----------|-------|-------|------|--------|\n");

        for (i, finding) in report.findings.iter().enumerate() {
            let icon = Self::severity_icon(&finding.severity);
            let cvss = finding.cvss_score.map_or("-".to_string(), |s| format!("{:.1}", s));
            let cves = if finding.cve_ids.is_empty() { "-".to_string() } else { finding.cve_ids.join(", ") };
            md.push_str(&format!(
                "| {} | {} {:?} | {} | {} | {} | {} |\n",
                i + 1, icon, finding.severity, finding.title,
                finding.affected_hosts.len(), cvss, cves
            ));
        }

        md.push_str("\n### Detailed Findings\n\n");
        for (i, finding) in report.findings.iter().enumerate() {
            let icon = Self::severity_icon(&finding.severity);
            md.push_str(&format!("#### {}. {} {} {:?}\n\n", i + 1, icon, finding.title, finding.severity));
            md.push_str(&format!("**Description:** {}\n\n", finding.description));
            md.push_str(&format!("**Affected Hosts:** {}\n\n", finding.affected_hosts.join(", ")));
            if let Some(cvss) = finding.cvss_score {
                md.push_str(&format!("**CVSS Score:** {:.1}\n\n", cvss));
            }
            if !finding.cve_ids.is_empty() {
                md.push_str(&format!("**CVE IDs:** {}\n\n", finding.cve_ids.join(", ")));
            }
            md.push_str(&format!("**Remediation:** {}\n\n", finding.remediation));
            md.push_str("---\n\n");
        }

        md
    }

    fn compliance(report: &ScanReport) -> String {
        let mut md = format!(
            "## Compliance Status\n\n\
             **Overall Score:** {:.1}%\n\n",
            report.compliance.overall_score
        );

        if !report.compliance.frameworks.is_empty() {
            md.push_str("| Framework | Version | Passing | Failing | Score |\n");
            md.push_str("|-----------|---------|---------|---------|-------|\n");
            for fw in &report.compliance.frameworks {
                md.push_str(&format!(
                    "| {} | {} | {} | {} | {:.1}% |\n",
                    fw.name, fw.version, fw.controls_passing, fw.controls_failing, fw.score
                ));
            }
            md.push('\n');
        }

        md
    }

    fn recommendations(report: &ScanReport) -> String {
        if report.recommendations.is_empty() {
            return String::new();
        }

        let mut md = String::from("## Recommendations\n\n");
        md.push_str("| Priority | Category | Title | Impact | Effort |\n");
        md.push_str("|----------|----------|-------|--------|--------|\n");

        for rec in &report.recommendations {
            let icon = Self::priority_icon(&rec.priority);
            md.push_str(&format!(
                "| {} {:?} | {} | {} | {} | {} |\n",
                icon, rec.priority, rec.category, rec.title, rec.impact, rec.effort
            ));
        }

        md.push('\n');
        md
    }

    fn footer() -> String {
        "\n---\n\n*Generated by Nemue Security Scanner v0.1.0*\n".to_string()
    }

    fn severity_icon(severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical => "[CRIT]",
            Severity::High => "[HIGH]",
            Severity::Medium => "[MED]",
            Severity::Low => "[LOW]",
            Severity::Info => "[INFO]",
        }
    }

    fn priority_icon(priority: &Priority) -> &'static str {
        match priority {
            Priority::Critical => "[!]",
            Priority::High => "[!]",
            Priority::Medium => "[-]",
            Priority::Low => "[~]",
        }
    }

    fn pct(value: usize, total: usize) -> f64 {
        if total == 0 { 0.0 } else { value as f64 / total as f64 * 100.0 }
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
                frameworks: vec![ComplianceFramework {
                    name: "PCI-DSS".to_string(),
                    version: "4.0".to_string(),
                    controls_total: 10,
                    controls_passing: 8,
                    controls_failing: 2,
                    score: 80.0,
                    findings: vec![],
                }],
                overall_score: 80.0,
            })
            .add_finding(Finding {
                id: "f-001".to_string(),
                severity: Severity::Critical,
                title: "SQL Injection".to_string(),
                description: "SQL injection in login".to_string(),
                affected_hosts: vec!["192.168.1.1".to_string()],
                cvss_score: Some(9.8),
                cve_ids: vec!["CVE-2021-1234".to_string()],
                remediation: "Use parameterized queries".to_string(),
            })
            .add_recommendation(Recommendation {
                priority: Priority::Critical,
                category: "App".to_string(),
                title: "Fix SQLi".to_string(),
                description: "Fix it".to_string(),
                impact: "High".to_string(),
                effort: "Medium".to_string(),
            })
            .build()
            .unwrap()
    }

    #[test]
    fn test_markdown_generation() {
        let report = sample_report();
        let md = MarkdownReportGenerator::generate(&report);
        assert!(md.starts_with("# Security Scan Report"));
        assert!(md.contains("report-001"));
    }

    #[test]
    fn test_markdown_executive_summary() {
        let report = sample_report();
        let md = MarkdownReportGenerator::generate(&report);
        assert!(md.contains("## Executive Summary"));
        assert!(md.contains("Total Hosts"));
        assert!(md.contains("7.5"));
    }

    #[test]
    fn test_markdown_vulnerability_summary() {
        let report = sample_report();
        let md = MarkdownReportGenerator::generate(&report);
        assert!(md.contains("## Vulnerability Summary"));
        assert!(md.contains("[CRIT]"));
        assert!(md.contains("[HIGH]"));
    }

    #[test]
    fn test_markdown_findings() {
        let report = sample_report();
        let md = MarkdownReportGenerator::generate(&report);
        assert!(md.contains("## Findings"));
        assert!(md.contains("SQL Injection"));
        assert!(md.contains("9.8"));
        assert!(md.contains("CVE-2021-1234"));
        assert!(md.contains("parameterized queries"));
    }

    #[test]
    fn test_markdown_compliance() {
        let report = sample_report();
        let md = MarkdownReportGenerator::generate(&report);
        assert!(md.contains("## Compliance Status"));
        assert!(md.contains("PCI-DSS"));
        assert!(md.contains("80.0%"));
    }

    #[test]
    fn test_markdown_recommendations() {
        let report = sample_report();
        let md = MarkdownReportGenerator::generate(&report);
        assert!(md.contains("## Recommendations"));
        assert!(md.contains("Fix SQLi"));
    }

    #[test]
    fn test_markdown_footer() {
        let report = sample_report();
        let md = MarkdownReportGenerator::generate(&report);
        assert!(md.contains("Nemue Security Scanner"));
    }

    #[test]
    fn test_markdown_empty_findings() {
        let report = ReportBuilder::new()
            .metadata(ReportMetadata {
                scan_id: "s".to_string(), report_id: "r".to_string(),
                generated_at: Utc::now(), scan_start: Utc::now(), scan_end: Utc::now(),
                target_count: 0, version: "0.1.0".to_string(),
            })
            .summary(ExecutiveSummary {
                total_hosts: 0, hosts_up: 0, total_ports: 0, open_ports: 0,
                vulnerabilities: VulnerabilitySummary { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                risk_score: 0.0, compliance_score: 0.0,
            })
            .compliance(ComplianceStatus { frameworks: vec![], overall_score: 0.0 })
            .build()
            .unwrap();
        let md = MarkdownReportGenerator::generate(&report);
        assert!(md.contains("No findings to report"));
    }

    #[test]
    fn test_severity_icon() {
        assert_eq!(MarkdownReportGenerator::severity_icon(&Severity::Critical), "[CRIT]");
        assert_eq!(MarkdownReportGenerator::severity_icon(&Severity::Info), "[INFO]");
    }

    #[test]
    fn test_priority_icon() {
        assert_eq!(MarkdownReportGenerator::priority_icon(&Priority::Critical), "[!]");
        assert_eq!(MarkdownReportGenerator::priority_icon(&Priority::Low), "[~]");
    }

    #[test]
    fn test_pct() {
        assert_eq!(MarkdownReportGenerator::pct(50, 100), 50.0);
        assert_eq!(MarkdownReportGenerator::pct(0, 0), 0.0);
    }
}
