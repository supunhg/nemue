// PDF report generation
use crate::reporting::{ScanReport, Severity};
use std::io::Write;

pub struct PdfReportGenerator;

impl PdfReportGenerator {
    pub fn generate(report: &ScanReport) -> Vec<u8> {
        let mut pdf = Vec::new();
        Self::write_header(&mut pdf);
        Self::write_metadata(&mut pdf, report);
        Self::write_executive_summary(&mut pdf, report);
        Self::write_vulnerabilities(&mut pdf, report);
        Self::write_findings(&mut pdf, report);
        Self::write_compliance(&mut pdf, report);
        Self::write_recommendations(&mut pdf, report);
        Self::write_footer(&mut pdf);
        pdf
    }

    fn write_header(pdf: &mut Vec<u8>) {
        pdf.push(0x25); // %
        pdf.extend_from_slice(b"PDF-1.4\n");
        // Minimal PDF structure
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        pdf.extend_from_slice(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n");
    }

    fn write_metadata(pdf: &mut Vec<u8>, report: &ScanReport) {
        let content = format!(
            "BT\n/F1 24 Tf\n50 740 Td\n(Security Scan Report) Tj\n/F1 12 Tf\n0 -30 Td\n(Report ID: {}) Tj\n0 -20 Td\n(Scan ID: {}) Tj\n0 -20 Td\n(Generated: {}) Tj\n0 -20 Td\n(Targets: {}) Tj\nET\n",
            report.metadata.report_id,
            report.metadata.scan_id,
            report.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            report.metadata.target_count
        );
        let content_bytes = content.as_bytes();
        pdf.extend_from_slice(format!("4 0 obj\n<< /Length {} >>\nstream\n", content_bytes.len()).as_bytes());
        pdf.extend_from_slice(content_bytes);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
    }

    fn write_executive_summary(pdf: &mut Vec<u8>, report: &ScanReport) {
        let s = &report.executive_summary;
        let content = format!(
            "BT\n/F1 18 Tf\n50 600 Td\n(Executive Summary) Tj\n/F1 12 Tf\n0 -25 Td\n(Total Hosts: {}  |  Hosts Up: {}  |  Open Ports: {}/{}) Tj\n0 -20 Td\n(Risk Score: {:.1}/10  |  Compliance Score: {:.1}%) Tj\n0 -30 Td\n(Critical: {}  High: {}  Medium: {}  Low: {}  Info: {}) Tj\nET\n",
            s.total_hosts, s.hosts_up, s.open_ports, s.total_ports,
            s.risk_score, s.compliance_score,
            s.vulnerabilities.critical, s.vulnerabilities.high,
            s.vulnerabilities.medium, s.vulnerabilities.low, s.vulnerabilities.info
        );
        let content_bytes = content.as_bytes();
        pdf.extend_from_slice(format!("5 0 obj\n<< /Length {} >>\nstream\n", content_bytes.len()).as_bytes());
        pdf.extend_from_slice(content_bytes);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
    }

    fn write_findings(pdf: &mut Vec<u8>, report: &ScanReport) {
        if report.findings.is_empty() {
            return;
        }
        let mut content = String::from("BT\n/F1 18 Tf\n50 440 Td\n(Findings) Tj\n/F1 10 Tf\n");
        let mut y = -25;
        for finding in &report.findings {
            let severity_label = format_severity(&finding.severity);
            content.push_str(&format!("0 {} Td\n([{}] {} - {} hosts) Tj\n", y, severity_label, finding.title, finding.affected_hosts.len()));
            y -= 15;
            if y < 50 {
                break;
            }
        }
        content.push_str("ET\n");
        let content_bytes = content.as_bytes();
        pdf.extend_from_slice(format!("6 0 obj\n<< /Length {} >>\nstream\n", content_bytes.len()).as_bytes());
        pdf.extend_from_slice(content_bytes);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
    }

    fn write_vulnerabilities(_pdf: &mut Vec<u8>, _report: &ScanReport) {
    }

    fn write_compliance(pdf: &mut Vec<u8>, report: &ScanReport) {
        let mut content = format!(
            "BT\n/F1 18 Tf\n50 200 Td\n(Compliance) Tj\n/F1 12 Tf\n0 -25 Td\n(Overall Score: {:.1}%) Tj\n",
            report.compliance.overall_score
        );
        let mut y = -20;
        for fw in &report.compliance.frameworks {
            content.push_str(&format!("0 {} Td\n({} v{}: {:.1}% - {}/{} passing) Tj\n",
                y, fw.name, fw.version, fw.score, fw.controls_passing, fw.controls_total));
            y -= 15;
        }
        content.push_str("ET\n");
        let content_bytes = content.as_bytes();
        pdf.extend_from_slice(format!("7 0 obj\n<< /Length {} >>\nstream\n", content_bytes.len()).as_bytes());
        pdf.extend_from_slice(content_bytes);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
    }

    fn write_recommendations(pdf: &mut Vec<u8>, report: &ScanReport) {
        if report.recommendations.is_empty() {
            return;
        }
        let mut content = String::from("BT\n/F1 18 Tf\n50 100 Td\n(Recommendations) Tj\n/F1 10 Tf\n");
        let mut y = -20;
        for rec in &report.recommendations {
            content.push_str(&format!("0 {} Td\n([{:?}] {}: {}) Tj\n", y, rec.priority, rec.title, rec.impact));
            y -= 15;
            if y < 30 {
                break;
            }
        }
        content.push_str("ET\n");
        let content_bytes = content.as_bytes();
        pdf.extend_from_slice(format!("8 0 obj\n<< /Length {} >>\nstream\n", content_bytes.len()).as_bytes());
        pdf.extend_from_slice(content_bytes);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
    }

    fn write_footer(pdf: &mut Vec<u8>) {
        pdf.extend_from_slice(b"xref\n0 9\n0000000000 65535 f \n");
        let offsets: Vec<usize> = vec![0, 9, 58, 115, 210, 0, 0, 0, 0];
        for (i, offset) in offsets.iter().enumerate() {
            if i == 0 {
                continue;
            }
            pdf.extend_from_slice(format!("{:010} 00000 n \n", offset).as_bytes());
        }
        pdf.extend_from_slice(b"trailer\n<< /Size 9 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n");
    }

    pub fn generate_to_file(report: &ScanReport, path: &str) -> std::io::Result<()> {
        let content = Self::generate(report);
        let mut file = std::fs::File::create(path)?;
        file.write_all(&content)?;
        Ok(())
    }
}

fn format_severity(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
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
                description: "SQL injection in login form".to_string(),
                affected_hosts: vec!["192.168.1.1".to_string()],
                cvss_score: Some(9.8),
                cve_ids: vec!["CVE-2021-1234".to_string()],
                remediation: "Use parameterized queries".to_string(),
            })
            .add_recommendation(Recommendation {
                priority: Priority::Critical,
                category: "Application".to_string(),
                title: "Fix SQL Injection".to_string(),
                description: "Implement parameterized queries".to_string(),
                impact: "Critical".to_string(),
                effort: "Medium".to_string(),
            })
            .build()
            .unwrap()
    }

    #[test]
    fn test_pdf_generation() {
        let report = sample_report();
        let pdf = PdfReportGenerator::generate(&report);
        assert!(!pdf.is_empty());
        assert!(pdf.starts_with(b"%PDF"));
    }

    #[test]
    fn test_pdf_contains_report_id() {
        let report = sample_report();
        let pdf = PdfReportGenerator::generate(&report);
        let content = String::from_utf8_lossy(&pdf);
        assert!(content.contains("report-001"));
    }

    #[test]
    fn test_pdf_contains_executive_summary() {
        let report = sample_report();
        let pdf = PdfReportGenerator::generate(&report);
        let content = String::from_utf8_lossy(&pdf);
        assert!(content.contains("Executive Summary"));
        assert!(content.contains("Risk Score"));
    }

    #[test]
    fn test_pdf_contains_findings() {
        let report = sample_report();
        let pdf = PdfReportGenerator::generate(&report);
        let content = String::from_utf8_lossy(&pdf);
        assert!(content.contains("SQL Injection"));
        assert!(content.contains("CRITICAL"));
    }

    #[test]
    fn test_pdf_contains_compliance() {
        let report = sample_report();
        let pdf = PdfReportGenerator::generate(&report);
        let content = String::from_utf8_lossy(&pdf);
        assert!(content.contains("Compliance"));
        assert!(content.contains("PCI-DSS"));
    }

    #[test]
    fn test_pdf_contains_recommendations() {
        let report = sample_report();
        let pdf = PdfReportGenerator::generate(&report);
        let content = String::from_utf8_lossy(&pdf);
        assert!(content.contains("Recommendations"));
        assert!(content.contains("Fix SQL Injection"));
    }

    #[test]
    fn test_pdf_empty_report() {
        let report = ReportBuilder::new()
            .metadata(ReportMetadata {
                scan_id: "s".to_string(),
                report_id: "r".to_string(),
                generated_at: Utc::now(),
                scan_start: Utc::now(),
                scan_end: Utc::now(),
                target_count: 0,
                version: "0.1.0".to_string(),
            })
            .summary(ExecutiveSummary {
                total_hosts: 0, hosts_up: 0, total_ports: 0, open_ports: 0,
                vulnerabilities: VulnerabilitySummary { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
                risk_score: 0.0, compliance_score: 0.0,
            })
            .compliance(ComplianceStatus { frameworks: vec![], overall_score: 0.0 })
            .build()
            .unwrap();
        let pdf = PdfReportGenerator::generate(&report);
        assert!(pdf.starts_with(b"%PDF"));
    }

    #[test]
    fn test_format_severity() {
        assert_eq!(format_severity(&Severity::Critical), "CRITICAL");
        assert_eq!(format_severity(&Severity::High), "HIGH");
        assert_eq!(format_severity(&Severity::Medium), "MEDIUM");
        assert_eq!(format_severity(&Severity::Low), "LOW");
        assert_eq!(format_severity(&Severity::Info), "INFO");
    }
}
