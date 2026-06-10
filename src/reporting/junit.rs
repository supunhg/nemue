// JUnit XML report generation for CI/CD integration
use crate::reporting::{ScanReport, Severity};

pub struct JunitReportGenerator;

impl JunitReportGenerator {
    pub fn generate(report: &ScanReport) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str(&Self::testsuites(report));
        xml
    }

    fn testsuites(report: &ScanReport) -> String {
        let vuln = &report.executive_summary.vulnerabilities;
        let total_tests = vuln.critical + vuln.high + vuln.medium + vuln.low + vuln.info;
        let failures = vuln.critical + vuln.high + vuln.medium;
        let skipped = vuln.info;

        let mut xml = format!(
            "<testsuites name=\"Nemue Security Scan\" tests=\"{}\" failures=\"{}\" skipped=\"{}\" time=\"{}\">\n",
            total_tests,
            failures,
            skipped,
            Self::scan_duration_secs(report),
        );

        xml.push_str(&Self::vulnerability_testsuite(report));
        xml.push_str(&Self::finding_tests(report));
        xml.push_str(&Self::compliance_testsuite(report));

        xml.push_str("</testsuites>\n");
        xml
    }

    fn vulnerability_testsuite(report: &ScanReport) -> String {
        let vuln = &report.executive_summary.vulnerabilities;
        let total = vuln.critical + vuln.high + vuln.medium + vuln.low + vuln.info;

        let mut xml = format!(
            "  <testsuite name=\"Vulnerability Summary\" tests=\"{}\" failures=\"{}\">\n",
            total, vuln.critical + vuln.high + vuln.medium
        );

        for _ in 0..vuln.critical {
            xml.push_str("    <testcase name=\"Critical Vulnerability\" classname=\"vulnerabilities.critical\">\n");
            xml.push_str("      <failure message=\"Critical severity vulnerability detected\" type=\"critical\" />\n");
            xml.push_str("    </testcase>\n");
        }
        for _ in 0..vuln.high {
            xml.push_str("    <testcase name=\"High Vulnerability\" classname=\"vulnerabilities.high\">\n");
            xml.push_str("      <failure message=\"High severity vulnerability detected\" type=\"high\" />\n");
            xml.push_str("    </testcase>\n");
        }
        for _ in 0..vuln.medium {
            xml.push_str("    <testcase name=\"Medium Vulnerability\" classname=\"vulnerabilities.medium\">\n");
            xml.push_str("      <failure message=\"Medium severity vulnerability detected\" type=\"medium\" />\n");
            xml.push_str("    </testcase>\n");
        }
        for _ in 0..vuln.low {
            xml.push_str("    <testcase name=\"Low Vulnerability\" classname=\"vulnerabilities.low\" />\n");
        }
        for _ in 0..vuln.info {
            xml.push_str("    <testcase name=\"Info Finding\" classname=\"vulnerabilities.info\">\n");
            xml.push_str("      <skipped message=\"Informational finding\" />\n");
            xml.push_str("    </testcase>\n");
        }

        xml.push_str("  </testsuite>\n");
        xml
    }

    fn finding_tests(report: &ScanReport) -> String {
        if report.findings.is_empty() {
            return String::new();
        }

        let mut xml = format!(
            "  <testsuite name=\"Security Findings\" tests=\"{}\" failures=\"{}\">\n",
            report.findings.len(),
            report.findings.iter().filter(|f| matches!(f.severity, Severity::Critical | Severity::High | Severity::Medium)).count()
        );

        for finding in &report.findings {
            let classname = format!("findings.{}", finding.id);
            xml.push_str(&format!(
                "    <testcase name=\"{}\" classname=\"{}\" time=\"0\">\n",
                Self::esc(&finding.title), Self::esc(&classname)
            ));

            match finding.severity {
                Severity::Critical | Severity::High | Severity::Medium => {
                    xml.push_str(&format!(
                        "      <failure message=\"{}\" type=\"{:?}\">\n",
                        Self::esc(&finding.title), finding.severity
                    ));
                    xml.push_str(&format!("        {}\n", Self::esc(&finding.description)));
                    xml.push_str(&format!("        Affected hosts: {}\n", finding.affected_hosts.join(", ")));
                    if let Some(cvss) = finding.cvss_score {
                        xml.push_str(&format!("        CVSS: {:.1}\n", cvss));
                    }
                    if !finding.cve_ids.is_empty() {
                        xml.push_str(&format!("        CVEs: {}\n", finding.cve_ids.join(", ")));
                    }
                    xml.push_str(&format!("        Remediation: {}\n", Self::esc(&finding.remediation)));
                    xml.push_str("      </failure>\n");
                }
                Severity::Low => {}
                Severity::Info => {
                    xml.push_str("      <skipped message=\"Informational\" />\n");
                }
            }
            xml.push_str("    </testcase>\n");
        }

        xml.push_str("  </testsuite>\n");
        xml
    }

    fn compliance_testsuite(report: &ScanReport) -> String {
        if report.compliance.frameworks.is_empty() {
            return String::new();
        }

        let total: usize = report.compliance.frameworks.iter().map(|f| f.controls_total).sum();
        let failing: usize = report.compliance.frameworks.iter().map(|f| f.controls_failing).sum();

        let mut xml = format!(
            "  <testsuite name=\"Compliance\" tests=\"{}\" failures=\"{}\">\n",
            total, failing
        );

        for fw in &report.compliance.frameworks {
            for i in 0..fw.controls_total {
                let passing = i < fw.controls_passing;
                xml.push_str(&format!(
                    "    <testcase name=\"{} Control {}\" classname=\"compliance.{}\">\n",
                    Self::esc(&fw.name), i + 1, Self::esc(&fw.name)
                ));
                if !passing {
                    xml.push_str(&format!(
                        "      <failure message=\"Control {} failed\" type=\"compliance\" />\n",
                        i + 1
                    ));
                }
                xml.push_str("    </testcase>\n");
            }
        }

        xml.push_str("  </testsuite>\n");
        xml
    }

    fn scan_duration_secs(report: &ScanReport) -> i64 {
        (report.metadata.scan_end - report.metadata.scan_start).num_seconds().max(0)
    }

    fn esc(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
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
                    critical: 1, high: 2, medium: 1, low: 1, info: 1,
                },
                risk_score: 7.5,
                compliance_score: 75.0,
            })
            .compliance(ComplianceStatus {
                frameworks: vec![ComplianceFramework {
                    name: "PCI-DSS".to_string(),
                    version: "4.0".to_string(),
                    controls_total: 3,
                    controls_passing: 2,
                    controls_failing: 1,
                    score: 66.7,
                    findings: vec![],
                }],
                overall_score: 66.7,
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
            .build()
            .unwrap()
    }

    #[test]
    fn test_junit_xml_header() {
        let report = sample_report();
        let xml = JunitReportGenerator::generate(&report);
        assert!(xml.starts_with("<?xml version=\"1.0\""));
    }

    #[test]
    fn test_junit_testsuites() {
        let report = sample_report();
        let xml = JunitReportGenerator::generate(&report);
        assert!(xml.contains("<testsuites"));
        assert!(xml.contains("tests=\"6\"")); // 1+2+1+1+1
        assert!(xml.contains("failures=\"4\"")); // critical+high+medium
    }

    #[test]
    fn test_junit_vulnerability_testsuite() {
        let report = sample_report();
        let xml = JunitReportGenerator::generate(&report);
        assert!(xml.contains("Vulnerability Summary"));
        assert!(xml.contains("Critical Vulnerability"));
        assert!(xml.contains("High Vulnerability"));
    }

    #[test]
    fn test_junit_finding_tests() {
        let report = sample_report();
        let xml = JunitReportGenerator::generate(&report);
        assert!(xml.contains("Security Findings"));
        assert!(xml.contains("SQL Injection"));
        assert!(xml.contains("f-001"));
    }

    #[test]
    fn test_junit_compliance_tests() {
        let report = sample_report();
        let xml = JunitReportGenerator::generate(&report);
        assert!(xml.contains("Compliance"));
        assert!(xml.contains("PCI-DSS Control 1"));
        assert!(xml.contains("PCI-DSS Control 3"));
    }

    #[test]
    fn test_junit_escaping() {
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
            .add_finding(Finding {
                id: "f-001".to_string(),
                severity: Severity::High,
                title: "XSS <script>".to_string(),
                description: "Test & check".to_string(),
                affected_hosts: vec![],
                cvss_score: None,
                cve_ids: vec![],
                remediation: "Fix \"it\"".to_string(),
            })
            .build()
            .unwrap();
        let xml = JunitReportGenerator::generate(&report);
        assert!(xml.contains("&lt;script&gt;"));
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&quot;"));
    }

    #[test]
    fn test_junit_empty_report() {
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
        let xml = JunitReportGenerator::generate(&report);
        assert!(xml.contains("tests=\"0\""));
        assert!(xml.contains("failures=\"0\""));
    }
}
