// Enhanced XML report generation with schema support
use crate::reporting::{ScanReport};

pub struct XmlReportGenerator;

impl XmlReportGenerator {
    pub fn generate(report: &ScanReport) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<security_report xmlns=\"urn:nemue:security-report:v1\">\n");
        Self::write_metadata(&mut xml, report);
        Self::write_executive_summary(&mut xml, report);
        Self::write_findings(&mut xml, report);
        Self::write_compliance(&mut xml, report);
        Self::write_recommendations(&mut xml, report);
        Self::write_statistics(&mut xml, report);
        xml.push_str("</security_report>\n");
        xml
    }

    fn write_metadata(xml: &mut String, report: &ScanReport) {
        xml.push_str("  <metadata>\n");
        xml.push_str(&format!("    <report_id>{}</report_id>\n", Self::esc(&report.metadata.report_id)));
        xml.push_str(&format!("    <scan_id>{}</scan_id>\n", Self::esc(&report.metadata.scan_id)));
        xml.push_str(&format!("    <generated_at>{}</generated_at>\n", report.metadata.generated_at.format("%Y-%m-%dT%H:%M:%SZ")));
        xml.push_str(&format!("    <scan_start>{}</scan_start>\n", report.metadata.scan_start.format("%Y-%m-%dT%H:%M:%SZ")));
        xml.push_str(&format!("    <scan_end>{}</scan_end>\n", report.metadata.scan_end.format("%Y-%m-%dT%H:%M:%SZ")));
        xml.push_str(&format!("    <target_count>{}</target_count>\n", report.metadata.target_count));
        xml.push_str(&format!("    <version>{}</version>\n", Self::esc(&report.metadata.version)));
        xml.push_str("  </metadata>\n");
    }

    fn write_executive_summary(xml: &mut String, report: &ScanReport) {
        let s = &report.executive_summary;
        xml.push_str("  <executive_summary>\n");
        xml.push_str(&format!("    <total_hosts>{}</total_hosts>\n", s.total_hosts));
        xml.push_str(&format!("    <hosts_up>{}</hosts_up>\n", s.hosts_up));
        xml.push_str(&format!("    <total_ports>{}</total_ports>\n", s.total_ports));
        xml.push_str(&format!("    <open_ports>{}</open_ports>\n", s.open_ports));
        xml.push_str(&format!("    <risk_score>{:.1}</risk_score>\n", s.risk_score));
        xml.push_str(&format!("    <compliance_score>{:.1}</compliance_score>\n", s.compliance_score));
        xml.push_str(&format!("    <vulnerabilities critical=\"{}\" high=\"{}\" medium=\"{}\" low=\"{}\" info=\"{}\" />\n",
            s.vulnerabilities.critical, s.vulnerabilities.high,
            s.vulnerabilities.medium, s.vulnerabilities.low, s.vulnerabilities.info));
        xml.push_str("  </executive_summary>\n");
    }

    fn write_findings(xml: &mut String, report: &ScanReport) {
        xml.push_str(&format!("  <findings count=\"{}\">\n", report.findings.len()));
        for finding in &report.findings {
            xml.push_str(&format!("    <finding id=\"{}\" severity=\"{:?}\">\n", Self::esc(&finding.id), finding.severity));
            xml.push_str(&format!("      <title>{}</title>\n", Self::esc(&finding.title)));
            xml.push_str(&format!("      <description>{}</description>\n", Self::esc(&finding.description)));
            xml.push_str("      <affected_hosts>\n");
            for host in &finding.affected_hosts {
                xml.push_str(&format!("        <host>{}</host>\n", Self::esc(host)));
            }
            xml.push_str("      </affected_hosts>\n");
            if let Some(cvss) = finding.cvss_score {
                xml.push_str(&format!("      <cvss_score>{:.1}</cvss_score>\n", cvss));
            }
            if !finding.cve_ids.is_empty() {
                xml.push_str("      <cve_ids>\n");
                for cve in &finding.cve_ids {
                    xml.push_str(&format!("        <cve>{}</cve>\n", Self::esc(cve)));
                }
                xml.push_str("      </cve_ids>\n");
            }
            xml.push_str(&format!("      <remediation>{}</remediation>\n", Self::esc(&finding.remediation)));
            xml.push_str("    </finding>\n");
        }
        xml.push_str("  </findings>\n");
    }

    fn write_compliance(xml: &mut String, report: &ScanReport) {
        xml.push_str(&format!("  <compliance overall_score=\"{:.1}\">\n", report.compliance.overall_score));
        for fw in &report.compliance.frameworks {
            xml.push_str(&format!("    <framework name=\"{}\" version=\"{}\" score=\"{:.1}\" total_controls=\"{}\" passing=\"{}\" failing=\"{}\">\n",
                Self::esc(&fw.name), Self::esc(&fw.version), fw.score, fw.controls_total, fw.controls_passing, fw.controls_failing));
            if !fw.findings.is_empty() {
                xml.push_str("      <findings>\n");
                for finding in &fw.findings {
                    xml.push_str(&format!("        <finding>{}</finding>\n", Self::esc(finding)));
                }
                xml.push_str("      </findings>\n");
            }
            xml.push_str("    </framework>\n");
        }
        xml.push_str("  </compliance>\n");
    }

    fn write_recommendations(xml: &mut String, report: &ScanReport) {
        xml.push_str(&format!("  <recommendations count=\"{}\">\n", report.recommendations.len()));
        for rec in &report.recommendations {
            xml.push_str(&format!("    <recommendation priority=\"{:?}\">\n", rec.priority));
            xml.push_str(&format!("      <category>{}</category>\n", Self::esc(&rec.category)));
            xml.push_str(&format!("      <title>{}</title>\n", Self::esc(&rec.title)));
            xml.push_str(&format!("      <description>{}</description>\n", Self::esc(&rec.description)));
            xml.push_str(&format!("      <impact>{}</impact>\n", Self::esc(&rec.impact)));
            xml.push_str(&format!("      <effort>{}</effort>\n", Self::esc(&rec.effort)));
            xml.push_str("    </recommendation>\n");
        }
        xml.push_str("  </recommendations>\n");
    }

    fn write_statistics(xml: &mut String, report: &ScanReport) {
        let total_findings = report.findings.len();
        let total_cves: usize = report.findings.iter().map(|f| f.cve_ids.len()).sum();
        let avg_cvss = if total_findings > 0 {
            report.findings.iter().filter_map(|f| f.cvss_score).sum::<f64>()
                / report.findings.iter().filter(|f| f.cvss_score.is_some()).count().max(1) as f64
        } else {
            0.0
        };
        let total_affected_hosts: usize = report.findings.iter().map(|f| f.affected_hosts.len()).sum();

        xml.push_str("  <statistics>\n");
        xml.push_str(&format!("    <total_findings>{}</total_findings>\n", total_findings));
        xml.push_str(&format!("    <total_cves>{}</total_cves>\n", total_cves));
        xml.push_str(&format!("    <average_cvss>{:.1}</average_cvss>\n", avg_cvss));
        xml.push_str(&format!("    <total_affected_host_instances>{}</total_affected_host_instances>\n", total_affected_hosts));
        xml.push_str(&format!("    <total_recommendations>{}</total_recommendations>\n", report.recommendations.len()));
        xml.push_str(&format!("    <compliance_frameworks>{}</compliance_frameworks>\n", report.compliance.frameworks.len()));
        xml.push_str("  </statistics>\n");
    }

    fn esc(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
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
                    findings: vec!["Weak cipher".to_string()],
                }],
                overall_score: 80.0,
            })
            .add_finding(Finding {
                id: "f-001".to_string(),
                severity: Severity::Critical,
                title: "SQL Injection <test>".to_string(),
                description: "SQL injection in 'login' form".to_string(),
                affected_hosts: vec!["192.168.1.1".to_string()],
                cvss_score: Some(9.8),
                cve_ids: vec!["CVE-2021-1234".to_string()],
                remediation: "Use parameterized queries & input validation".to_string(),
            })
            .add_recommendation(Recommendation {
                priority: Priority::Critical,
                category: "Application".to_string(),
                title: "Fix SQLi".to_string(),
                description: "Fix SQL injection".to_string(),
                impact: "Critical".to_string(),
                effort: "Medium".to_string(),
            })
            .build()
            .unwrap()
    }

    #[test]
    fn test_xml_generation() {
        let report = sample_report();
        let xml = XmlReportGenerator::generate(&report);
        assert!(xml.starts_with("<?xml version=\"1.0\""));
        assert!(xml.contains("xmlns=\"urn:nemue:security-report:v1\""));
        assert!(xml.contains("</security_report>"));
    }

    #[test]
    fn test_xml_metadata() {
        let report = sample_report();
        let xml = XmlReportGenerator::generate(&report);
        assert!(xml.contains("<report_id>report-001</report_id>"));
        assert!(xml.contains("<scan_id>scan-001</scan_id>"));
        assert!(xml.contains("<target_count>10</target_count>"));
    }

    #[test]
    fn test_xml_executive_summary() {
        let report = sample_report();
        let xml = XmlReportGenerator::generate(&report);
        assert!(xml.contains("<total_hosts>10</total_hosts>"));
        assert!(xml.contains("<risk_score>7.5</risk_score>"));
        assert!(xml.contains("critical=\"2\""));
    }

    #[test]
    fn test_xml_findings() {
        let report = sample_report();
        let xml = XmlReportGenerator::generate(&report);
        assert!(xml.contains("<findings count=\"1\">"));
        assert!(xml.contains("severity=\"Critical\""));
        assert!(xml.contains("<cvss_score>9.8</cvss_score>"));
    }

    #[test]
    fn test_xml_escaping() {
        let report = sample_report();
        let xml = XmlReportGenerator::generate(&report);
        assert!(xml.contains("&lt;test&gt;"));
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&apos;"));
    }

    #[test]
    fn test_xml_compliance() {
        let report = sample_report();
        let xml = XmlReportGenerator::generate(&report);
        assert!(xml.contains("<compliance overall_score=\"80.0\">"));
        assert!(xml.contains("name=\"PCI-DSS\""));
        assert!(xml.contains("<finding>Weak cipher</finding>"));
    }

    #[test]
    fn test_xml_recommendations() {
        let report = sample_report();
        let xml = XmlReportGenerator::generate(&report);
        assert!(xml.contains("<recommendations count=\"1\">"));
        assert!(xml.contains("priority=\"Critical\""));
    }

    #[test]
    fn test_xml_statistics() {
        let report = sample_report();
        let xml = XmlReportGenerator::generate(&report);
        assert!(xml.contains("<statistics>"));
        assert!(xml.contains("<total_findings>1</total_findings>"));
        assert!(xml.contains("<total_cves>1</total_cves>"));
        assert!(xml.contains("<average_cvss>"));
    }

    #[test]
    fn test_xml_empty_report() {
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
        let xml = XmlReportGenerator::generate(&report);
        assert!(xml.contains("<findings count=\"0\">"));
        assert!(xml.contains("<recommendations count=\"0\">"));
        assert!(xml.contains("<total_findings>0</total_findings>"));
    }
}
