// CycloneDX SBOM (Software Bill of Materials) report generation
use crate::reporting::{ScanReport, Severity};

pub struct CycloneDxReportGenerator;

impl CycloneDxReportGenerator {
    pub fn generate(report: &ScanReport) -> String {
        let bom = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "version": 1,
            "metadata": {
                "timestamp": report.metadata.generated_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                "tools": [{
                    "vendor": "Nemue",
                    "name": "Nemue Security Scanner",
                    "version": report.metadata.version,
                }],
                "component": {
                    "type": "application",
                    "name": format!("scan-{}", report.metadata.scan_id),
                    "version": report.metadata.version,
                }
            },
            "components": Self::build_components(report),
            "vulnerabilities": Self::build_vulnerabilities(report),
        });

        serde_json::to_string_pretty(&bom).unwrap_or_else(|_| "{}".to_string())
    }

    fn build_components(report: &ScanReport) -> Vec<serde_json::Value> {
        report.findings.iter().flat_map(|f| {
            f.affected_hosts.iter().map(move |host| {
                serde_json::json!({
                    "type": "application",
                    "name": host,
                    "bom-ref": format!("{}:{}", f.id, host),
                    "properties": [{
                        "name": "nemue:finding",
                        "value": f.id,
                    }],
                })
            })
        }).collect()
    }

    fn build_vulnerabilities(report: &ScanReport) -> Vec<serde_json::Value> {
        report.findings.iter().map(|f| {
            serde_json::json!({
                "id": f.id,
                "bom-ref": format!("vuln:{}", f.id),
                "description": f.description,
                "ratings": Self::build_ratings(f),
                "affects": f.affected_hosts.iter().map(|host| {
                    serde_json::json!({ "ref": format!("{}:{}", f.id, host) })
                }).collect::<Vec<_>>(),
                "recommendation": f.remediation,
                "source": {
                    "name": "Nemue Security Scanner",
                },
                "properties": [{
                    "name": "nemue:severity",
                    "value": format!("{:?}", f.severity),
                }],
            })
        }).collect()
    }

    fn build_ratings(finding: &crate::reporting::Finding) -> Vec<serde_json::Value> {
        let mut ratings = vec![serde_json::json!({
            "severity": Self::severity_to_cyclonedx(&finding.severity),
            "method": "other",
            "source": { "name": "Nemue" },
        })];

        if let Some(cvss) = finding.cvss_score {
            ratings.push(serde_json::json!({
                "score": cvss,
                "severity": Self::cvss_to_severity(cvss),
                "method": "CVSSv3",
                "vector": format!("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            }));
        }

        ratings
    }

    fn severity_to_cyclonedx(severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    fn cvss_to_severity(cvss: f64) -> &'static str {
        if cvss >= 9.0 { "critical" }
        else if cvss >= 7.0 { "high" }
        else if cvss >= 4.0 { "medium" }
        else if cvss >= 0.1 { "low" }
        else { "info" }
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
                target_count: 5,
                version: "0.1.0".to_string(),
            })
            .summary(ExecutiveSummary {
                total_hosts: 5, hosts_up: 4, total_ports: 500, open_ports: 20,
                vulnerabilities: VulnerabilitySummary { critical: 1, high: 2, medium: 3, low: 1, info: 1 },
                risk_score: 7.0, compliance_score: 80.0,
            })
            .compliance(ComplianceStatus { frameworks: vec![], overall_score: 80.0 })
            .add_finding(Finding {
                id: "f-001".to_string(),
                severity: Severity::Critical,
                title: "SQL Injection".to_string(),
                description: "SQL injection vulnerability".to_string(),
                affected_hosts: vec!["192.168.1.1".to_string()],
                cvss_score: Some(9.8),
                cve_ids: vec!["CVE-2021-1234".to_string()],
                remediation: "Use parameterized queries".to_string(),
            })
            .add_finding(Finding {
                id: "f-002".to_string(),
                severity: Severity::Medium,
                title: "XSS".to_string(),
                description: "Cross-site scripting".to_string(),
                affected_hosts: vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()],
                cvss_score: Some(5.4),
                cve_ids: vec![],
                remediation: "Sanitize input".to_string(),
            })
            .build()
            .unwrap()
    }

    #[test]
    fn test_cyclonedx_format() {
        let report = sample_report();
        let json: serde_json::Value = serde_json::from_str(&CycloneDxReportGenerator::generate(&report)).unwrap();
        assert_eq!(json["bomFormat"], "CycloneDX");
        assert_eq!(json["specVersion"], "1.5");
    }

    #[test]
    fn test_cyclonedx_metadata() {
        let report = sample_report();
        let json: serde_json::Value = serde_json::from_str(&CycloneDxReportGenerator::generate(&report)).unwrap();
        assert_eq!(json["metadata"]["tools"][0]["vendor"], "Nemue");
        assert_eq!(json["metadata"]["component"]["name"], "scan-scan-001");
    }

    #[test]
    fn test_cyclonedx_components() {
        let report = sample_report();
        let json: serde_json::Value = serde_json::from_str(&CycloneDxReportGenerator::generate(&report)).unwrap();
        let components = json["components"].as_array().unwrap();
        assert_eq!(components.len(), 3); // 1 host for f-001 + 2 hosts for f-002
    }

    #[test]
    fn test_cyclonedx_vulnerabilities() {
        let report = sample_report();
        let json: serde_json::Value = serde_json::from_str(&CycloneDxReportGenerator::generate(&report)).unwrap();
        let vulns = json["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 2);
        assert_eq!(vulns[0]["id"], "f-001");
        assert_eq!(vulns[0]["recommendation"], "Use parameterized queries");
    }

    #[test]
    fn test_cyclonedx_ratings() {
        let report = sample_report();
        let json: serde_json::Value = serde_json::from_str(&CycloneDxReportGenerator::generate(&report)).unwrap();
        let ratings = &json["vulnerabilities"][0]["ratings"].as_array().unwrap();
        assert!(ratings.len() >= 2); // severity + CVSS
        assert_eq!(ratings[0]["severity"], "critical");
        assert_eq!(ratings[1]["method"], "CVSSv3");
    }

    #[test]
    fn test_cyclonedx_severity_mapping() {
        assert_eq!(CycloneDxReportGenerator::severity_to_cyclonedx(&Severity::Critical), "critical");
        assert_eq!(CycloneDxReportGenerator::severity_to_cyclonedx(&Severity::High), "high");
        assert_eq!(CycloneDxReportGenerator::severity_to_cyclonedx(&Severity::Medium), "medium");
        assert_eq!(CycloneDxReportGenerator::severity_to_cyclonedx(&Severity::Low), "low");
        assert_eq!(CycloneDxReportGenerator::severity_to_cyclonedx(&Severity::Info), "info");
    }

    #[test]
    fn test_cyclonedx_cvss_severity() {
        assert_eq!(CycloneDxReportGenerator::cvss_to_severity(9.5), "critical");
        assert_eq!(CycloneDxReportGenerator::cvss_to_severity(7.5), "high");
        assert_eq!(CycloneDxReportGenerator::cvss_to_severity(5.0), "medium");
        assert_eq!(CycloneDxReportGenerator::cvss_to_severity(2.0), "low");
        assert_eq!(CycloneDxReportGenerator::cvss_to_severity(0.0), "info");
    }

    #[test]
    fn test_cyclonedx_serial_number() {
        let report = sample_report();
        let json: serde_json::Value = serde_json::from_str(&CycloneDxReportGenerator::generate(&report)).unwrap();
        let serial = json["serialNumber"].as_str().unwrap();
        assert!(serial.starts_with("urn:uuid:"));
    }

    #[test]
    fn test_cyclonedx_empty_report() {
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
        let json: serde_json::Value = serde_json::from_str(&CycloneDxReportGenerator::generate(&report)).unwrap();
        assert_eq!(json["components"].as_array().unwrap().len(), 0);
        assert_eq!(json["vulnerabilities"].as_array().unwrap().len(), 0);
    }
}
