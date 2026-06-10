// SARIF (Static Analysis Results Interchange Format) report generation
// Compatible with GitHub Code Scanning and other SARIF consumers
use crate::reporting::{ScanReport, Severity};

pub struct SarifReportGenerator;

impl SarifReportGenerator {
    pub fn generate(report: &ScanReport) -> String {
        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Nemue",
                        "version": report.metadata.version,
                        "informationUri": "https://github.com/tabea/Nemue",
                        "rules": Self::build_rules(report),
                    }
                },
                "results": Self::build_results(report),
                "invocations": [{
                    "executionSuccessful": true,
                    "startTimeUtc": report.metadata.scan_start.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    "endTimeUtc": report.metadata.scan_end.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                }],
                "properties": {
                    "scanId": report.metadata.scan_id,
                    "reportId": report.metadata.report_id,
                    "targetCount": report.metadata.target_count,
                    "riskScore": report.executive_summary.risk_score,
                    "complianceScore": report.executive_summary.compliance_score,
                }
            }]
        });

        serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
    }

    fn build_rules(report: &ScanReport) -> Vec<serde_json::Value> {
        report
            .findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "id": f.id,
                    "name": f.title,
                    "shortDescription": { "text": f.title },
                    "fullDescription": { "text": f.description },
                    "help": { "text": f.remediation },
                    "defaultConfiguration": {
                        "level": Self::severity_to_level(&f.severity),
                    },
                    "properties": {
                        "tags": Self::build_tags(f),
                    }
                })
            })
            .collect()
    }

    fn build_results(report: &ScanReport) -> Vec<serde_json::Value> {
        report
            .findings
            .iter()
            .flat_map(|f| {
                f.affected_hosts.iter().map(move |host| {
                    serde_json::json!({
                        "ruleId": f.id,
                        "level": Self::severity_to_level(&f.severity),
                        "message": { "text": format!("{}: {}", f.title, f.description) },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": { "uri": host },
                            },
                            "logicalLocations": [{ "name": host }],
                        }],
                        "partialFingerprints": {
                            "primaryLocationLineHash": f.id,
                        },
                        "properties": {
                            "cvssScore": f.cvss_score,
                            "cveIds": f.cve_ids,
                        }
                    })
                })
            })
            .collect()
    }

    fn severity_to_level(severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
            Severity::Info => "none",
        }
    }

    fn build_tags(finding: &crate::reporting::Finding) -> Vec<String> {
        let mut tags = vec![format!("severity/{:?}", finding.severity).to_lowercase()];
        for cve in &finding.cve_ids {
            tags.push(cve.clone());
        }
        if let Some(cvss) = finding.cvss_score {
            if cvss >= 9.0 {
                tags.push("security/critical".to_string());
            } else if cvss >= 7.0 {
                tags.push("security/high".to_string());
            } else if cvss >= 4.0 {
                tags.push("security/medium".to_string());
            } else {
                tags.push("security/low".to_string());
            }
        }
        tags
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
                description: "SQL injection in login form".to_string(),
                affected_hosts: vec!["192.168.1.1".to_string(), "10.0.0.5".to_string()],
                cvss_score: Some(9.8),
                cve_ids: vec!["CVE-2021-1234".to_string()],
                remediation: "Use parameterized queries".to_string(),
            })
            .add_finding(Finding {
                id: "f-002".to_string(),
                severity: Severity::Medium,
                title: "XSS Vulnerability".to_string(),
                description: "Cross-site scripting in search".to_string(),
                affected_hosts: vec!["192.168.1.2".to_string()],
                cvss_score: Some(5.4),
                cve_ids: vec![],
                remediation: "Sanitize user input".to_string(),
            })
            .build()
            .unwrap()
    }

    #[test]
    fn test_sarif_schema() {
        let report = sample_report();
        let json: serde_json::Value =
            serde_json::from_str(&SarifReportGenerator::generate(&report)).unwrap();
        assert_eq!(json["version"], "2.1.0");
        assert!(json["$schema"].as_str().unwrap().contains("sarif-schema"));
    }

    #[test]
    fn test_sarif_tool_info() {
        let report = sample_report();
        let json: serde_json::Value =
            serde_json::from_str(&SarifReportGenerator::generate(&report)).unwrap();
        let driver = &json["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "Nemue");
        assert_eq!(driver["version"], "0.1.0");
    }

    #[test]
    fn test_sarif_rules() {
        let report = sample_report();
        let json: serde_json::Value =
            serde_json::from_str(&SarifReportGenerator::generate(&report)).unwrap();
        let rules = json["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["id"], "f-001");
        assert_eq!(rules[0]["defaultConfiguration"]["level"], "error");
    }

    #[test]
    fn test_sarif_results() {
        let report = sample_report();
        let json: serde_json::Value =
            serde_json::from_str(&SarifReportGenerator::generate(&report)).unwrap();
        let results = json["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 3); // 2 hosts for f-001 + 1 host for f-002
    }

    #[test]
    fn test_sarif_invocation() {
        let report = sample_report();
        let json: serde_json::Value =
            serde_json::from_str(&SarifReportGenerator::generate(&report)).unwrap();
        let inv = &json["runs"][0]["invocations"][0];
        assert_eq!(inv["executionSuccessful"], true);
    }

    #[test]
    fn test_sarif_properties() {
        let report = sample_report();
        let json: serde_json::Value =
            serde_json::from_str(&SarifReportGenerator::generate(&report)).unwrap();
        let props = &json["runs"][0]["properties"];
        assert_eq!(props["scanId"], "scan-001");
        assert_eq!(props["riskScore"], 7.5);
    }

    #[test]
    fn test_sarif_severity_mapping() {
        assert_eq!(
            SarifReportGenerator::severity_to_level(&Severity::Critical),
            "error"
        );
        assert_eq!(
            SarifReportGenerator::severity_to_level(&Severity::High),
            "error"
        );
        assert_eq!(
            SarifReportGenerator::severity_to_level(&Severity::Medium),
            "warning"
        );
        assert_eq!(
            SarifReportGenerator::severity_to_level(&Severity::Low),
            "note"
        );
        assert_eq!(
            SarifReportGenerator::severity_to_level(&Severity::Info),
            "none"
        );
    }

    #[test]
    fn test_sarif_tags() {
        let finding = Finding {
            id: "f-001".to_string(),
            severity: Severity::Critical,
            title: "Test".to_string(),
            description: "Test".to_string(),
            affected_hosts: vec![],
            cvss_score: Some(9.8),
            cve_ids: vec!["CVE-2021-1234".to_string()],
            remediation: "Fix".to_string(),
        };
        let tags = SarifReportGenerator::build_tags(&finding);
        assert!(tags.contains(&"severity/critical".to_string()));
        assert!(tags.contains(&"CVE-2021-1234".to_string()));
        assert!(tags.contains(&"security/critical".to_string()));
    }

    #[test]
    fn test_sarif_empty_report() {
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
                total_hosts: 0,
                hosts_up: 0,
                total_ports: 0,
                open_ports: 0,
                vulnerabilities: VulnerabilitySummary {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                    info: 0,
                },
                risk_score: 0.0,
                compliance_score: 0.0,
            })
            .compliance(ComplianceStatus {
                frameworks: vec![],
                overall_score: 0.0,
            })
            .build()
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&SarifReportGenerator::generate(&report)).unwrap();
        assert_eq!(json["runs"][0]["results"].as_array().unwrap().len(), 0);
    }
}
