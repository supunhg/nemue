// SPDX (Software Package Data Exchange) report generation for license compliance
use crate::reporting::{ScanReport, Severity};

pub struct SpdxReportGenerator;

impl SpdxReportGenerator {
    pub fn generate(report: &ScanReport) -> String {
        let mut spdx = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": format!("nemue-scan-{}", report.metadata.scan_id),
            "documentNamespace": format!("https://nemue.dev/spdx/{}/{}", report.metadata.scan_id, report.metadata.report_id),
            "creationInfo": {
                "created": report.metadata.generated_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                "creators": ["Tool: Nemue-{}", report.metadata.version],
                "licenseListVersion": "3.21",
            },
            "packages": Self::build_packages(report),
            "relationships": Self::build_relationships(report),
            "annotations": Self::build_annotations(report),
        });

        serde_json::to_string_pretty(&spdx).unwrap_or_else(|_| "{}".to_string())
    }

    fn build_packages(report: &ScanReport) -> Vec<serde_json::Value> {
        let mut packages = vec![serde_json::json!({
            "SPDXID": "SPDXRef-ScanTarget",
            "name": format!("scan-{}", report.metadata.scan_id),
            "versionInfo": report.metadata.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "checksums": [{
                "algorithm": "SHA256",
                "checksumValue": report.metadata.report_id,
            }],
            "primaryPackagePurpose": "APPLICATION",
            "supplier": "Organization: Nemue Security",
            "annotations": [],
        })];

        for finding in &report.findings {
            packages.push(serde_json::json!({
                "SPDXID": format!("SPDXRef-Finding-{}", finding.id.replace('-', "")),
                "name": finding.title.clone(),
                "versionInfo": finding.id.clone(),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "primaryPackagePurpose": "FILE",
                "comment": finding.description.clone(),
                "externalRefs": Self::build_external_refs(finding),
                "annotations": [],
            }));
        }

        packages
    }

    fn build_external_refs(finding: &crate::reporting::Finding) -> Vec<serde_json::Value> {
        let mut refs = vec![serde_json::json!({
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": format!("cpe:2.3:a:nemue:{}:*:*:*:*:*:*:*:*", finding.id),
            "comment": format!("Severity: {:?}, CVSS: {:?}", finding.severity, finding.cvss_score),
        })];

        for cve in &finding.cve_ids {
            refs.push(serde_json::json!({
                "referenceCategory": "SECURITY",
                "referenceType": "cve",
                "referenceLocator": cve.clone(),
                "comment": format!("Associated with finding {}", finding.id),
            }));
        }

        refs
    }

    fn build_relationships(report: &ScanReport) -> Vec<serde_json::Value> {
        let mut rels = vec![serde_json::json!({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-ScanTarget",
        })];

        for finding in &report.findings {
            rels.push(serde_json::json!({
                "spdxElementId": "SPDXRef-ScanTarget",
                "relationshipType": "HAS_VULNERABILITY",
                "relatedSpdxElement": format!("SPDXRef-Finding-{}", finding.id.replace('-', "")),
                "comment": format!("{:?} severity", finding.severity),
            }));
        }

        for fw in &report.compliance.frameworks {
            let fw_id = format!("SPDXRef-Framework-{}", fw.name.replace([' ', '-'], ""));
            rels.push(serde_json::json!({
                "spdxElementId": "SPDXRef-ScanTarget",
                "relationshipType": "HAS_VULNERABILITY",
                "relatedSpdxElement": fw_id,
                "comment": format!("Compliance framework: {} v{}", fw.name, fw.version),
            }));
        }

        rels
    }

    fn build_annotations(report: &ScanReport) -> Vec<serde_json::Value> {
        let mut annotations = vec![serde_json::json!({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "annotationType": "OTHER",
            "annotator": format!("Tool: Nemue-{}", report.metadata.version),
            "annotationDate": report.metadata.generated_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "annotationComment": format!(
                "Risk score: {:.1}, Compliance: {:.1}%, Findings: {}",
                report.executive_summary.risk_score,
                report.compliance.overall_score,
                report.findings.len()
            ),
        })];

        let vuln = &report.executive_summary.vulnerabilities;
        annotations.push(serde_json::json!({
            "spdxElementId": "SPDXRef-ScanTarget",
            "annotationType": "OTHER",
            "annotator": format!("Tool: Nemue-{}", report.metadata.version),
            "annotationDate": report.metadata.generated_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "annotationComment": format!(
                "Vulnerabilities: {} critical, {} high, {} medium, {} low, {} info",
                vuln.critical, vuln.high, vuln.medium, vuln.low, vuln.info
            ),
        }));

        annotations
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
                vulnerabilities: VulnerabilitySummary { critical: 1, high: 2, medium: 1, low: 0, info: 0 },
                risk_score: 7.5, compliance_score: 80.0,
            })
            .compliance(ComplianceStatus {
                frameworks: vec![ComplianceFramework {
                    name: "PCI-DSS".to_string(),
                    version: "4.0".to_string(),
                    controls_total: 10, controls_passing: 8, controls_failing: 2,
                    score: 80.0, findings: vec![],
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
            .build()
            .unwrap()
    }

    #[test]
    fn test_spdx_version() {
        let report = sample_report();
        let json: serde_json::Value = serde_json::from_str(&SpdxReportGenerator::generate(&report)).unwrap();
        assert_eq!(json["spdxVersion"], "SPDX-2.3");
        assert_eq!(json["dataLicense"], "CC0-1.0");
        assert_eq!(json["SPDXID"], "SPDXRef-DOCUMENT");
    }

    #[test]
    fn test_spdx_document_info() {
        let report = sample_report();
        let json: serde_json::Value = serde_json::from_str(&SpdxReportGenerator::generate(&report)).unwrap();
        assert_eq!(json["name"], "nemue-scan-scan-001");
        assert!(json["documentNamespace"].as_str().unwrap().contains("scan-001"));
    }

    #[test]
    fn test_spdx_creation_info() {
        let report = sample_report();
        let json: serde_json::Value = serde_json::from_str(&SpdxReportGenerator::generate(&report)).unwrap();
        let creators = json["creationInfo"]["creators"].as_array().unwrap();
        assert!(creators[0].as_str().unwrap().contains("Nemue"));
    }

    #[test]
    fn test_spdx_packages() {
        let report = sample_report();
        let json: serde_json::Value = serde_json::from_str(&SpdxReportGenerator::generate(&report)).unwrap();
        let packages = json["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 2); // scan target + 1 finding
        assert_eq!(packages[0]["SPDXID"], "SPDXRef-ScanTarget");
    }

    #[test]
    fn test_spdx_relationships() {
        let report = sample_report();
        let json: serde_json::Value = serde_json::from_str(&SpdxReportGenerator::generate(&report)).unwrap();
        let rels = json["relationships"].as_array().unwrap();
        assert!(rels.len() >= 2); // DESCRIBES + HAS_VULNERABILITY
        assert_eq!(rels[0]["relationshipType"], "DESCRIBES");
    }

    #[test]
    fn test_spdx_annotations() {
        let report = sample_report();
        let json: serde_json::Value = serde_json::from_str(&SpdxReportGenerator::generate(&report)).unwrap();
        let annotations = json["annotations"].as_array().unwrap();
        assert!(annotations.len() >= 2);
        assert!(annotations[0]["annotationComment"].as_str().unwrap().contains("Risk score"));
    }

    #[test]
    fn test_spdx_external_refs() {
        let report = sample_report();
        let json: serde_json::Value = serde_json::from_str(&SpdxReportGenerator::generate(&report)).unwrap();
        let refs = &json["packages"][1]["externalRefs"].as_array().unwrap();
        assert!(refs.len() >= 2); // CPE + CVE
        assert_eq!(refs[0]["referenceType"], "cpe23Type");
        assert_eq!(refs[1]["referenceType"], "cve");
        assert_eq!(refs[1]["referenceLocator"], "CVE-2021-1234");
    }

    #[test]
    fn test_spdx_compliance_relationships() {
        let report = sample_report();
        let json: serde_json::Value = serde_json::from_str(&SpdxReportGenerator::generate(&report)).unwrap();
        let rels = json["relationships"].as_array().unwrap();
        let fw_rel = rels.iter().find(|r| r["comment"].as_str().map_or(false, |c| c.contains("PCI-DSS")));
        assert!(fw_rel.is_some());
    }

    #[test]
    fn test_spdx_empty_report() {
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
        let json: serde_json::Value = serde_json::from_str(&SpdxReportGenerator::generate(&report)).unwrap();
        assert_eq!(json["packages"].as_array().unwrap().len(), 1); // just scan target
        assert_eq!(json["relationships"].as_array().unwrap().len(), 1); // just DESCRIBES
    }
}
