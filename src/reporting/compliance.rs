// Compliance framework mappings and assessments
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMapper {
    frameworks: HashMap<String, Framework>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Framework {
    pub name: String,
    pub version: String,
    pub controls: Vec<Control>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub requirements: Vec<String>,
    pub tests: Vec<ControlTest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlTest {
    pub test_id: String,
    pub description: String,
    pub check_type: CheckType,
    pub expected: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CheckType {
    PortOpen,
    PortClosed,
    ServiceVersion,
    VulnerabilityAbsent,
    ConfigurationPresent,
    EncryptionEnabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub framework: String,
    pub version: String,
    pub total_controls: usize,
    pub passed: usize,
    pub failed: usize,
    pub not_applicable: usize,
    pub score: f64,
    pub control_results: Vec<ControlResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResult {
    pub control_id: String,
    pub status: ControlStatus,
    pub findings: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlStatus {
    Pass,
    Fail,
    NotApplicable,
    NotTested,
}

impl ComplianceMapper {
    pub fn new() -> Self {
        Self {
            frameworks: HashMap::new(),
        }
    }

    pub fn add_framework(&mut self, framework: Framework) {
        self.frameworks.insert(framework.name.clone(), framework);
    }

    pub fn get_framework(&self, name: &str) -> Option<&Framework> {
        self.frameworks.get(name)
    }

    pub fn list_frameworks(&self) -> Vec<String> {
        self.frameworks.keys().cloned().collect()
    }

    pub fn pci_dss_v4() -> Framework {
        Framework {
            name: "PCI-DSS".to_string(),
            version: "4.0".to_string(),
            controls: vec![
                Control {
                    id: "1.1".to_string(),
                    title: "Install and maintain network security controls".to_string(),
                    description: "Network security controls protect the cardholder data environment".to_string(),
                    category: "Network Security".to_string(),
                    requirements: vec![
                        "Firewall rules documented".to_string(),
                        "Unnecessary ports closed".to_string(),
                    ],
                    tests: vec![
                        ControlTest {
                            test_id: "1.1.1".to_string(),
                            description: "Check for open administrative ports".to_string(),
                            check_type: CheckType::PortClosed,
                            expected: "22,23,3389".to_string(),
                        },
                    ],
                },
                Control {
                    id: "2.2".to_string(),
                    title: "Apply secure configurations to all system components".to_string(),
                    description: "Default configurations often have insecure settings".to_string(),
                    category: "Configuration Management".to_string(),
                    requirements: vec![
                        "Remove default accounts".to_string(),
                        "Disable unnecessary services".to_string(),
                    ],
                    tests: vec![
                        ControlTest {
                            test_id: "2.2.1".to_string(),
                            description: "Check for default credentials".to_string(),
                            check_type: CheckType::VulnerabilityAbsent,
                            expected: "No default credentials".to_string(),
                        },
                    ],
                },
                Control {
                    id: "4.2".to_string(),
                    title: "Protect cardholder data with strong cryptography".to_string(),
                    description: "Encryption protects data in transit".to_string(),
                    category: "Encryption".to_string(),
                    requirements: vec![
                        "Use TLS 1.2 or higher".to_string(),
                        "Strong cipher suites only".to_string(),
                    ],
                    tests: vec![
                        ControlTest {
                            test_id: "4.2.1".to_string(),
                            description: "Verify TLS version".to_string(),
                            check_type: CheckType::EncryptionEnabled,
                            expected: "TLS 1.2+".to_string(),
                        },
                    ],
                },
            ],
        }
    }

    pub fn nist_csf() -> Framework {
        Framework {
            name: "NIST-CSF".to_string(),
            version: "1.1".to_string(),
            controls: vec![
                Control {
                    id: "ID.AM-1".to_string(),
                    title: "Physical devices and systems inventory".to_string(),
                    description: "Maintain inventory of authorized devices".to_string(),
                    category: "Asset Management".to_string(),
                    requirements: vec![
                        "Device inventory maintained".to_string(),
                        "Unauthorized devices detected".to_string(),
                    ],
                    tests: vec![],
                },
                Control {
                    id: "PR.AC-5".to_string(),
                    title: "Network integrity protection".to_string(),
                    description: "Protect network integrity with segmentation".to_string(),
                    category: "Access Control".to_string(),
                    requirements: vec![
                        "Network segmentation implemented".to_string(),
                        "Firewall rules enforced".to_string(),
                    ],
                    tests: vec![],
                },
                Control {
                    id: "DE.CM-1".to_string(),
                    title: "Network monitoring".to_string(),
                    description: "Monitor network to detect cybersecurity events".to_string(),
                    category: "Detection".to_string(),
                    requirements: vec![
                        "Network traffic monitored".to_string(),
                        "Anomalies detected".to_string(),
                    ],
                    tests: vec![],
                },
            ],
        }
    }

    pub fn cis_controls() -> Framework {
        Framework {
            name: "CIS-Controls".to_string(),
            version: "8.0".to_string(),
            controls: vec![
                Control {
                    id: "1.1".to_string(),
                    title: "Establish and maintain detailed enterprise asset inventory".to_string(),
                    description: "Actively manage all enterprise assets".to_string(),
                    category: "Asset Management".to_string(),
                    requirements: vec![
                        "Asset inventory complete".to_string(),
                        "Inventory updated regularly".to_string(),
                    ],
                    tests: vec![],
                },
                Control {
                    id: "4.1".to_string(),
                    title: "Establish and maintain secure configuration process".to_string(),
                    description: "Secure configurations for all assets".to_string(),
                    category: "Configuration Management".to_string(),
                    requirements: vec![
                        "Hardening standards applied".to_string(),
                        "Unnecessary services disabled".to_string(),
                    ],
                    tests: vec![],
                },
                Control {
                    id: "13.1".to_string(),
                    title: "Centralize security event alerting".to_string(),
                    description: "Aggregate security events for analysis".to_string(),
                    category: "Monitoring".to_string(),
                    requirements: vec![
                        "Security events logged".to_string(),
                        "Alerts generated".to_string(),
                    ],
                    tests: vec![],
                },
            ],
        }
    }
}

impl ComplianceResult {
    pub fn new(framework: String, version: String) -> Self {
        Self {
            framework,
            version,
            total_controls: 0,
            passed: 0,
            failed: 0,
            not_applicable: 0,
            score: 0.0,
            control_results: Vec::new(),
        }
    }

    pub fn add_result(&mut self, result: ControlResult) {
        self.total_controls += 1;
        match result.status {
            ControlStatus::Pass => self.passed += 1,
            ControlStatus::Fail => self.failed += 1,
            ControlStatus::NotApplicable => self.not_applicable += 1,
            ControlStatus::NotTested => {}
        }
        self.control_results.push(result);
        self.calculate_score();
    }

    fn calculate_score(&mut self) {
        let applicable = self.total_controls - self.not_applicable;
        if applicable > 0 {
            self.score = (self.passed as f64 / applicable as f64) * 100.0;
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "{} v{}: {}/{} passed ({:.1}%)",
            self.framework,
            self.version,
            self.passed,
            self.total_controls - self.not_applicable,
            self.score
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_mapper_creation() {
        let mapper = ComplianceMapper::new();
        assert_eq!(mapper.list_frameworks().len(), 0);
    }

    #[test]
    fn test_add_framework() {
        let mut mapper = ComplianceMapper::new();
        let framework = ComplianceMapper::pci_dss_v4();
        
        mapper.add_framework(framework.clone());
        assert_eq!(mapper.list_frameworks().len(), 1);
        assert!(mapper.get_framework("PCI-DSS").is_some());
    }

    #[test]
    fn test_pci_dss_framework() {
        let framework = ComplianceMapper::pci_dss_v4();
        assert_eq!(framework.name, "PCI-DSS");
        assert_eq!(framework.version, "4.0");
        assert_eq!(framework.controls.len(), 3);
    }

    #[test]
    fn test_nist_csf_framework() {
        let framework = ComplianceMapper::nist_csf();
        assert_eq!(framework.name, "NIST-CSF");
        assert_eq!(framework.version, "1.1");
        assert!(framework.controls.len() >= 3);
    }

    #[test]
    fn test_cis_controls_framework() {
        let framework = ComplianceMapper::cis_controls();
        assert_eq!(framework.name, "CIS-Controls");
        assert_eq!(framework.version, "8.0");
        assert!(framework.controls.len() >= 3);
    }

    #[test]
    fn test_compliance_result_creation() {
        let result = ComplianceResult::new("PCI-DSS".to_string(), "4.0".to_string());
        assert_eq!(result.framework, "PCI-DSS");
        assert_eq!(result.total_controls, 0);
        assert_eq!(result.score, 0.0);
    }

    #[test]
    fn test_add_control_result() {
        let mut result = ComplianceResult::new("PCI-DSS".to_string(), "4.0".to_string());
        
        result.add_result(ControlResult {
            control_id: "1.1".to_string(),
            status: ControlStatus::Pass,
            findings: vec![],
            evidence: vec![],
        });

        assert_eq!(result.total_controls, 1);
        assert_eq!(result.passed, 1);
    }

    #[test]
    fn test_compliance_score_calculation() {
        let mut result = ComplianceResult::new("PCI-DSS".to_string(), "4.0".to_string());
        
        result.add_result(ControlResult {
            control_id: "1.1".to_string(),
            status: ControlStatus::Pass,
            findings: vec![],
            evidence: vec![],
        });

        result.add_result(ControlResult {
            control_id: "2.2".to_string(),
            status: ControlStatus::Fail,
            findings: vec!["Issue found".to_string()],
            evidence: vec![],
        });

        assert_eq!(result.score, 50.0);
    }

    #[test]
    fn test_compliance_summary() {
        let mut result = ComplianceResult::new("PCI-DSS".to_string(), "4.0".to_string());
        
        result.add_result(ControlResult {
            control_id: "1.1".to_string(),
            status: ControlStatus::Pass,
            findings: vec![],
            evidence: vec![],
        });

        let summary = result.summary();
        assert!(summary.contains("PCI-DSS"));
        assert!(summary.contains("100.0%"));
    }
}
