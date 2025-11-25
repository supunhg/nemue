// Compliance framework mapping and reporting
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMapper {
    frameworks: HashMap<String, Framework>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Framework {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub controls: Vec<Control>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub name: String,
    pub description: String,
    pub check_type: CheckType,
    pub severity: f64,
    pub remediation: String,
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
    Vulnerability,
    Configuration,
    Policy,
    Cryptography,
    Network,
    Authentication,
    Audit,
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
        let mut mapper = Self {
            frameworks: HashMap::new(),
        };
        
        mapper.add_framework(Self::pci_dss_framework());
        mapper.add_framework(Self::nist_csf_framework());
        mapper.add_framework(Self::cis_controls_framework());
        mapper.add_framework(Self::iso27001_framework());
        mapper.add_framework(Self::hipaa_framework());
        mapper.add_framework(Self::soc2_framework());
        mapper.add_framework(Self::gdpr_framework());
        
        mapper
    }

    pub fn add_framework(&mut self, framework: Framework) {
        self.frameworks.insert(framework.id.clone(), framework);
    }

    pub fn get_framework(&self, name: &str) -> Option<&Framework> {
        self.frameworks.get(name)
    }

    pub fn list_frameworks(&self) -> Vec<String> {
        self.frameworks.keys().cloned().collect()
    }

    pub fn pci_dss_framework() -> Framework {
        Framework {
            id: "pci-dss".to_string(),
            name: "PCI-DSS v4.0".to_string(),
            version: "4.0".to_string(),
            description: "Payment Card Industry Data Security Standard".to_string(),
            controls: vec![
                Control {
                    id: "1.1".to_string(),
                    name: "Network Security Controls".to_string(),
                    description: "Install and maintain network security controls".to_string(),
                    check_type: CheckType::Network,
                    severity: 8.0,
                    remediation: "Implement firewall rules and close unnecessary ports".to_string(),
                },
                Control {
                    id: "2.2".to_string(),
                    name: "Secure Configurations".to_string(),
                    description: "Apply secure configurations to all system components".to_string(),
                    check_type: CheckType::Configuration,
                    severity: 8.0,
                    remediation: "Remove default credentials and disable unnecessary services".to_string(),
                },
                Control {
                    id: "4.2".to_string(),
                    name: "Strong Cryptography".to_string(),
                    description: "Protect cardholder data with strong cryptography".to_string(),
                    check_type: CheckType::Cryptography,
                    severity: 9.0,
                    remediation: "Use TLS 1.2+ and strong cipher suites".to_string(),
                },
            ],
        }
    }

    pub fn nist_csf_framework() -> Framework {
        Framework {
            id: "nist-csf".to_string(),
            name: "NIST CSF v1.1".to_string(),
            version: "1.1".to_string(),
            description: "NIST Cybersecurity Framework".to_string(),
            controls: vec![
                Control {
                    id: "ID.AM-1".to_string(),
                    name: "Asset Inventory".to_string(),
                    description: "Physical devices and systems inventory".to_string(),
                    check_type: CheckType::Configuration,
                    severity: 7.0,
                    remediation: "Maintain complete inventory of all assets".to_string(),
                },
                Control {
                    id: "PR.AC-1".to_string(),
                    name: "Access Control".to_string(),
                    description: "Identities and credentials are managed".to_string(),
                    check_type: CheckType::Authentication,
                    severity: 9.0,
                    remediation: "Implement identity and access management".to_string(),
                },
                Control {
                    id: "DE.CM-1".to_string(),
                    name: "Network Monitoring".to_string(),
                    description: "Network monitored to detect potential cybersecurity events".to_string(),
                    check_type: CheckType::Audit,
                    severity: 8.0,
                    remediation: "Deploy network monitoring and intrusion detection".to_string(),
                },
            ],
        }
    }

    pub fn cis_controls_framework() -> Framework {
        Framework {
            id: "cis-controls".to_string(),
            name: "CIS Controls v8.0".to_string(),
            version: "8.0".to_string(),
            description: "Center for Internet Security Controls".to_string(),
            controls: vec![
                Control {
                    id: "7.1".to_string(),
                    name: "Vulnerability Management".to_string(),
                    description: "Establish and maintain a vulnerability management process".to_string(),
                    check_type: CheckType::Vulnerability,
                    severity: 9.0,
                    remediation: "Perform regular vulnerability assessments".to_string(),
                },
                Control {
                    id: "3.1".to_string(),
                    name: "Data Protection".to_string(),
                    description: "Establish and maintain data protection processes".to_string(),
                    check_type: CheckType::Cryptography,
                    severity: 9.0,
                    remediation: "Encrypt sensitive data at rest and in transit".to_string(),
                },
                Control {
                    id: "4.1".to_string(),
                    name: "Secure Configuration".to_string(),
                    description: "Establish and maintain secure configurations".to_string(),
                    check_type: CheckType::Configuration,
                    severity: 8.0,
                    remediation: "Implement and maintain secure baselines".to_string(),
                },
            ],
        }
    }

    pub fn iso27001_framework() -> Framework {
        Framework {
            id: "iso27001".to_string(),
            name: "ISO/IEC 27001:2022".to_string(),
            version: "2022".to_string(),
            description: "Information Security Management System".to_string(),
            controls: vec![
                Control {
                    id: "A.8.8".to_string(),
                    name: "Management of Technical Vulnerabilities".to_string(),
                    description: "Information about technical vulnerabilities obtained in timely manner".to_string(),
                    check_type: CheckType::Vulnerability,
                    severity: 8.0,
                    remediation: "Implement vulnerability management with regular scanning".to_string(),
                },
                Control {
                    id: "A.8.24".to_string(),
                    name: "Use of Cryptography".to_string(),
                    description: "Rules for effective use of cryptography shall be defined".to_string(),
                    check_type: CheckType::Cryptography,
                    severity: 9.0,
                    remediation: "Enforce strong encryption standards".to_string(),
                },
            ],
        }
    }

    pub fn hipaa_framework() -> Framework {
        Framework {
            id: "hipaa".to_string(),
            name: "HIPAA Security Rule".to_string(),
            version: "2013".to_string(),
            description: "Health Insurance Portability and Accountability Act".to_string(),
            controls: vec![
                Control {
                    id: "164.312(a)(1)".to_string(),
                    name: "Access Control".to_string(),
                    description: "Implement technical policies to allow only authorized access".to_string(),
                    check_type: CheckType::Authentication,
                    severity: 9.0,
                    remediation: "Implement role-based access control".to_string(),
                },
                Control {
                    id: "164.312(e)(1)".to_string(),
                    name: "Transmission Security".to_string(),
                    description: "Guard ePHI during transmission".to_string(),
                    check_type: CheckType::Cryptography,
                    severity: 9.0,
                    remediation: "Encrypt ePHI in transit using TLS 1.2+".to_string(),
                },
            ],
        }
    }

    pub fn soc2_framework() -> Framework {
        Framework {
            id: "soc2".to_string(),
            name: "SOC 2 Trust Service Criteria".to_string(),
            version: "2017".to_string(),
            description: "Service Organization Control 2".to_string(),
            controls: vec![
                Control {
                    id: "CC6.1".to_string(),
                    name: "Access Controls".to_string(),
                    description: "Restrict logical and physical access to authorized individuals".to_string(),
                    check_type: CheckType::Authentication,
                    severity: 9.0,
                    remediation: "Implement MFA and network segmentation".to_string(),
                },
                Control {
                    id: "CC6.6".to_string(),
                    name: "Encryption in Transit".to_string(),
                    description: "Protect data during transmission using encryption".to_string(),
                    check_type: CheckType::Cryptography,
                    severity: 9.0,
                    remediation: "Enforce TLS 1.2+ for all communications".to_string(),
                },
            ],
        }
    }

    pub fn gdpr_framework() -> Framework {
        Framework {
            id: "gdpr".to_string(),
            name: "GDPR Technical Measures".to_string(),
            version: "2016/679".to_string(),
            description: "General Data Protection Regulation".to_string(),
            controls: vec![
                Control {
                    id: "Art.32(1)(a)".to_string(),
                    name: "Pseudonymisation and Encryption".to_string(),
                    description: "Implement appropriate technical measures including encryption".to_string(),
                    check_type: CheckType::Cryptography,
                    severity: 9.0,
                    remediation: "Encrypt all personal data in transit and at rest".to_string(),
                },
                Control {
                    id: "Art.32(1)(d)".to_string(),
                    name: "Testing and Assessment".to_string(),
                    description: "Regularly test and evaluate effectiveness".to_string(),
                    check_type: CheckType::Vulnerability,
                    severity: 8.0,
                    remediation: "Conduct regular security assessments".to_string(),
                },
            ],
        }
    }

    pub fn cis_controls() -> Framework {
        Framework {
            id: "cis-controls-old".to_string(),
            name: "CIS-Controls".to_string(),
            version: "8.0".to_string(),
            description: "Legacy CIS Controls format".to_string(),
            controls: vec![],
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
        assert_eq!(mapper.list_frameworks().len(), 7);
    }

    #[test]
    fn test_add_framework() {
        let mut mapper = ComplianceMapper::new();
        
        // Create custom framework
        let custom_framework = Framework {
            id: "custom".to_string(),
            name: "Custom Framework".to_string(),
            version: "1.0".to_string(),
            description: "Custom test framework".to_string(),
            controls: vec![],
        };
        
        mapper.add_framework(custom_framework);
        assert_eq!(mapper.list_frameworks().len(), 8);
        assert!(mapper.get_framework("custom").is_some());
    }

    #[test]
    fn test_pci_dss_framework() {
        let framework = ComplianceMapper::pci_dss_framework();
        assert_eq!(framework.id, "pci-dss");
        assert_eq!(framework.version, "4.0");
        assert_eq!(framework.controls.len(), 3);
    }

    #[test]
    fn test_nist_csf_framework() {
        let framework = ComplianceMapper::nist_csf_framework();
        assert_eq!(framework.id, "nist-csf");
        assert_eq!(framework.version, "1.1");
        assert!(framework.controls.len() >= 3);
    }

    #[test]
    fn test_cis_controls_framework() {
        let framework = ComplianceMapper::cis_controls_framework();
        assert_eq!(framework.id, "cis-controls");
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
