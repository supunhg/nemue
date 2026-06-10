use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComplianceStandard {
    OWASPIoT,
    NISTIoT,
    ETSIEN303645,
    IoTFoundation,
    BestPractices,
}

impl ComplianceStandard {
    pub fn as_str(&self) -> &str {
        match self {
            ComplianceStandard::OWASPIoT => "OWASP IoT Top 10",
            ComplianceStandard::NISTIoT => "NIST IoT Guidelines",
            ComplianceStandard::ETSIEN303645 => "ETSI EN 303 645",
            ComplianceStandard::IoTFoundation => "IoT Foundation",
            ComplianceStandard::BestPractices => "IoT Security Best Practices",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    PartiallyCompliant,
    NotApplicable,
    Unknown,
}

impl ComplianceStatus {
    pub fn as_str(&self) -> &str {
        match self {
            ComplianceStatus::Compliant => "Compliant",
            ComplianceStatus::NonCompliant => "Non-Compliant",
            ComplianceStatus::PartiallyCompliant => "Partially Compliant",
            ComplianceStatus::NotApplicable => "Not Applicable",
            ComplianceStatus::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheck {
    pub id: String,
    pub standard: ComplianceStandard,
    pub category: String,
    pub title: String,
    pub description: String,
    pub status: ComplianceStatus,
    pub severity: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub standard: ComplianceStandard,
    pub checks: Vec<ComplianceCheck>,
    pub total_checks: usize,
    pub compliant_count: usize,
    pub non_compliant_count: usize,
    pub partial_count: usize,
    pub compliance_score: f64,
}

pub struct IoTComplianceChecker;

impl IoTComplianceChecker {
    pub fn check_owasp_iot() -> ComplianceReport {
        let checks = vec![
            ComplianceCheck {
                id: "OWASP-I1".to_string(),
                standard: ComplianceStandard::OWASPIoT,
                category: "Authentication".to_string(),
                title: "Weak, guessable, or hardcoded passwords".to_string(),
                description: "IoT devices should not use default or hardcoded credentials"
                    .to_string(),
                status: ComplianceStatus::Unknown,
                severity: "CRITICAL".to_string(),
                recommendation: "Enforce strong, unique passwords and disable default credentials"
                    .to_string(),
            },
            ComplianceCheck {
                id: "OWASP-I2".to_string(),
                standard: ComplianceStandard::OWASPIoT,
                category: "Network Security".to_string(),
                title: "Insecure network services".to_string(),
                description: "Devices should minimize exposed network services".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "HIGH".to_string(),
                recommendation: "Disable unnecessary services and use firewalls to restrict access"
                    .to_string(),
            },
            ComplianceCheck {
                id: "OWASP-I3".to_string(),
                standard: ComplianceStandard::OWASPIoT,
                category: "Ecosystem".to_string(),
                title: "Insecure ecosystem interfaces".to_string(),
                description: "Web, mobile, and cloud interfaces should be secured".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "HIGH".to_string(),
                recommendation:
                    "Implement proper authentication and input validation on all interfaces"
                        .to_string(),
            },
            ComplianceCheck {
                id: "OWASP-I4".to_string(),
                standard: ComplianceStandard::OWASPIoT,
                category: "Privacy".to_string(),
                title: "Lack of secure update mechanism".to_string(),
                description: "Devices should support secure firmware updates".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "HIGH".to_string(),
                recommendation: "Implement signed firmware updates with rollback protection"
                    .to_string(),
            },
            ComplianceCheck {
                id: "OWASP-I5".to_string(),
                standard: ComplianceStandard::OWASPIoT,
                category: "Secure Communication".to_string(),
                title: "Use of insecure or outdated components".to_string(),
                description: "Devices should use up-to-date and secure libraries".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "MEDIUM".to_string(),
                recommendation: "Regularly update all software components and dependencies"
                    .to_string(),
            },
            ComplianceCheck {
                id: "OWASP-I6".to_string(),
                standard: ComplianceStandard::OWASPIoT,
                category: "Privacy".to_string(),
                title: "Insufficient privacy protection".to_string(),
                description: "User data should be properly protected".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "HIGH".to_string(),
                recommendation: "Implement data encryption and minimize data collection"
                    .to_string(),
            },
            ComplianceCheck {
                id: "OWASP-I7".to_string(),
                standard: ComplianceStandard::OWASPIoT,
                category: "Configuration".to_string(),
                title: "Insecure data transfer and storage".to_string(),
                description: "Data should be encrypted in transit and at rest".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "HIGH".to_string(),
                recommendation: "Use TLS for data in transit and encryption for data at rest"
                    .to_string(),
            },
            ComplianceCheck {
                id: "OWASP-I8".to_string(),
                standard: ComplianceStandard::OWASPIoT,
                category: "Configuration".to_string(),
                title: "Lack of device management".to_string(),
                description: "Devices should support secure management capabilities".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "MEDIUM".to_string(),
                recommendation: "Implement secure device management with audit logging".to_string(),
            },
            ComplianceCheck {
                id: "OWASP-I9".to_string(),
                standard: ComplianceStandard::OWASPIoT,
                category: "Physical Security".to_string(),
                title: "Insecure default settings".to_string(),
                description: "Devices should ship with secure default configurations".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "MEDIUM".to_string(),
                recommendation:
                    "Disable unnecessary features by default and enforce secure defaults"
                        .to_string(),
            },
            ComplianceCheck {
                id: "OWASP-I10".to_string(),
                standard: ComplianceStandard::OWASPIoT,
                category: "Physical Security".to_string(),
                title: "Lack of physical hardening".to_string(),
                description: "Devices should be physically tamper-resistant".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "LOW".to_string(),
                recommendation: "Implement tamper detection and secure debug interfaces"
                    .to_string(),
            },
        ];

        Self::build_report(ComplianceStandard::OWASPIoT, checks)
    }

    pub fn check_nist_iot() -> ComplianceReport {
        let checks = vec![
            ComplianceCheck {
                id: "NIST-IoT-1".to_string(),
                standard: ComplianceStandard::NISTIoT,
                category: "Device Security".to_string(),
                title: "Device identification and management".to_string(),
                description: "Each device should be uniquely identifiable and manageable"
                    .to_string(),
                status: ComplianceStatus::Unknown,
                severity: "HIGH".to_string(),
                recommendation: "Implement unique device identifiers and centralized management"
                    .to_string(),
            },
            ComplianceCheck {
                id: "NIST-IoT-2".to_string(),
                standard: ComplianceStandard::NISTIoT,
                category: "Device Security".to_string(),
                title: "Device configuration protection".to_string(),
                description: "Device configuration should be secured against unauthorized changes"
                    .to_string(),
                status: ComplianceStatus::Unknown,
                severity: "HIGH".to_string(),
                recommendation: "Implement configuration change auditing and access controls"
                    .to_string(),
            },
            ComplianceCheck {
                id: "NIST-IoT-3".to_string(),
                standard: ComplianceStandard::NISTIoT,
                category: "Data Protection".to_string(),
                title: "Data protection at rest and in transit".to_string(),
                description: "Sensitive data should be encrypted at rest and in transit"
                    .to_string(),
                status: ComplianceStatus::Unknown,
                severity: "HIGH".to_string(),
                recommendation: "Use industry-standard encryption algorithms for data protection"
                    .to_string(),
            },
            ComplianceCheck {
                id: "NIST-IoT-4".to_string(),
                standard: ComplianceStandard::NISTIoT,
                category: "Access Control".to_string(),
                title: "Logical access control".to_string(),
                description: "Access to device interfaces should be controlled".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "CRITICAL".to_string(),
                recommendation: "Implement role-based access control and strong authentication"
                    .to_string(),
            },
            ComplianceCheck {
                id: "NIST-IoT-5".to_string(),
                standard: ComplianceStandard::NISTIoT,
                category: "Software Security".to_string(),
                title: "Software update capability".to_string(),
                description: "Devices should support secure software updates".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "HIGH".to_string(),
                recommendation: "Implement automatic and secure firmware update mechanisms"
                    .to_string(),
            },
            ComplianceCheck {
                id: "NIST-IoT-6".to_string(),
                standard: ComplianceStandard::NISTIoT,
                category: "Network Security".to_string(),
                title: "Network security".to_string(),
                description: "Devices should minimize network attack surface".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "HIGH".to_string(),
                recommendation: "Disable unnecessary network services and use firewalls"
                    .to_string(),
            },
        ];

        Self::build_report(ComplianceStandard::NISTIoT, checks)
    }

    pub fn check_best_practices() -> ComplianceReport {
        let checks = vec![
            ComplianceCheck {
                id: "BP-1".to_string(),
                standard: ComplianceStandard::BestPractices,
                category: "Authentication".to_string(),
                title: "Change default passwords".to_string(),
                description: "All default passwords should be changed before deployment"
                    .to_string(),
                status: ComplianceStatus::Unknown,
                severity: "CRITICAL".to_string(),
                recommendation: "Enforce password change on first use".to_string(),
            },
            ComplianceCheck {
                id: "BP-2".to_string(),
                standard: ComplianceStandard::BestPractices,
                category: "Network".to_string(),
                title: "Disable unnecessary services".to_string(),
                description: "Unused network services should be disabled".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "MEDIUM".to_string(),
                recommendation: "Audit and disable services not required for operation".to_string(),
            },
            ComplianceCheck {
                id: "BP-3".to_string(),
                standard: ComplianceStandard::BestPractices,
                category: "Encryption".to_string(),
                title: "Enable encryption".to_string(),
                description: "All communications should use encryption".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "HIGH".to_string(),
                recommendation: "Use TLS/DTLS for all network communications".to_string(),
            },
            ComplianceCheck {
                id: "BP-4".to_string(),
                standard: ComplianceStandard::BestPractices,
                category: "Updates".to_string(),
                title: "Keep firmware updated".to_string(),
                description: "Device firmware should be kept up to date".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "HIGH".to_string(),
                recommendation: "Enable automatic updates or schedule regular update checks"
                    .to_string(),
            },
            ComplianceCheck {
                id: "BP-5".to_string(),
                standard: ComplianceStandard::BestPractices,
                category: "Logging".to_string(),
                title: "Enable security logging".to_string(),
                description: "Security events should be logged for audit purposes".to_string(),
                status: ComplianceStatus::Unknown,
                severity: "MEDIUM".to_string(),
                recommendation:
                    "Configure logging for authentication, configuration changes, and access"
                        .to_string(),
            },
        ];

        Self::build_report(ComplianceStandard::BestPractices, checks)
    }

    pub fn check_all_standards() -> Vec<ComplianceReport> {
        vec![
            Self::check_owasp_iot(),
            Self::check_nist_iot(),
            Self::check_best_practices(),
        ]
    }

    fn build_report(
        standard: ComplianceStandard,
        checks: Vec<ComplianceCheck>,
    ) -> ComplianceReport {
        let total_checks = checks.len();
        let compliant_count = checks
            .iter()
            .filter(|c| c.status == ComplianceStatus::Compliant)
            .count();
        let non_compliant_count = checks
            .iter()
            .filter(|c| c.status == ComplianceStatus::NonCompliant)
            .count();
        let partial_count = checks
            .iter()
            .filter(|c| c.status == ComplianceStatus::PartiallyCompliant)
            .count();

        let compliance_score = if total_checks > 0 {
            (compliant_count as f64 + partial_count as f64 * 0.5) / total_checks as f64 * 100.0
        } else {
            0.0
        };

        ComplianceReport {
            standard,
            checks,
            total_checks,
            compliant_count,
            non_compliant_count,
            partial_count,
            compliance_score,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_standard_as_str() {
        assert_eq!(ComplianceStandard::OWASPIoT.as_str(), "OWASP IoT Top 10");
        assert_eq!(ComplianceStandard::NISTIoT.as_str(), "NIST IoT Guidelines");
        assert_eq!(ComplianceStandard::ETSIEN303645.as_str(), "ETSI EN 303 645");
        assert_eq!(
            ComplianceStandard::BestPractices.as_str(),
            "IoT Security Best Practices"
        );
    }

    #[test]
    fn test_compliance_status_as_str() {
        assert_eq!(ComplianceStatus::Compliant.as_str(), "Compliant");
        assert_eq!(ComplianceStatus::NonCompliant.as_str(), "Non-Compliant");
        assert_eq!(
            ComplianceStatus::PartiallyCompliant.as_str(),
            "Partially Compliant"
        );
        assert_eq!(ComplianceStatus::NotApplicable.as_str(), "Not Applicable");
    }

    #[test]
    fn test_owasp_iot_checks() {
        let report = IoTComplianceChecker::check_owasp_iot();
        assert_eq!(report.standard, ComplianceStandard::OWASPIoT);
        assert_eq!(report.total_checks, 10);
        assert!(report.checks.iter().any(|c| c.id == "OWASP-I1"));
        assert!(report.checks.iter().any(|c| c.id == "OWASP-I10"));
    }

    #[test]
    fn test_nist_iot_checks() {
        let report = IoTComplianceChecker::check_nist_iot();
        assert_eq!(report.standard, ComplianceStandard::NISTIoT);
        assert_eq!(report.total_checks, 6);
        assert!(report.checks.iter().any(|c| c.id == "NIST-IoT-1"));
    }

    #[test]
    fn test_best_practices_checks() {
        let report = IoTComplianceChecker::check_best_practices();
        assert_eq!(report.standard, ComplianceStandard::BestPractices);
        assert_eq!(report.total_checks, 5);
        assert!(report.checks.iter().any(|c| c.id == "BP-1"));
    }

    #[test]
    fn test_check_all_standards() {
        let reports = IoTComplianceChecker::check_all_standards();
        assert_eq!(reports.len(), 3);
    }

    #[test]
    fn test_compliance_report_scoring() {
        let mut report = IoTComplianceChecker::check_best_practices();
        // All checks are Unknown so score should be 0
        assert_eq!(report.compliance_score, 0.0);

        // Manually set some statuses
        report.checks[0].status = ComplianceStatus::Compliant;
        report.checks[1].status = ComplianceStatus::PartiallyCompliant;
        report.checks[2].status = ComplianceStatus::NonCompliant;

        // Recalculate
        let compliant = report
            .checks
            .iter()
            .filter(|c| c.status == ComplianceStatus::Compliant)
            .count();
        let partial = report
            .checks
            .iter()
            .filter(|c| c.status == ComplianceStatus::PartiallyCompliant)
            .count();
        let score = (compliant as f64 + partial as f64 * 0.5) / report.total_checks as f64 * 100.0;
        assert!((score - 30.0).abs() < 0.01); // (1 + 0.5) / 5 * 100 = 30
    }

    #[test]
    fn test_check_serialization() {
        let report = IoTComplianceChecker::check_best_practices();
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("BestPractices") || json.contains("Best Practices"));
    }

    #[test]
    fn test_compliance_check_fields() {
        let report = IoTComplianceChecker::check_owasp_iot();
        let check = &report.checks[0];
        assert!(!check.id.is_empty());
        assert!(!check.title.is_empty());
        assert!(!check.description.is_empty());
        assert!(!check.severity.is_empty());
        assert!(!check.recommendation.is_empty());
    }
}
