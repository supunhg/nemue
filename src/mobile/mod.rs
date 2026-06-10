//! Mobile Device Security Scanning Module
//!
//! Provides comprehensive mobile device security scanning including:
//! - Android ADB enumeration and security assessment
//! - iOS service discovery and configuration analysis
//! - OWASP Mobile compliance checking
//! - Mobile device fingerprinting and identification

pub mod android;
pub mod ios;
pub mod compliance;
pub mod fingerprint;

pub use android::{AndroidScanner, AndroidConfig, AndroidResults, AdbDevice, AndroidService, AndroidVulnerability, AndroidSecurityFinding};
pub use ios::{IosScanner, IosConfig, IosResults, IosDevice, IosService, IosVulnerability, IosConfiguration};
pub use compliance::{MobileComplianceScanner, MobileComplianceConfig, MobileComplianceReport, MobileComplianceCheck, MobileComplianceResult, MobileBenchmarkType};
pub use fingerprint::{MobileFingerprinter, FingerprintConfig, FingerprintResults, DeviceFingerprint, DeviceType, OsInfo};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum MobileSeverity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl PartialOrd for MobileSeverity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MobileSeverity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_u8().cmp(&other.as_u8())
    }
}

impl MobileSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            MobileSeverity::Critical => "CRITICAL",
            MobileSeverity::High => "HIGH",
            MobileSeverity::Medium => "MEDIUM",
            MobileSeverity::Low => "LOW",
            MobileSeverity::Info => "INFO",
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            MobileSeverity::Info => 0,
            MobileSeverity::Low => 1,
            MobileSeverity::Medium => 2,
            MobileSeverity::High => 3,
            MobileSeverity::Critical => 4,
        }
    }
}

impl std::fmt::Display for MobileSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileSecurityAssessment {
    pub android_results: Option<AndroidResults>,
    pub ios_results: Option<IosResults>,
    pub compliance_report: Option<MobileComplianceReport>,
    pub fingerprint_results: Option<FingerprintResults>,
    pub overall_score: u8,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

impl MobileSecurityAssessment {
    pub fn new() -> Self {
        Self {
            android_results: None,
            ios_results: None,
            compliance_report: None,
            fingerprint_results: None,
            overall_score: 100,
            total_findings: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
        }
    }

    pub fn calculate_score(&mut self) {
        let mut deductions = 0u8;
        self.total_findings = 0;
        self.critical_count = 0;
        self.high_count = 0;
        self.medium_count = 0;
        self.low_count = 0;

        if let Some(ref android) = self.android_results {
            for finding in &android.security_findings {
                self.total_findings += 1;
                match finding.severity {
                    MobileSeverity::Critical => { deductions = deductions.saturating_add(15); self.critical_count += 1; }
                    MobileSeverity::High => { deductions = deductions.saturating_add(10); self.high_count += 1; }
                    MobileSeverity::Medium => { deductions = deductions.saturating_add(5); self.medium_count += 1; }
                    MobileSeverity::Low => { deductions = deductions.saturating_add(2); self.low_count += 1; }
                    MobileSeverity::Info => {}
                }
            }
        }

        if let Some(ref ios) = self.ios_results {
            for finding in &ios.security_findings {
                self.total_findings += 1;
                match finding.severity {
                    MobileSeverity::Critical => { deductions = deductions.saturating_add(15); self.critical_count += 1; }
                    MobileSeverity::High => { deductions = deductions.saturating_add(10); self.high_count += 1; }
                    MobileSeverity::Medium => { deductions = deductions.saturating_add(5); self.medium_count += 1; }
                    MobileSeverity::Low => { deductions = deductions.saturating_add(2); self.low_count += 1; }
                    MobileSeverity::Info => {}
                }
            }
        }

        self.overall_score = 100u8.saturating_sub(deductions);
    }
}

impl Default for MobileSecurityAssessment {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobile_severity_ordering() {
        assert!(MobileSeverity::Critical > MobileSeverity::High);
        assert!(MobileSeverity::High > MobileSeverity::Medium);
        assert!(MobileSeverity::Medium > MobileSeverity::Low);
        assert!(MobileSeverity::Low > MobileSeverity::Info);
    }

    #[test]
    fn test_mobile_severity_display() {
        assert_eq!(format!("{}", MobileSeverity::Critical), "CRITICAL");
        assert_eq!(format!("{}", MobileSeverity::High), "HIGH");
        assert_eq!(format!("{}", MobileSeverity::Medium), "MEDIUM");
        assert_eq!(format!("{}", MobileSeverity::Low), "LOW");
        assert_eq!(format!("{}", MobileSeverity::Info), "INFO");
    }

    #[test]
    fn test_assessment_new() {
        let assessment = MobileSecurityAssessment::new();
        assert_eq!(assessment.overall_score, 100);
        assert_eq!(assessment.total_findings, 0);
    }

    #[test]
    fn test_assessment_score_calculation() {
        let mut assessment = MobileSecurityAssessment::new();
        let mut android_results = AndroidResults::default();
        android_results.security_findings.push(AndroidSecurityFinding {
            title: "Test".to_string(),
            description: "Test".to_string(),
            severity: MobileSeverity::Critical,
            category: "test".to_string(),
            recommendation: "Fix it".to_string(),
        });
        assessment.android_results = Some(android_results);
        assessment.calculate_score();

        assert_eq!(assessment.overall_score, 85);
        assert_eq!(assessment.total_findings, 1);
        assert_eq!(assessment.critical_count, 1);
    }

    #[test]
    fn test_assessment_default() {
        let assessment = MobileSecurityAssessment::default();
        assert_eq!(assessment.overall_score, 100);
    }
}
