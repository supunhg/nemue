//! Container and Kubernetes Security Scanning Module
//!
//! Provides comprehensive container security scanning including:
//! - Docker daemon enumeration and security assessment
//! - Kubernetes API server and resource enumeration
//! - CIS Docker and Kubernetes benchmark compliance
//! - Container runtime scanning (containerd, CRI-O, Podman)

pub mod docker;
pub mod kubernetes;
pub mod compliance;
pub mod runtime;

pub use docker::{DockerScanner, DockerConfig, DockerResults, DockerContainer, DockerImage, DockerNetwork, DockerVolume, DockerSecurityFinding};
pub use kubernetes::{KubernetesScanner, KubeConfig, KubernetesResults, KubePod, KubeService, KubeDeployment, KubeRbacAssessment, KubeSecurityFinding};
pub use compliance::{ComplianceScanner, ComplianceConfig, ComplianceReport, ComplianceCheck, ComplianceResult, BenchmarkType};
pub use runtime::{RuntimeScanner, RuntimeConfig, RuntimeResults, RuntimeType, RuntimeFinding};

use serde::{Deserialize, Serialize};

/// Severity levels for container security findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContainerSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl PartialOrd for ContainerSeverity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ContainerSeverity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_u8().cmp(&other.as_u8())
    }
}

impl ContainerSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContainerSeverity::Critical => "CRITICAL",
            ContainerSeverity::High => "HIGH",
            ContainerSeverity::Medium => "MEDIUM",
            ContainerSeverity::Low => "LOW",
            ContainerSeverity::Info => "INFO",
        }
    }

    fn as_u8(&self) -> u8 {
        match self {
            ContainerSeverity::Info => 0,
            ContainerSeverity::Low => 1,
            ContainerSeverity::Medium => 2,
            ContainerSeverity::High => 3,
            ContainerSeverity::Critical => 4,
        }
    }
}

impl std::fmt::Display for ContainerSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Overall container security assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecurityAssessment {
    pub docker_results: Option<DockerResults>,
    pub kubernetes_results: Option<KubernetesResults>,
    pub runtime_results: Option<RuntimeResults>,
    pub compliance_report: Option<ComplianceReport>,
    pub overall_score: u8,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

impl ContainerSecurityAssessment {
    pub fn new() -> Self {
        Self {
            docker_results: None,
            kubernetes_results: None,
            runtime_results: None,
            compliance_report: None,
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

        if let Some(ref docker) = self.docker_results {
            for finding in &docker.security_findings {
                self.total_findings += 1;
                match finding.severity {
                    ContainerSeverity::Critical => {
                        deductions = deductions.saturating_add(15);
                        self.critical_count += 1;
                    }
                    ContainerSeverity::High => {
                        deductions = deductions.saturating_add(10);
                        self.high_count += 1;
                    }
                    ContainerSeverity::Medium => {
                        deductions = deductions.saturating_add(5);
                        self.medium_count += 1;
                    }
                    ContainerSeverity::Low => {
                        deductions = deductions.saturating_add(2);
                        self.low_count += 1;
                    }
                    ContainerSeverity::Info => {}
                }
            }
        }

        if let Some(ref k8s) = self.kubernetes_results {
            for finding in &k8s.security_findings {
                self.total_findings += 1;
                match finding.severity {
                    ContainerSeverity::Critical => {
                        deductions = deductions.saturating_add(15);
                        self.critical_count += 1;
                    }
                    ContainerSeverity::High => {
                        deductions = deductions.saturating_add(10);
                        self.high_count += 1;
                    }
                    ContainerSeverity::Medium => {
                        deductions = deductions.saturating_add(5);
                        self.medium_count += 1;
                    }
                    ContainerSeverity::Low => {
                        deductions = deductions.saturating_add(2);
                        self.low_count += 1;
                    }
                    ContainerSeverity::Info => {}
                }
            }
        }

        if let Some(ref runtime) = self.runtime_results {
            for finding in &runtime.findings {
                self.total_findings += 1;
                match finding.severity {
                    ContainerSeverity::Critical => {
                        deductions = deductions.saturating_add(15);
                        self.critical_count += 1;
                    }
                    ContainerSeverity::High => {
                        deductions = deductions.saturating_add(10);
                        self.high_count += 1;
                    }
                    ContainerSeverity::Medium => {
                        deductions = deductions.saturating_add(5);
                        self.medium_count += 1;
                    }
                    ContainerSeverity::Low => {
                        deductions = deductions.saturating_add(2);
                        self.low_count += 1;
                    }
                    ContainerSeverity::Info => {}
                }
            }
        }

        self.overall_score = 100u8.saturating_sub(deductions);
    }
}

impl Default for ContainerSecurityAssessment {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::docker::DockerSecurityFinding;

    #[test]
    fn test_severity_ordering() {
        assert!(ContainerSeverity::Critical > ContainerSeverity::High);
        assert!(ContainerSeverity::High > ContainerSeverity::Medium);
        assert!(ContainerSeverity::Medium > ContainerSeverity::Low);
        assert!(ContainerSeverity::Low > ContainerSeverity::Info);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", ContainerSeverity::Critical), "CRITICAL");
        assert_eq!(format!("{}", ContainerSeverity::High), "HIGH");
        assert_eq!(format!("{}", ContainerSeverity::Medium), "MEDIUM");
        assert_eq!(format!("{}", ContainerSeverity::Low), "LOW");
        assert_eq!(format!("{}", ContainerSeverity::Info), "INFO");
    }

    #[test]
    fn test_assessment_new() {
        let assessment = ContainerSecurityAssessment::new();
        assert_eq!(assessment.overall_score, 100);
        assert_eq!(assessment.total_findings, 0);
    }

    #[test]
    fn test_assessment_score_calculation() {
        let mut assessment = ContainerSecurityAssessment::new();
        let mut docker_results = DockerResults::default();
        docker_results.security_findings.push(DockerSecurityFinding {
            title: "Test".to_string(),
            description: "Test".to_string(),
            severity: ContainerSeverity::Critical,
            category: "test".to_string(),
            recommendation: "Fix it".to_string(),
        });
        assessment.docker_results = Some(docker_results);
        assessment.calculate_score();

        assert_eq!(assessment.overall_score, 85);
        assert_eq!(assessment.total_findings, 1);
        assert_eq!(assessment.critical_count, 1);
    }

    #[test]
    fn test_assessment_default() {
        let assessment = ContainerSecurityAssessment::default();
        assert_eq!(assessment.overall_score, 100);
    }
}
