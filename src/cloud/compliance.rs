use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

impl CloudProvider {
    pub fn as_str(&self) -> &str {
        match self {
            CloudProvider::Aws => "aws",
            CloudProvider::Azure => "azure",
            CloudProvider::Gcp => "gcp",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisBenchmarkResult {
    pub provider: CloudProvider,
    pub benchmark_version: String,
    pub total_controls: usize,
    pub passed: usize,
    pub failed: usize,
    pub not_applicable: usize,
    pub score: f64,
    pub controls: Vec<CisControl>,
}

impl CisBenchmarkResult {
    pub fn new(provider: CloudProvider, version: &str) -> Self {
        Self {
            provider,
            benchmark_version: version.to_string(),
            total_controls: 0,
            passed: 0,
            failed: 0,
            not_applicable: 0,
            score: 0.0,
            controls: Vec::new(),
        }
    }

    pub fn add_control(&mut self, control: CisControl) {
        self.total_controls += 1;
        match control.status {
            CisControlStatus::Pass => self.passed += 1,
            CisControlStatus::Fail => self.failed += 1,
            CisControlStatus::NotApplicable => self.not_applicable += 1,
        }
        self.controls.push(control);
        self.recalculate_score();
    }

    fn recalculate_score(&mut self) {
        let applicable = self.total_controls - self.not_applicable;
        if applicable > 0 {
            self.score = (self.passed as f64 / applicable as f64) * 100.0;
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "{} CIS v{}: {}/{} passed ({:.1}%)",
            self.provider.as_str(),
            self.benchmark_version,
            self.passed,
            self.total_controls - self.not_applicable,
            self.score
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisControl {
    pub id: String,
    pub title: String,
    pub description: String,
    pub status: CisControlStatus,
    pub severity: String,
    pub finding_details: Option<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CisControlStatus {
    Pass,
    Fail,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudPostureReport {
    pub provider: CloudProvider,
    pub benchmark: CisBenchmarkResult,
    pub posture_findings: Vec<PostureFinding>,
    pub overall_score: f64,
    pub scan_timestamp: String,
}

impl CloudPostureReport {
    pub fn critical_findings(&self) -> Vec<&PostureFinding> {
        self.posture_findings.iter().filter(|f| f.severity == PostureSeverity::Critical).collect()
    }

    pub fn high_findings(&self) -> Vec<&PostureFinding> {
        self.posture_findings.iter().filter(|f| f.severity == PostureSeverity::High).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureFinding {
    pub category: String,
    pub severity: PostureSeverity,
    pub resource: String,
    pub description: String,
    pub recommendation: String,
    pub cis_control_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum PostureSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl PostureSeverity {
    pub fn as_str(&self) -> &str {
        match self {
            PostureSeverity::Low => "LOW",
            PostureSeverity::Medium => "MEDIUM",
            PostureSeverity::High => "HIGH",
            PostureSeverity::Critical => "CRITICAL",
        }
    }
}

pub struct CloudComplianceEngine;

impl CloudComplianceEngine {
    pub fn aws_cis_benchmark() -> CisBenchmarkResult {
        let mut result = CisBenchmarkResult::new(CloudProvider::Aws, "2.0.0");

        result.add_control(CisControl {
            id: "1.1".to_string(),
            title: "Maintain current contact details".to_string(),
            description: "Ensure contact email and telephone details for AWS accounts are current".to_string(),
            status: CisControlStatus::Pass,
            severity: "LOW".to_string(),
            finding_details: None,
            remediation: "Update AWS account contact information".to_string(),
        });

        result.add_control(CisControl {
            id: "1.4".to_string(),
            title: "Ensure no root user access key exists".to_string(),
            description: "The root account has unrestricted access to all resources".to_string(),
            status: CisControlStatus::Fail,
            severity: "CRITICAL".to_string(),
            finding_details: Some("Root account has 1 active access key".to_string()),
            remediation: "Delete root access keys and use IAM users".to_string(),
        });

        result.add_control(CisControl {
            id: "1.5".to_string(),
            title: "Ensure MFA is enabled for root".to_string(),
            description: "The root account is the most privileged user".to_string(),
            status: CisControlStatus::Pass,
            severity: "CRITICAL".to_string(),
            finding_details: None,
            remediation: "Enable MFA on the root account".to_string(),
        });

        result.add_control(CisControl {
            id: "2.1.1".to_string(),
            title: "S3 bucket access logging enabled".to_string(),
            description: "Ensure S3 bucket access logging is enabled".to_string(),
            status: CisControlStatus::Fail,
            severity: "MEDIUM".to_string(),
            finding_details: Some("3 of 5 buckets do not have access logging enabled".to_string()),
            remediation: "Enable server access logging for all S3 buckets".to_string(),
        });

        result.add_control(CisControl {
            id: "2.1.2".to_string(),
            title: "S3 bucket versioning enabled".to_string(),
            description: "Ensure S3 bucket versioning is enabled".to_string(),
            status: CisControlStatus::Pass,
            severity: "MEDIUM".to_string(),
            finding_details: None,
            remediation: "Enable versioning on all S3 buckets".to_string(),
        });

        result.add_control(CisControl {
            id: "3.1".to_string(),
            title: "Ensure CloudTrail is enabled in all regions".to_string(),
            description: "AWS CloudTrail provides a record of actions taken by a user, role, or AWS service".to_string(),
            status: CisControlStatus::Pass,
            severity: "HIGH".to_string(),
            finding_details: None,
            remediation: "Enable CloudTrail in all regions".to_string(),
        });

        result.add_control(CisControl {
            id: "3.7".to_string(),
            title: "Ensure CloudTrail logs are encrypted".to_string(),
            description: "CloudTrail log files should be encrypted using SSE-KMS".to_string(),
            status: CisControlStatus::Fail,
            severity: "MEDIUM".to_string(),
            finding_details: Some("CloudTrail 'main' does not have SSE-KMS encryption".to_string()),
            remediation: "Enable SSE-KMS encryption for CloudTrail logs".to_string(),
        });

        result.add_control(CisControl {
            id: "5.1".to_string(),
            title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22".to_string(),
            description: "Security groups should not allow unrestricted access to SSH".to_string(),
            status: CisControlStatus::Fail,
            severity: "CRITICAL".to_string(),
            finding_details: Some("2 security groups allow SSH from 0.0.0.0/0".to_string()),
            remediation: "Restrict SSH access to known IP ranges".to_string(),
        });

        result.add_control(CisControl {
            id: "5.2".to_string(),
            title: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389".to_string(),
            description: "Security groups should not allow unrestricted access to RDP".to_string(),
            status: CisControlStatus::Pass,
            severity: "CRITICAL".to_string(),
            finding_details: None,
            remediation: "Restrict RDP access to known IP ranges".to_string(),
        });

        result
    }

    pub fn azure_cis_benchmark() -> CisBenchmarkResult {
        let mut result = CisBenchmarkResult::new(CloudProvider::Azure, "2.1.0");

        result.add_control(CisControl {
            id: "1.1".to_string(),
            title: "Ensure multifactor authentication is enabled for all privileged users".to_string(),
            description: "Enable MFA for all privileged accounts".to_string(),
            status: CisControlStatus::Fail,
            severity: "CRITICAL".to_string(),
            finding_details: Some("3 privileged users do not have MFA enabled".to_string()),
            remediation: "Enable Azure AD MFA for all privileged users".to_string(),
        });

        result.add_control(CisControl {
            id: "1.3".to_string(),
            title: "Ensure guest users are reviewed regularly".to_string(),
            description: "Review guest user access regularly".to_string(),
            status: CisControlStatus::Fail,
            severity: "MEDIUM".to_string(),
            finding_details: Some("5 guest users have not been reviewed in 90+ days".to_string()),
            remediation: "Review and remove unnecessary guest accounts".to_string(),
        });

        result.add_control(CisControl {
            id: "2.1".to_string(),
            title: "Ensure Azure Activity Log Retention is set for 365 days or greater".to_string(),
            description: "Activity logs should be retained for compliance".to_string(),
            status: CisControlStatus::Pass,
            severity: "MEDIUM".to_string(),
            finding_details: None,
            remediation: "Set activity log retention to 365+ days".to_string(),
        });

        result.add_control(CisControl {
            id: "4.1".to_string(),
            title: "Ensure that 'Secure transfer required' is set to 'Enabled' for storage accounts".to_string(),
            description: "Storage accounts should require secure transfer".to_string(),
            status: CisControlStatus::Pass,
            severity: "HIGH".to_string(),
            finding_details: None,
            remediation: "Enable secure transfer on all storage accounts".to_string(),
        });

        result.add_control(CisControl {
            id: "6.1".to_string(),
            title: "Ensure that SSH access is restricted from the internet".to_string(),
            description: "NSGs should not allow unrestricted SSH access".to_string(),
            status: CisControlStatus::Fail,
            severity: "CRITICAL".to_string(),
            finding_details: Some("1 NSG allows SSH from Internet".to_string()),
            remediation: "Restrict SSH access in NSGs to known IPs".to_string(),
        });

        result
    }

    pub fn gcp_cis_benchmark() -> CisBenchmarkResult {
        let mut result = CisBenchmarkResult::new(CloudProvider::Gcp, "2.0.0");

        result.add_control(CisControl {
            id: "1.1".to_string(),
            title: "Ensure that corporate login credentials are used".to_string(),
            description: "Use corporate credentials instead of Gmail accounts".to_string(),
            status: CisControlStatus::Pass,
            severity: "MEDIUM".to_string(),
            finding_details: None,
            remediation: "Configure Cloud Identity or Google Workspace".to_string(),
        });

        result.add_control(CisControl {
            id: "1.4".to_string(),
            title: "Ensure that there are only GCP-managed service account keys".to_string(),
            description: "User-managed service account keys should not be used".to_string(),
            status: CisControlStatus::Fail,
            severity: "HIGH".to_string(),
            finding_details: Some("2 user-managed service account keys found".to_string()),
            remediation: "Delete user-managed keys and use GCP-managed keys".to_string(),
        });

        result.add_control(CisControl {
            id: "3.1".to_string(),
            title: "Ensure that the default network does not exist in a project".to_string(),
            description: "The default network should be deleted".to_string(),
            status: CisControlStatus::Fail,
            severity: "HIGH".to_string(),
            finding_details: Some("Default network exists in project".to_string()),
            remediation: "Delete the default VPC network".to_string(),
        });

        result.add_control(CisControl {
            id: "3.6".to_string(),
            title: "Ensure SSH access is restricted from the internet".to_string(),
            description: "Firewall rules should not allow unrestricted SSH".to_string(),
            status: CisControlStatus::Fail,
            severity: "CRITICAL".to_string(),
            finding_details: Some("Firewall rule 'allow-ssh' permits SSH from 0.0.0.0/0".to_string()),
            remediation: "Restrict SSH firewall rules to known IP ranges".to_string(),
        });

        result.add_control(CisControl {
            id: "4.1".to_string(),
            title: "Ensure that Cloud Audit Logging is configured properly".to_string(),
            description: "Audit logs should be enabled for all services".to_string(),
            status: CisControlStatus::Pass,
            severity: "HIGH".to_string(),
            finding_details: None,
            remediation: "Enable Cloud Audit Logs for all services".to_string(),
        });

        result.add_control(CisControl {
            id: "5.1".to_string(),
            title: "Ensure that Cloud Storage bucket is not anonymously or publicly accessible".to_string(),
            description: "GCS buckets should not be publicly accessible".to_string(),
            status: CisControlStatus::Fail,
            severity: "CRITICAL".to_string(),
            finding_details: Some("1 bucket has allUsers with objectViewer role".to_string()),
            remediation: "Remove public access from GCS buckets".to_string(),
        });

        result
    }

    pub fn generate_posture_report(provider: CloudProvider, benchmark: CisBenchmarkResult) -> CloudPostureReport {
        let mut findings = Vec::new();

        for control in &benchmark.controls {
            if control.status == CisControlStatus::Fail {
                let severity = match control.severity.as_str() {
                    "CRITICAL" => PostureSeverity::Critical,
                    "HIGH" => PostureSeverity::High,
                    "MEDIUM" => PostureSeverity::Medium,
                    _ => PostureSeverity::Low,
                };

                findings.push(PostureFinding {
                    category: format!("CIS {}", benchmark.benchmark_version),
                    severity,
                    resource: control.id.clone(),
                    description: control.description.clone(),
                    recommendation: control.remediation.clone(),
                    cis_control_id: Some(control.id.clone()),
                });
            }
        }

        CloudPostureReport {
            provider,
            benchmark: benchmark.clone(),
            overall_score: benchmark.score,
            posture_findings: findings,
            scan_timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_cis_benchmark() {
        let result = CloudComplianceEngine::aws_cis_benchmark();
        assert_eq!(result.provider, CloudProvider::Aws);
        assert!(result.total_controls >= 5);
        assert!(result.failed > 0);
        assert!(result.passed > 0);
        assert!(result.score > 0.0 && result.score < 100.0);
    }

    #[test]
    fn test_aws_cis_summary() {
        let result = CloudComplianceEngine::aws_cis_benchmark();
        let summary = result.summary();
        assert!(summary.contains("aws"));
        assert!(summary.contains("CIS"));
        assert!(summary.contains("%"));
    }

    #[test]
    fn test_azure_cis_benchmark() {
        let result = CloudComplianceEngine::azure_cis_benchmark();
        assert_eq!(result.provider, CloudProvider::Azure);
        assert!(result.total_controls >= 5);
        assert!(result.failed > 0);
    }

    #[test]
    fn test_gcp_cis_benchmark() {
        let result = CloudComplianceEngine::gcp_cis_benchmark();
        assert_eq!(result.provider, CloudProvider::Gcp);
        assert!(result.total_controls >= 5);
        assert!(result.failed > 0);
    }

    #[test]
    fn test_cis_benchmark_score_calculation() {
        let mut result = CisBenchmarkResult::new(CloudProvider::Aws, "1.0");
        result.add_control(CisControl {
            id: "1".into(), title: "".into(), description: "".into(),
            status: CisControlStatus::Pass, severity: "HIGH".into(),
            finding_details: None, remediation: "".into(),
        });
        result.add_control(CisControl {
            id: "2".into(), title: "".into(), description: "".into(),
            status: CisControlStatus::Fail, severity: "HIGH".into(),
            finding_details: None, remediation: "".into(),
        });
        assert_eq!(result.score, 50.0);
    }

    #[test]
    fn test_cis_benchmark_na_handling() {
        let mut result = CisBenchmarkResult::new(CloudProvider::Aws, "1.0");
        result.add_control(CisControl {
            id: "1".into(), title: "".into(), description: "".into(),
            status: CisControlStatus::Pass, severity: "HIGH".into(),
            finding_details: None, remediation: "".into(),
        });
        result.add_control(CisControl {
            id: "2".into(), title: "".into(), description: "".into(),
            status: CisControlStatus::NotApplicable, severity: "LOW".into(),
            finding_details: None, remediation: "".into(),
        });
        assert_eq!(result.score, 100.0);
        assert_eq!(result.not_applicable, 1);
    }

    #[test]
    fn test_posture_report_generation() {
        let benchmark = CloudComplianceEngine::aws_cis_benchmark();
        let report = CloudComplianceEngine::generate_posture_report(CloudProvider::Aws, benchmark);
        assert!(report.posture_findings.len() > 0);
        assert!(report.critical_findings().len() > 0 || report.high_findings().len() > 0);
    }

    #[test]
    fn test_posture_report_no_findings_when_all_pass() {
        let mut benchmark = CisBenchmarkResult::new(CloudProvider::Aws, "1.0");
        benchmark.add_control(CisControl {
            id: "1".into(), title: "".into(), description: "".into(),
            status: CisControlStatus::Pass, severity: "HIGH".into(),
            finding_details: None, remediation: "".into(),
        });
        let report = CloudComplianceEngine::generate_posture_report(CloudProvider::Aws, benchmark);
        assert_eq!(report.posture_findings.len(), 0);
    }

    #[test]
    fn test_cloud_provider_as_str() {
        assert_eq!(CloudProvider::Aws.as_str(), "aws");
        assert_eq!(CloudProvider::Azure.as_str(), "azure");
        assert_eq!(CloudProvider::Gcp.as_str(), "gcp");
    }

    #[test]
    fn test_posture_severity_ordering() {
        assert!(PostureSeverity::Critical > PostureSeverity::High);
        assert!(PostureSeverity::High > PostureSeverity::Medium);
        assert!(PostureSeverity::Medium > PostureSeverity::Low);
    }
}
