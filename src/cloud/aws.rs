#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsConfig {
    pub region: String,
    pub profile: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub endpoint_url: Option<String>,
}

impl Default for AwsConfig {
    fn default() -> Self {
        Self {
            region: "us-east-1".to_string(),
            profile: None,
            access_key_id: None,
            secret_access_key: None,
            session_token: None,
            endpoint_url: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Bucket {
    pub name: String,
    pub region: Option<String>,
    pub creation_date: Option<String>,
    pub public_access: S3PublicAccess,
    pub encryption: S3EncryptionStatus,
    pub versioning: bool,
    pub logging: bool,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum S3PublicAccess {
    Private,
    PublicRead,
    PublicReadWrite,
    AuthenticatedRead,
    Unknown,
}

impl S3PublicAccess {
    pub fn is_public(&self) -> bool {
        matches!(
            self,
            S3PublicAccess::PublicRead | S3PublicAccess::PublicReadWrite
        )
    }

    pub fn severity_label(&self) -> &str {
        match self {
            S3PublicAccess::PublicReadWrite => "CRITICAL",
            S3PublicAccess::PublicRead => "HIGH",
            S3PublicAccess::AuthenticatedRead => "MEDIUM",
            S3PublicAccess::Private => "NONE",
            S3PublicAccess::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum S3EncryptionStatus {
    SseS3,
    SseKms,
    SseC,
    None,
    Unknown,
}

impl S3EncryptionStatus {
    pub fn is_encrypted(&self) -> bool {
        !matches!(self, S3EncryptionStatus::None | S3EncryptionStatus::Unknown)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamFinding {
    pub finding_type: IamFindingType,
    pub resource: String,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IamFindingType {
    RootUserUsage,
    NoMfa,
    OverlyPermissivePolicy,
    UnusedCredentials,
    PasswordPolicyWeak,
    AdminAccessKey,
    InlinePolicy,
    CrossAccountAccess,
    ServiceWithoutRole,
}

impl IamFindingType {
    pub fn as_str(&self) -> &str {
        match self {
            IamFindingType::RootUserUsage => "root-user-usage",
            IamFindingType::NoMfa => "no-mfa",
            IamFindingType::OverlyPermissivePolicy => "overly-permissive-policy",
            IamFindingType::UnusedCredentials => "unused-credentials",
            IamFindingType::PasswordPolicyWeak => "password-policy-weak",
            IamFindingType::AdminAccessKey => "admin-access-key",
            IamFindingType::InlinePolicy => "inline-policy",
            IamFindingType::CrossAccountAccess => "cross-account-access",
            IamFindingType::ServiceWithoutRole => "service-without-role",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGroupFinding {
    pub group_id: String,
    pub group_name: String,
    pub vpc_id: Option<String>,
    pub finding_type: SecurityGroupFindingType,
    pub rule_description: String,
    pub port_range: String,
    pub protocol: String,
    pub source: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityGroupFindingType {
    OpenToWorld,
    UnrestrictedIngress,
    UnrestrictedEgress,
    UnrestrictedIcmp,
    UnrestrictedRdp,
    UnrestrictedSsh,
    DefaultSecurityGroup,
    UnusedSecurityGroup,
}

impl SecurityGroupFindingType {
    pub fn as_str(&self) -> &str {
        match self {
            SecurityGroupFindingType::OpenToWorld => "open-to-world",
            SecurityGroupFindingType::UnrestrictedIngress => "unrestricted-ingress",
            SecurityGroupFindingType::UnrestrictedEgress => "unrestricted-egress",
            SecurityGroupFindingType::UnrestrictedIcmp => "unrestricted-icmp",
            SecurityGroupFindingType::UnrestrictedRdp => "unrestricted-rdp",
            SecurityGroupFindingType::UnrestrictedSsh => "unrestricted-ssh",
            SecurityGroupFindingType::DefaultSecurityGroup => "default-security-group",
            SecurityGroupFindingType::UnusedSecurityGroup => "unused-security-group",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudTrailFinding {
    pub trail_name: String,
    pub finding_type: CloudTrailFindingType,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CloudTrailFindingType {
    NotEnabled,
    NotLoggingAllRegions,
    NoLogFileValidation,
    NoEncryption,
    NoS3AccessLogging,
    MultiRegionNotEnabled,
    NoGlobalServiceEvents,
}

impl CloudTrailFindingType {
    pub fn as_str(&self) -> &str {
        match self {
            CloudTrailFindingType::NotEnabled => "not-enabled",
            CloudTrailFindingType::NotLoggingAllRegions => "not-logging-all-regions",
            CloudTrailFindingType::NoLogFileValidation => "no-log-file-validation",
            CloudTrailFindingType::NoEncryption => "no-encryption",
            CloudTrailFindingType::NoS3AccessLogging => "no-s3-access-logging",
            CloudTrailFindingType::MultiRegionNotEnabled => "multi-region-not-enabled",
            CloudTrailFindingType::NoGlobalServiceEvents => "no-global-service-events",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsScanReport {
    pub config: AwsConfig,
    pub buckets: Vec<S3Bucket>,
    pub iam_findings: Vec<IamFinding>,
    pub sg_findings: Vec<SecurityGroupFinding>,
    pub cloudtrail_findings: Vec<CloudTrailFinding>,
    pub scan_timestamp: String,
}

impl AwsScanReport {
    pub fn total_findings(&self) -> usize {
        self.iam_findings.len() + self.sg_findings.len() + self.cloudtrail_findings.len()
    }

    pub fn critical_count(&self) -> usize {
        self.iam_findings
            .iter()
            .filter(|f| f.severity == "CRITICAL")
            .count()
            + self
                .sg_findings
                .iter()
                .filter(|f| f.severity == "CRITICAL")
                .count()
            + self
                .cloudtrail_findings
                .iter()
                .filter(|f| f.severity == "CRITICAL")
                .count()
    }

    pub fn high_count(&self) -> usize {
        self.iam_findings
            .iter()
            .filter(|f| f.severity == "HIGH")
            .count()
            + self
                .sg_findings
                .iter()
                .filter(|f| f.severity == "HIGH")
                .count()
            + self
                .cloudtrail_findings
                .iter()
                .filter(|f| f.severity == "HIGH")
                .count()
    }
}

pub struct AwsScanner {
    config: AwsConfig,
}

impl AwsScanner {
    pub fn new(config: AwsConfig) -> Self {
        Self { config }
    }

    pub fn analyze_s3_bucket(
        bucket_name: &str,
        public_acl: bool,
        encrypted: bool,
        versioning: bool,
        logging: bool,
    ) -> S3Bucket {
        S3Bucket {
            name: bucket_name.to_string(),
            region: None,
            creation_date: None,
            public_access: if public_acl {
                S3PublicAccess::PublicRead
            } else {
                S3PublicAccess::Private
            },
            encryption: if encrypted {
                S3EncryptionStatus::SseS3
            } else {
                S3EncryptionStatus::None
            },
            versioning,
            logging,
            tags: HashMap::new(),
        }
    }

    pub fn check_iam_misconfigs(users: &[(&str, bool, bool, u64, bool)]) -> Vec<IamFinding> {
        let mut findings = Vec::new();

        for &(username, has_mfa, is_active, days_since_last_use, has_admin) in users {
            if !has_mfa {
                findings.push(IamFinding {
                    finding_type: IamFindingType::NoMfa,
                    resource: username.to_string(),
                    severity: "HIGH".to_string(),
                    description: format!("IAM user '{}' does not have MFA enabled", username),
                    recommendation: "Enable MFA for all IAM users".to_string(),
                });
            }

            if !is_active && days_since_last_use > 90 {
                findings.push(IamFinding {
                    finding_type: IamFindingType::UnusedCredentials,
                    resource: username.to_string(),
                    severity: "MEDIUM".to_string(),
                    description: format!(
                        "IAM user '{}' has not been used in {} days",
                        username, days_since_last_use
                    ),
                    recommendation: "Remove or deactivate unused IAM credentials".to_string(),
                });
            }

            if has_admin {
                findings.push(IamFinding {
                    finding_type: IamFindingType::OverlyPermissivePolicy,
                    resource: username.to_string(),
                    severity: "HIGH".to_string(),
                    description: format!("IAM user '{}' has administrator access", username),
                    recommendation: "Apply least-privilege principle; use specific policies instead of AdministratorAccess".to_string(),
                });
            }
        }

        findings
    }

    pub fn check_password_policy(
        min_length: u32,
        require_symbols: bool,
        require_numbers: bool,
        require_uppercase: bool,
        require_lowercase: bool,
        max_age: u32,
    ) -> Vec<IamFinding> {
        let mut findings = Vec::new();

        if min_length < 14 {
            findings.push(IamFinding {
                finding_type: IamFindingType::PasswordPolicyWeak,
                resource: "account-password-policy".to_string(),
                severity: "MEDIUM".to_string(),
                description: format!(
                    "Password minimum length is {}, should be at least 14",
                    min_length
                ),
                recommendation: "Increase minimum password length to 14 or more characters"
                    .to_string(),
            });
        }

        if !require_symbols {
            findings.push(IamFinding {
                finding_type: IamFindingType::PasswordPolicyWeak,
                resource: "account-password-policy".to_string(),
                severity: "LOW".to_string(),
                description: "Password policy does not require symbols".to_string(),
                recommendation: "Require at least one symbol in passwords".to_string(),
            });
        }

        if !require_numbers {
            findings.push(IamFinding {
                finding_type: IamFindingType::PasswordPolicyWeak,
                resource: "account-password-policy".to_string(),
                severity: "LOW".to_string(),
                description: "Password policy does not require numbers".to_string(),
                recommendation: "Require at least one number in passwords".to_string(),
            });
        }

        if !require_uppercase {
            findings.push(IamFinding {
                finding_type: IamFindingType::PasswordPolicyWeak,
                resource: "account-password-policy".to_string(),
                severity: "LOW".to_string(),
                description: "Password policy does not require uppercase letters".to_string(),
                recommendation: "Require at least one uppercase letter in passwords".to_string(),
            });
        }

        if !require_lowercase {
            findings.push(IamFinding {
                finding_type: IamFindingType::PasswordPolicyWeak,
                resource: "account-password-policy".to_string(),
                severity: "LOW".to_string(),
                description: "Password policy does not require lowercase letters".to_string(),
                recommendation: "Require at least one lowercase letter in passwords".to_string(),
            });
        }

        if max_age > 90 {
            findings.push(IamFinding {
                finding_type: IamFindingType::PasswordPolicyWeak,
                resource: "account-password-policy".to_string(),
                severity: "MEDIUM".to_string(),
                description: format!(
                    "Password maximum age is {} days, should be 90 or less",
                    max_age
                ),
                recommendation: "Set maximum password age to 90 days or less".to_string(),
            });
        }

        findings
    }

    pub fn check_root_account(has_mfa: bool, access_keys_count: u32) -> Vec<IamFinding> {
        let mut findings = Vec::new();

        if !has_mfa {
            findings.push(IamFinding {
                finding_type: IamFindingType::NoMfa,
                resource: "root".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Root account does not have MFA enabled".to_string(),
                recommendation: "Enable MFA on the root account immediately".to_string(),
            });
        }

        if access_keys_count > 0 {
            findings.push(IamFinding {
                finding_type: IamFindingType::RootUserUsage,
                resource: "root".to_string(),
                severity: "CRITICAL".to_string(),
                description: format!(
                    "Root account has {} active access key(s)",
                    access_keys_count
                ),
                recommendation: "Delete root account access keys and use IAM users instead"
                    .to_string(),
            });
        }

        findings
    }

    pub fn analyze_security_groups(
        groups: &[(&str, &str, Option<&str>, &[(u16, u16, &str, &str)])],
    ) -> Vec<SecurityGroupFinding> {
        let mut findings = Vec::new();

        for &(group_id, group_name, vpc_id, rules) in groups {
            for &(port_from, port_to, protocol, source) in rules {
                let is_world = source == "0.0.0.0/0" || source == "::/0";

                if is_world {
                    let finding_type = if port_from <= 22 && port_to >= 22 {
                        SecurityGroupFindingType::UnrestrictedSsh
                    } else if port_from <= 3389 && port_to >= 3389 {
                        SecurityGroupFindingType::UnrestrictedRdp
                    } else if protocol == "icmp" {
                        SecurityGroupFindingType::UnrestrictedIcmp
                    } else {
                        SecurityGroupFindingType::OpenToWorld
                    };

                    let severity = if matches!(
                        finding_type,
                        SecurityGroupFindingType::UnrestrictedSsh
                            | SecurityGroupFindingType::UnrestrictedRdp
                    ) {
                        "CRITICAL"
                    } else {
                        "HIGH"
                    };

                    findings.push(SecurityGroupFinding {
                        group_id: group_id.to_string(),
                        group_name: group_name.to_string(),
                        vpc_id: vpc_id.map(|s| s.to_string()),
                        finding_type,
                        rule_description: format!(
                            "Port {}/{} open to {}",
                            port_from, port_to, source
                        ),
                        port_range: format!("{}-{}", port_from, port_to),
                        protocol: protocol.to_string(),
                        source: source.to_string(),
                        severity: severity.to_string(),
                    });
                }
            }
        }

        findings
    }

    pub fn analyze_cloudtrail(
        trails: &[(&str, bool, bool, bool, bool, bool)],
    ) -> Vec<CloudTrailFinding> {
        let mut findings = Vec::new();

        for &(
            trail_name,
            is_multi_region,
            is_logging,
            has_validation,
            has_encryption,
            has_s3_logging,
        ) in trails
        {
            if !is_logging {
                findings.push(CloudTrailFinding {
                    trail_name: trail_name.to_string(),
                    finding_type: CloudTrailFindingType::NotEnabled,
                    severity: "HIGH".to_string(),
                    description: format!("CloudTrail '{}' is not actively logging", trail_name),
                    recommendation: "Enable logging on CloudTrail".to_string(),
                });
            }

            if !is_multi_region {
                findings.push(CloudTrailFinding {
                    trail_name: trail_name.to_string(),
                    finding_type: CloudTrailFindingType::MultiRegionNotEnabled,
                    severity: "MEDIUM".to_string(),
                    description: format!(
                        "CloudTrail '{}' is not configured for multi-region",
                        trail_name
                    ),
                    recommendation:
                        "Enable multi-region logging to capture events across all regions"
                            .to_string(),
                });
            }

            if !has_validation {
                findings.push(CloudTrailFinding {
                    trail_name: trail_name.to_string(),
                    finding_type: CloudTrailFindingType::NoLogFileValidation,
                    severity: "MEDIUM".to_string(),
                    description: format!(
                        "CloudTrail '{}' does not have log file validation enabled",
                        trail_name
                    ),
                    recommendation: "Enable log file validation to ensure log integrity"
                        .to_string(),
                });
            }

            if !has_encryption {
                findings.push(CloudTrailFinding {
                    trail_name: trail_name.to_string(),
                    finding_type: CloudTrailFindingType::NoEncryption,
                    severity: "MEDIUM".to_string(),
                    description: format!("CloudTrail '{}' logs are not encrypted", trail_name),
                    recommendation: "Enable SSE-KMS encryption for CloudTrail logs".to_string(),
                });
            }

            if !has_s3_logging {
                findings.push(CloudTrailFinding {
                    trail_name: trail_name.to_string(),
                    finding_type: CloudTrailFindingType::NoS3AccessLogging,
                    severity: "LOW".to_string(),
                    description: format!(
                        "S3 bucket for CloudTrail '{}' does not have access logging enabled",
                        trail_name
                    ),
                    recommendation: "Enable S3 access logging for the CloudTrail bucket"
                        .to_string(),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s3_bucket_analysis_public() {
        let bucket = AwsScanner::analyze_s3_bucket("test-bucket", true, false, false, false);
        assert_eq!(bucket.name, "test-bucket");
        assert!(bucket.public_access.is_public());
        assert!(!bucket.encryption.is_encrypted());
    }

    #[test]
    fn test_s3_bucket_analysis_private() {
        let bucket = AwsScanner::analyze_s3_bucket("private-bucket", false, true, true, true);
        assert!(!bucket.public_access.is_public());
        assert!(bucket.encryption.is_encrypted());
        assert!(bucket.versioning);
        assert!(bucket.logging);
    }

    #[test]
    fn test_s3_public_access_severity() {
        assert_eq!(S3PublicAccess::PublicReadWrite.severity_label(), "CRITICAL");
        assert_eq!(S3PublicAccess::PublicRead.severity_label(), "HIGH");
        assert_eq!(S3PublicAccess::Private.severity_label(), "NONE");
    }

    #[test]
    fn test_iam_findings_no_mfa() {
        let users = vec![
            ("alice", false, true, 10, false),
            ("bob", true, true, 5, false),
        ];
        let findings = AwsScanner::check_iam_misconfigs(&users);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].resource, "alice");
        assert_eq!(findings[0].finding_type, IamFindingType::NoMfa);
    }

    #[test]
    fn test_iam_findings_unused_credentials() {
        let users = vec![("olduser", true, false, 120, false)];
        let findings = AwsScanner::check_iam_misconfigs(&users);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == IamFindingType::UnusedCredentials));
    }

    #[test]
    fn test_iam_findings_admin_access() {
        let users = vec![("admin-user", true, true, 5, true)];
        let findings = AwsScanner::check_iam_misconfigs(&users);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == IamFindingType::OverlyPermissivePolicy));
    }

    #[test]
    fn test_password_policy_weak() {
        let findings = AwsScanner::check_password_policy(8, false, false, false, false, 180);
        assert!(findings.len() >= 3);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == IamFindingType::PasswordPolicyWeak));
    }

    #[test]
    fn test_password_policy_strong() {
        let findings = AwsScanner::check_password_policy(16, true, true, true, true, 60);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_root_account_no_mfa_with_keys() {
        let findings = AwsScanner::check_root_account(false, 2);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == "CRITICAL"));
    }

    #[test]
    fn test_root_account_secure() {
        let findings = AwsScanner::check_root_account(true, 0);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_security_group_ssh_open() {
        let groups = vec![(
            "sg-123",
            "web-sg",
            Some("vpc-abc"),
            &[(22, 22, "tcp", "0.0.0.0/0")][..],
        )];
        let findings = AwsScanner::analyze_security_groups(&groups);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].finding_type,
            SecurityGroupFindingType::UnrestrictedSsh
        );
        assert_eq!(findings[0].severity, "CRITICAL");
    }

    #[test]
    fn test_security_group_rdp_open() {
        let groups = vec![(
            "sg-456",
            "rdp-sg",
            Some("vpc-abc"),
            &[(3389, 3389, "tcp", "0.0.0.0/0")][..],
        )];
        let findings = AwsScanner::analyze_security_groups(&groups);
        assert_eq!(
            findings[0].finding_type,
            SecurityGroupFindingType::UnrestrictedRdp
        );
    }

    #[test]
    fn test_security_group_private() {
        let groups = vec![(
            "sg-789",
            "internal-sg",
            Some("vpc-abc"),
            &[(8080, 8080, "tcp", "10.0.0.0/8")][..],
        )];
        let findings = AwsScanner::analyze_security_groups(&groups);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_cloudtrail_not_logging() {
        let trails = vec![("main-trail", true, false, true, true, true)];
        let findings = AwsScanner::analyze_cloudtrail(&trails);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == CloudTrailFindingType::NotEnabled));
    }

    #[test]
    fn test_cloudtrail_no_validation() {
        let trails = vec![("main-trail", true, true, false, true, true)];
        let findings = AwsScanner::analyze_cloudtrail(&trails);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == CloudTrailFindingType::NoLogFileValidation));
    }

    #[test]
    fn test_cloudtrail_full_audit() {
        let trails = vec![("main-trail", true, true, true, true, true)];
        let findings = AwsScanner::analyze_cloudtrail(&trails);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_scan_report_finding_counts() {
        let report = AwsScanReport {
            config: AwsConfig::default(),
            buckets: vec![],
            iam_findings: vec![
                IamFinding {
                    finding_type: IamFindingType::NoMfa,
                    resource: "u1".into(),
                    severity: "CRITICAL".into(),
                    description: "".into(),
                    recommendation: "".into(),
                },
                IamFinding {
                    finding_type: IamFindingType::NoMfa,
                    resource: "u2".into(),
                    severity: "HIGH".into(),
                    description: "".into(),
                    recommendation: "".into(),
                },
            ],
            sg_findings: vec![SecurityGroupFinding {
                group_id: "sg1".into(),
                group_name: "".into(),
                vpc_id: None,
                finding_type: SecurityGroupFindingType::OpenToWorld,
                rule_description: "".into(),
                port_range: "".into(),
                protocol: "".into(),
                source: "".into(),
                severity: "HIGH".into(),
            }],
            cloudtrail_findings: vec![],
            scan_timestamp: "2024-01-01T00:00:00Z".into(),
        };
        assert_eq!(report.total_findings(), 3);
        assert_eq!(report.critical_count(), 1);
        assert_eq!(report.high_count(), 2);
    }

    #[test]
    fn test_default_aws_config() {
        let config = AwsConfig::default();
        assert_eq!(config.region, "us-east-1");
        assert!(config.profile.is_none());
    }
}
