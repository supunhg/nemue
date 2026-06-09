use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpConfig {
    pub project_id: String,
    pub zone: Option<String>,
    pub service_account_key: Option<String>,
    pub credentials_file: Option<String>,
}

impl Default for GcpConfig {
    fn default() -> Self {
        Self {
            project_id: String::new(),
            zone: None,
            service_account_key: None,
            credentials_file: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcsBucket {
    pub name: String,
    pub location: Option<String>,
    pub storage_class: Option<String>,
    pub public_access: GcsPublicAccess,
    pub encryption: GcsEncryptionStatus,
    pub versioning: bool,
    pub logging: bool,
    pub retention_period: Option<u64>,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GcsPublicAccess {
    Private,
    PublicRead,
    PublicReadWrite,
    AuthenticatedRead,
    UniformBucketLevelAccess,
}

impl GcsPublicAccess {
    pub fn is_public(&self) -> bool {
        matches!(self, GcsPublicAccess::PublicRead | GcsPublicAccess::PublicReadWrite)
    }

    pub fn severity_label(&self) -> &str {
        match self {
            GcsPublicAccess::PublicReadWrite => "CRITICAL",
            GcsPublicAccess::PublicRead => "HIGH",
            GcsPublicAccess::AuthenticatedRead => "MEDIUM",
            GcsPublicAccess::Private => "NONE",
            GcsPublicAccess::UniformBucketLevelAccess => "NONE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GcsEncryptionStatus {
    GoogleManaged,
    CustomerManaged,
    CustomerSupplied,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpIamFinding {
    pub finding_type: GcpIamFindingType,
    pub resource: String,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GcpIamFindingType {
    PrimitiveRoles,
    OverlyPermissiveBinding,
    ServiceAccountKeyAge,
    NoServiceAccountKeyRotation,
    DefaultServiceAccount,
    OwnerRoleGranted,
    ServiceAccountUser,
    WorkloadIdentityUnused,
}

impl GcpIamFindingType {
    pub fn as_str(&self) -> &str {
        match self {
            GcpIamFindingType::PrimitiveRoles => "primitive-roles",
            GcpIamFindingType::OverlyPermissiveBinding => "overly-permissive-binding",
            GcpIamFindingType::ServiceAccountKeyAge => "sa-key-age",
            GcpIamFindingType::NoServiceAccountKeyRotation => "no-sa-key-rotation",
            GcpIamFindingType::DefaultServiceAccount => "default-service-account",
            GcpIamFindingType::OwnerRoleGranted => "owner-role-granted",
            GcpIamFindingType::ServiceAccountUser => "service-account-user",
            GcpIamFindingType::WorkloadIdentityUnused => "workload-identity-unused",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleFinding {
    pub rule_name: String,
    pub network: String,
    pub finding_type: FirewallRuleFindingType,
    pub direction: String,
    pub source_ranges: Vec<String>,
    pub allowed_ports: Vec<String>,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FirewallRuleFindingType {
    OpenToWorld,
    UnrestrictedSsh,
    UnrestrictedRdp,
    AllPortsAllProtocols,
    DefaultRuleModified,
    EgressOpenToWorld,
    NoDenyAllEgress,
}

impl FirewallRuleFindingType {
    pub fn as_str(&self) -> &str {
        match self {
            FirewallRuleFindingType::OpenToWorld => "open-to-world",
            FirewallRuleFindingType::UnrestrictedSsh => "unrestricted-ssh",
            FirewallRuleFindingType::UnrestrictedRdp => "unrestricted-rdp",
            FirewallRuleFindingType::AllPortsAllProtocols => "all-ports-all-protocols",
            FirewallRuleFindingType::DefaultRuleModified => "default-rule-modified",
            FirewallRuleFindingType::EgressOpenToWorld => "egress-open-to-world",
            FirewallRuleFindingType::NoDenyAllEgress => "no-deny-all-egress",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogFinding {
    pub finding_type: AuditLogFindingType,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditLogFindingType {
    NotEnabled,
    NoDataAccessLogs,
    NoRetention,
    NoAlertPolicies,
    AdminActivityDisabled,
}

impl AuditLogFindingType {
    pub fn as_str(&self) -> &str {
        match self {
            AuditLogFindingType::NotEnabled => "not-enabled",
            AuditLogFindingType::NoDataAccessLogs => "no-data-access-logs",
            AuditLogFindingType::NoRetention => "no-retention",
            AuditLogFindingType::NoAlertPolicies => "no-alert-policies",
            AuditLogFindingType::AdminActivityDisabled => "admin-activity-disabled",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpScanReport {
    pub config: GcpConfig,
    pub buckets: Vec<GcsBucket>,
    pub iam_findings: Vec<GcpIamFinding>,
    pub firewall_findings: Vec<FirewallRuleFinding>,
    pub audit_log_findings: Vec<AuditLogFinding>,
    pub scan_timestamp: String,
}

impl GcpScanReport {
    pub fn total_findings(&self) -> usize {
        self.iam_findings.len() + self.firewall_findings.len() + self.audit_log_findings.len()
    }

    pub fn critical_count(&self) -> usize {
        self.iam_findings.iter().filter(|f| f.severity == "CRITICAL").count()
            + self.firewall_findings.iter().filter(|f| f.severity == "CRITICAL").count()
            + self.audit_log_findings.iter().filter(|f| f.severity == "CRITICAL").count()
    }
}

pub struct GcpScanner {
    config: GcpConfig,
}

impl GcpScanner {
    pub fn new(config: GcpConfig) -> Self {
        Self { config }
    }

    pub fn analyze_gcs_bucket(
        name: &str,
        public_level: u8,
        encrypted: bool,
        versioning: bool,
        logging: bool,
    ) -> GcsBucket {
        GcsBucket {
            name: name.to_string(),
            location: None,
            storage_class: None,
            public_access: match public_level {
                2 => GcsPublicAccess::PublicReadWrite,
                1 => GcsPublicAccess::PublicRead,
                _ => GcsPublicAccess::Private,
            },
            encryption: if encrypted { GcsEncryptionStatus::GoogleManaged } else { GcsEncryptionStatus::None },
            versioning,
            logging,
            retention_period: None,
            labels: HashMap::new(),
        }
    }

    pub fn check_iam(bindings: &[(&str, Vec<&str>, bool, bool)]) -> Vec<GcpIamFinding> {
        let mut findings = Vec::new();

        for &(member, ref roles, _is_service_account, key_age_days_flag) in bindings {
            for role in roles {
                if *role == "roles/owner" || *role == "roles/editor" || *role == "roles/viewer" {
                    findings.push(GcpIamFinding {
                        finding_type: GcpIamFindingType::PrimitiveRoles,
                        resource: format!("{}:{}", member, role),
                        severity: if *role == "roles/owner" { "CRITICAL" } else { "HIGH" }.to_string(),
                        description: format!("{} is bound to primitive role '{}'", member, role),
                        recommendation: "Use predefined or custom roles instead of primitive roles".to_string(),
                    });
                }

                if *role == "roles/owner" {
                    findings.push(GcpIamFinding {
                        finding_type: GcpIamFindingType::OwnerRoleGranted,
                        resource: format!("{}:{}", member, role),
                        severity: "CRITICAL".to_string(),
                        description: format!("Owner role granted to '{}'", member),
                        recommendation: "Remove Owner role; use least-privilege predefined roles".to_string(),
                    });
                }

                if role.contains("admin") && (*role == "roles/iam.securityAdmin" || *role == "roles/resourcemanager.organizationAdmin") {
                    findings.push(GcpIamFinding {
                        finding_type: GcpIamFindingType::OverlyPermissiveBinding,
                        resource: format!("{}:{}", member, role),
                        severity: "HIGH".to_string(),
                        description: format!("Highly privileged role '{}' granted to '{}'", role, member),
                        recommendation: "Review and restrict privileged role assignments".to_string(),
                    });
                }
            }

            if key_age_days_flag {
                findings.push(GcpIamFinding {
                    finding_type: GcpIamFindingType::ServiceAccountKeyAge,
                    resource: member.to_string(),
                    severity: "MEDIUM".to_string(),
                    description: format!("Service account key for '{}' is older than 90 days", member),
                    recommendation: "Rotate service account keys every 90 days".to_string(),
                });
            }
        }

        findings
    }

    pub fn analyze_firewall_rules(rules: &[(&str, &str, &str, Vec<&str>, Vec<&str>)]) -> Vec<FirewallRuleFinding> {
        let mut findings = Vec::new();

        for &(rule_name, network, direction, ref source_ranges, ref allowed_ports) in rules {
            let is_world = source_ranges.iter().any(|r| *r == "0.0.0.0/0");

            if !is_world {
                continue;
            }

            for port_spec in allowed_ports {
                if *port_spec == "all" || *port_spec == "0-65535" {
                    findings.push(FirewallRuleFinding {
                        rule_name: rule_name.to_string(),
                        network: network.to_string(),
                        finding_type: FirewallRuleFindingType::AllPortsAllProtocols,
                        direction: direction.to_string(),
                        source_ranges: source_ranges.iter().map(|s| s.to_string()).collect(),
                        allowed_ports: allowed_ports.iter().map(|s| s.to_string()).collect(),
                        severity: "CRITICAL".to_string(),
                    });
                } else if port_spec.contains("22") {
                    findings.push(FirewallRuleFinding {
                        rule_name: rule_name.to_string(),
                        network: network.to_string(),
                        finding_type: FirewallRuleFindingType::UnrestrictedSsh,
                        direction: direction.to_string(),
                        source_ranges: source_ranges.iter().map(|s| s.to_string()).collect(),
                        allowed_ports: allowed_ports.iter().map(|s| s.to_string()).collect(),
                        severity: "CRITICAL".to_string(),
                    });
                } else if port_spec.contains("3389") {
                    findings.push(FirewallRuleFinding {
                        rule_name: rule_name.to_string(),
                        network: network.to_string(),
                        finding_type: FirewallRuleFindingType::UnrestrictedRdp,
                        direction: direction.to_string(),
                        source_ranges: source_ranges.iter().map(|s| s.to_string()).collect(),
                        allowed_ports: allowed_ports.iter().map(|s| s.to_string()).collect(),
                        severity: "CRITICAL".to_string(),
                    });
                } else {
                    findings.push(FirewallRuleFinding {
                        rule_name: rule_name.to_string(),
                        network: network.to_string(),
                        finding_type: FirewallRuleFindingType::OpenToWorld,
                        direction: direction.to_string(),
                        source_ranges: source_ranges.iter().map(|s| s.to_string()).collect(),
                        allowed_ports: allowed_ports.iter().map(|s| s.to_string()).collect(),
                        severity: "HIGH".to_string(),
                    });
                }
            }
        }

        findings
    }

    pub fn analyze_audit_logs(
        enabled: bool,
        data_access_enabled: bool,
        retention_days: u32,
        has_alerts: bool,
    ) -> Vec<AuditLogFinding> {
        let mut findings = Vec::new();

        if !enabled {
            findings.push(AuditLogFinding {
                finding_type: AuditLogFindingType::NotEnabled,
                severity: "HIGH".to_string(),
                description: "Cloud Audit Logs are not enabled".to_string(),
                recommendation: "Enable Cloud Audit Logs for all services".to_string(),
            });
        }

        if !data_access_enabled {
            findings.push(AuditLogFinding {
                finding_type: AuditLogFindingType::NoDataAccessLogs,
                severity: "MEDIUM".to_string(),
                description: "Data access audit logs are not enabled".to_string(),
                recommendation: "Enable data access audit logs for sensitive services".to_string(),
            });
        }

        if retention_days < 365 {
            findings.push(AuditLogFinding {
                finding_type: AuditLogFindingType::NoRetention,
                severity: "MEDIUM".to_string(),
                description: format!("Audit log retention is {} days, should be at least 365", retention_days),
                recommendation: "Set audit log retention to at least 365 days".to_string(),
            });
        }

        if !has_alerts {
            findings.push(AuditLogFinding {
                finding_type: AuditLogFindingType::NoAlertPolicies,
                severity: "MEDIUM".to_string(),
                description: "No alert policies configured for audit log events".to_string(),
                recommendation: "Create alert policies for critical admin operations".to_string(),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcs_bucket_public() {
        let bucket = GcpScanner::analyze_gcs_bucket("my-bucket", 1, false, false, false);
        assert!(bucket.public_access.is_public());
        assert_eq!(bucket.public_access.severity_label(), "HIGH");
    }

    #[test]
    fn test_gcs_bucket_private() {
        let bucket = GcpScanner::analyze_gcs_bucket("my-bucket", 0, true, true, true);
        assert!(!bucket.public_access.is_public());
        assert!(bucket.versioning);
        assert!(bucket.logging);
    }

    #[test]
    fn test_gcs_bucket_public_read_write() {
        let bucket = GcpScanner::analyze_gcs_bucket("open-bucket", 2, true, false, false);
        assert!(bucket.public_access.is_public());
        assert_eq!(bucket.public_access.severity_label(), "CRITICAL");
    }

    #[test]
    fn test_gcp_iam_primitive_roles() {
        let bindings = vec![
            ("user:alice@example.com", vec!["roles/viewer"], false, false),
        ];
        let findings = GcpScanner::check_iam(&bindings);
        assert!(findings.iter().any(|f| f.finding_type == GcpIamFindingType::PrimitiveRoles));
    }

    #[test]
    fn test_gcp_iam_owner() {
        let bindings = vec![
            ("user:admin@example.com", vec!["roles/owner"], false, false),
        ];
        let findings = GcpScanner::check_iam(&bindings);
        assert!(findings.iter().any(|f| f.finding_type == GcpIamFindingType::OwnerRoleGranted));
        assert!(findings.iter().any(|f| f.severity == "CRITICAL"));
    }

    #[test]
    fn test_gcp_iam_no_issues() {
        let bindings = vec![
            ("user:dev@example.com", vec!["roles/storage.objectViewer"], false, false),
        ];
        let findings = GcpScanner::check_iam(&bindings);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_gcp_iam_key_age() {
        let bindings = vec![
            ("sa@project.iam.gserviceaccount.com", vec!["roles/storage.admin"], true, true),
        ];
        let findings = GcpScanner::check_iam(&bindings);
        assert!(findings.iter().any(|f| f.finding_type == GcpIamFindingType::ServiceAccountKeyAge));
    }

    #[test]
    fn test_firewall_ssh_open() {
        let rules = vec![
            ("allow-ssh", "default", "Ingress", vec!["0.0.0.0/0"], vec!["22"]),
        ];
        let findings = GcpScanner::analyze_firewall_rules(&rules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, FirewallRuleFindingType::UnrestrictedSsh);
        assert_eq!(findings[0].severity, "CRITICAL");
    }

    #[test]
    fn test_firewall_rdp_open() {
        let rules = vec![
            ("allow-rdp", "default", "Ingress", vec!["0.0.0.0/0"], vec!["3389"]),
        ];
        let findings = GcpScanner::analyze_firewall_rules(&rules);
        assert_eq!(findings[0].finding_type, FirewallRuleFindingType::UnrestrictedRdp);
    }

    #[test]
    fn test_firewall_all_ports() {
        let rules = vec![
            ("allow-all", "default", "Ingress", vec!["0.0.0.0/0"], vec!["all"]),
        ];
        let findings = GcpScanner::analyze_firewall_rules(&rules);
        assert_eq!(findings[0].finding_type, FirewallRuleFindingType::AllPortsAllProtocols);
        assert_eq!(findings[0].severity, "CRITICAL");
    }

    #[test]
    fn test_firewall_private_source() {
        let rules = vec![
            ("internal-ssh", "default", "Ingress", vec!["10.0.0.0/8"], vec!["22"]),
        ];
        let findings = GcpScanner::analyze_firewall_rules(&rules);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_audit_logs_disabled() {
        let findings = GcpScanner::analyze_audit_logs(false, false, 30, false);
        assert_eq!(findings.len(), 4);
    }

    #[test]
    fn test_audit_logs_fully_configured() {
        let findings = GcpScanner::analyze_audit_logs(true, true, 400, true);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_audit_logs_partial() {
        let findings = GcpScanner::analyze_audit_logs(true, false, 365, true);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, AuditLogFindingType::NoDataAccessLogs);
    }

    #[test]
    fn test_gcp_scan_report_counts() {
        let report = GcpScanReport {
            config: GcpConfig::default(),
            buckets: vec![],
            iam_findings: vec![
                GcpIamFinding { finding_type: GcpIamFindingType::OwnerRoleGranted, resource: "x".into(), severity: "CRITICAL".into(), description: "".into(), recommendation: "".into() },
            ],
            firewall_findings: vec![
                FirewallRuleFinding { rule_name: "r1".into(), network: "default".into(), finding_type: FirewallRuleFindingType::UnrestrictedSsh, direction: "".into(), source_ranges: vec![], allowed_ports: vec![], severity: "CRITICAL".into() },
            ],
            audit_log_findings: vec![],
            scan_timestamp: "2024-01-01T00:00:00Z".into(),
        };
        assert_eq!(report.total_findings(), 2);
        assert_eq!(report.critical_count(), 2);
    }
}
