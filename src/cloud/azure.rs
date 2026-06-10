#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AzureConfig {
    pub subscription_id: String,
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub resource_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobContainer {
    pub name: String,
    pub account_name: String,
    pub public_access: BlobPublicAccess,
    pub encryption: BlobEncryptionStatus,
    pub lease_status: String,
    pub last_modified: Option<String>,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlobPublicAccess {
    None,
    Blob,
    Container,
}

impl BlobPublicAccess {
    pub fn is_public(&self) -> bool {
        !matches!(self, BlobPublicAccess::None)
    }

    pub fn severity_label(&self) -> &str {
        match self {
            BlobPublicAccess::Container => "CRITICAL",
            BlobPublicAccess::Blob => "HIGH",
            BlobPublicAccess::None => "NONE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlobEncryptionStatus {
    MicrosoftManaged,
    CustomerManaged,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureAdFinding {
    pub finding_type: AzureAdFindingType,
    pub resource: String,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AzureAdFindingType {
    NoMfa,
    GuestUsers,
    StaleAccounts,
    OverPrivilegedRoles,
    NoConditionalAccess,
    WeakPasswordPolicy,
    ApplicationWithoutKeyRotation,
    ServicePrincipalNoCredentialRotation,
}

impl AzureAdFindingType {
    pub fn as_str(&self) -> &str {
        match self {
            AzureAdFindingType::NoMfa => "no-mfa",
            AzureAdFindingType::GuestUsers => "guest-users",
            AzureAdFindingType::StaleAccounts => "stale-accounts",
            AzureAdFindingType::OverPrivilegedRoles => "over-privileged-roles",
            AzureAdFindingType::NoConditionalAccess => "no-conditional-access",
            AzureAdFindingType::WeakPasswordPolicy => "weak-password-policy",
            AzureAdFindingType::ApplicationWithoutKeyRotation => "app-no-key-rotation",
            AzureAdFindingType::ServicePrincipalNoCredentialRotation => "sp-no-cred-rotation",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsgFinding {
    pub nsg_name: String,
    pub resource_group: String,
    pub finding_type: NsgFindingType,
    pub rule_name: String,
    pub direction: String,
    pub priority: u32,
    pub source_address: String,
    pub destination_port: String,
    pub protocol: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NsgFindingType {
    InboundOpenToWorld,
    UnrestrictedSsh,
    UnrestrictedRdp,
    ManagementPortsOpen,
    AnyPortAnyProtocol,
    DefaultDenitMissing,
}

impl NsgFindingType {
    pub fn as_str(&self) -> &str {
        match self {
            NsgFindingType::InboundOpenToWorld => "inbound-open-to-world",
            NsgFindingType::UnrestrictedSsh => "unrestricted-ssh",
            NsgFindingType::UnrestrictedRdp => "unrestricted-rdp",
            NsgFindingType::ManagementPortsOpen => "mgmt-ports-open",
            NsgFindingType::AnyPortAnyProtocol => "any-port-any-protocol",
            NsgFindingType::DefaultDenitMissing => "default-deny-missing",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityLogFinding {
    pub finding_type: ActivityLogFindingType,
    pub severity: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActivityLogFindingType {
    NotEnabled,
    NoRetentionPolicy,
    NoAlertRules,
    DiagnosticSettingsMissing,
}

impl ActivityLogFindingType {
    pub fn as_str(&self) -> &str {
        match self {
            ActivityLogFindingType::NotEnabled => "not-enabled",
            ActivityLogFindingType::NoRetentionPolicy => "no-retention-policy",
            ActivityLogFindingType::NoAlertRules => "no-alert-rules",
            ActivityLogFindingType::DiagnosticSettingsMissing => "diagnostic-settings-missing",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureScanReport {
    pub config: AzureConfig,
    pub blob_containers: Vec<BlobContainer>,
    pub ad_findings: Vec<AzureAdFinding>,
    pub nsg_findings: Vec<NsgFinding>,
    pub activity_log_findings: Vec<ActivityLogFinding>,
    pub scan_timestamp: String,
}

impl AzureScanReport {
    pub fn total_findings(&self) -> usize {
        self.ad_findings.len() + self.nsg_findings.len() + self.activity_log_findings.len()
    }

    pub fn critical_count(&self) -> usize {
        self.ad_findings
            .iter()
            .filter(|f| f.severity == "CRITICAL")
            .count()
            + self
                .nsg_findings
                .iter()
                .filter(|f| f.severity == "CRITICAL")
                .count()
            + self
                .activity_log_findings
                .iter()
                .filter(|f| f.severity == "CRITICAL")
                .count()
    }
}

pub struct AzureScanner {
    config: AzureConfig,
}

impl AzureScanner {
    pub fn new(config: AzureConfig) -> Self {
        Self { config }
    }

    pub fn analyze_blob_container(
        name: &str,
        account_name: &str,
        public_level: u8,
        encrypted: bool,
    ) -> BlobContainer {
        BlobContainer {
            name: name.to_string(),
            account_name: account_name.to_string(),
            public_access: match public_level {
                2 => BlobPublicAccess::Container,
                1 => BlobPublicAccess::Blob,
                _ => BlobPublicAccess::None,
            },
            encryption: if encrypted {
                BlobEncryptionStatus::MicrosoftManaged
            } else {
                BlobEncryptionStatus::None
            },
            lease_status: "unlocked".to_string(),
            last_modified: None,
            tags: HashMap::new(),
        }
    }

    pub fn check_azure_ad(users: &[(&str, bool, bool, u64, bool, bool)]) -> Vec<AzureAdFinding> {
        let mut findings = Vec::new();

        for &(user, has_mfa, is_guest, days_inactive, is_global_admin, has_conditional_access) in
            users
        {
            if !has_mfa {
                findings.push(AzureAdFinding {
                    finding_type: AzureAdFindingType::NoMfa,
                    resource: user.to_string(),
                    severity: "HIGH".to_string(),
                    description: format!("User '{}' does not have MFA enabled", user),
                    recommendation: "Enable MFA for all users using Azure AD Conditional Access"
                        .to_string(),
                });
            }

            if is_guest {
                findings.push(AzureAdFinding {
                    finding_type: AzureAdFindingType::GuestUsers,
                    resource: user.to_string(),
                    severity: "MEDIUM".to_string(),
                    description: format!("User '{}' is a guest account", user),
                    recommendation: "Review guest user access and remove unnecessary guests"
                        .to_string(),
                });
            }

            if days_inactive > 90 {
                findings.push(AzureAdFinding {
                    finding_type: AzureAdFindingType::StaleAccounts,
                    resource: user.to_string(),
                    severity: "MEDIUM".to_string(),
                    description: format!(
                        "User '{}' has been inactive for {} days",
                        user, days_inactive
                    ),
                    recommendation: "Disable or remove stale user accounts".to_string(),
                });
            }

            if is_global_admin {
                findings.push(AzureAdFinding {
                    finding_type: AzureAdFindingType::OverPrivilegedRoles,
                    resource: user.to_string(),
                    severity: "HIGH".to_string(),
                    description: format!("User '{}' has Global Administrator role", user),
                    recommendation:
                        "Limit Global Administrator role; use PIM for just-in-time access"
                            .to_string(),
                });
            }

            if !has_conditional_access {
                findings.push(AzureAdFinding {
                    finding_type: AzureAdFindingType::NoConditionalAccess,
                    resource: user.to_string(),
                    severity: "MEDIUM".to_string(),
                    description: format!(
                        "User '{}' has no conditional access policies applied",
                        user
                    ),
                    recommendation:
                        "Apply Conditional Access policies for risk-based authentication"
                            .to_string(),
                });
            }
        }

        findings
    }

    pub fn analyze_nsg(rules: &[(&str, &str, &str, &str, &str, &str, &str)]) -> Vec<NsgFinding> {
        let mut findings = Vec::new();

        for &(nsg_name, rg, direction, source, port, protocol, rule_name) in rules {
            if direction != "Inbound" {
                continue;
            }

            let is_world = source == "*" || source == "0.0.0.0/0" || source == "Internet";

            if is_world {
                let finding_type = if port == "22" || port.contains("22") {
                    NsgFindingType::UnrestrictedSsh
                } else if port == "3389" || port.contains("3389") {
                    NsgFindingType::UnrestrictedRdp
                } else if port == "*" {
                    NsgFindingType::AnyPortAnyProtocol
                } else {
                    NsgFindingType::InboundOpenToWorld
                };

                let severity = match finding_type {
                    NsgFindingType::UnrestrictedSsh | NsgFindingType::UnrestrictedRdp => "CRITICAL",
                    NsgFindingType::AnyPortAnyProtocol => "CRITICAL",
                    _ => "HIGH",
                };

                findings.push(NsgFinding {
                    nsg_name: nsg_name.to_string(),
                    resource_group: rg.to_string(),
                    finding_type,
                    rule_name: rule_name.to_string(),
                    direction: direction.to_string(),
                    priority: 100,
                    source_address: source.to_string(),
                    destination_port: port.to_string(),
                    protocol: protocol.to_string(),
                    severity: severity.to_string(),
                });
            }
        }

        findings
    }

    pub fn analyze_activity_logs(
        has_diagnostic: bool,
        retention_days: u32,
        has_alerts: bool,
    ) -> Vec<ActivityLogFinding> {
        let mut findings = Vec::new();

        if !has_diagnostic {
            findings.push(ActivityLogFinding {
                finding_type: ActivityLogFindingType::DiagnosticSettingsMissing,
                severity: "HIGH".to_string(),
                description: "Activity log diagnostic settings are not configured".to_string(),
                recommendation: "Configure diagnostic settings to export activity logs".to_string(),
            });
        }

        if retention_days < 365 {
            findings.push(ActivityLogFinding {
                finding_type: ActivityLogFindingType::NoRetentionPolicy,
                severity: "MEDIUM".to_string(),
                description: format!(
                    "Activity log retention is {} days, should be at least 365",
                    retention_days
                ),
                recommendation: "Set activity log retention to at least 365 days".to_string(),
            });
        }

        if !has_alerts {
            findings.push(ActivityLogFinding {
                finding_type: ActivityLogFindingType::NoAlertRules,
                severity: "MEDIUM".to_string(),
                description: "No alert rules configured for activity log events".to_string(),
                recommendation:
                    "Create alert rules for critical operations (e.g., security policy changes)"
                        .to_string(),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_container_public() {
        let container = AzureScanner::analyze_blob_container("data", "storage1", 2, true);
        assert!(container.public_access.is_public());
        assert_eq!(container.public_access.severity_label(), "CRITICAL");
    }

    #[test]
    fn test_blob_container_private() {
        let container = AzureScanner::analyze_blob_container("data", "storage1", 0, true);
        assert!(!container.public_access.is_public());
    }

    #[test]
    fn test_blob_container_blob_public() {
        let container = AzureScanner::analyze_blob_container("images", "storage1", 1, true);
        assert!(container.public_access.is_public());
        assert_eq!(container.public_access.severity_label(), "HIGH");
    }

    #[test]
    fn test_azure_ad_no_mfa() {
        let users = vec![("user1", false, false, 10, false, true)];
        let findings = AzureScanner::check_azure_ad(&users);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == AzureAdFindingType::NoMfa));
    }

    #[test]
    fn test_azure_ad_stale_account() {
        let users = vec![("user2", true, false, 150, false, true)];
        let findings = AzureScanner::check_azure_ad(&users);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == AzureAdFindingType::StaleAccounts));
    }

    #[test]
    fn test_azure_ad_global_admin() {
        let users = vec![("admin", true, false, 5, true, true)];
        let findings = AzureScanner::check_azure_ad(&users);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == AzureAdFindingType::OverPrivilegedRoles));
    }

    #[test]
    fn test_azure_ad_guest_user() {
        let users = vec![("external@partner.com", true, true, 5, false, false)];
        let findings = AzureScanner::check_azure_ad(&users);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == AzureAdFindingType::GuestUsers));
        assert!(findings
            .iter()
            .any(|f| f.finding_type == AzureAdFindingType::NoConditionalAccess));
    }

    #[test]
    fn test_nsg_ssh_open() {
        let rules = vec![(
            "nsg-web",
            "rg-prod",
            "Inbound",
            "*",
            "22",
            "tcp",
            "allow-ssh",
        )];
        let findings = AzureScanner::analyze_nsg(&rules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, NsgFindingType::UnrestrictedSsh);
        assert_eq!(findings[0].severity, "CRITICAL");
    }

    #[test]
    fn test_nsg_rdp_open() {
        let rules = vec![(
            "nsg-win",
            "rg-prod",
            "Inbound",
            "0.0.0.0/0",
            "3389",
            "tcp",
            "allow-rdp",
        )];
        let findings = AzureScanner::analyze_nsg(&rules);
        assert_eq!(findings[0].finding_type, NsgFindingType::UnrestrictedRdp);
    }

    #[test]
    fn test_nsg_outbound_ignored() {
        let rules = vec![(
            "nsg-web",
            "rg-prod",
            "Outbound",
            "*",
            "443",
            "tcp",
            "allow-https",
        )];
        let findings = AzureScanner::analyze_nsg(&rules);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_nsg_private_source() {
        let rules = vec![(
            "nsg-internal",
            "rg-prod",
            "Inbound",
            "10.0.0.0/8",
            "22",
            "tcp",
            "allow-ssh-internal",
        )];
        let findings = AzureScanner::analyze_nsg(&rules);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_activity_log_no_diagnostic() {
        let findings = AzureScanner::analyze_activity_logs(false, 90, false);
        assert_eq!(findings.len(), 3);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == ActivityLogFindingType::DiagnosticSettingsMissing));
        assert!(findings
            .iter()
            .any(|f| f.finding_type == ActivityLogFindingType::NoRetentionPolicy));
        assert!(findings
            .iter()
            .any(|f| f.finding_type == ActivityLogFindingType::NoAlertRules));
    }

    #[test]
    fn test_activity_log_fully_configured() {
        let findings = AzureScanner::analyze_activity_logs(true, 400, true);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_azure_scan_report_counts() {
        let report = AzureScanReport {
            config: AzureConfig::default(),
            blob_containers: vec![],
            ad_findings: vec![AzureAdFinding {
                finding_type: AzureAdFindingType::NoMfa,
                resource: "u1".into(),
                severity: "CRITICAL".into(),
                description: "".into(),
                recommendation: "".into(),
            }],
            nsg_findings: vec![NsgFinding {
                nsg_name: "n1".into(),
                resource_group: "rg".into(),
                finding_type: NsgFindingType::UnrestrictedSsh,
                rule_name: "".into(),
                direction: "".into(),
                priority: 0,
                source_address: "".into(),
                destination_port: "".into(),
                protocol: "".into(),
                severity: "HIGH".into(),
            }],
            activity_log_findings: vec![],
            scan_timestamp: "2024-01-01T00:00:00Z".into(),
        };
        assert_eq!(report.total_findings(), 2);
        assert_eq!(report.critical_count(), 1);
    }
}
