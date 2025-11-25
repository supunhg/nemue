//! X.509 Certificate parsing and validation

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// X.509 Certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// Subject (domain name)
    pub subject: String,
    /// Issuer (CA)
    pub issuer: String,
    /// Serial number
    pub serial: String,
    /// Valid from timestamp
    pub not_before: SystemTime,
    /// Valid until timestamp
    pub not_after: SystemTime,
    /// Subject Alternative Names (SAN)
    pub subject_alt_names: Vec<String>,
    /// Public key algorithm
    pub public_key_algorithm: String,
    /// Signature algorithm
    pub signature_algorithm: String,
    /// Key size in bits
    pub key_size: usize,
    /// Whether certificate is self-signed
    pub self_signed: bool,
    /// Certificate fingerprint (SHA256)
    pub fingerprint: String,
}

impl Certificate {
    /// Check if certificate is expired
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.not_after
    }

    /// Check if certificate is not yet valid
    pub fn is_not_yet_valid(&self) -> bool {
        SystemTime::now() < self.not_before
    }

    /// Get days until expiry (negative if expired)
    pub fn days_until_expiry(&self) -> i64 {
        match self.not_after.duration_since(SystemTime::now()) {
            Ok(duration) => (duration.as_secs() / 86400) as i64,
            Err(_) => {
                // Certificate already expired
                match SystemTime::now().duration_since(self.not_after) {
                    Ok(duration) => -((duration.as_secs() / 86400) as i64),
                    Err(_) => 0,
                }
            }
        }
    }

    /// Check if certificate is valid for a specific hostname
    pub fn is_valid_for_hostname(&self, hostname: &str) -> bool {
        // Check subject common name
        if self.subject.contains(hostname) {
            return true;
        }

        // Check subject alternative names
        for san in &self.subject_alt_names {
            if san == hostname || self.matches_wildcard(san, hostname) {
                return true;
            }
        }

        false
    }

    /// Match wildcard certificate name
    fn matches_wildcard(&self, pattern: &str, hostname: &str) -> bool {
        if !pattern.starts_with("*.") {
            return pattern == hostname;
        }

        let pattern_parts: Vec<&str> = pattern.split('.').collect();
        let hostname_parts: Vec<&str> = hostname.split('.').collect();

        if pattern_parts.len() != hostname_parts.len() {
            return false;
        }

        // Check all parts except the first (wildcard)
        pattern_parts.iter().skip(1).zip(hostname_parts.iter().skip(1)).all(|(p, h)| p == h)
    }
}

/// Certificate chain information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateChain {
    /// Leaf certificate (server certificate)
    pub leaf: Certificate,
    /// Intermediate certificates
    pub intermediates: Vec<Certificate>,
    /// Root certificate (if present)
    pub root: Option<Certificate>,
    /// Whether chain is valid
    pub is_valid: bool,
    /// Validation errors
    pub validation_errors: Vec<String>,
}

impl CertificateChain {
    /// Get total chain length
    pub fn length(&self) -> usize {
        1 + self.intermediates.len() + if self.root.is_some() { 1 } else { 0 }
    }

    /// Check if any certificate in chain is expired
    pub fn has_expired_certificate(&self) -> bool {
        self.leaf.is_expired()
            || self.intermediates.iter().any(|cert| cert.is_expired())
            || self.root.as_ref().map(|cert| cert.is_expired()).unwrap_or(false)
    }

    /// Get the soonest expiry date in the chain
    pub fn days_until_first_expiry(&self) -> i64 {
        let mut min_days = self.leaf.days_until_expiry();

        for cert in &self.intermediates {
            let days = cert.days_until_expiry();
            if days < min_days {
                min_days = days;
            }
        }

        if let Some(root) = &self.root {
            let days = root.days_until_expiry();
            if days < min_days {
                min_days = days;
            }
        }

        min_days
    }
}

/// Certificate information summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Certificate chain
    pub chain: CertificateChain,
    /// Whether certificate is trusted
    pub is_trusted: bool,
    /// Whether certificate matches hostname
    pub hostname_match: bool,
    /// Certificate transparency status
    pub ct_compliant: bool,
    /// Issues found
    pub issues: Vec<CertificateIssue>,
}

/// Certificate validation issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateIssue {
    /// Issue severity
    pub severity: IssueSeverity,
    /// Issue type
    pub issue_type: IssueType,
    /// Description
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueType {
    Expired,
    NotYetValid,
    SelfSigned,
    UntrustedIssuer,
    HostnameMismatch,
    WeakKey,
    WeakSignature,
    MissingCT,
    ChainIncomplete,
}

impl std::fmt::Display for IssueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssueType::Expired => write!(f, "Certificate Expired"),
            IssueType::NotYetValid => write!(f, "Certificate Not Yet Valid"),
            IssueType::SelfSigned => write!(f, "Self-Signed Certificate"),
            IssueType::UntrustedIssuer => write!(f, "Untrusted Issuer"),
            IssueType::HostnameMismatch => write!(f, "Hostname Mismatch"),
            IssueType::WeakKey => write!(f, "Weak Key Size"),
            IssueType::WeakSignature => write!(f, "Weak Signature Algorithm"),
            IssueType::MissingCT => write!(f, "Missing Certificate Transparency"),
            IssueType::ChainIncomplete => write!(f, "Incomplete Certificate Chain"),
        }
    }
}

/// Certificate validator
pub struct CertificateValidator;

impl CertificateValidator {
    /// Validate a certificate chain
    pub fn validate_chain(chain: &CertificateChain, hostname: &str) -> Vec<CertificateIssue> {
        let mut issues = Vec::new();

        // Check expiry
        if chain.leaf.is_expired() {
            issues.push(CertificateIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::Expired,
                description: format!("Certificate expired {} days ago", -chain.leaf.days_until_expiry()),
            });
        } else if chain.leaf.days_until_expiry() < 30 {
            issues.push(CertificateIssue {
                severity: IssueSeverity::High,
                issue_type: IssueType::Expired,
                description: format!("Certificate expires in {} days", chain.leaf.days_until_expiry()),
            });
        }

        // Check if not yet valid
        if chain.leaf.is_not_yet_valid() {
            issues.push(CertificateIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::NotYetValid,
                description: "Certificate is not yet valid".to_string(),
            });
        }

        // Check self-signed
        if chain.leaf.self_signed {
            issues.push(CertificateIssue {
                severity: IssueSeverity::High,
                issue_type: IssueType::SelfSigned,
                description: "Certificate is self-signed".to_string(),
            });
        }

        // Check hostname match
        if !chain.leaf.is_valid_for_hostname(hostname) {
            issues.push(CertificateIssue {
                severity: IssueSeverity::Critical,
                issue_type: IssueType::HostnameMismatch,
                description: format!("Certificate not valid for hostname: {}", hostname),
            });
        }

        // Check key size
        if chain.leaf.key_size < 2048 {
            issues.push(CertificateIssue {
                severity: IssueSeverity::High,
                issue_type: IssueType::WeakKey,
                description: format!("Weak key size: {} bits (minimum 2048)", chain.leaf.key_size),
            });
        }

        // Check signature algorithm
        if chain.leaf.signature_algorithm.contains("MD5") || chain.leaf.signature_algorithm.contains("SHA1") {
            issues.push(CertificateIssue {
                severity: IssueSeverity::Medium,
                issue_type: IssueType::WeakSignature,
                description: format!("Weak signature algorithm: {}", chain.leaf.signature_algorithm),
            });
        }

        // Check chain completeness
        if chain.root.is_none() && !chain.is_valid {
            issues.push(CertificateIssue {
                severity: IssueSeverity::Medium,
                issue_type: IssueType::ChainIncomplete,
                description: "Certificate chain is incomplete".to_string(),
            });
        }

        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_certificate() -> Certificate {
        Certificate {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial: "1234567890".to_string(),
            not_before: SystemTime::now() - std::time::Duration::from_secs(86400 * 30),
            not_after: SystemTime::now() + std::time::Duration::from_secs(86400 * 365),
            subject_alt_names: vec!["example.com".to_string(), "*.example.com".to_string()],
            public_key_algorithm: "RSA".to_string(),
            signature_algorithm: "SHA256withRSA".to_string(),
            key_size: 2048,
            self_signed: false,
            fingerprint: "abcd1234".to_string(),
        }
    }

    #[test]
    fn test_certificate_expiry() {
        let cert = create_test_certificate();
        assert!(!cert.is_expired());
        assert!(!cert.is_not_yet_valid());
        assert!(cert.days_until_expiry() > 0);
    }

    #[test]
    fn test_hostname_validation() {
        let cert = create_test_certificate();
        assert!(cert.is_valid_for_hostname("example.com"));
        assert!(cert.is_valid_for_hostname("www.example.com"));
        assert!(!cert.is_valid_for_hostname("other.com"));
    }

    #[test]
    fn test_wildcard_matching() {
        let cert = create_test_certificate();
        assert!(cert.matches_wildcard("*.example.com", "www.example.com"));
        assert!(cert.matches_wildcard("*.example.com", "api.example.com"));
        assert!(!cert.matches_wildcard("*.example.com", "example.com"));
        assert!(!cert.matches_wildcard("*.example.com", "sub.api.example.com"));
    }

    #[test]
    fn test_certificate_chain_length() {
        let leaf = create_test_certificate();
        let chain = CertificateChain {
            leaf: leaf.clone(),
            intermediates: vec![leaf.clone()],
            root: Some(leaf),
            is_valid: true,
            validation_errors: vec![],
        };
        assert_eq!(chain.length(), 3);
    }

    #[test]
    fn test_weak_key_detection() {
        let mut cert = create_test_certificate();
        cert.key_size = 1024;
        
        let chain = CertificateChain {
            leaf: cert,
            intermediates: vec![],
            root: None,
            is_valid: true,
            validation_errors: vec![],
        };

        let issues = CertificateValidator::validate_chain(&chain, "example.com");
        assert!(issues.iter().any(|i| matches!(i.issue_type, IssueType::WeakKey)));
    }

    #[test]
    fn test_self_signed_detection() {
        let mut cert = create_test_certificate();
        cert.self_signed = true;
        
        let chain = CertificateChain {
            leaf: cert,
            intermediates: vec![],
            root: None,
            is_valid: false,
            validation_errors: vec![],
        };

        let issues = CertificateValidator::validate_chain(&chain, "example.com");
        assert!(issues.iter().any(|i| matches!(i.issue_type, IssueType::SelfSigned)));
    }

    #[test]
    fn test_hostname_mismatch() {
        let cert = create_test_certificate();
        let chain = CertificateChain {
            leaf: cert,
            intermediates: vec![],
            root: None,
            is_valid: true,
            validation_errors: vec![],
        };

        let issues = CertificateValidator::validate_chain(&chain, "wrong.com");
        assert!(issues.iter().any(|i| matches!(i.issue_type, IssueType::HostnameMismatch)));
    }
}
