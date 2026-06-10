//! SSL/TLS Analysis Module
//!
//! Comprehensive SSL/TLS security testing including:
//! - Certificate parsing and validation
//! - Cipher suite enumeration
//! - Protocol version detection
//! - Vulnerability scanning (Heartbleed, POODLE, etc.)

pub mod certificate;
pub mod cipher;
pub mod scanner;
pub mod vulnerabilities;

pub use certificate::{Certificate, CertificateChain, CertificateInfo};
pub use cipher::{CipherStrength, CipherSuite, SupportedCiphers};
pub use scanner::{SslScanResult, SslScanner};
pub use vulnerabilities::{SslVulnerability, VulnerabilityScanner};

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// SSL/TLS protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsVersion {
    #[serde(rename = "SSLv2")]
    SslV2,
    #[serde(rename = "SSLv3")]
    SslV3,
    #[serde(rename = "TLS 1.0")]
    Tls10,
    #[serde(rename = "TLS 1.1")]
    Tls11,
    #[serde(rename = "TLS 1.2")]
    Tls12,
    #[serde(rename = "TLS 1.3")]
    Tls13,
}

impl TlsVersion {
    pub fn is_deprecated(&self) -> bool {
        matches!(
            self,
            TlsVersion::SslV2 | TlsVersion::SslV3 | TlsVersion::Tls10 | TlsVersion::Tls11
        )
    }

    pub fn as_str(&self) -> &str {
        match self {
            TlsVersion::SslV2 => "SSLv2",
            TlsVersion::SslV3 => "SSLv3",
            TlsVersion::Tls10 => "TLS 1.0",
            TlsVersion::Tls11 => "TLS 1.1",
            TlsVersion::Tls12 => "TLS 1.2",
            TlsVersion::Tls13 => "TLS 1.3",
        }
    }

    pub fn protocol_version_bytes(&self) -> [u8; 2] {
        match self {
            TlsVersion::SslV2 => [0x00, 0x02],
            TlsVersion::SslV3 => [0x03, 0x00],
            TlsVersion::Tls10 => [0x03, 0x01],
            TlsVersion::Tls11 => [0x03, 0x02],
            TlsVersion::Tls12 => [0x03, 0x03],
            TlsVersion::Tls13 => [0x03, 0x04],
        }
    }
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// SSL/TLS scan configuration
#[derive(Debug, Clone)]
pub struct SslConfig {
    /// Target IP address
    pub target: IpAddr,
    /// Target port
    pub port: u16,
    /// Connection timeout
    pub timeout: std::time::Duration,
    /// Check for vulnerabilities
    pub check_vulnerabilities: bool,
    /// Enumerate cipher suites
    pub enumerate_ciphers: bool,
    /// Validate certificate chain
    pub validate_certificates: bool,
}

impl Default for SslConfig {
    fn default() -> Self {
        Self {
            target: "127.0.0.1".parse().unwrap(),
            port: 443,
            timeout: std::time::Duration::from_secs(10),
            check_vulnerabilities: true,
            enumerate_ciphers: true,
            validate_certificates: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_deprecated() {
        assert!(TlsVersion::SslV2.is_deprecated());
        assert!(TlsVersion::SslV3.is_deprecated());
        assert!(TlsVersion::Tls10.is_deprecated());
        assert!(TlsVersion::Tls11.is_deprecated());
        assert!(!TlsVersion::Tls12.is_deprecated());
        assert!(!TlsVersion::Tls13.is_deprecated());
    }

    #[test]
    fn test_tls_version_bytes() {
        assert_eq!(TlsVersion::SslV3.protocol_version_bytes(), [0x03, 0x00]);
        assert_eq!(TlsVersion::Tls12.protocol_version_bytes(), [0x03, 0x03]);
        assert_eq!(TlsVersion::Tls13.protocol_version_bytes(), [0x03, 0x04]);
    }

    #[test]
    fn test_tls_version_display() {
        assert_eq!(format!("{}", TlsVersion::Tls12), "TLS 1.2");
        assert_eq!(format!("{}", TlsVersion::SslV3), "SSLv3");
    }

    #[test]
    fn test_ssl_config_default() {
        let config = SslConfig::default();
        assert_eq!(config.port, 443);
        assert!(config.check_vulnerabilities);
        assert!(config.enumerate_ciphers);
        assert!(config.validate_certificates);
    }
}
