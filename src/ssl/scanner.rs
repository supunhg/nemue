//! SSL/TLS Scanner - Main scanning interface

use super::*;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Complete SSL/TLS scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslScanResult {
    /// Target address
    pub target: IpAddr,
    /// Target port
    pub port: u16,
    /// Supported TLS versions
    pub supported_versions: Vec<TlsVersion>,
    /// Supported cipher suites by version
    pub supported_ciphers: Vec<SupportedCiphers>,
    /// Certificate information
    pub certificate_info: Option<CertificateInfo>,
    /// Detected vulnerabilities
    pub vulnerabilities: Vec<vulnerabilities::VulnerabilityScanResult>,
    /// Overall security grade (A+ to F)
    pub security_grade: SecurityGrade,
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Security grade
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityGrade {
    #[serde(rename = "A+")]
    APlus,
    A,
    #[serde(rename = "A-")]
    AMinus,
    #[serde(rename = "B+")]
    BPlus,
    B,
    #[serde(rename = "B-")]
    BMinus,
    C,
    D,
    E,
    F,
}

impl std::fmt::Display for SecurityGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityGrade::APlus => write!(f, "A+"),
            SecurityGrade::A => write!(f, "A"),
            SecurityGrade::AMinus => write!(f, "A-"),
            SecurityGrade::BPlus => write!(f, "B+"),
            SecurityGrade::B => write!(f, "B"),
            SecurityGrade::BMinus => write!(f, "B-"),
            SecurityGrade::C => write!(f, "C"),
            SecurityGrade::D => write!(f, "D"),
            SecurityGrade::E => write!(f, "E"),
            SecurityGrade::F => write!(f, "F"),
        }
    }
}

/// SSL/TLS Scanner
pub struct SslScanner {
    config: SslConfig,
}

impl SslScanner {
    pub fn new(config: SslConfig) -> Self {
        Self { config }
    }

    /// Perform complete SSL/TLS scan
    pub async fn scan(&self) -> Result<SslScanResult> {
        let target_addr = SocketAddr::new(self.config.target, self.config.port);
        
        // 1. Detect supported TLS versions
        let supported_versions = self.detect_tls_versions(target_addr).await?;
        
        // 2. Enumerate cipher suites for each version
        let mut supported_ciphers = Vec::new();
        for version in &supported_versions {
            if let Ok(ciphers) = self.enumerate_ciphers(target_addr, *version).await {
                supported_ciphers.push(ciphers);
            }
        }
        
        // 3. Get certificate information (if supported)
        let certificate_info = if self.config.validate_certificates {
            self.get_certificate_info(target_addr).await.ok()
        } else {
            None
        };
        
        // 4. Check for vulnerabilities
        let vulnerabilities = if self.config.check_vulnerabilities {
            let vuln_scanner = vulnerabilities::VulnerabilityScanner::new(self.config.timeout);
            vuln_scanner.scan_all(target_addr).await
        } else {
            Vec::new()
        };
        
        // 5. Calculate security grade
        let security_grade = self.calculate_security_grade(
            &supported_versions,
            &supported_ciphers,
            &certificate_info,
            &vulnerabilities,
        );
        
        // 6. Generate recommendations
        let recommendations = self.generate_recommendations(
            &supported_versions,
            &supported_ciphers,
            &certificate_info,
            &vulnerabilities,
        );
        
        Ok(SslScanResult {
            target: self.config.target,
            port: self.config.port,
            supported_versions,
            supported_ciphers,
            certificate_info,
            vulnerabilities,
            security_grade,
            recommendations,
        })
    }

    /// Detect supported TLS versions
    async fn detect_tls_versions(&self, target: SocketAddr) -> Result<Vec<TlsVersion>> {
        let mut supported = Vec::new();
        
        let versions_to_test = vec![
            TlsVersion::Tls13,
            TlsVersion::Tls12,
            TlsVersion::Tls11,
            TlsVersion::Tls10,
            TlsVersion::SslV3,
            TlsVersion::SslV2,
        ];
        
        for version in versions_to_test {
            if self.test_tls_version(target, version).await {
                supported.push(version);
            }
        }
        
        Ok(supported)
    }

    /// Test if a specific TLS version is supported
    async fn test_tls_version(&self, target: SocketAddr, version: TlsVersion) -> bool {
        let hello = self.build_client_hello(version);
        
        match timeout(self.config.timeout, TcpStream::connect(target)).await {
            Ok(Ok(mut stream)) => {
                if stream.write_all(&hello).await.is_err() {
                    return false;
                }
                
                let mut response = vec![0u8; 4096];
                match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Check if ServerHello matches requested version
                        self.check_version_response(&response[..n], version)
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// Enumerate supported cipher suites for a TLS version
    async fn enumerate_ciphers(&self, target: SocketAddr, version: TlsVersion) -> Result<SupportedCiphers> {
        // Test common cipher suites
        let cipher_ids = self.get_common_cipher_ids();
        let mut supported = Vec::new();
        
        for id in cipher_ids {
            if let Some(cipher) = cipher::CipherDatabase::get_cipher(id) {
                if cipher.tls_versions.contains(&version) {
                    if self.test_cipher(target, version, id).await {
                        supported.push(cipher);
                    }
                }
            }
        }
        
        // Determine preferred cipher
        let preferred_cipher = if !supported.is_empty() {
            Some(supported[0].clone())
        } else {
            None
        };
        
        Ok(SupportedCiphers {
            tls_version: version,
            ciphers: supported,
            preferred_cipher,
        })
    }

    /// Test if a specific cipher suite is supported
    async fn test_cipher(&self, target: SocketAddr, version: TlsVersion, cipher_id: u16) -> bool {
        let hello = self.build_client_hello_with_cipher(version, cipher_id);
        
        match timeout(self.config.timeout, TcpStream::connect(target)).await {
            Ok(Ok(mut stream)) => {
                if stream.write_all(&hello).await.is_err() {
                    return false;
                }
                
                let mut response = vec![0u8; 4096];
                match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
                    Ok(Ok(n)) if n > 0 => {
                        self.check_cipher_acceptance(&response[..n], cipher_id)
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// Get certificate information
    async fn get_certificate_info(&self, _target: SocketAddr) -> Result<CertificateInfo> {
        // Placeholder - in production, use rustls or native-tls
        // to properly parse X.509 certificates
        
        // For now, return a mock certificate chain
        let mock_cert = certificate::Certificate {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Let's Encrypt Authority X3".to_string(),
            serial: "1234567890".to_string(),
            not_before: std::time::SystemTime::now() - Duration::from_secs(86400 * 30),
            not_after: std::time::SystemTime::now() + Duration::from_secs(86400 * 90),
            subject_alt_names: vec!["example.com".to_string()],
            public_key_algorithm: "RSA".to_string(),
            signature_algorithm: "SHA256withRSA".to_string(),
            key_size: 2048,
            self_signed: false,
            fingerprint: "".to_string(),
        };
        
        let chain = certificate::CertificateChain {
            leaf: mock_cert,
            intermediates: Vec::new(),
            root: None,
            is_valid: true,
            validation_errors: Vec::new(),
        };
        
        Ok(CertificateInfo {
            chain,
            is_trusted: true,
            hostname_match: true,
            ct_compliant: true,
            issues: Vec::new(),
        })
    }

    /// Calculate overall security grade
    fn calculate_security_grade(
        &self,
        versions: &[TlsVersion],
        ciphers: &[SupportedCiphers],
        cert_info: &Option<CertificateInfo>,
        vulnerabilities: &[vulnerabilities::VulnerabilityScanResult],
    ) -> SecurityGrade {
        let mut score = 100;
        
        // Check for critical vulnerabilities
        let has_critical_vuln = vulnerabilities.iter().any(|v| {
            v.vulnerable && v.vulnerability.severity() == vulnerabilities::VulnerabilitySeverity::Critical
        });
        if has_critical_vuln {
            return SecurityGrade::F;
        }
        
        // Check for deprecated protocols
        if versions.contains(&TlsVersion::SslV2) || versions.contains(&TlsVersion::SslV3) {
            score -= 30;
        }
        if versions.contains(&TlsVersion::Tls10) {
            score -= 10;
        }
        if versions.contains(&TlsVersion::Tls11) {
            score -= 5;
        }
        
        // Check cipher strength
        for cipher_set in ciphers {
            if cipher_set.has_weak_ciphers() {
                score -= 15;
            }
            let cipher_score = cipher_set.security_score();
            if cipher_score < 50 {
                score -= 20;
            }
        }
        
        // Check certificate issues
        if let Some(cert) = cert_info {
            if !cert.is_trusted {
                score -= 20;
            }
            if !cert.hostname_match {
                score -= 15;
            }
            if !cert.issues.is_empty() {
                score -= cert.issues.len() as i32 * 5;
            }
        }
        
        // Check for high severity vulnerabilities
        let high_vuln_count = vulnerabilities.iter().filter(|v| {
            v.vulnerable && v.vulnerability.severity() == vulnerabilities::VulnerabilitySeverity::High
        }).count();
        score -= high_vuln_count as i32 * 10;
        
        // Map score to grade
        match score {
            95.. => SecurityGrade::APlus,
            90..=94 => SecurityGrade::A,
            85..=89 => SecurityGrade::AMinus,
            80..=84 => SecurityGrade::BPlus,
            75..=79 => SecurityGrade::B,
            70..=74 => SecurityGrade::BMinus,
            60..=69 => SecurityGrade::C,
            50..=59 => SecurityGrade::D,
            40..=49 => SecurityGrade::E,
            _ => SecurityGrade::F,
        }
    }

    /// Generate security recommendations
    fn generate_recommendations(
        &self,
        versions: &[TlsVersion],
        ciphers: &[SupportedCiphers],
        cert_info: &Option<CertificateInfo>,
        vulnerabilities: &[vulnerabilities::VulnerabilityScanResult],
    ) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        // Protocol recommendations
        if versions.contains(&TlsVersion::SslV2) {
            recommendations.push("Disable SSLv2 immediately (CRITICAL)".to_string());
        }
        if versions.contains(&TlsVersion::SslV3) {
            recommendations.push("Disable SSLv3 to prevent POODLE attacks".to_string());
        }
        if versions.contains(&TlsVersion::Tls10) || versions.contains(&TlsVersion::Tls11) {
            recommendations.push("Disable TLS 1.0 and TLS 1.1 (deprecated)".to_string());
        }
        if !versions.contains(&TlsVersion::Tls13) {
            recommendations.push("Enable TLS 1.3 for best security and performance".to_string());
        }
        
        // Cipher recommendations
        for cipher_set in ciphers {
            if cipher_set.has_weak_ciphers() {
                recommendations.push(format!(
                    "Remove weak cipher suites from {} configuration",
                    cipher_set.tls_version
                ));
            }
            
            let no_pfs = cipher_set.ciphers.iter().filter(|c| !c.pfs).count();
            if no_pfs > 0 {
                recommendations.push(format!(
                    "Prefer cipher suites with Perfect Forward Secrecy (PFS) for {}",
                    cipher_set.tls_version
                ));
            }
        }
        
        // Certificate recommendations
        if let Some(cert) = cert_info {
            for issue in &cert.issues {
                recommendations.push(format!("Certificate: {}", issue.description));
            }
            
            if cert.chain.leaf.days_until_expiry() < 30 {
                recommendations.push(format!(
                    "Certificate expires in {} days - renew soon",
                    cert.chain.leaf.days_until_expiry()
                ));
            }
        }
        
        // Vulnerability recommendations
        for vuln_result in vulnerabilities {
            if vuln_result.vulnerable {
                let vuln = vuln_result.vulnerability;
                recommendations.push(format!(
                    "{} detected ({}) - {}",
                    vuln.name(),
                    vuln.cve(),
                    vuln.description()
                ));
            }
        }
        
        recommendations
    }

    // Helper methods for building TLS handshake messages
    
    fn build_client_hello(&self, version: TlsVersion) -> Vec<u8> {
        let version_bytes = version.protocol_version_bytes();
        vec![
            0x16, version_bytes[0], version_bytes[1], // Handshake
            0x00, 0x35, // Length
            0x01, 0x00, 0x00, 0x31, // ClientHello
            version_bytes[0], version_bytes[1], // Version
            // Random (32 bytes - simplified)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // Session ID length
            0x00, 0x02, // Cipher suites length
            0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x01, 0x00, // Compression: null
        ]
    }

    fn build_client_hello_with_cipher(&self, version: TlsVersion, cipher_id: u16) -> Vec<u8> {
        let version_bytes = version.protocol_version_bytes();
        let cipher_bytes = cipher_id.to_be_bytes();
        
        vec![
            0x16, version_bytes[0], version_bytes[1],
            0x00, 0x35,
            0x01, 0x00, 0x00, 0x31,
            version_bytes[0], version_bytes[1],
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
            0x00, 0x02, // Cipher suites length
            cipher_bytes[0], cipher_bytes[1], // Requested cipher
            0x01, 0x00,
        ]
    }

    fn check_version_response(&self, data: &[u8], version: TlsVersion) -> bool {
        if data.len() < 11 {
            return false;
        }
        let version_bytes = version.protocol_version_bytes();
        data[9] == version_bytes[0] && data[10] == version_bytes[1]
    }

    fn check_cipher_acceptance(&self, data: &[u8], cipher_id: u16) -> bool {
        let cipher_bytes = cipher_id.to_be_bytes();
        data.windows(2).any(|w| w == cipher_bytes)
    }

    fn get_common_cipher_ids(&self) -> Vec<u16> {
        vec![
            // TLS 1.3
            0x1301, 0x1302, 0x1303,
            // TLS 1.2 strong
            0xc02f, 0xc030, 0xcca8,
            // TLS 1.2 medium
            0xc013, 0xc014,
            // Weak (for detection)
            0x0005, 0x000a,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_grade_display() {
        assert_eq!(format!("{}", SecurityGrade::APlus), "A+");
        assert_eq!(format!("{}", SecurityGrade::B), "B");
        assert_eq!(format!("{}", SecurityGrade::F), "F");
    }

    #[test]
    fn test_scanner_creation() {
        let config = SslConfig::default();
        let scanner = SslScanner::new(config);
        assert_eq!(scanner.config.port, 443);
    }

    #[test]
    fn test_client_hello_format() {
        let config = SslConfig::default();
        let scanner = SslScanner::new(config);
        
        let hello = scanner.build_client_hello(TlsVersion::Tls12);
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[1], 0x03); // TLS 1.x
        assert_eq!(hello[2], 0x03); // TLS 1.2
    }

    #[test]
    fn test_common_cipher_ids() {
        let config = SslConfig::default();
        let scanner = SslScanner::new(config);
        let ids = scanner.get_common_cipher_ids();
        
        assert!(!ids.is_empty());
        assert!(ids.contains(&0x1301)); // TLS 1.3 cipher
        assert!(ids.contains(&0xc02f)); // TLS 1.2 strong cipher
    }
}
