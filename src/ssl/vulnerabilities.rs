//! SSL/TLS Vulnerability Scanner

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Known SSL/TLS vulnerabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SslVulnerability {
    /// Heartbleed (CVE-2014-0160)
    Heartbleed,
    /// POODLE (CVE-2014-3566)
    Poodle,
    /// BEAST (Browser Exploit Against SSL/TLS)
    Beast,
    /// CRIME (Compression Ratio Info-leak Made Easy)
    Crime,
    /// BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext)
    Breach,
    /// FREAK (Factoring RSA Export Keys)
    Freak,
    /// Logjam (DH export downgrade)
    Logjam,
    /// DROWN (Decrypting RSA with Obsolete and Weakened eNcryption)
    Drown,
    /// ROBOT (Return Of Bleichenbacher's Oracle Threat)
    Robot,
    /// Renegotiation vulnerability
    InsecureRenegotiation,
}

impl SslVulnerability {
    pub fn cve(&self) -> &str {
        match self {
            SslVulnerability::Heartbleed => "CVE-2014-0160",
            SslVulnerability::Poodle => "CVE-2014-3566",
            SslVulnerability::Beast => "CVE-2011-3389",
            SslVulnerability::Crime => "CVE-2012-4929",
            SslVulnerability::Breach => "CVE-2013-3587",
            SslVulnerability::Freak => "CVE-2015-0204",
            SslVulnerability::Logjam => "CVE-2015-4000",
            SslVulnerability::Drown => "CVE-2016-0800",
            SslVulnerability::Robot => "CVE-2017-13098",
            SslVulnerability::InsecureRenegotiation => "CVE-2009-3555",
        }
    }

    pub fn name(&self) -> &str {
        match self {
            SslVulnerability::Heartbleed => "Heartbleed",
            SslVulnerability::Poodle => "POODLE",
            SslVulnerability::Beast => "BEAST",
            SslVulnerability::Crime => "CRIME",
            SslVulnerability::Breach => "BREACH",
            SslVulnerability::Freak => "FREAK",
            SslVulnerability::Logjam => "Logjam",
            SslVulnerability::Drown => "DROWN",
            SslVulnerability::Robot => "ROBOT",
            SslVulnerability::InsecureRenegotiation => "Insecure Renegotiation",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            SslVulnerability::Heartbleed => "Memory disclosure vulnerability in OpenSSL heartbeat extension",
            SslVulnerability::Poodle => "Padding oracle attack against SSLv3",
            SslVulnerability::Beast => "Chosen plaintext attack against TLS 1.0 CBC mode",
            SslVulnerability::Crime => "TLS compression attack allowing session hijacking",
            SslVulnerability::Breach => "HTTP compression attack extracting secrets",
            SslVulnerability::Freak => "Man-in-the-middle attack forcing export-grade encryption",
            SslVulnerability::Logjam => "Diffie-Hellman downgrade attack",
            SslVulnerability::Drown => "Cross-protocol attack using SSLv2",
            SslVulnerability::Robot => "RSA padding oracle allowing private key recovery",
            SslVulnerability::InsecureRenegotiation => "Man-in-the-middle attack during renegotiation",
        }
    }

    pub fn severity(&self) -> VulnerabilitySeverity {
        match self {
            SslVulnerability::Heartbleed => VulnerabilitySeverity::Critical,
            SslVulnerability::Poodle => VulnerabilitySeverity::High,
            SslVulnerability::Beast => VulnerabilitySeverity::Medium,
            SslVulnerability::Crime => VulnerabilitySeverity::Medium,
            SslVulnerability::Breach => VulnerabilitySeverity::Medium,
            SslVulnerability::Freak => VulnerabilitySeverity::High,
            SslVulnerability::Logjam => VulnerabilitySeverity::High,
            SslVulnerability::Drown => VulnerabilitySeverity::Critical,
            SslVulnerability::Robot => VulnerabilitySeverity::High,
            SslVulnerability::InsecureRenegotiation => VulnerabilitySeverity::Medium,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnerabilitySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for VulnerabilitySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnerabilitySeverity::Info => write!(f, "INFO"),
            VulnerabilitySeverity::Low => write!(f, "LOW"),
            VulnerabilitySeverity::Medium => write!(f, "MEDIUM"),
            VulnerabilitySeverity::High => write!(f, "HIGH"),
            VulnerabilitySeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Vulnerability scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityScanResult {
    pub vulnerability: SslVulnerability,
    pub vulnerable: bool,
    pub details: Option<String>,
}

/// SSL/TLS vulnerability scanner
pub struct VulnerabilityScanner {
    timeout_duration: Duration,
}

impl VulnerabilityScanner {
    pub fn new(timeout_duration: Duration) -> Self {
        Self { timeout_duration }
    }

    /// Scan for all known vulnerabilities
    pub async fn scan_all(&self, target: SocketAddr) -> Vec<VulnerabilityScanResult> {
        let mut results = Vec::new();

        // Heartbleed check
        if let Ok(result) = self.check_heartbleed(target).await {
            results.push(result);
        }

        // POODLE check
        if let Ok(result) = self.check_poodle(target).await {
            results.push(result);
        }

        // CRIME check
        if let Ok(result) = self.check_crime(target).await {
            results.push(result);
        }

        // FREAK check
        if let Ok(result) = self.check_freak(target).await {
            results.push(result);
        }

        // Logjam check
        if let Ok(result) = self.check_logjam(target).await {
            results.push(result);
        }

        // DROWN check
        if let Ok(result) = self.check_drown(target).await {
            results.push(result);
        }

        results
    }

    /// Check for Heartbleed vulnerability (CVE-2014-0160)
    pub async fn check_heartbleed(&self, target: SocketAddr) -> Result<VulnerabilityScanResult> {
        // TLS 1.2 ClientHello with heartbeat extension
        let client_hello = self.build_heartbeat_client_hello();
        
        match timeout(self.timeout_duration, TcpStream::connect(target)).await {
            Ok(Ok(mut stream)) => {
                // Send ClientHello
                if stream.write_all(&client_hello).await.is_err() {
                    return Ok(VulnerabilityScanResult {
                        vulnerability: SslVulnerability::Heartbleed,
                        vulnerable: false,
                        details: Some("Failed to send ClientHello".to_string()),
                    });
                }

                // Read ServerHello
                let mut response = vec![0u8; 8192];
                match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Check if server supports heartbeat
                        let supports_heartbeat = self.check_heartbeat_support(&response[..n]);
                        
                        if supports_heartbeat {
                            // Send malformed heartbeat request
                            let heartbeat_request = self.build_malformed_heartbeat();
                            let _ = stream.write_all(&heartbeat_request).await;

                            // Check for vulnerable response
                            let mut heartbeat_response = vec![0u8; 65536];
                            match timeout(Duration::from_secs(2), stream.read(&mut heartbeat_response)).await {
                                Ok(Ok(n)) if n > 0 => {
                                    // Vulnerable if response is larger than expected
                                    let vulnerable = n > 100;
                                    Ok(VulnerabilityScanResult {
                                        vulnerability: SslVulnerability::Heartbleed,
                                        vulnerable,
                                        details: if vulnerable {
                                            Some(format!("Server returned {} bytes (indicates memory leak)", n))
                                        } else {
                                            Some("Server supports heartbeat but not vulnerable".to_string())
                                        },
                                    })
                                }
                                _ => Ok(VulnerabilityScanResult {
                                    vulnerability: SslVulnerability::Heartbleed,
                                    vulnerable: false,
                                    details: Some("No response to heartbeat request".to_string()),
                                }),
                            }
                        } else {
                            Ok(VulnerabilityScanResult {
                                vulnerability: SslVulnerability::Heartbleed,
                                vulnerable: false,
                                details: Some("Server does not support heartbeat extension".to_string()),
                            })
                        }
                    }
                    _ => Ok(VulnerabilityScanResult {
                        vulnerability: SslVulnerability::Heartbleed,
                        vulnerable: false,
                        details: Some("No response from server".to_string()),
                    }),
                }
            }
            _ => Ok(VulnerabilityScanResult {
                vulnerability: SslVulnerability::Heartbleed,
                vulnerable: false,
                details: Some("Connection failed".to_string()),
            }),
        }
    }

    /// Check for POODLE vulnerability (CVE-2014-3566)
    pub async fn check_poodle(&self, target: SocketAddr) -> Result<VulnerabilityScanResult> {
        // Try SSLv3 connection
        let sslv3_hello = self.build_sslv3_client_hello();
        
        match timeout(self.timeout_duration, TcpStream::connect(target)).await {
            Ok(Ok(mut stream)) => {
                if stream.write_all(&sslv3_hello).await.is_err() {
                    return Ok(VulnerabilityScanResult {
                        vulnerability: SslVulnerability::Poodle,
                        vulnerable: false,
                        details: Some("SSLv3 not supported".to_string()),
                    });
                }

                let mut response = vec![0u8; 4096];
                match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Check if server accepts SSLv3
                        let accepts_sslv3 = self.check_sslv3_acceptance(&response[..n]);
                        Ok(VulnerabilityScanResult {
                            vulnerability: SslVulnerability::Poodle,
                            vulnerable: accepts_sslv3,
                            details: if accepts_sslv3 {
                                Some("Server accepts SSLv3 connections".to_string())
                            } else {
                                Some("Server does not accept SSLv3".to_string())
                            },
                        })
                    }
                    _ => Ok(VulnerabilityScanResult {
                        vulnerability: SslVulnerability::Poodle,
                        vulnerable: false,
                        details: Some("SSLv3 not supported".to_string()),
                    }),
                }
            }
            _ => Ok(VulnerabilityScanResult {
                vulnerability: SslVulnerability::Poodle,
                vulnerable: false,
                details: Some("Connection failed".to_string()),
            }),
        }
    }

    /// Check for CRIME vulnerability (CVE-2012-4929)
    pub async fn check_crime(&self, target: SocketAddr) -> Result<VulnerabilityScanResult> {
        // TLS ClientHello with compression
        let hello_with_compression = self.build_client_hello_with_compression();
        
        match timeout(self.timeout_duration, TcpStream::connect(target)).await {
            Ok(Ok(mut stream)) => {
                if stream.write_all(&hello_with_compression).await.is_err() {
                    return Ok(VulnerabilityScanResult {
                        vulnerability: SslVulnerability::Crime,
                        vulnerable: false,
                        details: Some("Failed to send ClientHello".to_string()),
                    });
                }

                let mut response = vec![0u8; 4096];
                match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
                    Ok(Ok(n)) if n > 0 => {
                        // Check if server accepts compression
                        let compression_accepted = self.check_compression_support(&response[..n]);
                        Ok(VulnerabilityScanResult {
                            vulnerability: SslVulnerability::Crime,
                            vulnerable: compression_accepted,
                            details: if compression_accepted {
                                Some("Server supports TLS compression".to_string())
                            } else {
                                Some("Server does not support TLS compression".to_string())
                            },
                        })
                    }
                    _ => Ok(VulnerabilityScanResult {
                        vulnerability: SslVulnerability::Crime,
                        vulnerable: false,
                        details: Some("No response from server".to_string()),
                    }),
                }
            }
            _ => Ok(VulnerabilityScanResult {
                vulnerability: SslVulnerability::Crime,
                vulnerable: false,
                details: Some("Connection failed".to_string()),
            }),
        }
    }

    /// Check for FREAK vulnerability (CVE-2015-0204)
    pub async fn check_freak(&self, target: SocketAddr) -> Result<VulnerabilityScanResult> {
        // ClientHello with export cipher suites
        let export_hello = self.build_export_cipher_hello();
        
        match timeout(self.timeout_duration, TcpStream::connect(target)).await {
            Ok(Ok(mut stream)) => {
                if stream.write_all(&export_hello).await.is_err() {
                    return Ok(VulnerabilityScanResult {
                        vulnerability: SslVulnerability::Freak,
                        vulnerable: false,
                        details: Some("Failed to send ClientHello".to_string()),
                    });
                }

                let mut response = vec![0u8; 4096];
                match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let accepts_export = self.check_export_cipher_acceptance(&response[..n]);
                        Ok(VulnerabilityScanResult {
                            vulnerability: SslVulnerability::Freak,
                            vulnerable: accepts_export,
                            details: if accepts_export {
                                Some("Server accepts export-grade ciphers".to_string())
                            } else {
                                Some("Server does not accept export ciphers".to_string())
                            },
                        })
                    }
                    _ => Ok(VulnerabilityScanResult {
                        vulnerability: SslVulnerability::Freak,
                        vulnerable: false,
                        details: Some("No response from server".to_string()),
                    }),
                }
            }
            _ => Ok(VulnerabilityScanResult {
                vulnerability: SslVulnerability::Freak,
                vulnerable: false,
                details: Some("Connection failed".to_string()),
            }),
        }
    }

    /// Check for Logjam vulnerability (CVE-2015-4000)
    pub async fn check_logjam(&self, target: SocketAddr) -> Result<VulnerabilityScanResult> {
        // ClientHello with export DH cipher suites
        let dh_export_hello = self.build_dh_export_hello();
        
        match timeout(self.timeout_duration, TcpStream::connect(target)).await {
            Ok(Ok(mut stream)) => {
                if stream.write_all(&dh_export_hello).await.is_err() {
                    return Ok(VulnerabilityScanResult {
                        vulnerability: SslVulnerability::Logjam,
                        vulnerable: false,
                        details: Some("Failed to send ClientHello".to_string()),
                    });
                }

                let mut response = vec![0u8; 4096];
                match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let weak_dh = self.check_weak_dh_params(&response[..n]);
                        Ok(VulnerabilityScanResult {
                            vulnerability: SslVulnerability::Logjam,
                            vulnerable: weak_dh,
                            details: if weak_dh {
                                Some("Server uses weak Diffie-Hellman parameters".to_string())
                            } else {
                                Some("Server DH parameters appear secure".to_string())
                            },
                        })
                    }
                    _ => Ok(VulnerabilityScanResult {
                        vulnerability: SslVulnerability::Logjam,
                        vulnerable: false,
                        details: Some("No response from server".to_string()),
                    }),
                }
            }
            _ => Ok(VulnerabilityScanResult {
                vulnerability: SslVulnerability::Logjam,
                vulnerable: false,
                details: Some("Connection failed".to_string()),
            }),
        }
    }

    /// Check for DROWN vulnerability (CVE-2016-0800)
    pub async fn check_drown(&self, target: SocketAddr) -> Result<VulnerabilityScanResult> {
        // Try SSLv2 connection
        let sslv2_hello = self.build_sslv2_client_hello();
        
        match timeout(self.timeout_duration, TcpStream::connect(target)).await {
            Ok(Ok(mut stream)) => {
                if stream.write_all(&sslv2_hello).await.is_err() {
                    return Ok(VulnerabilityScanResult {
                        vulnerability: SslVulnerability::Drown,
                        vulnerable: false,
                        details: Some("SSLv2 not supported".to_string()),
                    });
                }

                let mut response = vec![0u8; 4096];
                match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let accepts_sslv2 = self.check_sslv2_acceptance(&response[..n]);
                        Ok(VulnerabilityScanResult {
                            vulnerability: SslVulnerability::Drown,
                            vulnerable: accepts_sslv2,
                            details: if accepts_sslv2 {
                                Some("Server accepts SSLv2 connections (CRITICAL!)".to_string())
                            } else {
                                Some("Server does not accept SSLv2".to_string())
                            },
                        })
                    }
                    _ => Ok(VulnerabilityScanResult {
                        vulnerability: SslVulnerability::Drown,
                        vulnerable: false,
                        details: Some("SSLv2 not supported".to_string()),
                    }),
                }
            }
            _ => Ok(VulnerabilityScanResult {
                vulnerability: SslVulnerability::Drown,
                vulnerable: false,
                details: Some("Connection failed".to_string()),
            }),
        }
    }

    // Helper functions to build TLS handshake messages
    
    fn build_heartbeat_client_hello(&self) -> Vec<u8> {
        // Simplified TLS 1.2 ClientHello with heartbeat extension
        // In production, use proper TLS library
        vec![
            0x16, 0x03, 0x03, // TLS 1.2 Handshake
            0x00, 0x40, // Length (64 bytes)
            0x01, // ClientHello
            0x00, 0x00, 0x3c, // Handshake length
            0x03, 0x03, // TLS 1.2
            // Random (32 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // Session ID length
            0x00, 0x04, // Cipher suites length
            0x00, 0x2f, 0x00, 0x35, // AES128-SHA, AES256-SHA
            0x01, 0x00, // Compression: null
            0x00, 0x09, // Extensions length
            0x00, 0x0f, // Heartbeat extension
            0x00, 0x01, 0x01, // Peer allowed to send
        ]
    }

    fn build_malformed_heartbeat(&self) -> Vec<u8> {
        // Malformed heartbeat request (claims more data than provided)
        vec![
            0x18, 0x03, 0x03, // Heartbeat, TLS 1.2
            0x00, 0x03, // Length
            0x01, // Request
            0x40, 0x00, // Payload length (16384 - much larger than actual)
        ]
    }

    fn build_sslv3_client_hello(&self) -> Vec<u8> {
        vec![
            0x16, 0x03, 0x00, // SSLv3 Handshake
            0x00, 0x30, // Length
            0x01, // ClientHello
            0x00, 0x00, 0x2c,
            0x03, 0x00, // SSLv3
            // Random + rest of handshake...
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // Session ID
            0x00, 0x02, 0x00, 0x35, // Cipher: AES256-SHA
            0x01, 0x00, // Compression: null
        ]
    }

    fn build_sslv2_client_hello(&self) -> Vec<u8> {
        vec![
            0x80, 0x1e, // SSLv2 length
            0x01, // ClientHello
            0x00, 0x02, // SSLv2
            0x00, 0x15, // Cipher specs length
            0x00, 0x00, // Session ID length
            0x00, 0x10, // Challenge length
            // Cipher specs
            0x01, 0x00, 0x80, // RC4_128_WITH_MD5
            0x07, 0x00, 0xc0, // 3DES_168_WITH_MD5
            // Challenge (16 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn build_client_hello_with_compression(&self) -> Vec<u8> {
        vec![
            0x16, 0x03, 0x03, // TLS 1.2
            0x00, 0x35,
            0x01, 0x00, 0x00, 0x31,
            0x03, 0x03,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
            0x00, 0x02, 0x00, 0x2f,
            0x02, 0x01, 0x00, // Compression: DEFLATE, null
        ]
    }

    fn build_export_cipher_hello(&self) -> Vec<u8> {
        vec![
            0x16, 0x03, 0x03,
            0x00, 0x38,
            0x01, 0x00, 0x00, 0x34,
            0x03, 0x03,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
            0x00, 0x04,
            0x00, 0x03, // RSA_EXPORT_WITH_RC4_40_MD5
            0x00, 0x06, // RSA_EXPORT_WITH_RC2_CBC_40_MD5
            0x01, 0x00,
        ]
    }

    fn build_dh_export_hello(&self) -> Vec<u8> {
        vec![
            0x16, 0x03, 0x03,
            0x00, 0x36,
            0x01, 0x00, 0x00, 0x32,
            0x03, 0x03,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
            0x00, 0x02,
            0x00, 0x11, // DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
            0x01, 0x00,
        ]
    }

    // Helper functions to check responses

    fn check_heartbeat_support(&self, data: &[u8]) -> bool {
        // Check for heartbeat extension in ServerHello
        data.windows(2).any(|w| w == [0x00, 0x0f])
    }

    fn check_sslv3_acceptance(&self, data: &[u8]) -> bool {
        // Check if ServerHello contains SSLv3 version (0x03 0x00)
        data.len() > 10 && data[9] == 0x03 && data[10] == 0x00
    }

    fn check_sslv2_acceptance(&self, data: &[u8]) -> bool {
        // Check for SSLv2 ServerHello
        data.len() > 2 && (data[0] & 0x80) != 0 && data[2] == 0x04
    }

    fn check_compression_support(&self, data: &[u8]) -> bool {
        // Look for non-zero compression method in ServerHello
        // This is simplified - real implementation needs proper parsing
        data.windows(2).any(|w| w[0] == 0x01 && w[1] != 0x00)
    }

    fn check_export_cipher_acceptance(&self, data: &[u8]) -> bool {
        // Check if server selected export cipher
        // Export cipher IDs: 0x0003, 0x0006, 0x0008, 0x0009, etc.
        data.windows(2).any(|w| {
            w == [0x00, 0x03] || w == [0x00, 0x06] ||
            w == [0x00, 0x08] || w == [0x00, 0x09]
        })
    }

    fn check_weak_dh_params(&self, data: &[u8]) -> bool {
        // Simplified check for export DH acceptance
        self.check_export_cipher_acceptance(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_metadata() {
        let heartbleed = SslVulnerability::Heartbleed;
        assert_eq!(heartbleed.cve(), "CVE-2014-0160");
        assert_eq!(heartbleed.name(), "Heartbleed");
        assert_eq!(heartbleed.severity(), VulnerabilitySeverity::Critical);
        assert!(heartbleed.description().contains("OpenSSL"));
    }

    #[test]
    fn test_all_vulnerabilities_have_metadata() {
        let vulns = vec![
            SslVulnerability::Heartbleed,
            SslVulnerability::Poodle,
            SslVulnerability::Beast,
            SslVulnerability::Crime,
            SslVulnerability::Breach,
            SslVulnerability::Freak,
            SslVulnerability::Logjam,
            SslVulnerability::Drown,
            SslVulnerability::Robot,
            SslVulnerability::InsecureRenegotiation,
        ];

        for vuln in vulns {
            assert!(!vuln.cve().is_empty());
            assert!(!vuln.name().is_empty());
            assert!(!vuln.description().is_empty());
        }
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", VulnerabilitySeverity::Critical), "CRITICAL");
        assert_eq!(format!("{}", VulnerabilitySeverity::High), "HIGH");
        assert_eq!(format!("{}", VulnerabilitySeverity::Medium), "MEDIUM");
    }

    #[test]
    fn test_scanner_creation() {
        let scanner = VulnerabilityScanner::new(Duration::from_secs(10));
        assert_eq!(scanner.timeout_duration, Duration::from_secs(10));
    }

    #[test]
    fn test_heartbeat_hello_format() {
        let scanner = VulnerabilityScanner::new(Duration::from_secs(5));
        let hello = scanner.build_heartbeat_client_hello();
        
        // Should be TLS handshake
        assert_eq!(hello[0], 0x16);
        // Should be TLS 1.2
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x03);
    }

    #[test]
    fn test_sslv3_hello_format() {
        let scanner = VulnerabilityScanner::new(Duration::from_secs(5));
        let hello = scanner.build_sslv3_client_hello();
        
        // Should be SSLv3
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x00);
    }

    #[test]
    fn test_sslv2_hello_format() {
        let scanner = VulnerabilityScanner::new(Duration::from_secs(5));
        let hello = scanner.build_sslv2_client_hello();
        
        // Should have SSLv2 length indicator
        assert_eq!(hello[0] & 0x80, 0x80);
    }
}
