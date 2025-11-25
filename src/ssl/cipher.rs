//! SSL/TLS Cipher Suite Analysis

use serde::{Deserialize, Serialize};
use std::fmt;

/// Cipher suite strength classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CipherStrength {
    Null,       // NULL cipher (no encryption)
    Weak,       // Export, DES, RC4, <128-bit
    Medium,     // 128-bit
    Strong,     // 256-bit AES-GCM, ChaCha20
    Recommended, // TLS 1.3 ciphers
}

impl fmt::Display for CipherStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CipherStrength::Null => write!(f, "NULL"),
            CipherStrength::Weak => write!(f, "WEAK"),
            CipherStrength::Medium => write!(f, "MEDIUM"),
            CipherStrength::Strong => write!(f, "STRONG"),
            CipherStrength::Recommended => write!(f, "RECOMMENDED"),
        }
    }
}

/// SSL/TLS Cipher Suite
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherSuite {
    /// IANA cipher suite name
    pub name: String,
    /// OpenSSL cipher suite name
    pub openssl_name: String,
    /// Cipher suite ID (hex)
    pub id: u16,
    /// Key exchange algorithm
    pub kex: String,
    /// Authentication algorithm
    pub auth: String,
    /// Encryption algorithm
    pub enc: String,
    /// Key size in bits
    pub key_size: usize,
    /// MAC algorithm
    pub mac: String,
    /// Whether cipher supports Perfect Forward Secrecy
    pub pfs: bool,
    /// Cipher strength
    pub strength: CipherStrength,
    /// TLS version support
    pub tls_versions: Vec<super::TlsVersion>,
}

impl CipherSuite {
    /// Check if cipher is considered secure
    pub fn is_secure(&self) -> bool {
        matches!(self.strength, CipherStrength::Strong | CipherStrength::Recommended)
            && self.pfs
            && !self.has_weak_components()
    }

    /// Check for weak cryptographic components
    pub fn has_weak_components(&self) -> bool {
        // Weak key exchange
        let weak_kex = self.kex.contains("DH_anon")
            || self.kex.contains("ECDH_anon")
            || self.kex.contains("NULL")
            || self.kex.contains("EXPORT");

        // Weak encryption
        let weak_enc = self.enc.contains("NULL")
            || self.enc.contains("DES")
            || self.enc.contains("RC4")
            || self.enc.contains("EXPORT");

        // Weak MAC
        let weak_mac = self.mac.contains("NULL") || self.mac.contains("MD5");

        weak_kex || weak_enc || weak_mac
    }

    /// Get security issues with this cipher
    pub fn security_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();

        if self.strength == CipherStrength::Null {
            issues.push("No encryption (NULL cipher)".to_string());
        }

        if self.strength == CipherStrength::Weak {
            issues.push("Weak encryption strength".to_string());
        }

        if !self.pfs {
            issues.push("No Perfect Forward Secrecy".to_string());
        }

        if self.enc.contains("RC4") {
            issues.push("RC4 cipher (known vulnerabilities)".to_string());
        }

        if self.enc.contains("DES") && !self.enc.contains("3DES") {
            issues.push("DES encryption (insecure)".to_string());
        }

        if self.enc.contains("3DES") {
            issues.push("3DES encryption (legacy, consider upgrading)".to_string());
        }

        if self.mac.contains("MD5") {
            issues.push("MD5 MAC (cryptographically broken)".to_string());
        }

        if self.mac.contains("SHA1") {
            issues.push("SHA1 MAC (deprecated)".to_string());
        }

        if self.key_size < 128 {
            issues.push(format!("Weak key size: {} bits", self.key_size));
        }

        issues
    }
}

/// Supported cipher suites for a target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedCiphers {
    /// TLS version
    pub tls_version: super::TlsVersion,
    /// List of supported ciphers
    pub ciphers: Vec<CipherSuite>,
    /// Preferred cipher (server's choice)
    pub preferred_cipher: Option<CipherSuite>,
}

impl SupportedCiphers {
    /// Get ciphers by strength
    pub fn by_strength(&self, strength: CipherStrength) -> Vec<&CipherSuite> {
        self.ciphers.iter().filter(|c| c.strength == strength).collect()
    }

    /// Check if any weak ciphers are supported
    pub fn has_weak_ciphers(&self) -> bool {
        self.ciphers.iter().any(|c| matches!(c.strength, CipherStrength::Weak | CipherStrength::Null))
    }

    /// Get count by strength
    pub fn count_by_strength(&self) -> std::collections::HashMap<CipherStrength, usize> {
        let mut counts = std::collections::HashMap::new();
        for cipher in &self.ciphers {
            *counts.entry(cipher.strength).or_insert(0) += 1;
        }
        counts
    }

    /// Get security score (0-100)
    pub fn security_score(&self) -> u8 {
        if self.ciphers.is_empty() {
            return 0;
        }

        let mut score = 100;

        // Penalize weak ciphers
        let weak_count = self.by_strength(CipherStrength::Weak).len();
        let null_count = self.by_strength(CipherStrength::Null).len();
        score -= (weak_count as u8 * 10).min(40);
        score -= (null_count as u8 * 20).min(60);

        // Reward strong ciphers
        let strong_count = self.by_strength(CipherStrength::Strong).len();
        let recommended_count = self.by_strength(CipherStrength::Recommended).len();
        if strong_count + recommended_count == 0 {
            score -= 30;
        }

        // Check PFS support
        let pfs_count = self.ciphers.iter().filter(|c| c.pfs).count();
        if pfs_count == 0 {
            score -= 20;
        }

        // Preferred cipher matters
        if let Some(ref preferred) = self.preferred_cipher {
            if !preferred.is_secure() {
                score -= 15;
            }
        }

        score.max(0)
    }
}

/// Cipher suite database
pub struct CipherDatabase;

impl CipherDatabase {
    /// Get cipher suite by ID
    pub fn get_cipher(id: u16) -> Option<CipherSuite> {
        // Common cipher suites (subset)
        match id {
            // TLS 1.3 ciphers (recommended)
            0x1301 => Some(Self::tls13_aes_128_gcm_sha256()),
            0x1302 => Some(Self::tls13_aes_256_gcm_sha384()),
            0x1303 => Some(Self::tls13_chacha20_poly1305_sha256()),

            // TLS 1.2 strong ciphers
            0xc02f => Some(Self::ecdhe_rsa_aes_128_gcm_sha256()),
            0xc030 => Some(Self::ecdhe_rsa_aes_256_gcm_sha384()),
            0xcca8 => Some(Self::ecdhe_rsa_chacha20_poly1305()),

            // TLS 1.2 medium ciphers
            0xc013 => Some(Self::ecdhe_rsa_aes_128_cbc_sha()),
            0xc014 => Some(Self::ecdhe_rsa_aes_256_cbc_sha()),

            // Weak ciphers
            0x0005 => Some(Self::rsa_rc4_128_sha()),
            0x000a => Some(Self::rsa_3des_ede_cbc_sha()),

            _ => None,
        }
    }

    // TLS 1.3 ciphers
    fn tls13_aes_128_gcm_sha256() -> CipherSuite {
        CipherSuite {
            name: "TLS_AES_128_GCM_SHA256".to_string(),
            openssl_name: "TLS_AES_128_GCM_SHA256".to_string(),
            id: 0x1301,
            kex: "TLS13".to_string(),
            auth: "TLS13".to_string(),
            enc: "AES-128-GCM".to_string(),
            key_size: 128,
            mac: "AEAD".to_string(),
            pfs: true,
            strength: CipherStrength::Recommended,
            tls_versions: vec![super::TlsVersion::Tls13],
        }
    }

    fn tls13_aes_256_gcm_sha384() -> CipherSuite {
        CipherSuite {
            name: "TLS_AES_256_GCM_SHA384".to_string(),
            openssl_name: "TLS_AES_256_GCM_SHA384".to_string(),
            id: 0x1302,
            kex: "TLS13".to_string(),
            auth: "TLS13".to_string(),
            enc: "AES-256-GCM".to_string(),
            key_size: 256,
            mac: "AEAD".to_string(),
            pfs: true,
            strength: CipherStrength::Recommended,
            tls_versions: vec![super::TlsVersion::Tls13],
        }
    }

    fn tls13_chacha20_poly1305_sha256() -> CipherSuite {
        CipherSuite {
            name: "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            openssl_name: "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            id: 0x1303,
            kex: "TLS13".to_string(),
            auth: "TLS13".to_string(),
            enc: "CHACHA20-POLY1305".to_string(),
            key_size: 256,
            mac: "AEAD".to_string(),
            pfs: true,
            strength: CipherStrength::Recommended,
            tls_versions: vec![super::TlsVersion::Tls13],
        }
    }

    // TLS 1.2 strong ciphers
    fn ecdhe_rsa_aes_128_gcm_sha256() -> CipherSuite {
        CipherSuite {
            name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
            openssl_name: "ECDHE-RSA-AES128-GCM-SHA256".to_string(),
            id: 0xc02f,
            kex: "ECDHE".to_string(),
            auth: "RSA".to_string(),
            enc: "AES-128-GCM".to_string(),
            key_size: 128,
            mac: "SHA256".to_string(),
            pfs: true,
            strength: CipherStrength::Strong,
            tls_versions: vec![super::TlsVersion::Tls12],
        }
    }

    fn ecdhe_rsa_aes_256_gcm_sha384() -> CipherSuite {
        CipherSuite {
            name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
            openssl_name: "ECDHE-RSA-AES256-GCM-SHA384".to_string(),
            id: 0xc030,
            kex: "ECDHE".to_string(),
            auth: "RSA".to_string(),
            enc: "AES-256-GCM".to_string(),
            key_size: 256,
            mac: "SHA384".to_string(),
            pfs: true,
            strength: CipherStrength::Strong,
            tls_versions: vec![super::TlsVersion::Tls12],
        }
    }

    fn ecdhe_rsa_chacha20_poly1305() -> CipherSuite {
        CipherSuite {
            name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
            openssl_name: "ECDHE-RSA-CHACHA20-POLY1305".to_string(),
            id: 0xcca8,
            kex: "ECDHE".to_string(),
            auth: "RSA".to_string(),
            enc: "CHACHA20-POLY1305".to_string(),
            key_size: 256,
            mac: "SHA256".to_string(),
            pfs: true,
            strength: CipherStrength::Strong,
            tls_versions: vec![super::TlsVersion::Tls12],
        }
    }

    fn ecdhe_rsa_aes_128_cbc_sha() -> CipherSuite {
        CipherSuite {
            name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".to_string(),
            openssl_name: "ECDHE-RSA-AES128-SHA".to_string(),
            id: 0xc013,
            kex: "ECDHE".to_string(),
            auth: "RSA".to_string(),
            enc: "AES-128-CBC".to_string(),
            key_size: 128,
            mac: "SHA1".to_string(),
            pfs: true,
            strength: CipherStrength::Medium,
            tls_versions: vec![super::TlsVersion::Tls12, super::TlsVersion::Tls11, super::TlsVersion::Tls10],
        }
    }

    fn ecdhe_rsa_aes_256_cbc_sha() -> CipherSuite {
        CipherSuite {
            name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA".to_string(),
            openssl_name: "ECDHE-RSA-AES256-SHA".to_string(),
            id: 0xc014,
            kex: "ECDHE".to_string(),
            auth: "RSA".to_string(),
            enc: "AES-256-CBC".to_string(),
            key_size: 256,
            mac: "SHA1".to_string(),
            pfs: true,
            strength: CipherStrength::Medium,
            tls_versions: vec![super::TlsVersion::Tls12, super::TlsVersion::Tls11, super::TlsVersion::Tls10],
        }
    }

    // Weak ciphers
    fn rsa_rc4_128_sha() -> CipherSuite {
        CipherSuite {
            name: "TLS_RSA_WITH_RC4_128_SHA".to_string(),
            openssl_name: "RC4-SHA".to_string(),
            id: 0x0005,
            kex: "RSA".to_string(),
            auth: "RSA".to_string(),
            enc: "RC4-128".to_string(),
            key_size: 128,
            mac: "SHA1".to_string(),
            pfs: false,
            strength: CipherStrength::Weak,
            tls_versions: vec![super::TlsVersion::Tls12, super::TlsVersion::Tls11, super::TlsVersion::Tls10, super::TlsVersion::SslV3],
        }
    }

    fn rsa_3des_ede_cbc_sha() -> CipherSuite {
        CipherSuite {
            name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA".to_string(),
            openssl_name: "DES-CBC3-SHA".to_string(),
            id: 0x000a,
            kex: "RSA".to_string(),
            auth: "RSA".to_string(),
            enc: "3DES-EDE-CBC".to_string(),
            key_size: 168,
            mac: "SHA1".to_string(),
            pfs: false,
            strength: CipherStrength::Weak,
            tls_versions: vec![super::TlsVersion::Tls12, super::TlsVersion::Tls11, super::TlsVersion::Tls10, super::TlsVersion::SslV3],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_strength_ordering() {
        assert!(CipherStrength::Recommended > CipherStrength::Strong);
        assert!(CipherStrength::Strong > CipherStrength::Medium);
        assert!(CipherStrength::Medium > CipherStrength::Weak);
        assert!(CipherStrength::Weak > CipherStrength::Null);
    }

    #[test]
    fn test_tls13_cipher_is_secure() {
        let cipher = CipherDatabase::tls13_aes_256_gcm_sha384();
        assert!(cipher.is_secure());
        assert_eq!(cipher.strength, CipherStrength::Recommended);
        assert!(cipher.pfs);
    }

    #[test]
    fn test_weak_cipher_detection() {
        let cipher = CipherDatabase::rsa_rc4_128_sha();
        assert!(!cipher.is_secure());
        assert_eq!(cipher.strength, CipherStrength::Weak);
        assert!(!cipher.pfs);
        
        let issues = cipher.security_issues();
        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.contains("RC4")));
    }

    #[test]
    fn test_3des_cipher() {
        let cipher = CipherDatabase::rsa_3des_ede_cbc_sha();
        assert!(!cipher.is_secure());
        let issues = cipher.security_issues();
        assert!(issues.iter().any(|i| i.contains("3DES")));
    }

    #[test]
    fn test_supported_ciphers_security_score() {
        let strong_ciphers = SupportedCiphers {
            tls_version: crate::ssl::TlsVersion::Tls13,
            ciphers: vec![
                CipherDatabase::tls13_aes_128_gcm_sha256(),
                CipherDatabase::tls13_aes_256_gcm_sha384(),
            ],
            preferred_cipher: Some(CipherDatabase::tls13_aes_256_gcm_sha384()),
        };
        assert!(strong_ciphers.security_score() >= 90);

        let weak_ciphers = SupportedCiphers {
            tls_version: crate::ssl::TlsVersion::Tls10,
            ciphers: vec![
                CipherDatabase::rsa_rc4_128_sha(),
                CipherDatabase::rsa_3des_ede_cbc_sha(),
            ],
            preferred_cipher: Some(CipherDatabase::rsa_rc4_128_sha()),
        };
        assert!(weak_ciphers.security_score() < 50);
    }

    #[test]
    fn test_cipher_database_lookup() {
        assert!(CipherDatabase::get_cipher(0x1301).is_some());
        assert!(CipherDatabase::get_cipher(0xc02f).is_some());
        assert!(CipherDatabase::get_cipher(0x9999).is_none());
    }

    #[test]
    fn test_count_by_strength() {
        let ciphers = SupportedCiphers {
            tls_version: crate::ssl::TlsVersion::Tls12,
            ciphers: vec![
                CipherDatabase::tls13_aes_128_gcm_sha256(),
                CipherDatabase::ecdhe_rsa_aes_128_gcm_sha256(),
                CipherDatabase::rsa_rc4_128_sha(),
            ],
            preferred_cipher: None,
        };

        let counts = ciphers.count_by_strength();
        assert_eq!(counts.get(&CipherStrength::Recommended), Some(&1));
        assert_eq!(counts.get(&CipherStrength::Strong), Some(&1));
        assert_eq!(counts.get(&CipherStrength::Weak), Some(&1));
    }
}
