use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

use crate::scanner::ScanResults;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub key_size: KeySize,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            key_size: KeySize::Bits256,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum KeySize {
    Bits256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionStats {
    pub plaintext_size: usize,
    pub ciphertext_size: usize,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub version: u32,
}

impl EncryptedData {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(self)?;
        Ok(json)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let encrypted: EncryptedData = serde_json::from_slice(data)?;
        Ok(encrypted)
    }
}

pub struct EncryptionKey {
    key_bytes: Vec<u8>,
}

impl EncryptionKey {
    pub fn new(key_bytes: Vec<u8>) -> Result<Self> {
        if key_bytes.len() != 32 {
            return Err(anyhow!(
                "Invalid key length: expected 32 bytes, got {}",
                key_bytes.len()
            ));
        }
        Ok(Self { key_bytes })
    }

    pub fn generate() -> Self {
        use rand::RngCore;
        let mut key_bytes = vec![0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        Self { key_bytes }
    }

    pub fn from_passphrase(passphrase: &str, salt: &[u8]) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut key_bytes = vec![0u8; 32];
        let mut hasher = DefaultHasher::new();
        passphrase.hash(&mut hasher);
        salt.hash(&mut hasher);
        let hash = hasher.finish();

        for i in 0..32 {
            key_bytes[i] = ((hash >> ((i % 8) * 8)) & 0xFF) as u8;
            if i >= 8 {
                key_bytes[i] ^= salt.get(i % salt.len()).copied().unwrap_or(0);
            }
        }

        Self { key_bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key_bytes
    }
}

pub struct ScanEncryptor {
    config: EncryptionConfig,
    key: EncryptionKey,
}

impl ScanEncryptor {
    pub fn new(key: EncryptionKey) -> Self {
        Self {
            config: EncryptionConfig::default(),
            key,
        }
    }

    pub fn with_config(key: EncryptionKey, config: EncryptionConfig) -> Self {
        Self { config, key }
    }

    pub fn encrypt(&self, results: &ScanResults) -> Result<(EncryptedData, EncryptionStats)> {
        let plaintext = serde_json::to_vec(results)?;
        let plaintext_size = plaintext.len();

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key.key_bytes));

        let mut nonce_bytes = [0u8; 12];
        use rand::RngCore;
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        let ciphertext_size = ciphertext.len() + 12;

        Ok((
            EncryptedData {
                nonce: nonce_bytes.to_vec(),
                ciphertext,
                version: 1,
            },
            EncryptionStats {
                plaintext_size,
                ciphertext_size,
                algorithm: "AES-256-GCM".to_string(),
            },
        ))
    }

    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<ScanResults> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key.key_bytes));
        let nonce = Nonce::from_slice(&encrypted.nonce);

        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        let results: ScanResults = serde_json::from_slice(&plaintext)?;
        Ok(results)
    }

    pub fn encrypt_to_writer<W: Write>(
        &self,
        results: &ScanResults,
        writer: &mut W,
    ) -> Result<EncryptionStats> {
        let (encrypted, stats) = self.encrypt(results)?;
        let bytes = encrypted.to_bytes()?;
        writer.write_all(&bytes)?;
        Ok(stats)
    }

    pub fn decrypt_from_reader<R: Read>(&self, reader: &mut R) -> Result<ScanResults> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        let encrypted = EncryptedData::from_bytes(&data)?;
        self.decrypt(&encrypted)
    }

    pub fn reencrypt(
        &self,
        encrypted: &EncryptedData,
        new_key: &EncryptionKey,
    ) -> Result<(EncryptedData, EncryptionStats)> {
        let results = self.decrypt(encrypted)?;
        let new_encryptor = ScanEncryptor::new(EncryptionKey::new(new_key.key_bytes.clone())?);
        new_encryptor.encrypt(&results)
    }

    pub fn config(&self) -> &EncryptionConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{PortState, Protocol, ScanResult, ScanResults};
    use chrono::Utc;
    use std::net::IpAddr;

    fn create_test_results(count: usize) -> ScanResults {
        let results: Vec<ScanResult> = (0..count)
            .map(|i| ScanResult {
                target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                port: (80 + i) as u16,
                state: PortState::Open,
                protocol: Protocol::TCP,
                service: Some(format!("service-{}", i)),
                service_info: None,
                hostname: None,
                reason: None,
                timestamp: Utc::now(),
            })
            .collect();

        ScanResults {
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 1,
            port_count: count,
            results,
            os_fingerprints: Vec::new(),
            script_results: Vec::new(),
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = EncryptionKey::generate();
        let encryptor = ScanEncryptor::new(key);
        let results = create_test_results(5);

        let (encrypted, stats) = encryptor.encrypt(&results).unwrap();
        assert_eq!(stats.algorithm, "AES-256-GCM");
        assert!(stats.ciphertext_size > 0);

        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted.results.len(), 5);
        assert_eq!(decrypted.results[0].port, 80);
    }

    #[test]
    fn test_different_keys_fail() {
        let key1 = EncryptionKey::generate();
        let key2 = EncryptionKey::generate();
        let encryptor1 = ScanEncryptor::new(key1);
        let encryptor2 = ScanEncryptor::new(key2);

        let results = create_test_results(3);
        let (encrypted, _) = encryptor1.encrypt(&results).unwrap();

        assert!(encryptor2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let key = EncryptionKey::generate();
        let encryptor = ScanEncryptor::new(key);
        let results = create_test_results(3);

        let (encrypted, _) = encryptor.encrypt(&results).unwrap();
        let bytes = encrypted.to_bytes().unwrap();
        let restored = EncryptedData::from_bytes(&bytes).unwrap();

        assert_eq!(restored.nonce, encrypted.nonce);
        assert_eq!(restored.ciphertext, encrypted.ciphertext);
    }

    #[test]
    fn test_key_from_passphrase() {
        let key1 = EncryptionKey::from_passphrase("test-password", b"salt1");
        let key2 = EncryptionKey::from_passphrase("test-password", b"salt1");
        let key3 = EncryptionKey::from_passphrase("test-password", b"salt2");

        assert_eq!(key1.as_bytes(), key2.as_bytes());
        assert_ne!(key1.as_bytes(), key3.as_bytes());
    }

    #[test]
    fn test_invalid_key_length() {
        assert!(EncryptionKey::new(vec![0u8; 16]).is_err());
        assert!(EncryptionKey::new(vec![0u8; 32]).is_ok());
    }

    #[test]
    fn test_reencrypt() {
        let key1 = EncryptionKey::generate();
        let key2 = EncryptionKey::generate();
        let encryptor = ScanEncryptor::new(EncryptionKey::new(key1.key_bytes.clone()).unwrap());

        let results = create_test_results(3);
        let (encrypted, _) = encryptor.encrypt(&results).unwrap();

        let new_encryptor = ScanEncryptor::new(EncryptionKey::new(key2.key_bytes.clone()).unwrap());
        let (reencrypted, _) = encryptor.reencrypt(&encrypted, &key2).unwrap();

        let decrypted = new_encryptor.decrypt(&reencrypted).unwrap();
        assert_eq!(decrypted.results.len(), 3);
    }

    #[test]
    fn test_streaming_encrypt_decrypt() {
        let key = EncryptionKey::generate();
        let encryptor = ScanEncryptor::new(key);
        let results = create_test_results(5);

        let mut buffer = Vec::new();
        encryptor
            .encrypt_to_writer(&results, &mut buffer)
            .unwrap();
        assert!(!buffer.is_empty());

        let mut cursor = std::io::Cursor::new(buffer);
        let decrypted = encryptor.decrypt_from_reader(&mut cursor).unwrap();
        assert_eq!(decrypted.results.len(), 5);
    }

    #[test]
    fn test_empty_results() {
        let key = EncryptionKey::generate();
        let encryptor = ScanEncryptor::new(key);
        let results = create_test_results(0);

        let (encrypted, _) = encryptor.encrypt(&results).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        assert!(decrypted.results.is_empty());
    }

    #[test]
    fn test_nonce_uniqueness() {
        let key = EncryptionKey::generate();
        let encryptor = ScanEncryptor::new(key);
        let results = create_test_results(1);

        let (enc1, _) = encryptor.encrypt(&results).unwrap();
        let (enc2, _) = encryptor.encrypt(&results).unwrap();

        assert_ne!(enc1.nonce, enc2.nonce);
    }

    #[test]
    fn test_tampered_ciphertext() {
        let key = EncryptionKey::generate();
        let encryptor = ScanEncryptor::new(key);
        let results = create_test_results(3);

        let (mut encrypted, _) = encryptor.encrypt(&results).unwrap();
        encrypted.ciphertext[0] ^= 0xFF;

        assert!(encryptor.decrypt(&encrypted).is_err());
    }
}
