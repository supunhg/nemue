use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Threat intelligence information for an IP or domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub ip: String,
    pub is_malicious: bool,
    pub threat_level: ThreatLevel,
    pub categories: Vec<String>,
    pub last_seen: Option<String>,
    pub confidence_score: u8, // 0-100
    pub sources: Vec<String>,
}

/// Threat severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatLevel {
    Critical, // Known active attacks
    High,     // Known malicious infrastructure
    Medium,   // Suspicious activity
    Low,      // Minimal risk
    None,     // Clean
}

impl ThreatLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatLevel::Critical => "CRITICAL",
            ThreatLevel::High => "HIGH",
            ThreatLevel::Medium => "MEDIUM",
            ThreatLevel::Low => "LOW",
            ThreatLevel::None => "NONE",
        }
    }

    pub fn from_score(score: u8) -> Self {
        match score {
            s if s >= 90 => ThreatLevel::Critical,
            s if s >= 70 => ThreatLevel::High,
            s if s >= 40 => ThreatLevel::Medium,
            s if s >= 10 => ThreatLevel::Low,
            _ => ThreatLevel::None,
        }
    }
}

/// Threat intelligence database
pub struct ThreatDatabase {
    cache: HashMap<String, ThreatInfo>,
    use_cache: bool,
    // In production, these would be API keys for various services
    abuseipdb_key: Option<String>,
    virustotal_key: Option<String>,
}

impl ThreatDatabase {
    pub fn new(use_cache: bool) -> Self {
        Self {
            cache: HashMap::new(),
            use_cache,
            abuseipdb_key: None,
            virustotal_key: None,
        }
    }

    /// Configure API keys for threat intelligence services
    pub fn configure_apis(
        &mut self,
        abuseipdb_key: Option<String>,
        virustotal_key: Option<String>,
    ) {
        self.abuseipdb_key = abuseipdb_key;
        self.virustotal_key = virustotal_key;
    }

    /// Lookup threat intelligence for an IP address
    pub async fn lookup_ip(&mut self, ip: &IpAddr) -> Result<ThreatInfo> {
        let ip_str = ip.to_string();

        // Check cache first
        if self.use_cache {
            if let Some(cached) = self.cache.get(&ip_str) {
                return Ok(cached.clone());
            }
        }

        // In production, this would query multiple threat intel APIs
        let threat_info = self.query_threat_services(&ip_str).await?;

        // Cache the results
        if self.use_cache {
            self.cache.insert(ip_str, threat_info.clone());
        }

        Ok(threat_info)
    }

    /// Query threat intelligence services
    /// In production, this would make actual API calls to:
    /// - AbuseIPDB: https://www.abuseipdb.com/api
    /// - VirusTotal: https://developers.virustotal.com/reference/overview
    /// - AlienVault OTX: https://otx.alienvault.com/api
    async fn query_threat_services(&self, ip: &str) -> Result<ThreatInfo> {
        // For demonstration, use a local blacklist
        let threat_info = self.check_local_blacklist(ip);

        // In production, you would aggregate results from multiple sources:
        // let abuseipdb_result = self.query_abuseipdb(ip).await?;
        // let virustotal_result = self.query_virustotal(ip).await?;
        // let otx_result = self.query_otx(ip).await?;
        // then combine and correlate the results

        Ok(threat_info)
    }

    /// Check against local threat blacklist
    fn check_local_blacklist(&self, ip: &str) -> ThreatInfo {
        // Known malicious IP patterns (simplified for demo)
        let _known_threats = [
            ("192.0.2.0/24", "TEST-NET-1 (RFC 5737)", 0),
            ("198.51.100.0/24", "TEST-NET-2 (RFC 5737)", 0),
            ("203.0.113.0/24", "TEST-NET-3 (RFC 5737)", 0),
        ];

        // Check for known C2 servers (example IPs - not real)
        let c2_patterns = vec![
            "45.142.",  // Common VPS provider
            "185.220.", // Tor exit nodes
            "194.180.", // Bulletproof hosting
        ];

        let mut categories = Vec::new();
        let mut confidence = 0u8;
        let mut is_malicious = false;

        // Check if IP matches known C2 patterns
        for pattern in c2_patterns {
            if ip.starts_with(pattern) {
                categories.push("Command & Control".to_string());
                confidence = 65;
                is_malicious = true;
                break;
            }
        }

        // Check for suspicious ports being scanned from this IP
        // (This would integrate with scan history in production)

        // Default to clean if no matches
        if categories.is_empty() {
            categories.push("Clean".to_string());
        }

        ThreatInfo {
            ip: ip.to_string(),
            is_malicious,
            threat_level: ThreatLevel::from_score(confidence),
            categories,
            last_seen: None,
            confidence_score: confidence,
            sources: vec!["LocalBlacklist".to_string()],
        }
    }

    /// Clear the cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> usize {
        self.cache.len()
    }

    /// Check if an IP is in known botnet ranges
    pub fn is_botnet(&self, ip: &IpAddr) -> bool {
        let ip_str = ip.to_string();

        // Common botnet IP patterns (simplified)
        let botnet_patterns = vec![
            "185.220.", // Tor exit nodes often used by botnets
            "45.142.",  // Cheap VPS providers
        ];

        botnet_patterns.iter().any(|p| ip_str.starts_with(p))
    }

    /// Check if an IP is a known Tor exit node
    pub fn is_tor_exit(&self, ip: &IpAddr) -> bool {
        let ip_str = ip.to_string();
        ip_str.starts_with("185.220.") // Simplified check
    }

    /// Get reputation score (0-100, higher is better)
    pub async fn get_reputation(&mut self, ip: &IpAddr) -> Result<u8> {
        let threat_info = self.lookup_ip(ip).await?;
        Ok(100 - threat_info.confidence_score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_clean_ip_lookup() {
        let mut db = ThreatDatabase::new(true);
        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        let info = db.lookup_ip(&ip).await.unwrap();
        assert!(!info.is_malicious);
        assert_eq!(info.threat_level, ThreatLevel::None);
    }

    #[tokio::test]
    async fn test_malicious_ip_detection() {
        let mut db = ThreatDatabase::new(true);
        let ip = IpAddr::from_str("45.142.1.1").unwrap();
        let info = db.lookup_ip(&ip).await.unwrap();
        assert!(info.is_malicious);
        assert!(info.confidence_score > 0);
    }

    #[tokio::test]
    async fn test_cache_functionality() {
        let mut db = ThreatDatabase::new(true);
        let ip = IpAddr::from_str("1.1.1.1").unwrap();

        // First lookup
        let _ = db.lookup_ip(&ip).await.unwrap();
        assert_eq!(db.cache_stats(), 1);

        // Second lookup should use cache
        let _ = db.lookup_ip(&ip).await.unwrap();
        assert_eq!(db.cache_stats(), 1);

        // Clear cache
        db.clear_cache();
        assert_eq!(db.cache_stats(), 0);
    }

    #[test]
    fn test_tor_detection() {
        let db = ThreatDatabase::new(false);
        let tor_ip = IpAddr::from_str("185.220.101.1").unwrap();
        assert!(db.is_tor_exit(&tor_ip));

        let clean_ip = IpAddr::from_str("8.8.8.8").unwrap();
        assert!(!db.is_tor_exit(&clean_ip));
    }

    #[test]
    fn test_threat_level_from_score() {
        assert_eq!(ThreatLevel::from_score(95), ThreatLevel::Critical);
        assert_eq!(ThreatLevel::from_score(75), ThreatLevel::High);
        assert_eq!(ThreatLevel::from_score(50), ThreatLevel::Medium);
        assert_eq!(ThreatLevel::from_score(15), ThreatLevel::Low);
        assert_eq!(ThreatLevel::from_score(5), ThreatLevel::None);
    }

    #[tokio::test]
    async fn test_reputation_score() {
        let mut db = ThreatDatabase::new(true);
        let clean_ip = IpAddr::from_str("8.8.8.8").unwrap();
        let rep = db.get_reputation(&clean_ip).await.unwrap();
        assert!(rep > 90); // Clean IPs should have high reputation
    }
}
