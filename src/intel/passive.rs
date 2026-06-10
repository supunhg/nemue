use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Passive reconnaissance data from external sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveData {
    pub ip: String,
    pub ports: Vec<PortInfo>,
    pub domains: Vec<String>,
    pub technologies: Vec<String>,
    pub last_updated: String,
    pub source: String,
}

/// Port information from passive sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub banner: Option<String>,
}

/// Passive reconnaissance engine
/// Queries services like Shodan, Censys, Netlas before active scanning
pub struct PassiveRecon {
    cache: HashMap<String, PassiveData>,
    use_cache: bool,
    // API keys for various services
    shodan_key: Option<String>,
    censys_key: Option<String>,
}

impl PassiveRecon {
    pub fn new(use_cache: bool) -> Self {
        Self {
            cache: HashMap::new(),
            use_cache,
            shodan_key: None,
            censys_key: None,
        }
    }

    /// Configure API keys for passive recon services
    pub fn configure_apis(&mut self, shodan_key: Option<String>, censys_key: Option<String>) {
        self.shodan_key = shodan_key;
        self.censys_key = censys_key;
    }

    /// Query passive intelligence sources for an IP
    pub async fn query(&mut self, ip: &str) -> Result<Option<PassiveData>> {
        // Check cache first
        if self.use_cache {
            if let Some(cached) = self.cache.get(ip) {
                return Ok(Some(cached.clone()));
            }
        }

        // In production, this would query actual APIs:
        // - Shodan: https://developer.shodan.io/api
        // - Censys: https://search.censys.io/api
        // - Netlas: https://netlas.io/api
        // - GreyNoise: https://docs.greynoise.io/

        let data = self.query_sources(ip).await?;

        // Cache the results
        if let Some(ref d) = data {
            if self.use_cache {
                self.cache.insert(ip.to_string(), d.clone());
            }
        }

        Ok(data)
    }

    /// Query multiple passive intelligence sources
    /// In production, this would make actual HTTP requests to APIs
    async fn query_sources(&self, ip: &str) -> Result<Option<PassiveData>> {
        // For demonstration, return simulated data for known patterns

        // Check if we have API keys configured
        if self.shodan_key.is_none() && self.censys_key.is_none() {
            // No API keys - return None (passive recon disabled)
            return Ok(None);
        }

        // Simulate passive data for demonstration
        // In production, replace with actual API calls
        let data = PassiveData {
            ip: ip.to_string(),
            ports: vec![
                PortInfo {
                    port: 80,
                    protocol: "tcp".to_string(),
                    service: "HTTP".to_string(),
                    banner: Some("nginx/1.18.0".to_string()),
                },
                PortInfo {
                    port: 443,
                    protocol: "tcp".to_string(),
                    service: "HTTPS".to_string(),
                    banner: Some("nginx/1.18.0".to_string()),
                },
            ],
            domains: vec!["example.com".to_string()],
            technologies: vec!["nginx".to_string(), "PHP".to_string()],
            last_updated: "2024-01-15".to_string(),
            source: "Simulated".to_string(),
        };

        // Only return data if we have API keys (in demo, always return some data)
        Ok(Some(data))
    }

    /// Check if passive data is available for an IP
    pub fn has_data(&self, ip: &str) -> bool {
        self.cache.contains_key(ip)
    }

    /// Get cached passive data
    pub fn get_cached(&self, ip: &str) -> Option<&PassiveData> {
        self.cache.get(ip)
    }

    /// Clear the cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get statistics
    pub fn stats(&self) -> PassiveReconStats {
        PassiveReconStats {
            cached_ips: self.cache.len(),
            total_ports: self.cache.values().map(|d| d.ports.len()).sum(),
            has_api_keys: self.shodan_key.is_some() || self.censys_key.is_some(),
        }
    }
}

/// Statistics for passive reconnaissance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveReconStats {
    pub cached_ips: usize,
    pub total_ports: usize,
    pub has_api_keys: bool,
}

/// Merge passive data with active scan results
pub fn merge_scan_data(
    passive: &PassiveData,
    active_ports: &[(u16, String)],
) -> Vec<(u16, String, bool)> {
    let mut merged = Vec::new();
    let passive_port_set: std::collections::HashSet<u16> =
        passive.ports.iter().map(|p| p.port).collect();

    // Add all active scan results
    for (port, service) in active_ports {
        let in_passive = passive_port_set.contains(port);
        merged.push((*port, service.clone(), in_passive));
    }

    // Add passive-only ports (not found in active scan)
    for port_info in &passive.ports {
        if !active_ports.iter().any(|(p, _)| *p == port_info.port) {
            merged.push((port_info.port, port_info.service.clone(), true));
        }
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_passive_recon_creation() {
        let recon = PassiveRecon::new(true);
        assert!(recon.use_cache);
        assert!(recon.shodan_key.is_none());
    }

    #[tokio::test]
    async fn test_configure_apis() {
        let mut recon = PassiveRecon::new(true);
        recon.configure_apis(
            Some("test_shodan_key".to_string()),
            Some("test_censys_key".to_string()),
        );
        assert!(recon.shodan_key.is_some());
        assert!(recon.censys_key.is_some());
    }

    #[tokio::test]
    async fn test_query_without_api_keys() {
        let mut recon = PassiveRecon::new(true);
        let result = recon.query("8.8.8.8").await.unwrap();
        // Without API keys, should return None
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_query_with_api_keys() {
        let mut recon = PassiveRecon::new(true);
        recon.configure_apis(Some("test_key".to_string()), None);

        let result = recon.query("1.2.3.4").await.unwrap();
        assert!(result.is_some());

        let data = result.unwrap();
        assert_eq!(data.ip, "1.2.3.4");
        assert!(!data.ports.is_empty());
    }

    #[tokio::test]
    async fn test_cache_functionality() {
        let mut recon = PassiveRecon::new(true);
        recon.configure_apis(Some("test".to_string()), None);

        // First query
        let _ = recon.query("1.2.3.4").await.unwrap();
        assert!(recon.has_data("1.2.3.4"));

        // Second query should use cache
        let cached = recon.get_cached("1.2.3.4");
        assert!(cached.is_some());

        // Clear cache
        recon.clear_cache();
        assert!(!recon.has_data("1.2.3.4"));
    }

    #[test]
    fn test_merge_scan_data() {
        let passive = PassiveData {
            ip: "1.2.3.4".to_string(),
            ports: vec![
                PortInfo {
                    port: 80,
                    protocol: "tcp".to_string(),
                    service: "HTTP".to_string(),
                    banner: None,
                },
                PortInfo {
                    port: 443,
                    protocol: "tcp".to_string(),
                    service: "HTTPS".to_string(),
                    banner: None,
                },
            ],
            domains: vec![],
            technologies: vec![],
            last_updated: "2024-01-01".to_string(),
            source: "Test".to_string(),
        };

        let active_ports = vec![(80, "HTTP".to_string()), (22, "SSH".to_string())];

        let merged = merge_scan_data(&passive, &active_ports);

        // Should have 3 ports: 80 (both), 22 (active only), 443 (passive only)
        assert_eq!(merged.len(), 3);

        // Port 80 should be in both
        let port_80 = merged.iter().find(|(p, _, _)| *p == 80).unwrap();
        assert!(port_80.2); // in_passive = true

        // Port 22 should be active only
        let port_22 = merged.iter().find(|(p, _, _)| *p == 22).unwrap();
        assert!(!port_22.2); // in_passive = false

        // Port 443 should be passive only
        let port_443 = merged.iter().find(|(p, _, _)| *p == 443).unwrap();
        assert!(port_443.2); // in_passive = true
    }

    #[tokio::test]
    async fn test_stats() {
        let mut recon = PassiveRecon::new(true);
        recon.configure_apis(Some("test".to_string()), None);

        let _ = recon.query("1.2.3.4").await.unwrap();

        let stats = recon.stats();
        assert_eq!(stats.cached_ips, 1);
        assert!(stats.has_api_keys);
        assert!(stats.total_ports > 0);
    }
}
