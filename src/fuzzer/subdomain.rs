// Subdomain Enumeration - DNS brute-forcing and discovery
// amass/subfinder-style subdomain enumeration

use anyhow::Result;
use std::collections::HashSet;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use serde::{Serialize, Deserialize};

/// Subdomain enumeration configuration
#[derive(Debug, Clone)]
pub struct SubdomainConfig {
    /// Target domain
    pub domain: String,
    /// DNS resolvers to use
    pub resolvers: Vec<String>,
    /// Check for wildcard DNS responses
    pub wildcard_detection: bool,
    /// Perform zone transfer attempts
    pub zone_transfer: bool,
    /// Use certificate transparency logs
    pub cert_transparency: bool,
    /// Check common DNS records (A, AAAA, CNAME, MX, NS, TXT)
    pub check_all_records: bool,
    /// Maximum concurrent DNS queries
    pub concurrency: usize,
    /// Timeout for DNS queries (milliseconds)
    pub timeout_ms: u64,
}

impl Default for SubdomainConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            resolvers: vec![
                "8.8.8.8".to_string(),      // Google
                "1.1.1.1".to_string(),      // Cloudflare
                "208.67.222.222".to_string(), // OpenDNS
            ],
            wildcard_detection: true,
            zone_transfer: true,
            cert_transparency: true,
            check_all_records: false,
            concurrency: 100,
            timeout_ms: 5000,
        }
    }
}

/// Subdomain enumeration result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    /// Subdomain name
    pub subdomain: String,
    /// IP addresses
    pub ips: Vec<IpAddr>,
    /// DNS record types found
    pub record_types: Vec<String>,
    /// CNAME if present
    pub cname: Option<String>,
    /// Source of discovery
    pub source: DiscoverySource,
}

/// Source of subdomain discovery
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoverySource {
    /// DNS brute-forcing
    BruteForce,
    /// Certificate transparency logs
    CertTransparency,
    /// Zone transfer
    ZoneTransfer,
    /// DNS search engines
    SearchEngine,
    /// Reverse DNS
    ReverseDNS,
}

/// Subdomain enumerator
pub struct SubdomainEnumerator {
    config: SubdomainConfig,
    discovered: Arc<RwLock<HashSet<String>>>,
    wildcard_ips: Arc<RwLock<Option<Vec<IpAddr>>>>,
}

impl SubdomainEnumerator {
    /// Create a new subdomain enumerator
    pub fn new(config: SubdomainConfig) -> Self {
        Self {
            config,
            discovered: Arc::new(RwLock::new(HashSet::new())),
            wildcard_ips: Arc::new(RwLock::new(None)),
        }
    }

    /// Enumerate subdomains using all configured methods
    pub async fn enumerate(&self, wordlist: Vec<String>) -> Result<Vec<SubdomainResult>> {
        info!("Starting subdomain enumeration for: {}", self.config.domain);

        let mut results = Vec::new();

        // Detect wildcard DNS
        if self.config.wildcard_detection {
            self.detect_wildcard().await?;
        }

        // DNS brute-forcing
        let brute_results = self.brute_force(&wordlist).await?;
        results.extend(brute_results);

        // Zone transfer attempt
        if self.config.zone_transfer {
            if let Ok(zone_results) = self.attempt_zone_transfer().await {
                results.extend(zone_results);
            }
        }

        // Certificate transparency
        if self.config.cert_transparency {
            if let Ok(cert_results) = self.enumerate_from_cert_transparency().await {
                results.extend(cert_results);
            }
        }

        // Reverse DNS on discovered IPs
        let reverse_results = self.reverse_dns_from_results(&results).await?;
        results.extend(reverse_results);

        info!("Subdomain enumeration complete. Found {} unique subdomains", results.len());
        Ok(results)
    }

    /// Brute-force subdomains using wordlist
    async fn brute_force(&self, wordlist: &[String]) -> Result<Vec<SubdomainResult>> {
        debug!("Brute-forcing {} subdomains", wordlist.len());
        
        let mut results = Vec::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.concurrency));
        let mut handles = Vec::new();

        for subdomain in wordlist {
            let fqdn = format!("{}.{}", subdomain, self.config.domain);
            
            // Skip if already discovered
            {
                let discovered = self.discovered.read().await;
                if discovered.contains(&fqdn) {
                    continue;
                }
            }

            let permit = semaphore.clone().acquire_owned().await.map_err(|_| anyhow::anyhow!("Semaphore closed"))?;
            let fqdn_clone = fqdn.clone();
            let wildcard_ips = self.wildcard_ips.clone();
            let discovered = self.discovered.clone();

            let handle = tokio::spawn(async move {
                let result = Self::resolve_subdomain(&fqdn_clone).await;
                drop(permit);

                if let Ok(Some(mut subdomain_result)) = result {
                    // Check if this is a wildcard response
                    let wildcard = wildcard_ips.read().await;
                    if let Some(ref wild_ips) = *wildcard {
                        if Self::is_wildcard_response(&subdomain_result.ips, wild_ips) {
                            return None;
                        }
                    }

                    // Mark as discovered
                    let mut disc = discovered.write().await;
                    disc.insert(fqdn_clone);

                    subdomain_result.source = DiscoverySource::BruteForce;
                    Some(subdomain_result)
                } else {
                    None
                }
            });

            handles.push(handle);
        }

        // Collect results
        for handle in handles {
            if let Ok(Some(result)) = handle.await {
                results.push(result);
            }
        }

        debug!("Brute-force found {} subdomains", results.len());
        Ok(results)
    }

    /// Resolve a subdomain to IP addresses
    async fn resolve_subdomain(fqdn: &str) -> Result<Option<SubdomainResult>> {
        // Try to resolve the subdomain
        let addr = format!("{}:80", fqdn);
        
        match addr.to_socket_addrs() {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                if ips.is_empty() {
                    return Ok(None);
                }

                Ok(Some(SubdomainResult {
                    subdomain: fqdn.to_string(),
                    ips,
                    record_types: vec!["A".to_string()],
                    cname: None,
                    source: DiscoverySource::BruteForce,
                }))
            }
            Err(_) => Ok(None),
        }
    }

    /// Detect wildcard DNS responses
    async fn detect_wildcard(&self) -> Result<()> {
        debug!("Detecting wildcard DNS for {}", self.config.domain);

        // Try to resolve a random non-existent subdomain
        let random_subdomains = vec![
            format!("xn--random-{}.{}", uuid::Uuid::new_v4(), self.config.domain),
            format!("nonexistent-{}.{}", uuid::Uuid::new_v4(), self.config.domain),
            format!("test-{}.{}", uuid::Uuid::new_v4(), self.config.domain),
        ];

        let mut wildcard_ips = Vec::new();

        for subdomain in random_subdomains {
            if let Ok(Some(result)) = Self::resolve_subdomain(&subdomain).await {
                wildcard_ips.extend(result.ips);
            }
        }

        if !wildcard_ips.is_empty() {
            warn!("Wildcard DNS detected for {}: {:?}", self.config.domain, wildcard_ips);
            let mut wild = self.wildcard_ips.write().await;
            *wild = Some(wildcard_ips);
        } else {
            debug!("No wildcard DNS detected");
        }

        Ok(())
    }

    /// Check if IPs match wildcard pattern
    fn is_wildcard_response(ips: &[IpAddr], wildcard_ips: &[IpAddr]) -> bool {
        // Check if there's significant overlap
        let common: Vec<_> = ips.iter()
            .filter(|ip| wildcard_ips.contains(ip))
            .collect();

        !common.is_empty()
    }

    /// Attempt DNS zone transfer
    async fn attempt_zone_transfer(&self) -> Result<Vec<SubdomainResult>> {
        debug!("Attempting zone transfer for {}", self.config.domain);
        
        // In a real implementation, this would:
        // 1. Query NS records for the domain
        // 2. Try AXFR on each nameserver
        // 3. Parse zone file if successful
        
        // Placeholder - zone transfers rarely work these days
        Ok(Vec::new())
    }

    /// Enumerate subdomains from certificate transparency logs
    async fn enumerate_from_cert_transparency(&self) -> Result<Vec<SubdomainResult>> {
        debug!("Querying certificate transparency logs for {}", self.config.domain);
        
        // In a real implementation, this would:
        // 1. Query crt.sh or similar CT log aggregator
        // 2. Parse JSON response
        // 3. Extract unique subdomains
        // 4. Resolve each to verify it's still active
        
        // Placeholder for now
        Ok(Vec::new())
    }

    /// Perform reverse DNS lookups on discovered IPs
    async fn reverse_dns_from_results(&self, results: &[SubdomainResult]) -> Result<Vec<SubdomainResult>> {
        debug!("Performing reverse DNS lookups");
        
        let reverse_results = Vec::new();
        let mut seen_ips = HashSet::new();

        for result in results {
            for ip in &result.ips {
                if seen_ips.contains(ip) {
                    continue;
                }
                seen_ips.insert(*ip);

                // In a real implementation, this would do reverse DNS lookup
                // For now, just a placeholder
            }
        }

        Ok(reverse_results)
    }
}

/// Permutation generator for subdomains
pub struct SubdomainPermutations;

impl SubdomainPermutations {
    /// Generate common subdomain permutations
    pub fn generate(domain: &str) -> Vec<String> {
        let mut permutations = Vec::new();

        // Extract base name (remove TLD)
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 {
            return permutations;
        }

        let base = parts[0];

        // Common patterns
        let prefixes = vec!["www", "api", "admin", "dev", "stage", "staging", 
                           "test", "qa", "uat", "prod", "app", "mobile"];
        let suffixes = vec!["dev", "test", "stage", "prod", "beta", "alpha", 
                           "new", "old", "backup"];

        // Add prefix variations
        for prefix in &prefixes {
            permutations.push(format!("{}-{}", prefix, base));
            permutations.push(format!("{}{}", prefix, base));
        }

        // Add suffix variations
        for suffix in &suffixes {
            permutations.push(format!("{}-{}", base, suffix));
            permutations.push(format!("{}{}", base, suffix));
        }

        // Add numbered variations
        for i in 1..=10 {
            permutations.push(format!("{}{}", base, i));
            permutations.push(format!("{}-{}", base, i));
        }

        permutations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subdomain_config_default() {
        let config = SubdomainConfig::default();
        assert_eq!(config.resolvers.len(), 3);
        assert!(config.wildcard_detection);
        assert_eq!(config.concurrency, 100);
    }

    #[test]
    fn test_discovery_source() {
        assert_ne!(DiscoverySource::BruteForce, DiscoverySource::CertTransparency);
        assert_eq!(DiscoverySource::BruteForce, DiscoverySource::BruteForce);
    }

    #[test]
    fn test_subdomain_permutations() {
        let perms = SubdomainPermutations::generate("example.com");
        assert!(!perms.is_empty());
        assert!(perms.contains(&"www-example".to_string()));
        assert!(perms.contains(&"api-example".to_string()));
    }

    #[test]
    fn test_is_wildcard_response() {
        let ips1 = vec!["192.168.1.1".parse().unwrap()];
        let ips2 = vec!["192.168.1.1".parse().unwrap()];
        
        assert!(SubdomainEnumerator::is_wildcard_response(&ips1, &ips2));
    }

    #[test]
    fn test_is_not_wildcard_response() {
        let ips1 = vec!["192.168.1.1".parse().unwrap()];
        let ips2 = vec!["192.168.1.2".parse().unwrap()];
        
        assert!(!SubdomainEnumerator::is_wildcard_response(&ips1, &ips2));
    }
}
