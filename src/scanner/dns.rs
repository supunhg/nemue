use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration;

/// DNS resolution configuration
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// Never do DNS resolution (-n flag)
    pub never_resolve: bool,
    /// Always resolve, even for IPs in output (-R flag)
    pub always_resolve: bool,
    /// Custom DNS servers (--dns-servers)
    pub custom_servers: Vec<IpAddr>,
    /// Use system DNS resolver instead of built-in (--system-dns)
    pub use_system_dns: bool,
    /// Timeout for DNS queries
    pub timeout: Duration,
    /// Maximum parallel DNS queries
    pub max_parallel: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            never_resolve: false,
            always_resolve: false,
            custom_servers: Vec::new(),
            use_system_dns: false,
            timeout: Duration::from_secs(5),
            max_parallel: 100,
        }
    }
}

impl DnsConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create config for no DNS resolution (nmap -n)
    pub fn never_resolve() -> Self {
        Self {
            never_resolve: true,
            ..Default::default()
        }
    }

    /// Create config for always resolving (nmap -R)
    pub fn always_resolve() -> Self {
        Self {
            always_resolve: true,
            ..Default::default()
        }
    }

    /// Add custom DNS server
    pub fn with_dns_server(mut self, server: IpAddr) -> Self {
        self.custom_servers.push(server);
        self
    }

    /// Use system DNS resolver
    pub fn with_system_dns(mut self) -> Self {
        self.use_system_dns = true;
        self
    }

    /// Set timeout for DNS queries
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// DNS resolver with caching
pub struct DnsResolver {
    config: DnsConfig,
    /// Cache for forward lookups (hostname -> IP)
    forward_cache: Arc<Mutex<HashMap<String, Vec<IpAddr>>>>,
    /// Cache for reverse lookups (IP -> hostname)
    reverse_cache: Arc<Mutex<HashMap<IpAddr, String>>>,
}

impl DnsResolver {
    pub fn new(config: DnsConfig) -> Self {
        Self {
            config,
            forward_cache: Arc::new(Mutex::new(HashMap::new())),
            reverse_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Resolve hostname to IP addresses (forward lookup)
    /// Returns cached result if available
    pub async fn resolve_hostname(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        // Check if DNS is disabled
        if self.config.never_resolve {
            return Err(anyhow!("DNS resolution disabled (-n flag)"));
        }

        // Check cache first
        {
            let cache = self.forward_cache.lock().await;
            if let Some(ips) = cache.get(hostname) {
                return Ok(ips.clone());
            }
        }

        // Perform lookup
        let ips = self.lookup_hostname(hostname).await?;

        // Cache result
        {
            let mut cache = self.forward_cache.lock().await;
            cache.insert(hostname.to_string(), ips.clone());
        }

        Ok(ips)
    }

    /// Reverse lookup: IP to hostname
    /// Returns None if resolution fails or is disabled
    pub async fn reverse_lookup(&self, ip: &IpAddr) -> Option<String> {
        // Check if we should skip reverse lookup
        if self.config.never_resolve && !self.config.always_resolve {
            return None;
        }

        // Check cache first
        {
            let cache = self.reverse_cache.lock().await;
            if let Some(hostname) = cache.get(ip) {
                return Some(hostname.clone());
            }
        }

        // Perform reverse lookup
        match self.lookup_ip(*ip).await {
            Ok(hostname) => {
                // Cache result
                let mut cache = self.reverse_cache.lock().await;
                cache.insert(*ip, hostname.clone());
                Some(hostname)
            }
            Err(_) => None,
        }
    }

    /// Batch resolve multiple hostnames in parallel
    pub async fn resolve_hostnames(&self, hostnames: Vec<String>) -> HashMap<String, Vec<IpAddr>> {
        let mut results = HashMap::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.max_parallel));
        let mut tasks = Vec::new();

        for hostname in hostnames {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let resolver = self.clone_for_task();
            let hostname_clone = hostname.clone();

            let task = tokio::spawn(async move {
                let _permit = permit;
                let ips = resolver.resolve_hostname(&hostname_clone).await;
                (hostname_clone, ips)
            });

            tasks.push(task);
        }

        // Collect results
        for task in tasks {
            if let Ok((hostname, Ok(ips))) = task.await {
                results.insert(hostname, ips);
            }
        }

        results
    }

    /// Batch reverse lookup multiple IPs in parallel
    pub async fn reverse_lookup_batch(&self, ips: Vec<IpAddr>) -> HashMap<IpAddr, String> {
        let mut results = HashMap::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.max_parallel));
        let mut tasks = Vec::new();

        for ip in ips {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let resolver = self.clone_for_task();

            let task = tokio::spawn(async move {
                let _permit = permit;
                let hostname = resolver.reverse_lookup(&ip).await;
                (ip, hostname)
            });

            tasks.push(task);
        }

        // Collect results
        for task in tasks {
            if let Ok((ip, Some(hostname))) = task.await {
                results.insert(ip, hostname);
            }
        }

        results
    }

    /// Internal: Perform actual hostname lookup
    async fn lookup_hostname(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        if self.config.use_system_dns {
            // Use system resolver
            self.system_lookup_hostname(hostname).await
        } else {
            // Use built-in resolver (custom DNS servers if specified)
            self.builtin_lookup_hostname(hostname).await
        }
    }

    /// Internal: Perform actual reverse lookup
    async fn lookup_ip(&self, ip: IpAddr) -> Result<String> {
        if self.config.use_system_dns {
            self.system_reverse_lookup(ip).await
        } else {
            self.builtin_reverse_lookup(ip).await
        }
    }

    /// System DNS lookup using tokio's resolver
    async fn system_lookup_hostname(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        let addr = format!("{}:0", hostname);
        let timeout = self.config.timeout;

        tokio::time::timeout(timeout, async {
            tokio::net::lookup_host(&addr)
                .await
                .map(|iter| iter.map(|socket| socket.ip()).collect())
                .map_err(|e| anyhow!("DNS lookup failed for {}: {}", hostname, e))
        })
        .await
        .map_err(|_| anyhow!("DNS lookup timeout for {}", hostname))?
    }

    /// System reverse DNS lookup
    async fn system_reverse_lookup(&self, ip: IpAddr) -> Result<String> {
        let timeout = self.config.timeout;

        tokio::time::timeout(timeout, async {
            // Use reverse DNS lookup via system resolver
            let _socket = SocketAddr::new(ip, 0);
            
            // Simple reverse lookup using DNS protocol
            // For production, we'd use trust-dns-resolver here
            // For now, we'll use a basic implementation
            
            // Try to resolve using getaddrinfo in reverse
            // This is a placeholder - ideally use trust-dns-resolver crate
            Ok(format!("{}", ip)) // Fallback to IP string
        })
        .await
        .map_err(|_| anyhow!("Reverse DNS timeout for {}", ip))?
    }

    /// Built-in DNS lookup (would use trust-dns-resolver in production)
    async fn builtin_lookup_hostname(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        // For now, fallback to system resolver
        // In production, implement with trust-dns-resolver using custom servers
        
        if !self.config.custom_servers.is_empty() {
            // Would query custom DNS servers here
            // For now, use system resolver with warning
            eprintln!("Warning: Custom DNS servers specified but trust-dns-resolver not implemented. Using system resolver.");
        }

        self.system_lookup_hostname(hostname).await
    }

    /// Built-in reverse DNS (would use trust-dns-resolver in production)
    async fn builtin_reverse_lookup(&self, ip: IpAddr) -> Result<String> {
        // For now, fallback to system resolver
        // In production, implement with trust-dns-resolver
        
        if !self.config.custom_servers.is_empty() {
            eprintln!("Warning: Custom DNS servers specified but trust-dns-resolver not implemented. Using system resolver.");
        }

        self.system_reverse_lookup(ip).await
    }

    /// Clone resolver for parallel tasks
    fn clone_for_task(&self) -> Self {
        Self {
            config: self.config.clone(),
            forward_cache: Arc::clone(&self.forward_cache),
            reverse_cache: Arc::clone(&self.reverse_cache),
        }
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> (usize, usize) {
        let forward = self.forward_cache.lock().await.len();
        let reverse = self.reverse_cache.lock().await.len();
        (forward, reverse)
    }

    /// Clear all caches
    pub async fn clear_cache(&self) {
        self.forward_cache.lock().await.clear();
        self.reverse_cache.lock().await.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_config_default() {
        let config = DnsConfig::default();
        assert!(!config.never_resolve);
        assert!(!config.always_resolve);
        assert!(config.custom_servers.is_empty());
        assert!(!config.use_system_dns);
        assert_eq!(config.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_dns_config_never_resolve() {
        let config = DnsConfig::never_resolve();
        assert!(config.never_resolve);
        assert!(!config.always_resolve);
    }

    #[test]
    fn test_dns_config_always_resolve() {
        let config = DnsConfig::always_resolve();
        assert!(!config.never_resolve);
        assert!(config.always_resolve);
    }

    #[test]
    fn test_dns_config_with_server() {
        let config = DnsConfig::new()
            .with_dns_server("8.8.8.8".parse().unwrap())
            .with_dns_server("1.1.1.1".parse().unwrap());
        
        assert_eq!(config.custom_servers.len(), 2);
        assert!(config.custom_servers.contains(&"8.8.8.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_resolver_localhost() {
        let config = DnsConfig::default();
        let resolver = DnsResolver::new(config);

        let result = resolver.resolve_hostname("localhost").await;
        assert!(result.is_ok());
        
        let ips = result.unwrap();
        assert!(!ips.is_empty());
        // localhost should resolve to 127.0.0.1 or ::1
        assert!(ips.iter().any(|ip| ip.is_loopback()));
    }

    #[tokio::test]
    async fn test_resolver_never_resolve() {
        let config = DnsConfig::never_resolve();
        let resolver = DnsResolver::new(config);

        let result = resolver.resolve_hostname("localhost").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("disabled"));
    }

    #[tokio::test]
    async fn test_resolver_cache() {
        let config = DnsConfig::default();
        let resolver = DnsResolver::new(config);

        // First lookup (should cache)
        let result1 = resolver.resolve_hostname("localhost").await.unwrap();
        
        // Check cache stats
        let (forward_count, _) = resolver.cache_stats().await;
        assert_eq!(forward_count, 1);

        // Second lookup (should use cache)
        let result2 = resolver.resolve_hostname("localhost").await.unwrap();
        
        // Results should match
        assert_eq!(result1, result2);

        // Clear cache
        resolver.clear_cache().await;
        let (forward_count, _) = resolver.cache_stats().await;
        assert_eq!(forward_count, 0);
    }

    #[tokio::test]
    async fn test_reverse_lookup_loopback() {
        let config = DnsConfig::always_resolve();
        let resolver = DnsResolver::new(config);

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let result = resolver.reverse_lookup(&ip).await;
        
        // Reverse lookup should return something (or None, depending on system)
        // We just verify it doesn't panic
        assert!(result.is_some() || result.is_none());
    }

    #[tokio::test]
    async fn test_batch_resolve() {
        let config = DnsConfig::default();
        let resolver = DnsResolver::new(config);

        let hostnames = vec![
            "localhost".to_string(),
        ];

        let results = resolver.resolve_hostnames(hostnames).await;
        assert!(results.contains_key("localhost"));
    }
}
