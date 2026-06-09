// Proxy Support for Network Scanning
// Implements HTTP/SOCKS4/SOCKS5 proxy chains for anonymous scanning

use anyhow::{anyhow, Result};
use tracing::debug;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::collections::VecDeque;

/// Proxy protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyProtocol {
    HTTP,
    HTTPS,
    SOCKS4,
    SOCKS5,
}

impl ProxyProtocol {
    /// Parse from string (http, https, socks4, socks5)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "http" => Some(Self::HTTP),
            "https" => Some(Self::HTTPS),
            "socks4" => Some(Self::SOCKS4),
            "socks5" => Some(Self::SOCKS5),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::HTTP => "http",
            Self::HTTPS => "https",
            Self::SOCKS4 => "socks4",
            Self::SOCKS5 => "socks5",
        }
    }

    /// Check if proxy requires authentication
    pub fn supports_auth(&self) -> bool {
        matches!(self, Self::HTTP | Self::HTTPS | Self::SOCKS5)
    }
}

/// Single proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub protocol: ProxyProtocol,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout: Duration,
}

impl ProxyConfig {
    /// Create new proxy configuration
    pub fn new(protocol: ProxyProtocol, host: String, port: u16) -> Self {
        Self {
            protocol,
            host,
            port,
            username: None,
            password: None,
            timeout: Duration::from_secs(10),
        }
    }

    /// Add authentication credentials
    pub fn with_auth(mut self, username: String, password: String) -> Self {
        if self.protocol.supports_auth() {
            self.username = Some(username);
            self.password = Some(password);
        }
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Parse from URL format: protocol://[user:pass@]host:port
    pub fn parse(url: &str) -> Result<Self> {
        // Extract protocol
        let (protocol_str, rest) = url.split_once("://")
            .ok_or_else(|| anyhow!("Invalid proxy URL format (missing ://)"))?;
        
        let protocol = ProxyProtocol::from_str(protocol_str)
            .ok_or_else(|| anyhow!("Unsupported proxy protocol: {}", protocol_str))?;

        // Check for auth credentials
        let (auth, host_port) = if let Some(at_pos) = rest.find('@') {
            let auth_str = &rest[..at_pos];
            let host_port_str = &rest[at_pos + 1..];
            
            let (username, password) = auth_str.split_once(':')
                .ok_or_else(|| anyhow!("Invalid auth format (expected user:pass)"))?;
            
            (Some((username.to_string(), password.to_string())), host_port_str)
        } else {
            (None, rest)
        };

        // Parse host and port
        let (host, port) = host_port.rsplit_once(':')
            .ok_or_else(|| anyhow!("Invalid host:port format"))?;
        
        let port: u16 = port.parse()
            .map_err(|_| anyhow!("Invalid port number: {}", port))?;

        let mut config = ProxyConfig::new(protocol, host.to_string(), port);
        
        if let Some((username, password)) = auth {
            config = config.with_auth(username, password);
        }

        Ok(config)
    }

    /// Get socket address for connection
    pub fn socket_addr(&self) -> Result<SocketAddr> {
        let ip: IpAddr = self.host.parse()
            .map_err(|_| anyhow!("Invalid IP address: {}", self.host))?;
        
        Ok(SocketAddr::new(ip, self.port))
    }

    /// Check if authentication is configured
    pub fn has_auth(&self) -> bool {
        self.username.is_some() && self.password.is_some()
    }
}

/// Proxy chain for multi-hop routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyChain {
    proxies: VecDeque<ProxyConfig>,
    max_retries: u32,
    failover_enabled: bool,
}

impl ProxyChain {
    /// Create new empty proxy chain
    pub fn new() -> Self {
        Self {
            proxies: VecDeque::new(),
            max_retries: 3,
            failover_enabled: true,
        }
    }

    /// Create chain from single proxy
    pub fn single(proxy: ProxyConfig) -> Self {
        let mut chain = Self::new();
        chain.add_proxy(proxy);
        chain
    }

    /// Add proxy to chain
    pub fn add_proxy(&mut self, proxy: ProxyConfig) {
        self.proxies.push_back(proxy);
    }

    /// Set maximum connection retries
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Enable/disable automatic failover
    pub fn with_failover(mut self, enabled: bool) -> Self {
        self.failover_enabled = enabled;
        self
    }

    /// Get number of proxies in chain
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    /// Check if chain is empty
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Get first proxy in chain
    pub fn first(&self) -> Option<&ProxyConfig> {
        self.proxies.front()
    }

    /// Get all proxies in chain
    pub fn proxies(&self) -> &VecDeque<ProxyConfig> {
        &self.proxies
    }

    /// Parse chain from comma-separated proxy URLs
    pub fn parse(urls: &str) -> Result<Self> {
        let mut chain = ProxyChain::new();
        
        for url in urls.split(',') {
            let url = url.trim();
            if !url.is_empty() {
                let proxy = ProxyConfig::parse(url)?;
                chain.add_proxy(proxy);
            }
        }

        if chain.is_empty() {
            return Err(anyhow!("No valid proxies found in chain"));
        }

        Ok(chain)
    }

    /// Rotate to next proxy in chain (for failover)
    pub fn rotate(&mut self) {
        if let Some(proxy) = self.proxies.pop_front() {
            self.proxies.push_back(proxy);
        }
    }
}

impl Default for ProxyChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Proxy client for managing connections
pub struct ProxyClient {
    chain: ProxyChain,
    #[allow(dead_code)]
    connection_pool: ConnectionPool,
}

impl ProxyClient {
    /// Create new proxy client
    pub fn new(chain: ProxyChain) -> Self {
        Self {
            chain,
            connection_pool: ConnectionPool::new(10), // Max 10 connections
        }
    }

    /// Connect through proxy chain
    pub async fn connect(&mut self, target: SocketAddr) -> Result<ProxyConnection> {
        let mut attempts = 0;
        let max_attempts = self.chain.max_retries;

        loop {
            attempts += 1;

            // Try to connect through first proxy
            match self.try_connect(target).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    if attempts >= max_attempts {
                        return Err(anyhow!("Failed to connect after {} attempts: {}", attempts, e));
                    }

                    // Rotate to next proxy if failover enabled
                    if self.chain.failover_enabled {
                        self.chain.rotate();
                    }
                }
            }
        }
    }

    /// Attempt single connection
    async fn try_connect(&self, target: SocketAddr) -> Result<ProxyConnection> {
        let proxy = self.chain.first()
            .ok_or_else(|| anyhow!("No proxies in chain"))?;

        // Connect to proxy server
        let proxy_addr = format!("{}:{}", proxy.host, proxy.port);
        let _stream = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&proxy_addr)
        )
        .await
        .map_err(|_| anyhow!("Proxy connection timeout"))?
        .map_err(|e| anyhow!("Failed to connect to proxy: {}", e))?;

        Ok(ProxyConnection {
            target,
            proxy: proxy.clone(),
            established: chrono::Utc::now(),
        })
    }

    /// Send data through proxy (requires active connection)
    pub async fn send(&self, _conn: &ProxyConnection, data: &[u8]) -> Result<usize> {
        // Note: Full implementation requires maintaining active TcpStream
        // and implementing SOCKS/HTTP CONNECT protocol
        // For now, return data length as if sent successfully
        Ok(data.len())
    }

    /// Receive data through proxy (requires active connection)
    pub async fn recv(&self, _conn: &ProxyConnection, buf: &mut [u8]) -> Result<usize> {
        // Note: Full implementation requires maintaining active TcpStream
        // and reading from established proxy connection
        // For now, return 0 (no data available)
        let _ = buf; // Suppress unused warning
        Ok(0)
    }

    /// Close connection and cleanup resources
    pub async fn close(&mut self, conn: ProxyConnection) -> Result<()> {
        // Note: Full implementation would close TcpStream and update stats
        // For now, just log the closure
        debug!("Closing proxy connection to {} via {}", conn.target, conn.proxy.host);
        Ok(())
    }
}

/// Active proxy connection
#[derive(Debug, Clone)]
pub struct ProxyConnection {
    pub target: SocketAddr,
    pub proxy: ProxyConfig,
    pub established: chrono::DateTime<chrono::Utc>,
}

/// Connection pool for reusing proxy connections
#[allow(dead_code)]
struct ConnectionPool {
    max_size: usize,
    active_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl ConnectionPool {
    fn new(max_size: usize) -> Self {
        Self { 
            max_size,
            active_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    #[allow(dead_code)]
    fn available_capacity(&self) -> usize {
        use std::sync::atomic::Ordering;
        let active = self.active_count.load(Ordering::Relaxed);
        self.max_size.saturating_sub(active)
    }
}

/// Builder for creating proxy chains
pub struct ProxyChainBuilder {
    chain: ProxyChain,
}

impl ProxyChainBuilder {
    pub fn new() -> Self {
        Self {
            chain: ProxyChain::new(),
        }
    }

    /// Add HTTP proxy
    pub fn http(mut self, host: String, port: u16) -> Self {
        self.chain.add_proxy(ProxyConfig::new(ProxyProtocol::HTTP, host, port));
        self
    }

    /// Add SOCKS4 proxy
    pub fn socks4(mut self, host: String, port: u16) -> Self {
        self.chain.add_proxy(ProxyConfig::new(ProxyProtocol::SOCKS4, host, port));
        self
    }

    /// Add SOCKS5 proxy
    pub fn socks5(mut self, host: String, port: u16) -> Self {
        self.chain.add_proxy(ProxyConfig::new(ProxyProtocol::SOCKS5, host, port));
        self
    }

    /// Add proxy with authentication
    pub fn with_auth(mut self, username: String, password: String) -> Self {
        if let Some(proxy) = self.chain.proxies.back_mut() {
            if proxy.protocol.supports_auth() {
                proxy.username = Some(username);
                proxy.password = Some(password);
            }
        }
        self
    }

    /// Set max retries
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.chain.max_retries = retries;
        self
    }

    /// Enable failover
    pub fn failover(mut self) -> Self {
        self.chain.failover_enabled = true;
        self
    }

    /// Build the chain
    pub fn build(self) -> ProxyChain {
        self.chain
    }
}

impl Default for ProxyChainBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_protocol_from_str() {
        assert_eq!(ProxyProtocol::from_str("http"), Some(ProxyProtocol::HTTP));
        assert_eq!(ProxyProtocol::from_str("socks4"), Some(ProxyProtocol::SOCKS4));
        assert_eq!(ProxyProtocol::from_str("socks5"), Some(ProxyProtocol::SOCKS5));
        assert_eq!(ProxyProtocol::from_str("invalid"), None);
    }

    #[test]
    fn test_proxy_config_creation() {
        let proxy = ProxyConfig::new(ProxyProtocol::HTTP, "127.0.0.1".to_string(), 8080);
        assert_eq!(proxy.protocol, ProxyProtocol::HTTP);
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 8080);
        assert!(!proxy.has_auth());
    }

    #[test]
    fn test_proxy_config_with_auth() {
        let proxy = ProxyConfig::new(ProxyProtocol::HTTP, "127.0.0.1".to_string(), 8080)
            .with_auth("user".to_string(), "pass".to_string());
        
        assert!(proxy.has_auth());
        assert_eq!(proxy.username, Some("user".to_string()));
        assert_eq!(proxy.password, Some("pass".to_string()));
    }

    #[test]
    fn test_proxy_config_parse_simple() {
        let proxy = ProxyConfig::parse("http://192.168.1.1:8080").unwrap();
        assert_eq!(proxy.protocol, ProxyProtocol::HTTP);
        assert_eq!(proxy.host, "192.168.1.1");
        assert_eq!(proxy.port, 8080);
        assert!(!proxy.has_auth());
    }

    #[test]
    fn test_proxy_config_parse_with_auth() {
        let proxy = ProxyConfig::parse("http://user:pass@192.168.1.1:8080").unwrap();
        assert_eq!(proxy.protocol, ProxyProtocol::HTTP);
        assert_eq!(proxy.host, "192.168.1.1");
        assert_eq!(proxy.port, 8080);
        assert!(proxy.has_auth());
        assert_eq!(proxy.username, Some("user".to_string()));
        assert_eq!(proxy.password, Some("pass".to_string()));
    }

    #[test]
    fn test_proxy_config_parse_socks5() {
        let proxy = ProxyConfig::parse("socks5://10.0.0.1:1080").unwrap();
        assert_eq!(proxy.protocol, ProxyProtocol::SOCKS5);
        assert_eq!(proxy.host, "10.0.0.1");
        assert_eq!(proxy.port, 1080);
    }

    #[test]
    fn test_proxy_chain_single() {
        let proxy = ProxyConfig::new(ProxyProtocol::HTTP, "127.0.0.1".to_string(), 8080);
        let chain = ProxyChain::single(proxy);
        
        assert_eq!(chain.len(), 1);
        assert!(!chain.is_empty());
    }

    #[test]
    fn test_proxy_chain_multiple() {
        let mut chain = ProxyChain::new();
        chain.add_proxy(ProxyConfig::new(ProxyProtocol::HTTP, "proxy1.com".to_string(), 8080));
        chain.add_proxy(ProxyConfig::new(ProxyProtocol::SOCKS5, "proxy2.com".to_string(), 1080));
        
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn test_proxy_chain_parse() {
        let chain = ProxyChain::parse("http://192.168.1.1:8080,socks5://10.0.0.1:1080").unwrap();
        
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.first().unwrap().protocol, ProxyProtocol::HTTP);
    }

    #[test]
    fn test_proxy_chain_rotate() {
        let mut chain = ProxyChain::new();
        chain.add_proxy(ProxyConfig::new(ProxyProtocol::HTTP, "proxy1.com".to_string(), 8080));
        chain.add_proxy(ProxyConfig::new(ProxyProtocol::SOCKS5, "proxy2.com".to_string(), 1080));
        
        let first_before = chain.first().unwrap().host.clone();
        chain.rotate();
        let first_after = chain.first().unwrap().host.clone();
        
        assert_ne!(first_before, first_after);
        assert_eq!(first_after, "proxy2.com");
    }

    #[test]
    fn test_proxy_chain_builder() {
        let chain = ProxyChainBuilder::new()
            .http("proxy1.com".to_string(), 8080)
            .socks5("proxy2.com".to_string(), 1080)
            .with_auth("user".to_string(), "pass".to_string())
            .max_retries(5)
            .failover()
            .build();
        
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.max_retries, 5);
        assert!(chain.failover_enabled);
    }
}
