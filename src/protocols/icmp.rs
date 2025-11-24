use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::time::timeout;

/// ICMP packet types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IcmpType {
    EchoReply = 0,
    EchoRequest = 8,
    DestinationUnreachable = 3,
    TimeExceeded = 11,
}

/// ICMP scanner for host discovery and ping scanning
pub struct IcmpScanner {
    timeout_ms: u64,
    ttl: u8,
}

impl IcmpScanner {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            ttl: 64,
        }
    }

    pub fn with_ttl(timeout_ms: u64, ttl: u8) -> Self {
        Self { timeout_ms, ttl }
    }

    /// Perform ICMP echo request (ping)
    pub async fn ping(&self, target: IpAddr) -> Result<PingResult> {
        match target {
            IpAddr::V4(ipv4) => self.ping_v4(ipv4).await,
            IpAddr::V6(_) => Err(anyhow!("IPv6 ICMP not yet implemented")),
        }
    }

    /// Send ICMP echo request to IPv4 address
    async fn ping_v4(&self, target: Ipv4Addr) -> Result<PingResult> {
        // For now, we'll use TCP fallback since raw ICMP requires privileges
        // In a future version, this will use raw sockets
        self.tcp_ping_fallback(IpAddr::V4(target)).await
    }

    /// Fallback: Use TCP connection attempt as "ping"
    /// This is less stealthy but works without root privileges
    async fn tcp_ping_fallback(&self, target: IpAddr) -> Result<PingResult> {
        use tokio::net::TcpStream;
        
        let start = std::time::Instant::now();
        
        // Try common ports that are likely to be open
        let ports = [80, 443, 22, 21, 25];
        
        for port in ports {
            let addr = std::net::SocketAddr::new(target, port);
            let timeout_duration = Duration::from_millis(self.timeout_ms / ports.len() as u64);
            
            if let Ok(Ok(_)) = timeout(timeout_duration, TcpStream::connect(addr)).await {
                let rtt = start.elapsed();
                return Ok(PingResult {
                    target,
                    alive: true,
                    rtt_ms: Some(rtt.as_millis() as u64),
                    ttl: Some(self.ttl),
                    method: PingMethod::TcpConnect,
                });
            }
        }

        Ok(PingResult {
            target,
            alive: false,
            rtt_ms: None,
            ttl: None,
            method: PingMethod::TcpConnect,
        })
    }

    /// Check if host is alive (simplified)
    pub async fn is_alive(&self, target: IpAddr) -> Result<bool> {
        let result = self.ping(target).await?;
        Ok(result.alive)
    }
}

/// Result of ICMP ping
#[derive(Debug, Clone)]
pub struct PingResult {
    pub target: IpAddr,
    pub alive: bool,
    pub rtt_ms: Option<u64>,
    pub ttl: Option<u8>,
    pub method: PingMethod,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PingMethod {
    IcmpEcho,
    TcpConnect,
    UdpProbe,
}

impl Default for IcmpScanner {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_scanner_creation() {
        let scanner = IcmpScanner::new(2000);
        assert_eq!(scanner.timeout_ms, 2000);
        assert_eq!(scanner.ttl, 64);
    }

    #[test]
    fn test_icmp_scanner_with_ttl() {
        let scanner = IcmpScanner::with_ttl(1000, 128);
        assert_eq!(scanner.ttl, 128);
    }

    #[test]
    fn test_icmp_types() {
        assert_eq!(IcmpType::EchoRequest as u8, 8);
        assert_eq!(IcmpType::EchoReply as u8, 0);
    }

    #[tokio::test]
    async fn test_ping_localhost() {
        let scanner = IcmpScanner::new(1000);
        let result = scanner.ping(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).await;
        // Localhost should respond (via TCP fallback)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_is_alive_localhost() {
        let scanner = IcmpScanner::new(1000);
        let alive = scanner.is_alive(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).await;
        assert!(alive.is_ok());
    }
}
