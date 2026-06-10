// Traceroute implementation with multiple protocols
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use serde::{Serialize, Deserialize};

/// Traceroute configuration
#[derive(Debug, Clone)]
pub struct TracerouteConfig {
    pub max_hops: u8,
    pub timeout: Duration,
    pub protocol: TracerouteProtocol,
    pub queries_per_hop: u8,
    pub parallel_probes: u8,
    pub port: u16,
    pub use_ecn: bool,
}

impl Default for TracerouteConfig {
    fn default() -> Self {
        Self {
            max_hops: 30,
            timeout: Duration::from_secs(5),
            protocol: TracerouteProtocol::Icmp,
            queries_per_hop: 3,
            parallel_probes: 1,
            port: 80,
            use_ecn: false,
        }
    }
}

/// Supported traceroute protocols
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TracerouteProtocol {
    Icmp,
    Udp,
    Tcp,
}

impl std::fmt::Display for TracerouteProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TracerouteProtocol::Icmp => write!(f, "ICMP"),
            TracerouteProtocol::Udp => write!(f, "UDP"),
            TracerouteProtocol::Tcp => write!(f, "TCP"),
        }
    }
}

/// Single hop information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopInfo {
    pub ttl: u8,
    pub address: Option<IpAddr>,
    pub hostname: Option<String>,
    pub rtt: Option<Duration>,
    pub attempt: u8,
    pub protocol: TracerouteProtocol,
    pub is_destination: bool,
}

/// Traceroute result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteResult {
    pub target: IpAddr,
    pub hops: Vec<HopInfo>,
    pub completed: bool,
    pub total_time: Duration,
    pub protocol: TracerouteProtocol,
}

/// Traceroute engine
pub struct Traceroute {
    config: TracerouteConfig,
}

impl Traceroute {
    pub fn new(config: TracerouteConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &TracerouteConfig {
        &self.config
    }

    /// Perform traceroute to target
    pub async fn trace(&self, target: IpAddr) -> Result<TracerouteResult, String> {
        let start_time = Instant::now();
        let mut hops = Vec::new();
        let mut reached_target = false;

        for ttl in 1..=self.config.max_hops {
            let mut hop_responses = Vec::new();

            for attempt in 1..=self.config.queries_per_hop {
                match self.send_probe(target, ttl, attempt).await {
                    Ok(hop_info) => {
                        if hop_info.is_destination {
                            reached_target = true;
                        }
                        hop_responses.push(hop_info);
                    }
                    Err(_) => {
                        hop_responses.push(HopInfo {
                            ttl,
                            address: None,
                            hostname: None,
                            rtt: None,
                            attempt,
                            protocol: self.config.protocol,
                            is_destination: false,
                        });
                    }
                }
            }

            // Use the fastest response for this hop
            if let Some(best_hop) = hop_responses.into_iter()
                .filter(|h| h.address.is_some())
                .min_by_key(|h| h.rtt)
            {
                hops.push(best_hop);
            } else if !hops.is_empty() {
                // Add timeout indicator
                hops.push(HopInfo {
                    ttl,
                    address: None,
                    hostname: None,
                    rtt: None,
                    attempt: 1,
                    protocol: self.config.protocol,
                    is_destination: false,
                });
            }

            if reached_target {
                break;
            }
        }

        Ok(TracerouteResult {
            target,
            hops,
            completed: reached_target,
            total_time: start_time.elapsed(),
            protocol: self.config.protocol,
        })
    }

    /// Perform parallel traceroute
    pub async fn trace_parallel(&self, target: IpAddr) -> Result<TracerouteResult, String> {
        if self.config.parallel_probes <= 1 {
            return self.trace(target).await;
        }

        let start_time = Instant::now();
        let mut hops = Vec::new();
        let mut reached_target = false;

        // Process hops in batches
        let batch_size = self.config.parallel_probes as usize;
        
        for ttl_batch in (1..=self.config.max_hops).collect::<Vec<u8>>().chunks(batch_size) {
            let mut batch_results = Vec::new();
            
            for &ttl in ttl_batch {
                let probe_result = self.send_probe(target, ttl, 1).await;
                batch_results.push((ttl, probe_result));
            }

            for (ttl, result) in batch_results {
                match result {
                    Ok(hop_info) => {
                        if hop_info.is_destination {
                            reached_target = true;
                        }
                        hops.push(hop_info);
                    }
                    Err(_) => {
                        hops.push(HopInfo {
                            ttl,
                            address: None,
                            hostname: None,
                            rtt: None,
                            attempt: 1,
                            protocol: self.config.protocol,
                            is_destination: false,
                        });
                    }
                }

                if reached_target {
                    break;
                }
            }

            if reached_target {
                break;
            }
        }

        Ok(TracerouteResult {
            target,
            hops,
            completed: reached_target,
            total_time: start_time.elapsed(),
            protocol: self.config.protocol,
        })
    }

    /// Send a single probe with specified TTL
    async fn send_probe(&self, target: IpAddr, ttl: u8, attempt: u8) -> Result<HopInfo, String> {
        let probe_start = Instant::now();

        match self.config.protocol {
            TracerouteProtocol::Icmp => self.send_icmp_probe(target, ttl, attempt, probe_start).await,
            TracerouteProtocol::Udp => self.send_udp_probe(target, ttl, attempt, probe_start).await,
            TracerouteProtocol::Tcp => self.send_tcp_probe(target, ttl, attempt, probe_start).await,
        }
    }

    /// Send ICMP probe
    async fn send_icmp_probe(
        &self,
        target: IpAddr,
        ttl: u8,
        attempt: u8,
        probe_start: Instant,
    ) -> Result<HopInfo, String> {
        // Simplified probe - in production would use raw sockets
        // For now, simulate with timeout
        let probe_result = timeout(
            self.config.timeout,
            self.simulate_icmp_probe(target, ttl)
        ).await;

        match probe_result {
            Ok(Ok((addr, is_dest))) => {
                let rtt = probe_start.elapsed();
                Ok(HopInfo {
                    ttl,
                    address: Some(addr),
                    hostname: None,
                    rtt: Some(rtt),
                    attempt,
                    protocol: TracerouteProtocol::Icmp,
                    is_destination: is_dest,
                })
            }
            _ => Err("ICMP probe timeout".to_string()),
        }
    }

    /// Send UDP probe
    async fn send_udp_probe(
        &self,
        target: IpAddr,
        ttl: u8,
        attempt: u8,
        probe_start: Instant,
    ) -> Result<HopInfo, String> {
        use tokio::net::UdpSocket;

        let probe_result = timeout(
            self.config.timeout,
            async {
                let local_addr = if target.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };

                let socket = UdpSocket::bind(local_addr).await
                    .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

                // Set TTL
                // Note: tokio doesn't have direct TTL setting, would need raw sockets
                // For now, simulate the behavior
                
                let dest_port = 33434 + ttl as u16;
                let dest = std::net::SocketAddr::new(target, dest_port);
                
                socket.send_to(&[0u8; 32], dest).await
                    .map_err(|e| format!("Failed to send UDP probe: {}", e))?;

                // Wait for ICMP Time Exceeded or Port Unreachable
                let mut buf = [0u8; 1024];
                let (len, addr) = socket.recv_from(&mut buf).await
                    .map_err(|e| format!("Failed to receive UDP response: {}", e))?;

                Ok::<_, String>((addr.ip(), len > 0))
            }
        ).await;

        match probe_result {
            Ok(Ok((addr, is_dest))) => {
                let rtt = probe_start.elapsed();
                Ok(HopInfo {
                    ttl,
                    address: Some(addr),
                    hostname: None,
                    rtt: Some(rtt),
                    attempt,
                    protocol: TracerouteProtocol::Udp,
                    is_destination: is_dest,
                })
            }
            _ => Err("UDP probe timeout".to_string()),
        }
    }

    /// Send TCP SYN probe
    async fn send_tcp_probe(
        &self,
        target: IpAddr,
        ttl: u8,
        attempt: u8,
        probe_start: Instant,
    ) -> Result<HopInfo, String> {
        use tokio::net::TcpStream;

        let probe_result = timeout(
            self.config.timeout,
            async {
                let dest = std::net::SocketAddr::new(target, self.config.port);
                
                // TCP traceroute works by sending SYN packets with increasing TTL
                // When TTL expires, routers send ICMP Time Exceeded
                // When destination is reached, it sends SYN-ACK or RST
                
                match TcpStream::connect(dest).await {
                    Ok(_stream) => {
                        // Connection successful - this is the destination
                        Ok::<_, String>((target, true))
                    }
                    Err(e) => {
                        // Connection failed - could be TTL exceeded or port unreachable
                        // In production, we would capture ICMP messages
                        Err(format!("TCP probe failed: {}", e))
                    }
                }
            }
        ).await;

        match probe_result {
            Ok(Ok((addr, is_dest))) => {
                let rtt = probe_start.elapsed();
                Ok(HopInfo {
                    ttl,
                    address: Some(addr),
                    hostname: None,
                    rtt: Some(rtt),
                    attempt,
                    protocol: TracerouteProtocol::Tcp,
                    is_destination: is_dest,
                })
            }
            _ => Err("TCP probe timeout".to_string()),
        }
    }

    /// Simulate ICMP probe (placeholder for raw socket implementation)
    async fn simulate_icmp_probe(&self, _target: IpAddr, _ttl: u8) -> Result<(IpAddr, bool), String> {
        // In production: send ICMP Echo Request with TTL
        // Wait for ICMP Time Exceeded or Echo Reply
        // Return the router IP that responded
        tokio::time::sleep(Duration::from_millis(10)).await;
        Err("Not implemented - requires raw sockets".to_string())
    }

    /// Resolve hostname for an IP address
    async fn resolve_hostname(&self, _addr: IpAddr) -> Option<String> {
        // In production, use DNS reverse lookup
        // For now, return None
        None
    }
}

/// ICMP Traceroute builder
pub struct IcmpTraceroute;

impl IcmpTraceroute {
    pub fn create() -> Traceroute {
        Traceroute::new(TracerouteConfig {
            protocol: TracerouteProtocol::Icmp,
            ..Default::default()
        })
    }

    pub fn with_max_hops(max_hops: u8) -> Traceroute {
        Traceroute::new(TracerouteConfig {
            protocol: TracerouteProtocol::Icmp,
            max_hops,
            ..Default::default()
        })
    }
}

/// UDP Traceroute builder
pub struct UdpTraceroute;

impl UdpTraceroute {
    pub fn create() -> Traceroute {
        Traceroute::new(TracerouteConfig {
            protocol: TracerouteProtocol::Udp,
            port: 33434,
            ..Default::default()
        })
    }

    pub fn with_port(port: u16) -> Traceroute {
        Traceroute::new(TracerouteConfig {
            protocol: TracerouteProtocol::Udp,
            port,
            ..Default::default()
        })
    }
}

/// TCP Traceroute builder
pub struct TcpTraceroute;

impl TcpTraceroute {
    pub fn create() -> Traceroute {
        Traceroute::new(TracerouteConfig {
            protocol: TracerouteProtocol::Tcp,
            port: 80,
            ..Default::default()
        })
    }

    pub fn with_port(port: u16) -> Traceroute {
        Traceroute::new(TracerouteConfig {
            protocol: TracerouteProtocol::Tcp,
            port,
            ..Default::default()
        })
    }
}

/// Parallel Traceroute builder
pub struct ParallelTraceroute;

impl ParallelTraceroute {
    pub fn create(parallel_probes: u8) -> Traceroute {
        Traceroute::new(TracerouteConfig {
            parallel_probes,
            ..Default::default()
        })
    }

    pub fn with_protocol(protocol: TracerouteProtocol, parallel_probes: u8) -> Traceroute {
        Traceroute::new(TracerouteConfig {
            protocol,
            parallel_probes,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_traceroute_config_default() {
        let config = TracerouteConfig::default();
        assert_eq!(config.max_hops, 30);
        assert_eq!(config.queries_per_hop, 3);
        assert_eq!(config.protocol, TracerouteProtocol::Icmp);
        assert_eq!(config.parallel_probes, 1);
        assert_eq!(config.port, 80);
        assert!(!config.use_ecn);
    }

    #[test]
    fn test_hop_info_creation() {
        let hop = HopInfo {
            ttl: 1,
            address: Some(IpAddr::from_str("192.168.1.1").unwrap()),
            hostname: Some("router.local".to_string()),
            rtt: Some(Duration::from_millis(5)),
            attempt: 1,
            protocol: TracerouteProtocol::Icmp,
            is_destination: false,
        };
        assert_eq!(hop.ttl, 1);
        assert!(hop.address.is_some());
        assert_eq!(hop.protocol, TracerouteProtocol::Icmp);
        assert!(!hop.is_destination);
    }

    #[test]
    fn test_traceroute_protocol_display() {
        assert_eq!(TracerouteProtocol::Icmp.to_string(), "ICMP");
        assert_eq!(TracerouteProtocol::Udp.to_string(), "UDP");
        assert_eq!(TracerouteProtocol::Tcp.to_string(), "TCP");
    }

    #[tokio::test]
    async fn test_traceroute_creation() {
        let tracer = Traceroute::new(TracerouteConfig::default());
        assert_eq!(tracer.config().max_hops, 30);
    }

    #[tokio::test]
    async fn test_traceroute_trace_timeout() {
        let config = TracerouteConfig {
            max_hops: 3,
            timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let tracer = Traceroute::new(config);
        let target = IpAddr::from_str("8.8.8.8").unwrap();
        
        // Will timeout since we don't have raw socket implementation
        let result = tracer.trace(target).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tcp_traceroute() {
        let tracer = TcpTraceroute::create();
        assert_eq!(tracer.config().protocol, TracerouteProtocol::Tcp);
        assert_eq!(tracer.config().port, 80);
    }

    #[tokio::test]
    async fn test_udp_traceroute() {
        let tracer = UdpTraceroute::create();
        assert_eq!(tracer.config().protocol, TracerouteProtocol::Udp);
        assert_eq!(tracer.config().port, 33434);
    }

    #[tokio::test]
    async fn test_icmp_traceroute() {
        let tracer = IcmpTraceroute::create();
        assert_eq!(tracer.config().protocol, TracerouteProtocol::Icmp);
    }

    #[tokio::test]
    async fn test_parallel_traceroute() {
        let tracer = ParallelTraceroute::create(5);
        assert_eq!(tracer.config().parallel_probes, 5);
    }

    #[tokio::test]
    async fn test_tcp_traceroute_with_port() {
        let tracer = TcpTraceroute::with_port(443);
        assert_eq!(tracer.config().protocol, TracerouteProtocol::Tcp);
        assert_eq!(tracer.config().port, 443);
    }

    #[tokio::test]
    async fn test_traceroute_result_serialization() {
        let result = TracerouteResult {
            target: IpAddr::from_str("8.8.8.8").unwrap(),
            hops: vec![
                HopInfo {
                    ttl: 1,
                    address: Some(IpAddr::from_str("192.168.1.1").unwrap()),
                    hostname: None,
                    rtt: Some(Duration::from_millis(5)),
                    attempt: 1,
                    protocol: TracerouteProtocol::Icmp,
                    is_destination: false,
                },
            ],
            completed: false,
            total_time: Duration::from_millis(100),
            protocol: TracerouteProtocol::Icmp,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: TracerouteResult = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.target, result.target);
        assert_eq!(deserialized.hops.len(), 1);
        assert_eq!(deserialized.protocol, TracerouteProtocol::Icmp);
    }
}
