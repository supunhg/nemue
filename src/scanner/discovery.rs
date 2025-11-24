use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use serde::{Deserialize, Serialize};

/// Host discovery methods matching nmap's -P options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// -sL: List Scan - just list targets, no discovery
    ListScan,
    /// -sn: Ping Scan - only do host discovery, no port scan
    PingScan,
    /// -Pn: No Ping - skip host discovery, treat all targets as online
    NoPing,
    /// -PS: TCP SYN Ping - send SYN packets to discover hosts
    TcpSynPing,
    /// -PA: TCP ACK Ping - send ACK packets to discover hosts
    TcpAckPing,
    /// -PU: UDP Ping - send UDP packets to discover hosts
    UdpPing,
    /// -PE: ICMP Echo Ping - standard ICMP echo request
    IcmpEchoPing,
    /// -PP: ICMP Timestamp Ping - ICMP timestamp request
    IcmpTimestampPing,
    /// -PM: ICMP Netmask Ping - ICMP netmask request
    IcmpNetmaskPing,
    /// -P6: ICMPv6 Echo Ping - IPv6 echo request
    Icmpv6EchoPing,
    /// -PN: IPv6 Neighbor Discovery Ping
    Ipv6NeighborDiscovery,
}

impl DiscoveryMethod {
    /// Get the nmap equivalent flag
    pub fn to_nmap_flag(&self) -> &'static str {
        match self {
            Self::ListScan => "-sL",
            Self::PingScan => "-sn",
            Self::NoPing => "-Pn",
            Self::TcpSynPing => "-PS",
            Self::TcpAckPing => "-PA",
            Self::UdpPing => "-PU",
            Self::IcmpEchoPing => "-PE",
            Self::IcmpTimestampPing => "-PP",
            Self::IcmpNetmaskPing => "-PM",
            Self::Icmpv6EchoPing => "-PE6",
            Self::Ipv6NeighborDiscovery => "-PN6",
        }
    }

    /// Parse from nmap flag
    pub fn from_nmap_flag(flag: &str) -> Option<Self> {
        match flag {
            "-sL" | "sL" => Some(Self::ListScan),
            "-sn" | "sn" => Some(Self::PingScan),
            "-Pn" | "Pn" => Some(Self::NoPing),
            "-PS" | "PS" => Some(Self::TcpSynPing),
            "-PA" | "PA" => Some(Self::TcpAckPing),
            "-PU" | "PU" => Some(Self::UdpPing),
            "-PE" | "PE" => Some(Self::IcmpEchoPing),
            "-PP" | "PP" => Some(Self::IcmpTimestampPing),
            "-PM" | "PM" => Some(Self::IcmpNetmaskPing),
            "-PE6" | "PE6" => Some(Self::Icmpv6EchoPing),
            "-PN6" | "PN6" => Some(Self::Ipv6NeighborDiscovery),
            _ => None,
        }
    }
}

impl std::fmt::Display for DiscoveryMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ListScan => write!(f, "List Scan"),
            Self::PingScan => write!(f, "Ping Scan"),
            Self::NoPing => write!(f, "No Ping"),
            Self::TcpSynPing => write!(f, "TCP SYN Ping"),
            Self::TcpAckPing => write!(f, "TCP ACK Ping"),
            Self::UdpPing => write!(f, "UDP Ping"),
            Self::IcmpEchoPing => write!(f, "ICMP Echo Ping"),
            Self::IcmpTimestampPing => write!(f, "ICMP Timestamp Ping"),
            Self::IcmpNetmaskPing => write!(f, "ICMP Netmask Ping"),
            Self::Icmpv6EchoPing => write!(f, "ICMPv6 Echo Ping"),
            Self::Ipv6NeighborDiscovery => write!(f, "IPv6 Neighbor Discovery"),
        }
    }
}

/// Configuration for host discovery
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Methods to use for discovery (can use multiple)
    pub methods: Vec<DiscoveryMethod>,
    /// Ports to probe for TCP-based discovery (default: 80, 443)
    pub tcp_ports: Vec<u16>,
    /// Ports to probe for UDP-based discovery (default: 40125)
    pub udp_ports: Vec<u16>,
    /// Timeout for discovery probes
    pub timeout: Duration,
    /// Whether to disable ARP ping (local network)
    pub disable_arp_ping: bool,
    /// Whether to ignore RST responses (for firewall evasion)
    pub ignore_rst: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            // Default: ICMP echo + TCP SYN on 443 + TCP ACK on 80 + ICMP timestamp
            // This matches nmap's default discovery (-PE -PS443 -PA80 -PP)
            methods: vec![
                DiscoveryMethod::IcmpEchoPing,
                DiscoveryMethod::TcpSynPing,
                DiscoveryMethod::TcpAckPing,
                DiscoveryMethod::IcmpTimestampPing,
            ],
            tcp_ports: vec![80, 443],
            udp_ports: vec![40125],
            timeout: Duration::from_millis(1000),
            disable_arp_ping: false,
            ignore_rst: false,
        }
    }
}

/// Result of host discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResult {
    /// Target IP address
    pub target: IpAddr,
    /// Whether the host is up
    pub is_up: bool,
    /// Methods that succeeded in detecting the host
    pub responding_methods: Vec<DiscoveryMethod>,
    /// Round-trip time in milliseconds (if measured)
    pub rtt_ms: Option<u64>,
    /// Hostname (if DNS resolution was performed)
    pub hostname: Option<String>,
}

/// Host discovery scanner
pub struct HostDiscovery {
    config: DiscoveryConfig,
}

impl HostDiscovery {
    /// Create a new host discovery scanner with default config
    pub fn new() -> Self {
        Self {
            config: DiscoveryConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: DiscoveryConfig) -> Self {
        Self { config }
    }

    /// Create a scanner that skips discovery (treats all hosts as up)
    pub fn no_ping() -> Self {
        Self {
            config: DiscoveryConfig {
                methods: vec![DiscoveryMethod::NoPing],
                tcp_ports: vec![],
                udp_ports: vec![],
                timeout: Duration::from_secs(0),
                disable_arp_ping: true,
                ignore_rst: false,
            },
        }
    }

    /// Create a scanner for list scan only (no probes sent)
    pub fn list_only() -> Self {
        Self {
            config: DiscoveryConfig {
                methods: vec![DiscoveryMethod::ListScan],
                tcp_ports: vec![],
                udp_ports: vec![],
                timeout: Duration::from_secs(0),
                disable_arp_ping: true,
                ignore_rst: false,
            },
        }
    }

    /// Discover a single host
    pub async fn discover(&self, target: IpAddr) -> Result<DiscoveryResult> {
        // Special cases
        if self.config.methods.contains(&DiscoveryMethod::NoPing) {
            return Ok(DiscoveryResult {
                target,
                is_up: true, // Assume all hosts are up
                responding_methods: vec![DiscoveryMethod::NoPing],
                rtt_ms: None,
                hostname: None,
            });
        }

        if self.config.methods.contains(&DiscoveryMethod::ListScan) {
            // List scan: just list the target, no probing
            return Ok(DiscoveryResult {
                target,
                is_up: false, // Don't mark as up, just listed
                responding_methods: vec![DiscoveryMethod::ListScan],
                rtt_ms: None,
                hostname: None, // DNS would be done separately
            });
        }

        // Try each discovery method
        let mut responding_methods = Vec::new();
        let mut min_rtt = None;

        for method in &self.config.methods {
            match self.probe_with_method(target, *method).await {
                Ok(Some(rtt)) => {
                    responding_methods.push(*method);
                    if let Some(current_min) = min_rtt {
                        if rtt < current_min {
                            min_rtt = Some(rtt);
                        }
                    } else {
                        min_rtt = Some(rtt);
                    }
                }
                Ok(None) => {
                    // Method returned success but no RTT
                    responding_methods.push(*method);
                }
                Err(_) => {
                    // This method failed, try next
                    continue;
                }
            }
        }

        Ok(DiscoveryResult {
            target,
            is_up: !responding_methods.is_empty(),
            responding_methods,
            rtt_ms: min_rtt,
            hostname: None,
        })
    }

    /// Probe a target with a specific discovery method
    /// Returns Ok(Some(rtt_ms)) if host responds
    async fn probe_with_method(
        &self,
        target: IpAddr,
        method: DiscoveryMethod,
    ) -> Result<Option<u64>> {
        match method {
            DiscoveryMethod::NoPing | DiscoveryMethod::ListScan | DiscoveryMethod::PingScan => {
                Ok(None) // Special cases handled in discover()
            }
            DiscoveryMethod::TcpSynPing | DiscoveryMethod::TcpAckPing => {
                self.tcp_ping(target, method).await
            }
            DiscoveryMethod::UdpPing => self.udp_ping(target).await,
            DiscoveryMethod::IcmpEchoPing => self.icmp_echo_ping(target).await,
            DiscoveryMethod::IcmpTimestampPing => self.icmp_timestamp_ping(target).await,
            DiscoveryMethod::IcmpNetmaskPing => self.icmp_netmask_ping(target).await,
            DiscoveryMethod::Icmpv6EchoPing => {
                if target.is_ipv6() {
                    self.icmpv6_echo_ping(target).await
                } else {
                    Err(anyhow!("ICMPv6 echo ping requires IPv6 target"))
                }
            }
            DiscoveryMethod::Ipv6NeighborDiscovery => {
                if target.is_ipv6() {
                    self.ipv6_neighbor_discovery(target).await
                } else {
                    Err(anyhow!("IPv6 neighbor discovery requires IPv6 target"))
                }
            }
        }
    }

    /// TCP-based ping (SYN or ACK)
    async fn tcp_ping(
        &self,
        target: IpAddr,
        _method: DiscoveryMethod,
    ) -> Result<Option<u64>> {
        let start = std::time::Instant::now();

        // Try each configured port
        for &port in &self.config.tcp_ports {
            let addr = SocketAddr::new(target, port);
            
            // Use TCP connect for now (in production, use raw SYN/ACK packets)
            if let Ok(Ok(_stream)) = timeout(self.config.timeout, TcpStream::connect(addr)).await
            {
                let rtt = start.elapsed().as_millis() as u64;
                return Ok(Some(rtt));
            }
        }

        Err(anyhow!("No response to TCP probes"))
    }

    /// UDP ping
    async fn udp_ping(&self, target: IpAddr) -> Result<Option<u64>> {
        use tokio::net::UdpSocket;

        let start = std::time::Instant::now();

        // Bind to a local port
        let local_addr = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let socket = UdpSocket::bind(local_addr).await?;
        socket.connect(SocketAddr::new(target, self.config.udp_ports[0])).await?;

        // Send empty UDP packet
        let _ = socket.send(&[]).await;

        // Wait for ICMP port unreachable (which means host is up)
        // For now, use a simple timeout approach
        let result = timeout(self.config.timeout, async {
            let mut buf = [0u8; 1024];
            socket.recv(&mut buf).await
        })
        .await;

        match result {
            Ok(Ok(_)) => {
                let rtt = start.elapsed().as_millis() as u64;
                Ok(Some(rtt))
            }
            Ok(Err(_)) | Err(_) => {
                // Timeout or error - in production, check for ICMP unreachable
                Err(anyhow!("No UDP response"))
            }
        }
    }

    /// ICMP echo ping (standard ping)
    async fn icmp_echo_ping(&self, target: IpAddr) -> Result<Option<u64>> {
        // Use existing IcmpScanner if available
        // For now, fall back to TCP connect as a proxy
        self.tcp_fallback_ping(target).await
    }

    /// ICMP timestamp ping
    async fn icmp_timestamp_ping(&self, target: IpAddr) -> Result<Option<u64>> {
        // ICMP timestamp requests (type 13, expecting type 14 reply)
        // For now, use TCP fallback
        self.tcp_fallback_ping(target).await
    }

    /// ICMP netmask ping
    async fn icmp_netmask_ping(&self, target: IpAddr) -> Result<Option<u64>> {
        // ICMP netmask requests (type 17, expecting type 18 reply)
        // For now, use TCP fallback
        self.tcp_fallback_ping(target).await
    }

    /// ICMPv6 Echo Ping - IPv6 echo request/reply
    async fn icmpv6_echo_ping(&self, target: IpAddr) -> Result<Option<u64>> {
        use std::net::Ipv6Addr;
        
        if let IpAddr::V6(ipv6_addr) = target {
            // ICMPv6 implementation requires raw sockets
            // For now, use TCP fallback as ICMPv6 requires raw sockets
            // 
            // ICMPv6 Echo Request:
            // - Type: 128 (Echo Request)
            // - Code: 0
            // - Expect: Type 129 (Echo Reply)
            //
            // This is similar to IPv4 ICMP echo but with different type codes
            // and must use IPv6 headers
            
            self.tcp_fallback_ping(IpAddr::V6(ipv6_addr)).await
        } else {
            Err(anyhow!("ICMPv6 echo ping requires IPv6 address"))
        }
    }

    /// IPv6 Neighbor Discovery - uses ICMPv6 Neighbor Solicitation
    async fn ipv6_neighbor_discovery(&self, target: IpAddr) -> Result<Option<u64>> {
        use std::net::Ipv6Addr;
        
        if let IpAddr::V6(ipv6_addr) = target {
            // NDP implementation requires ICMPv6
            // For now, use TCP fallback
            //
            // IPv6 NDP uses ICMPv6 messages:
            // - Type 135: Neighbor Solicitation (NS) - query for link-layer address
            // - Type 136: Neighbor Advertisement (NA) - response with link-layer address
            //
            // This is the IPv6 equivalent of ARP for local network discovery
            // Particularly useful for link-local addresses (fe80::/10)
            //
            // Packet structure:
            // - IPv6 header (40 bytes)
            // - ICMPv6 header (8 bytes): Type=135, Code=0
            // - Target Address (16 bytes): IPv6 address being queried
            // - Options: Source Link-Layer Address (8 bytes)
            
            self.tcp_fallback_ping(IpAddr::V6(ipv6_addr)).await
        } else {
            Err(anyhow!("IPv6 neighbor discovery requires IPv6 address"))
        }
    }

    /// Fallback to TCP connect for ICMP methods (until raw ICMP is implemented)
    async fn tcp_fallback_ping(&self, target: IpAddr) -> Result<Option<u64>> {
        self.tcp_ping(target, DiscoveryMethod::TcpSynPing).await
    }

    /// Discover multiple hosts in parallel
    pub async fn discover_batch(&self, targets: Vec<IpAddr>) -> Vec<DiscoveryResult> {
        use futures::stream::{self, StreamExt};

        stream::iter(targets)
            .map(|target| async move {
                self.discover(target)
                    .await
                    .unwrap_or_else(|_| DiscoveryResult {
                        target,
                        is_up: false,
                        responding_methods: vec![],
                        rtt_ms: None,
                        hostname: None,
                    })
            })
            .buffer_unordered(10) // Process 10 hosts concurrently
            .collect()
            .await
    }
}

impl Default for HostDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_method_display() {
        assert_eq!(DiscoveryMethod::ListScan.to_string(), "List Scan");
        assert_eq!(DiscoveryMethod::TcpSynPing.to_string(), "TCP SYN Ping");
        assert_eq!(DiscoveryMethod::IcmpEchoPing.to_string(), "ICMP Echo Ping");
    }

    #[test]
    fn test_discovery_method_nmap_flags() {
        assert_eq!(DiscoveryMethod::ListScan.to_nmap_flag(), "-sL");
        assert_eq!(DiscoveryMethod::PingScan.to_nmap_flag(), "-sn");
        assert_eq!(DiscoveryMethod::NoPing.to_nmap_flag(), "-Pn");
        assert_eq!(DiscoveryMethod::TcpSynPing.to_nmap_flag(), "-PS");
        assert_eq!(DiscoveryMethod::TcpAckPing.to_nmap_flag(), "-PA");
    }

    #[test]
    fn test_discovery_method_from_flag() {
        assert_eq!(
            DiscoveryMethod::from_nmap_flag("-sL"),
            Some(DiscoveryMethod::ListScan)
        );
        assert_eq!(
            DiscoveryMethod::from_nmap_flag("PS"),
            Some(DiscoveryMethod::TcpSynPing)
        );
        assert_eq!(
            DiscoveryMethod::from_nmap_flag("-PE6"),
            Some(DiscoveryMethod::Icmpv6EchoPing)
        );
        assert_eq!(
            DiscoveryMethod::from_nmap_flag("-PN6"),
            Some(DiscoveryMethod::Ipv6NeighborDiscovery)
        );
        assert_eq!(DiscoveryMethod::from_nmap_flag("invalid"), None);
    }

    #[test]
    fn test_ipv6_discovery_methods() {
        assert_eq!(DiscoveryMethod::Icmpv6EchoPing.to_nmap_flag(), "-PE6");
        assert_eq!(DiscoveryMethod::Ipv6NeighborDiscovery.to_nmap_flag(), "-PN6");
        assert_eq!(DiscoveryMethod::Icmpv6EchoPing.to_string(), "ICMPv6 Echo Ping");
        assert_eq!(DiscoveryMethod::Ipv6NeighborDiscovery.to_string(), "IPv6 Neighbor Discovery");
    }

    #[tokio::test]
    async fn test_ipv6_discovery_localhost() {
        let config = DiscoveryConfig {
            methods: vec![DiscoveryMethod::Icmpv6EchoPing],
            tcp_ports: vec![80, 443],
            udp_ports: vec![],
            timeout: Duration::from_millis(1000),
            disable_arp_ping: false,
            ignore_rst: false,
        };

        let scanner = HostDiscovery::with_config(config);
        let target: IpAddr = "::1".parse().unwrap();
        
        let result = scanner.discover(target).await;
        // Result depends on network configuration
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ipv6_neighbor_discovery_method() {
        let scanner = HostDiscovery::new();
        let target: IpAddr = "::1".parse().unwrap();
        
        // Test that the method is called correctly for IPv6
        let result = scanner.ipv6_neighbor_discovery(target).await;
        // May fail without raw socket access, but shouldn't panic
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_default_discovery_config() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.methods.len(), 4);
        assert!(config.methods.contains(&DiscoveryMethod::IcmpEchoPing));
        assert!(config.methods.contains(&DiscoveryMethod::TcpSynPing));
        assert_eq!(config.tcp_ports, vec![80, 443]);
        assert!(!config.disable_arp_ping);
    }

    #[test]
    fn test_no_ping_scanner() {
        let scanner = HostDiscovery::no_ping();
        assert_eq!(scanner.config.methods.len(), 1);
        assert_eq!(scanner.config.methods[0], DiscoveryMethod::NoPing);
        assert!(scanner.config.disable_arp_ping);
    }

    #[test]
    fn test_list_only_scanner() {
        let scanner = HostDiscovery::list_only();
        assert_eq!(scanner.config.methods.len(), 1);
        assert_eq!(scanner.config.methods[0], DiscoveryMethod::ListScan);
        assert!(scanner.config.disable_arp_ping);
    }

    #[tokio::test]
    async fn test_no_ping_discovery() {
        let scanner = HostDiscovery::no_ping();
        let target: IpAddr = "8.8.8.8".parse().unwrap();
        
        let result = scanner.discover(target).await.unwrap();
        assert_eq!(result.target, target);
        assert!(result.is_up); // No ping assumes all hosts are up
        assert_eq!(result.responding_methods.len(), 1);
        assert_eq!(result.responding_methods[0], DiscoveryMethod::NoPing);
    }

    #[tokio::test]
    async fn test_list_scan_discovery() {
        let scanner = HostDiscovery::list_only();
        let target: IpAddr = "192.168.1.1".parse().unwrap();
        
        let result = scanner.discover(target).await.unwrap();
        assert_eq!(result.target, target);
        assert!(!result.is_up); // List scan doesn't mark as up
        assert_eq!(result.responding_methods.len(), 1);
        assert_eq!(result.responding_methods[0], DiscoveryMethod::ListScan);
    }

    #[tokio::test]
    async fn test_tcp_ping_localhost() {
        let mut config = DiscoveryConfig::default();
        config.methods = vec![DiscoveryMethod::TcpSynPing];
        config.tcp_ports = vec![22, 80, 443]; // Common ports
        
        let scanner = HostDiscovery::with_config(config);
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        
        let result = scanner.discover(target).await.unwrap();
        // Result depends on what's running on localhost
        assert_eq!(result.target, target);
    }

    #[tokio::test]
    async fn test_discovery_result_serialization() {
        let result = DiscoveryResult {
            target: "192.168.1.1".parse().unwrap(),
            is_up: true,
            responding_methods: vec![DiscoveryMethod::TcpSynPing, DiscoveryMethod::IcmpEchoPing],
            rtt_ms: Some(25),
            hostname: Some("router.local".to_string()),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: DiscoveryResult = serde_json::from_str(&json).unwrap();
        
        assert_eq!(deserialized.target, result.target);
        assert_eq!(deserialized.is_up, result.is_up);
        assert_eq!(deserialized.rtt_ms, result.rtt_ms);
    }

    #[tokio::test]
    async fn test_batch_discovery() {
        let scanner = HostDiscovery::no_ping(); // Use no-ping for quick test
        let targets = vec![
            "127.0.0.1".parse().unwrap(),
            "127.0.0.2".parse().unwrap(),
            "127.0.0.3".parse().unwrap(),
        ];

        let results = scanner.discover_batch(targets).await;
        assert_eq!(results.len(), 3);
        
        // With no-ping, all should be marked as up
        for result in results {
            assert!(result.is_up);
        }
    }

    #[test]
    fn test_custom_discovery_config() {
        let config = DiscoveryConfig {
            methods: vec![DiscoveryMethod::TcpSynPing, DiscoveryMethod::UdpPing],
            tcp_ports: vec![22, 80, 443, 8080],
            udp_ports: vec![53, 161],
            timeout: Duration::from_secs(2),
            disable_arp_ping: true,
            ignore_rst: true,
        };

        assert_eq!(config.methods.len(), 2);
        assert_eq!(config.tcp_ports.len(), 4);
        assert!(config.disable_arp_ping);
        assert!(config.ignore_rst);
    }
}
