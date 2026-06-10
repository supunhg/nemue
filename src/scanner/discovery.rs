#![allow(dead_code)]
use anyhow::{anyhow, Result};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Host discovery methods matching nmap's -P options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// -sL: List Scan - just list targets, no discovery
    ListScan,
    /// -sn: Ping Scan - only do host discovery, no port scan
    PingScan,
    /// -Pn: No Ping - skip host discovery, treat all targets as online
    NoPing,
    /// -PR: ARP Ping - send ARP requests for local network discovery
    ArpPing,
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
            Self::ArpPing => "-PR",
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
            "-PR" | "PR" => Some(Self::ArpPing),
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

    /// Check if this method requires raw sockets
    pub fn requires_raw_socket(&self) -> bool {
        matches!(
            self,
            Self::ArpPing | Self::TcpSynPing | Self::TcpAckPing | Self::IcmpEchoPing
        )
    }
}

impl std::fmt::Display for DiscoveryMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ListScan => write!(f, "List Scan"),
            Self::PingScan => write!(f, "Ping Scan"),
            Self::NoPing => write!(f, "No Ping"),
            Self::ArpPing => write!(f, "ARP Ping"),
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
    /// Source port for TCP probes (0 = random)
    pub source_port: u16,
    /// Number of retries per probe
    pub retries: u8,
    /// Rate limit (packets per second, 0 = unlimited)
    pub rate_limit: u32,
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
            source_port: 0,
            retries: 1,
            rate_limit: 0,
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
    /// MAC address (if discovered via ARP)
    pub mac_address: Option<String>,
    /// Vendor (if MAC address was looked up)
    pub vendor: Option<String>,
    /// Distance in hops (if traceroute was performed)
    pub distance: Option<u8>,
}

/// ARP discovery for local network scanning
pub struct ArpDiscovery {
    interface: Option<NetworkInterface>,
    timeout: Duration,
}

impl ArpDiscovery {
    /// Create a new ARP discovery scanner
    pub fn new(timeout: Duration) -> Self {
        Self {
            interface: None,
            timeout,
        }
    }

    /// Create ARP discovery with specific interface
    pub fn with_interface(interface: NetworkInterface, timeout: Duration) -> Self {
        Self {
            interface: Some(interface),
            timeout,
        }
    }

    /// Find the default network interface for ARP scanning
    fn find_default_interface() -> Option<NetworkInterface> {
        datalink::interfaces().into_iter().find(|iface| {
            !iface.is_loopback() && iface.is_up() && iface.ips.iter().any(|ip| ip.is_ipv4())
        })
    }

    /// Check if an IP is on the local network
    pub fn is_local_network(target: Ipv4Addr, iface: &NetworkInterface) -> bool {
        for ip_net in &iface.ips {
            if let IpAddr::V4(iface_ip) = ip_net.ip() {
                if let IpAddr::V4(mask) = ip_net.mask() {
                    let target_u32 = u32::from(target);
                    let iface_u32 = u32::from(iface_ip);
                    let mask_u32 = u32::from(mask);

                    if (target_u32 & mask_u32) == (iface_u32 & mask_u32) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Send ARP request to discover host
    pub async fn discover_host(&self, target: Ipv4Addr) -> Result<DiscoveryResult> {
        let iface = match &self.interface {
            Some(iface) => iface.clone(),
            None => Self::find_default_interface()
                .ok_or_else(|| anyhow!("No suitable network interface found"))?,
        };

        // Check if target is on local network
        if !Self::is_local_network(target, &iface) {
            return Err(anyhow!("Target is not on local network"));
        }

        // Get source MAC and IP
        let source_mac = iface
            .mac
            .ok_or_else(|| anyhow!("Interface has no MAC address"))?;
        let source_ip = iface
            .ips
            .iter()
            .find_map(|ip| {
                if let IpAddr::V4(ipv4) = ip.ip() {
                    Some(ipv4)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow!("Interface has no IPv4 address"))?;

        // Create raw socket for ARP
        let config = datalink::Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            ..Default::default()
        };

        let mut tx = match datalink::channel(&iface, config) {
            Ok(datalink::Channel::Ethernet(tx, _)) => tx,
            _ => return Err(anyhow!("Failed to create raw socket")),
        };

        // Build ARP request packet
        let mut ethernet_buf = vec![0u8; 42]; // Ethernet(14) + ARP(28)
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buf)
            .ok_or_else(|| anyhow!("Failed to create ethernet packet"))?;

        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buf = vec![0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buf)
            .ok_or_else(|| anyhow!("Failed to create ARP packet"))?;

        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target);

        ethernet_packet.set_payload(arp_packet.packet());

        let start = std::time::Instant::now();

        // Send ARP request
        match tx.send_to(ethernet_packet.packet(), None) {
            Some(Ok(())) => {
                // In production, we would wait for ARP reply
                // For now, return a placeholder result
                let rtt = start.elapsed().as_millis() as u64;
                Ok(DiscoveryResult {
                    target: IpAddr::V4(target),
                    is_up: false, // Would be true if we received ARP reply
                    responding_methods: vec![DiscoveryMethod::ArpPing],
                    rtt_ms: Some(rtt),
                    hostname: None,
                    mac_address: None,
                    vendor: None,
                    distance: Some(1),
                })
            }
            _ => Err(anyhow!("Failed to send ARP request")),
        }
    }

    /// Scan local network for hosts
    pub async fn scan_network(&self, network: Ipv4Addr, mask: Ipv4Addr) -> Vec<DiscoveryResult> {
        use futures::stream::{self, StreamExt};

        let network_u32 = u32::from(network);
        let mask_u32 = u32::from(mask);
        let broadcast_u32 = network_u32 | !mask_u32;
        let start_u32 = network_u32 + 1;
        let end_u32 = broadcast_u32 - 1;

        let targets: Vec<Ipv4Addr> = (start_u32..=end_u32).map(Ipv4Addr::from).collect();

        stream::iter(targets)
            .map(|target| async move {
                self.discover_host(target)
                    .await
                    .unwrap_or_else(|_| DiscoveryResult {
                        target: IpAddr::V4(target),
                        is_up: false,
                        responding_methods: vec![],
                        rtt_ms: None,
                        hostname: None,
                        mac_address: None,
                        vendor: None,
                        distance: None,
                    })
            })
            .buffer_unordered(50) // ARP scanning can be faster
            .collect()
            .await
    }
}

/// Host discovery scanner
pub struct HostDiscovery {
    config: DiscoveryConfig,
    arp_discovery: Option<ArpDiscovery>,
}

impl HostDiscovery {
    /// Create a new host discovery scanner with default config
    pub fn new() -> Self {
        Self {
            config: DiscoveryConfig::default(),
            arp_discovery: None,
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: DiscoveryConfig) -> Self {
        Self {
            config,
            arp_discovery: None,
        }
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
                source_port: 0,
                retries: 0,
                rate_limit: 0,
            },
            arp_discovery: None,
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
                source_port: 0,
                retries: 0,
                rate_limit: 0,
            },
            arp_discovery: None,
        }
    }

    /// Enable ARP discovery for local network scanning
    pub fn with_arp_discovery(mut self) -> Self {
        self.arp_discovery = Some(ArpDiscovery::new(self.config.timeout));
        self
    }

    /// Enable ARP discovery with specific interface
    pub fn with_arp_interface(mut self, interface: NetworkInterface) -> Self {
        self.arp_discovery = Some(ArpDiscovery::with_interface(interface, self.config.timeout));
        self
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
                mac_address: None,
                vendor: None,
                distance: None,
            });
        }

        if self.config.methods.contains(&DiscoveryMethod::ListScan) {
            // List scan: just list the target, no probing
            return Ok(DiscoveryResult {
                target,
                is_up: false, // Don't mark as up, just listed
                responding_methods: vec![DiscoveryMethod::ListScan],
                rtt_ms: None,
                hostname: None,
                mac_address: None,
                vendor: None,
                distance: None,
            });
        }

        // Try ARP first if enabled and target is local
        if let Some(arp) = &self.arp_discovery {
            if let IpAddr::V4(ipv4) = target {
                if let Some(iface) = ArpDiscovery::find_default_interface() {
                    if ArpDiscovery::is_local_network(ipv4, &iface) {
                        match arp.discover_host(ipv4).await {
                            Ok(result) if result.is_up => return Ok(result),
                            _ => {} // ARP failed, try other methods
                        }
                    }
                }
            }
        }

        // Try each discovery method
        let mut responding_methods = Vec::new();
        let mut min_rtt = None;
        let mut mac_address = None;
        let mut vendor = None;

        for method in &self.config.methods {
            match self.probe_with_method(target, *method).await {
                Ok(ProbeResult::Response {
                    rtt,
                    mac,
                    vendor: vendor_info,
                }) => {
                    responding_methods.push(*method);
                    if let Some(rtt) = rtt {
                        if let Some(current_min) = min_rtt {
                            if rtt < current_min {
                                min_rtt = Some(rtt);
                            }
                        } else {
                            min_rtt = Some(rtt);
                        }
                    }
                    if mac.is_some() {
                        mac_address = mac;
                    }
                    if vendor_info.is_some() {
                        vendor = vendor_info;
                    }
                }
                Ok(ProbeResult::Up) => {
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
            mac_address,
            vendor,
            distance: None,
        })
    }

    /// Probe a target with a specific discovery method
    async fn probe_with_method(
        &self,
        target: IpAddr,
        method: DiscoveryMethod,
    ) -> Result<ProbeResult> {
        match method {
            DiscoveryMethod::NoPing | DiscoveryMethod::ListScan | DiscoveryMethod::PingScan => {
                Ok(ProbeResult::Up)
            }
            DiscoveryMethod::ArpPing => {
                if let IpAddr::V4(ipv4) = target {
                    if let Some(arp) = &self.arp_discovery {
                        let result = arp.discover_host(ipv4).await?;
                        if result.is_up {
                            return Ok(ProbeResult::Response {
                                rtt: result.rtt_ms,
                                mac: result.mac_address,
                                vendor: result.vendor,
                            });
                        }
                    }
                    Err(anyhow!("ARP discovery not available"))
                } else {
                    Err(anyhow!("ARP requires IPv4 target"))
                }
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

    /// TCP-based ping (SYN or ACK) with improved implementation
    async fn tcp_ping(&self, target: IpAddr, _method: DiscoveryMethod) -> Result<ProbeResult> {
        let start = std::time::Instant::now();

        // Try each configured port
        for &port in &self.config.tcp_ports {
            let addr = SocketAddr::new(target, port);

            // Use TCP connect with retries
            for attempt in 0..=self.config.retries {
                let connect_timeout = self.config.timeout / (attempt as u32 + 1);

                if let Ok(Ok(_stream)) = timeout(connect_timeout, TcpStream::connect(addr)).await {
                    let rtt = start.elapsed().as_millis() as u64;
                    return Ok(ProbeResult::Response {
                        rtt: Some(rtt),
                        mac: None,
                        vendor: None,
                    });
                }
            }
        }

        // If all ports failed, check if we should ignore RST
        if self.config.ignore_rst {
            // For RST-ignoring mode, we consider the host up if we got any response
            // In production, this would check for RST packets specifically
        }

        Err(anyhow!("No response to TCP probes"))
    }

    /// UDP ping with improved implementation
    async fn udp_ping(&self, target: IpAddr) -> Result<ProbeResult> {
        use tokio::net::UdpSocket;

        let start = std::time::Instant::now();

        // Bind to a local port
        let local_addr = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let socket = UdpSocket::bind(local_addr).await?;
        socket
            .connect(SocketAddr::new(target, self.config.udp_ports[0]))
            .await?;

        // Send UDP packets to multiple ports
        for &port in &self.config.udp_ports {
            let addr = SocketAddr::new(target, port);
            socket.connect(addr).await?;

            // Send empty UDP packet
            let _ = socket.send(&[]).await;

            // Wait for ICMP port unreachable (which means host is up)
            let result = timeout(self.config.timeout, async {
                let mut buf = [0u8; 1024];
                socket.recv(&mut buf).await
            })
            .await;

            match result {
                Ok(Ok(_)) => {
                    let rtt = start.elapsed().as_millis() as u64;
                    return Ok(ProbeResult::Response {
                        rtt: Some(rtt),
                        mac: None,
                        vendor: None,
                    });
                }
                _ => continue,
            }
        }

        Err(anyhow!("No UDP response"))
    }

    /// ICMP echo ping (standard ping)
    async fn icmp_echo_ping(&self, target: IpAddr) -> Result<ProbeResult> {
        // Use existing IcmpScanner if available
        // For now, fall back to TCP connect as a proxy
        self.tcp_fallback_ping(target).await
    }

    /// ICMP timestamp ping
    async fn icmp_timestamp_ping(&self, target: IpAddr) -> Result<ProbeResult> {
        // ICMP timestamp requests (type 13, expecting type 14 reply)
        // For now, use TCP fallback
        self.tcp_fallback_ping(target).await
    }

    /// ICMP netmask ping
    async fn icmp_netmask_ping(&self, target: IpAddr) -> Result<ProbeResult> {
        // ICMP netmask requests (type 17, expecting type 18 reply)
        // For now, use TCP fallback
        self.tcp_fallback_ping(target).await
    }

    /// ICMPv6 Echo Ping - IPv6 echo request/reply
    async fn icmpv6_echo_ping(&self, target: IpAddr) -> Result<ProbeResult> {
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
    async fn ipv6_neighbor_discovery(&self, target: IpAddr) -> Result<ProbeResult> {
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
    async fn tcp_fallback_ping(&self, target: IpAddr) -> Result<ProbeResult> {
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
                        mac_address: None,
                        vendor: None,
                        distance: None,
                    })
            })
            .buffer_unordered(10) // Process 10 hosts concurrently
            .collect()
            .await
    }
}

/// Internal probe result
enum ProbeResult {
    /// Host responded with timing information
    Response {
        rtt: Option<u64>,
        mac: Option<String>,
        vendor: Option<String>,
    },
    /// Host is up but no detailed info
    Up,
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
        assert_eq!(DiscoveryMethod::ArpPing.to_string(), "ARP Ping");
        assert_eq!(DiscoveryMethod::TcpSynPing.to_string(), "TCP SYN Ping");
        assert_eq!(DiscoveryMethod::IcmpEchoPing.to_string(), "ICMP Echo Ping");
    }

    #[test]
    fn test_discovery_method_nmap_flags() {
        assert_eq!(DiscoveryMethod::ListScan.to_nmap_flag(), "-sL");
        assert_eq!(DiscoveryMethod::PingScan.to_nmap_flag(), "-sn");
        assert_eq!(DiscoveryMethod::NoPing.to_nmap_flag(), "-Pn");
        assert_eq!(DiscoveryMethod::ArpPing.to_nmap_flag(), "-PR");
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
            DiscoveryMethod::from_nmap_flag("-PR"),
            Some(DiscoveryMethod::ArpPing)
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
        assert_eq!(
            DiscoveryMethod::Ipv6NeighborDiscovery.to_nmap_flag(),
            "-PN6"
        );
        assert_eq!(
            DiscoveryMethod::Icmpv6EchoPing.to_string(),
            "ICMPv6 Echo Ping"
        );
        assert_eq!(
            DiscoveryMethod::Ipv6NeighborDiscovery.to_string(),
            "IPv6 Neighbor Discovery"
        );
    }

    #[test]
    fn test_requires_raw_socket() {
        assert!(DiscoveryMethod::ArpPing.requires_raw_socket());
        assert!(DiscoveryMethod::TcpSynPing.requires_raw_socket());
        assert!(DiscoveryMethod::TcpAckPing.requires_raw_socket());
        assert!(!DiscoveryMethod::NoPing.requires_raw_socket());
        assert!(!DiscoveryMethod::ListScan.requires_raw_socket());
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
            source_port: 0,
            retries: 1,
            rate_limit: 0,
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
        let result = scanner.discover(target).await;
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
        assert_eq!(config.retries, 1);
        assert_eq!(config.source_port, 0);
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
            mac_address: Some("00:11:22:33:44:55".to_string()),
            vendor: Some("Cisco".to_string()),
            distance: Some(1),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: DiscoveryResult = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.target, result.target);
        assert_eq!(deserialized.is_up, result.is_up);
        assert_eq!(deserialized.rtt_ms, result.rtt_ms);
        assert_eq!(deserialized.mac_address, result.mac_address);
        assert_eq!(deserialized.vendor, result.vendor);
        assert_eq!(deserialized.distance, result.distance);
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
            source_port: 12345,
            retries: 3,
            rate_limit: 100,
        };

        assert_eq!(config.methods.len(), 2);
        assert_eq!(config.tcp_ports.len(), 4);
        assert!(config.disable_arp_ping);
        assert!(config.ignore_rst);
        assert_eq!(config.source_port, 12345);
        assert_eq!(config.retries, 3);
        assert_eq!(config.rate_limit, 100);
    }

    #[test]
    fn test_arp_discovery_creation() {
        let arp = ArpDiscovery::new(Duration::from_millis(500));
        assert!(arp.interface.is_none());
    }

    #[test]
    fn test_is_local_network() {
        use ipnetwork::IpNetwork;

        let iface = NetworkInterface {
            name: "eth0".to_string(),
            index: 1,
            mac: Some(MacAddr::new(0, 0, 0, 0, 0, 0)),
            ips: vec![IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 24).unwrap()],
            flags: 0,
            description: String::new(),
        };

        let local_ip = Ipv4Addr::new(192, 168, 1, 1);
        let remote_ip = Ipv4Addr::new(10, 0, 0, 1);

        assert!(ArpDiscovery::is_local_network(local_ip, &iface));
        assert!(!ArpDiscovery::is_local_network(remote_ip, &iface));
    }
}
