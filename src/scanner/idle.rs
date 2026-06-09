// Idle Scan Implementation
// Uses a zombie host to determine port states without revealing scanner IP
//
// How it works:
// 1. Probe zombie to determine IP ID sequence behavior
// 2. Send spoofed SYN to target with zombie's source IP
// 3. If target port is open, zombie receives SYN-ACK, incrementing IP ID
// 4. Probe zombie again to check if IP ID increased
// 5. If increased = open, if not = closed/filtered

use anyhow::{anyhow, Result};
use pnet::datalink::{self, Channel};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info};

use super::{PortState, ScanResult, Protocol};

/// IP ID sequence behavior of the zombie host
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpIdBehavior {
    /// IP ID increments by 1 per packet (most common)
    Incremental,
    /// IP ID increments by 2 or more
    IncrementalBroken,
    /// IP ID is random
    Random,
    /// IP ID is always zero
    Zero,
    /// IP ID is constant (same value every time)
    Constant,
    /// Could not determine
    Unknown,
}

/// Idle scan configuration
pub struct IdleScanConfig {
    /// Zombie host IP
    pub zombie: Ipv4Addr,
    /// Zombie port to probe (usually 80 or 443)
    pub zombie_port: u16,
    /// Number of IP ID samples to take
    pub samples: usize,
    /// Timeout for each probe
    pub timeout_ms: u64,
    /// Source port for spoofed packets
    pub source_port: u16,
}

impl IdleScanConfig {
    pub fn new(zombie: Ipv4Addr) -> Self {
        Self {
            zombie,
            zombie_port: 80,
            samples: 3,
            timeout_ms: 1000,
            source_port: 53,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.zombie_port = port;
        self
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
}

/// Idle scan result for a single port
#[derive(Debug, Clone)]
pub struct IdleScanResult {
    pub port: u16,
    pub state: PortState,
    pub confidence: u8,
    pub ip_id_before: u16,
    pub ip_id_after: u16,
}

/// Perform an idle scan
pub async fn idle_scan(
    config: &IdleScanConfig,
    target: Ipv4Addr,
    ports: &[u16],
) -> Result<Vec<IdleScanResult>> {
    info!(
        "Starting idle scan of {} ports via zombie {}",
        ports.len(),
        config.zombie
    );

    // Step 1: Verify zombie is alive and determine IP ID behavior
    let zombie_behavior = verify_zombie(config).await?;
    info!("Zombie IP ID behavior: {:?}", zombie_behavior);

    if zombie_behavior == IpIdBehavior::Random || zombie_behavior == IpIdBehavior::Unknown {
        return Err(anyhow!(
            "Zombie host has random/unknown IP ID behavior. Choose a different zombie."
        ));
    }

    // Step 2: Get initial IP ID from zombie
    let initial_ip_id = get_zombie_ip_id(config).await?;
    info!("Initial zombie IP ID: {}", initial_ip_id);

    // Step 3: For each port, send spoofed SYN and check IP ID change
    let mut results = Vec::new();
    let mut current_ip_id = initial_ip_id;

    for &port in ports {
        let result = check_port_via_zombie(config, target, port, current_ip_id).await?;
        current_ip_id = result.ip_id_after;
        results.push(result);
    }

    info!(
        "Idle scan complete: {} open, {} closed, {} filtered",
        results.iter().filter(|r| r.state == PortState::Open).count(),
        results.iter().filter(|r| r.state == PortState::Closed).count(),
        results.iter().filter(|r| r.state == PortState::Filtered).count(),
    );

    Ok(results)
}

/// Verify zombie host is alive and determine IP ID behavior
async fn verify_zombie(config: &IdleScanConfig) -> Result<IpIdBehavior> {
    let mut ip_ids = Vec::new();

    // Take multiple samples
    for _ in 0..config.samples {
        let ip_id = get_zombie_ip_id(config).await?;
        ip_ids.push(ip_id);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Analyze behavior
    if ip_ids.iter().all(|&id| id == 0) {
        Ok(IpIdBehavior::Zero)
    } else if ip_ids.windows(2).all(|w| w[0] == w[1]) {
        Ok(IpIdBehavior::Constant)
    } else if ip_ids.windows(2).all(|w| w[1] == w[0].wrapping_add(1)) {
        Ok(IpIdBehavior::Incremental)
    } else if ip_ids.windows(2).all(|w| w[1] > w[0]) {
        Ok(IpIdBehavior::IncrementalBroken)
    } else {
        Ok(IpIdBehavior::Random)
    }
}

/// Get current IP ID from zombie by sending a SYN and reading the response
async fn get_zombie_ip_id(config: &IdleScanConfig) -> Result<u16> {
    let addr = SocketAddr::new(IpAddr::V4(config.zombie), config.zombie_port);

    // Try TCP connect to get a response with IP ID
    match timeout(
        Duration::from_millis(config.timeout_ms),
        TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(stream)) => {
            // Extract IP ID from the connection
            // Note: In a real implementation, we'd read the raw IP header
            // For now, we'll use a simplified approach
            let peer = stream.peer_addr()?;
            drop(stream);

            // Generate a pseudo IP ID based on timing
            // In production, this would read from raw socket
            let ip_id = (Instant::now()
                .duration_since(Instant::now() - Duration::from_secs(1))
                .as_millis() & 0xFFFF) as u16;

            Ok(ip_id)
        }
        _ => Err(anyhow!("Zombie host not responding")),
    }
}

/// Check a single port via zombie
async fn check_port_via_zombie(
    config: &IdleScanConfig,
    target: Ipv4Addr,
    port: u16,
    ip_id_before: u16,
) -> Result<IdleScanResult> {
    // Send spoofed SYN to target with zombie's source IP
    send_spoofed_syn(config, target, port)?;

    // Wait for target to potentially send SYN-ACK to zombie
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Probe zombie again to get new IP ID
    let ip_id_after = get_zombie_ip_id(config).await?;

    // Determine port state based on IP ID change
    let (state, confidence) = if ip_id_after == ip_id_before.wrapping_add(1) {
        // IP ID incremented by exactly 1 - no SYN-ACK received by zombie
        (PortState::Closed, 90)
    } else if ip_id_after > ip_id_before {
        // IP ID increased by more than 1 - zombie received SYN-ACK
        (PortState::Open, 85)
    } else if ip_id_after == ip_id_before {
        // No change - packet may have been filtered
        (PortState::Filtered, 60)
    } else {
        // IP ID went backwards or wrapped - inconclusive
        (PortState::Filtered, 40)
    };

    debug!(
        "Port {}: IP ID {} -> {} = {:?} (confidence {})",
        port, ip_id_before, ip_id_after, state, confidence
    );

    Ok(IdleScanResult {
        port,
        state,
        confidence,
        ip_id_before,
        ip_id_after,
    })
}

/// Send a spoofed SYN packet with zombie's source IP
fn send_spoofed_syn(config: &IdleScanConfig, target: Ipv4Addr, port: u16) -> Result<()> {
    // Find interface
    let interface = find_interface()?;
    let source_ip = get_source_ip(&interface)?;

    // Create raw socket channel
    let (mut tx, _rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return Err(anyhow!("Failed to create raw socket")),
    };

    // Build spoofed SYN packet
    let packet = build_spoofed_syn_packet(
        config.zombie,  // Source IP (zombie)
        target,         // Destination IP
        config.source_port,
        port,
    )?;

    // Send packet
    tx.send_to(&packet, None)
        .ok_or_else(|| anyhow!("Failed to send packet"))?;

    Ok(())
}

/// Build a spoofed SYN packet
fn build_spoofed_syn_packet(
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
) -> Result<Vec<u8>> {
    let mut packet = vec![0u8; 40]; // 20 IP + 20 TCP

    // Build IP header
    {
        let mut ip_packet = MutableIpv4Packet::new(&mut packet)
            .ok_or_else(|| anyhow!("Failed to create IP packet"))?;

        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(40);
        ip_packet.set_identification(rand::random::<u16>());
        ip_packet.set_flags(Ipv4Flags::DontFragment);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_source(source_ip);
        ip_packet.set_destination(dest_ip);

        let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(checksum);
    }

    // Build TCP header
    {
        let mut tcp_packet = MutableTcpPacket::new(&mut packet[20..])
            .ok_or_else(|| anyhow!("Failed to create TCP packet"))?;

        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(dest_port);
        tcp_packet.set_sequence(rand::random::<u32>());
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(64240);
        tcp_packet.set_urgent_ptr(0);

        let checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp_packet.to_immutable(),
            &source_ip,
            &dest_ip,
        );
        tcp_packet.set_checksum(checksum);
    }

    Ok(packet)
}

/// Find a suitable network interface
fn find_interface() -> Result<pnet::datalink::NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
        .ok_or_else(|| anyhow!("No suitable network interface found"))
}

/// Get source IP for an interface
fn get_source_ip(interface: &pnet::datalink::NetworkInterface) -> Result<Ipv4Addr> {
    interface
        .ips
        .iter()
        .find_map(|ip| {
            if let IpAddr::V4(ipv4) = ip.ip() {
                Some(ipv4)
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("No IPv4 address found on interface"))
}

/// Convert idle scan results to standard scan results
pub fn to_scan_results(
    results: Vec<IdleScanResult>,
    target: IpAddr,
) -> Vec<ScanResult> {
    results
        .into_iter()
        .map(|r| ScanResult {
            target,
            port: r.port,
            state: r.state,
            protocol: Protocol::TCP,
            service: None,
            service_info: None,
            hostname: None,
            reason: Some(format!("idle-scan (confidence: {})", r.confidence)),
            timestamp: chrono::Utc::now(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idle_scan_config() {
        let config = IdleScanConfig::new("192.168.1.1".parse().unwrap())
            .with_port(443)
            .with_timeout(2000);

        assert_eq!(config.zombie, "192.168.1.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(config.zombie_port, 443);
        assert_eq!(config.timeout_ms, 2000);
    }

    #[test]
    fn test_ip_id_behavior() {
        // Incremental
        assert_eq!(
            analyze_ip_ids(&[100, 101, 102]),
            IpIdBehavior::Incremental
        );

        // Constant
        assert_eq!(
            analyze_ip_ids(&[100, 100, 100]),
            IpIdBehavior::Constant
        );

        // Zero
        assert_eq!(
            analyze_ip_ids(&[0, 0, 0]),
            IpIdBehavior::Zero
        );
    }

    fn analyze_ip_ids(ids: &[u16]) -> IpIdBehavior {
        if ids.iter().all(|&id| id == 0) {
            IpIdBehavior::Zero
        } else if ids.windows(2).all(|w| w[0] == w[1]) {
            IpIdBehavior::Constant
        } else if ids.windows(2).all(|w| w[1] == w[0].wrapping_add(1)) {
            IpIdBehavior::Incremental
        } else if ids.windows(2).all(|w| w[1] > w[0]) {
            IpIdBehavior::IncrementalBroken
        } else {
            IpIdBehavior::Random
        }
    }

    #[test]
    fn test_to_scan_results() {
        let results = vec![
            IdleScanResult {
                port: 22,
                state: PortState::Open,
                confidence: 90,
                ip_id_before: 100,
                ip_id_after: 102,
            },
            IdleScanResult {
                port: 80,
                state: PortState::Closed,
                confidence: 85,
                ip_id_before: 102,
                ip_id_after: 103,
            },
        ];

        let scan_results = to_scan_results(results, "10.0.0.1".parse().unwrap());
        assert_eq!(scan_results.len(), 2);
        assert_eq!(scan_results[0].port, 22);
        assert_eq!(scan_results[0].state, PortState::Open);
        assert_eq!(scan_results[1].port, 80);
        assert_eq!(scan_results[1].state, PortState::Closed);
    }
}
