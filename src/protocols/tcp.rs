use anyhow::{anyhow, Result};
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::scanner::{PortState, Protocol, ScanResult};

#[derive(Clone)]
pub struct TcpScanner {
    timeout_duration: Duration,
    use_raw_sockets: bool,
}

impl TcpScanner {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
            use_raw_sockets: false,
        }
    }

    pub fn with_raw_sockets(timeout_ms: u64, use_raw: bool) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
            use_raw_sockets: use_raw,
        }
    }

    /// Perform a TCP SYN scan (stealth scan)
    pub async fn syn_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        if self.use_raw_sockets {
            self.raw_syn_scan(target, port).await
        } else {
            // Fallback to connect scan
            self.connect_scan(target, port).await
        }
    }

    /// True SYN scan using raw sockets via pnet datalink layer
    async fn raw_syn_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        // Only IPv4 supported for now
        let target_ipv4 = match target {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => return Err(anyhow!("IPv6 not yet supported for raw SYN scan")),
        };

        // Find a suitable network interface
        let interface = Self::find_interface()?;

        // Get our source IP
        let source_ip = Self::get_source_ip(&interface, target_ipv4)?;

        // Create datalink channel
        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow!("Unsupported channel type")),
            Err(e) => return Err(anyhow!("Failed to create channel (requires root): {}", e)),
        };

        // Build and send SYN packet
        let src_port = rand::thread_rng().gen_range(1024..65535);
        let sequence = rand::thread_rng().gen::<u32>();

        let packet_data = Self::build_syn_packet(source_ip, target_ipv4, src_port, port, sequence)?;

        tx.send_to(&packet_data, None)
            .ok_or_else(|| anyhow!("Failed to send packet"))?
            .map_err(|e| anyhow!("Send error: {}", e))?;

        // Listen for response
        let state = match timeout(self.timeout_duration, async {
            loop {
                match rx.next() {
                    Ok(packet) => {
                        // Skip Ethernet header (14 bytes) to get to IP packet
                        if packet.len() < 14 {
                            continue;
                        }
                        let ip_packet = &packet[14..];

                        if let Some(ipv4) = Ipv4Packet::new(ip_packet) {
                            // Check if it's from our target
                            if ipv4.get_source() != target_ipv4 {
                                continue;
                            }

                            // Check if it's TCP
                            if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                                continue;
                            }

                            // Parse TCP packet
                            let tcp_offset = (ipv4.get_header_length() as usize) * 4;
                            if ip_packet.len() < tcp_offset {
                                continue;
                            }

                            if let Some(tcp) = TcpPacket::new(&ip_packet[tcp_offset..]) {
                                // Check if it's a response to our probe
                                if tcp.get_source() != port || tcp.get_destination() != src_port {
                                    continue;
                                }

                                let flags = tcp.get_flags();

                                // SYN-ACK = port is open
                                if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                                    // Send RST to close connection cleanly
                                    let rst_packet = Self::build_rst_packet(
                                        source_ip,
                                        target_ipv4,
                                        src_port,
                                        port,
                                        tcp.get_acknowledgement(),
                                    )?;
                                    let _ = tx.send_to(&rst_packet, None);
                                    return Ok(PortState::Open);
                                }

                                // RST = port is closed
                                if flags & TcpFlags::RST != 0 {
                                    return Ok(PortState::Closed);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error receiving packet: {}", e);
                        break;
                    }
                }
            }
            Ok(PortState::Filtered)
        })
        .await
        {
            Ok(Ok(state)) => state,
            Ok(Err(e)) => return Err(e),
            Err(_) => PortState::Filtered, // Timeout
        };

        Ok(ScanResult {
            target,
            port,
            state,
            protocol: Protocol::TCP,
            service: None,
            service_info: None,
            hostname: None,
            reason: None,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Find a suitable network interface
    fn find_interface() -> Result<NetworkInterface> {
        let interfaces = datalink::interfaces();
        interfaces
            .into_iter()
            .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
            .ok_or_else(|| anyhow!("No suitable network interface found"))
    }

    /// Get source IP for the given target
    fn get_source_ip(interface: &NetworkInterface, _target: Ipv4Addr) -> Result<Ipv4Addr> {
        // Find first IPv4 address on the interface
        for ip_network in &interface.ips {
            if let IpAddr::V4(ipv4) = ip_network.ip() {
                return Ok(ipv4);
            }
        }
        Err(anyhow!("No IPv4 address found on interface"))
    }

    /// Build a complete IP + TCP SYN packet
    fn build_syn_packet(
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        source_port: u16,
        dest_port: u16,
        sequence: u32,
    ) -> Result<Vec<u8>> {
        // Total packet size: Ethernet(14) + IP(20) + TCP(20) = 54 bytes minimum
        // We'll skip Ethernet header as pnet adds it
        const IP_HEADER_LEN: usize = 20;
        const TCP_HEADER_LEN: usize = 20;
        const TOTAL_LEN: usize = IP_HEADER_LEN + TCP_HEADER_LEN;

        let mut buffer = vec![0u8; TOTAL_LEN];

        // Build IP header
        {
            let mut ip_packet = MutableIpv4Packet::new(&mut buffer[..IP_HEADER_LEN])
                .ok_or_else(|| anyhow!("Failed to create IP packet"))?;

            ip_packet.set_version(4);
            ip_packet.set_header_length(5); // 5 * 4 = 20 bytes
            ip_packet.set_total_length(TOTAL_LEN as u16);
            ip_packet.set_identification(rand::thread_rng().gen());
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_packet.set_source(source_ip);
            ip_packet.set_destination(dest_ip);

            // Calculate IP checksum
            let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(checksum);
        }

        // Build TCP header
        {
            let mut tcp_packet = MutableTcpPacket::new(&mut buffer[IP_HEADER_LEN..])
                .ok_or_else(|| anyhow!("Failed to create TCP packet"))?;

            tcp_packet.set_source(source_port);
            tcp_packet.set_destination(dest_port);
            tcp_packet.set_sequence(sequence);
            tcp_packet.set_acknowledgement(0);
            tcp_packet.set_data_offset(5); // 5 * 4 = 20 bytes
            tcp_packet.set_flags(TcpFlags::SYN);
            tcp_packet.set_window(64240);
            tcp_packet.set_urgent_ptr(0);

            // Calculate TCP checksum
            let checksum =
                pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &source_ip, &dest_ip);
            tcp_packet.set_checksum(checksum);
        }

        Ok(buffer)
    }

    /// Build RST packet to close connection
    fn build_rst_packet(
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        source_port: u16,
        dest_port: u16,
        ack_num: u32,
    ) -> Result<Vec<u8>> {
        const IP_HEADER_LEN: usize = 20;
        const TCP_HEADER_LEN: usize = 20;
        const TOTAL_LEN: usize = IP_HEADER_LEN + TCP_HEADER_LEN;

        let mut buffer = vec![0u8; TOTAL_LEN];

        // Build IP header
        {
            let mut ip_packet = MutableIpv4Packet::new(&mut buffer[..IP_HEADER_LEN])
                .ok_or_else(|| anyhow!("Failed to create IP packet"))?;

            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_total_length(TOTAL_LEN as u16);
            ip_packet.set_identification(rand::thread_rng().gen());
            ip_packet.set_ttl(64);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_packet.set_source(source_ip);
            ip_packet.set_destination(dest_ip);

            let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(checksum);
        }

        // Build TCP RST
        {
            let mut tcp_packet = MutableTcpPacket::new(&mut buffer[IP_HEADER_LEN..])
                .ok_or_else(|| anyhow!("Failed to create TCP packet"))?;

            tcp_packet.set_source(source_port);
            tcp_packet.set_destination(dest_port);
            tcp_packet.set_sequence(ack_num);
            tcp_packet.set_acknowledgement(0);
            tcp_packet.set_data_offset(5);
            tcp_packet.set_flags(TcpFlags::RST);
            tcp_packet.set_window(0);
            tcp_packet.set_urgent_ptr(0);

            let checksum =
                pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &source_ip, &dest_ip);
            tcp_packet.set_checksum(checksum);
        }

        Ok(buffer)
    }

    /// Perform a TCP connect scan
    pub async fn connect_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        let addr = SocketAddr::new(target, port);

        let state = match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => PortState::Open,
            Ok(Err(_)) => PortState::Closed,
            Err(_) => PortState::Filtered,
        };

        Ok(ScanResult {
            target,
            port,
            state,
            protocol: Protocol::TCP,
            service: None, // Service detection will be added in Phase 2
            service_info: None,
            hostname: None,
            reason: None,
            timestamp: chrono::Utc::now(),
        })
    }
}
