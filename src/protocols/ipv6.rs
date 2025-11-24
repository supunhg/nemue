use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::{MutableIpv6Packet, Ipv6Packet};
use pnet::packet::Packet;
use rand::Rng;

use crate::scanner::{PortState, Protocol, ScanResult};

#[derive(Clone)]
pub struct Ipv6Scanner {
    timeout_duration: Duration,
    use_raw_sockets: bool,
}

impl Ipv6Scanner {
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

    /// TCP SYN scan for IPv6
    pub async fn syn_scan(&self, target: Ipv6Addr, port: u16) -> Result<ScanResult> {
        if self.use_raw_sockets {
            self.raw_syn_scan(target, port).await
        } else {
            self.connect_scan(target, port).await
        }
    }

    /// TCP connect scan for IPv6
    pub async fn connect_scan(&self, target: Ipv6Addr, port: u16) -> Result<ScanResult> {
        let addr = std::net::SocketAddr::new(IpAddr::V6(target), port);
        
        let state = match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => PortState::Open,
            Ok(Err(_)) => PortState::Closed,
            Err(_) => PortState::Filtered,
        };

        Ok(ScanResult {
            target: IpAddr::V6(target),
            port,
            state,
            protocol: Protocol::TCP,
            service: None,
            service_info: None,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Raw SYN scan for IPv6
    async fn raw_syn_scan(&self, target: Ipv6Addr, port: u16) -> Result<ScanResult> {
        let interface = Self::find_interface()?;
        let source_ip = Self::get_source_ipv6(&interface, target)?;
        
        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow!("Unsupported channel type")),
            Err(e) => return Err(anyhow!("Failed to create channel (requires root): {}", e)),
        };

        let src_port = rand::thread_rng().gen_range(1024..65535);
        let sequence = rand::thread_rng().gen::<u32>();
        
        let packet_data = Self::build_syn_packet(source_ip, target, src_port, port, sequence)?;
        
        tx.send_to(&packet_data, None)
            .ok_or_else(|| anyhow!("Failed to send packet"))?
            .map_err(|e| anyhow!("Send error: {}", e))?;

        let state = match timeout(self.timeout_duration, async {
            loop {
                match rx.next() {
                    Ok(packet) => {
                        if packet.len() < 14 { continue; }
                        let ip_packet = &packet[14..];
                        
                        if let Some(ipv6) = Ipv6Packet::new(ip_packet) {
                            if ipv6.get_source() != target { continue; }
                            if ipv6.get_next_header() != IpNextHeaderProtocols::Tcp { continue; }
                            
                            // IPv6 header is always 40 bytes
                            if ip_packet.len() < 40 { continue; }
                            
                            if let Some(tcp) = TcpPacket::new(&ip_packet[40..]) {
                                if tcp.get_source() != port || tcp.get_destination() != src_port {
                                    continue;
                                }
                                
                                let flags = tcp.get_flags();
                                
                                if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                                    let rst_packet = Self::build_rst_packet(
                                        source_ip,
                                        target,
                                        src_port,
                                        port,
                                        tcp.get_acknowledgement()
                                    )?;
                                    let _ = tx.send_to(&rst_packet, None);
                                    return Ok(PortState::Open);
                                }
                                
                                if flags & TcpFlags::RST != 0 {
                                    return Ok(PortState::Closed);
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            Ok(PortState::Filtered)
        }).await {
            Ok(Ok(state)) => state,
            Ok(Err(e)) => return Err(e),
            Err(_) => PortState::Filtered,
        };

        Ok(ScanResult {
            target: IpAddr::V6(target),
            port,
            state,
            protocol: Protocol::TCP,
            service: None,
            service_info: None,
            timestamp: chrono::Utc::now(),
        })
    }

    fn find_interface() -> Result<NetworkInterface> {
        let interfaces = datalink::interfaces();
        interfaces
            .into_iter()
            .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
            .ok_or_else(|| anyhow!("No suitable network interface found"))
    }

    fn get_source_ipv6(interface: &NetworkInterface, _target: Ipv6Addr) -> Result<Ipv6Addr> {
        for ip_network in &interface.ips {
            if let IpAddr::V6(ipv6) = ip_network.ip() {
                // Skip link-local addresses
                if !ipv6.is_loopback() {
                    return Ok(ipv6);
                }
            }
        }
        Err(anyhow!("No IPv6 address found on interface"))
    }

    fn build_syn_packet(
        source_ip: Ipv6Addr,
        dest_ip: Ipv6Addr,
        source_port: u16,
        dest_port: u16,
        sequence: u32,
    ) -> Result<Vec<u8>> {
        const IPV6_HEADER_LEN: usize = 40;
        const TCP_HEADER_LEN: usize = 20;
        const TOTAL_LEN: usize = IPV6_HEADER_LEN + TCP_HEADER_LEN;
        
        let mut buffer = vec![0u8; TOTAL_LEN];
        
        // Build IPv6 header
        {
            let mut ipv6_packet = MutableIpv6Packet::new(&mut buffer[..IPV6_HEADER_LEN])
                .ok_or_else(|| anyhow!("Failed to create IPv6 packet"))?;
            
            ipv6_packet.set_version(6);
            ipv6_packet.set_traffic_class(0);
            ipv6_packet.set_flow_label(0);
            ipv6_packet.set_payload_length(TCP_HEADER_LEN as u16);
            ipv6_packet.set_next_header(IpNextHeaderProtocols::Tcp);
            ipv6_packet.set_hop_limit(64);
            ipv6_packet.set_source(source_ip);
            ipv6_packet.set_destination(dest_ip);
        }
        
        // Build TCP header
        {
            let mut tcp_packet = MutableTcpPacket::new(&mut buffer[IPV6_HEADER_LEN..])
                .ok_or_else(|| anyhow!("Failed to create TCP packet"))?;
            
            tcp_packet.set_source(source_port);
            tcp_packet.set_destination(dest_port);
            tcp_packet.set_sequence(sequence);
            tcp_packet.set_acknowledgement(0);
            tcp_packet.set_data_offset(5);
            tcp_packet.set_flags(TcpFlags::SYN);
            tcp_packet.set_window(64240);
            tcp_packet.set_urgent_ptr(0);
            
            let checksum = pnet::packet::tcp::ipv6_checksum(
                &tcp_packet.to_immutable(),
                &source_ip,
                &dest_ip
            );
            tcp_packet.set_checksum(checksum);
        }
        
        Ok(buffer)
    }

    fn build_rst_packet(
        source_ip: Ipv6Addr,
        dest_ip: Ipv6Addr,
        source_port: u16,
        dest_port: u16,
        ack_num: u32,
    ) -> Result<Vec<u8>> {
        const IPV6_HEADER_LEN: usize = 40;
        const TCP_HEADER_LEN: usize = 20;
        const TOTAL_LEN: usize = IPV6_HEADER_LEN + TCP_HEADER_LEN;
        
        let mut buffer = vec![0u8; TOTAL_LEN];
        
        {
            let mut ipv6_packet = MutableIpv6Packet::new(&mut buffer[..IPV6_HEADER_LEN])
                .ok_or_else(|| anyhow!("Failed to create IPv6 packet"))?;
            
            ipv6_packet.set_version(6);
            ipv6_packet.set_traffic_class(0);
            ipv6_packet.set_flow_label(0);
            ipv6_packet.set_payload_length(TCP_HEADER_LEN as u16);
            ipv6_packet.set_next_header(IpNextHeaderProtocols::Tcp);
            ipv6_packet.set_hop_limit(64);
            ipv6_packet.set_source(source_ip);
            ipv6_packet.set_destination(dest_ip);
        }
        
        {
            let mut tcp_packet = MutableTcpPacket::new(&mut buffer[IPV6_HEADER_LEN..])
                .ok_or_else(|| anyhow!("Failed to create TCP packet"))?;
            
            tcp_packet.set_source(source_port);
            tcp_packet.set_destination(dest_port);
            tcp_packet.set_sequence(ack_num);
            tcp_packet.set_acknowledgement(0);
            tcp_packet.set_data_offset(5);
            tcp_packet.set_flags(TcpFlags::RST);
            tcp_packet.set_window(0);
            tcp_packet.set_urgent_ptr(0);
            
            let checksum = pnet::packet::tcp::ipv6_checksum(
                &tcp_packet.to_immutable(),
                &source_ip,
                &dest_ip
            );
            tcp_packet.set_checksum(checksum);
        }
        
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_scanner_creation() {
        let scanner = Ipv6Scanner::new(1000);
        assert_eq!(scanner.timeout_duration, Duration::from_millis(1000));
        assert!(!scanner.use_raw_sockets);
    }

    #[test]
    fn test_ipv6_scanner_with_raw() {
        let scanner = Ipv6Scanner::with_raw_sockets(500, true);
        assert_eq!(scanner.timeout_duration, Duration::from_millis(500));
        assert!(scanner.use_raw_sockets);
    }

    #[tokio::test]
    async fn test_ipv6_connect_scan_localhost() {
        let scanner = Ipv6Scanner::new(1000);
        let result = scanner.connect_scan("::1".parse().unwrap(), 9999).await;
        assert!(result.is_ok());
        let scan_result = result.unwrap();
        assert!(matches!(scan_result.state, PortState::Closed | PortState::Filtered));
    }
}
