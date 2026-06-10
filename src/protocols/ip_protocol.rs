use anyhow::{anyhow, Result};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::time::timeout;

use crate::scanner::ScanResult;

/// IP protocols that can be probed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp,
    Igmp,
    Tcp,
    Udp,
    Rdp,
    Gre,
    Esp,
    Ah,
    Icmpv6,
    Sctp,
    Ospf,
    Other(u8),
}

impl IpProtocol {
    pub fn number(&self) -> u8 {
        match self {
            IpProtocol::Icmp => 1,
            IpProtocol::Igmp => 2,
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::Rdp => 27,
            IpProtocol::Gre => 47,
            IpProtocol::Esp => 50,
            IpProtocol::Ah => 51,
            IpProtocol::Icmpv6 => 58,
            IpProtocol::Sctp => 132,
            IpProtocol::Ospf => 89,
            IpProtocol::Other(n) => *n,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            IpProtocol::Icmp => "icmp",
            IpProtocol::Igmp => "igmp",
            IpProtocol::Tcp => "tcp",
            IpProtocol::Udp => "udp",
            IpProtocol::Rdp => "rdp",
            IpProtocol::Gre => "gre",
            IpProtocol::Esp => "esp",
            IpProtocol::Ah => "ah",
            IpProtocol::Icmpv6 => "icmpv6",
            IpProtocol::Sctp => "sctp",
            IpProtocol::Ospf => "ospf",
            IpProtocol::Other(_) => "unknown",
        }
    }

    pub fn from_number(n: u8) -> Self {
        match n {
            1 => IpProtocol::Icmp,
            2 => IpProtocol::Igmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            27 => IpProtocol::Rdp,
            47 => IpProtocol::Gre,
            50 => IpProtocol::Esp,
            51 => IpProtocol::Ah,
            58 => IpProtocol::Icmpv6,
            89 => IpProtocol::Ospf,
            132 => IpProtocol::Sctp,
            _ => IpProtocol::Other(n),
        }
    }
}

impl std::fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.name(), self.number())
    }
}

/// State of an IP protocol on the target
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolState {
    /// Target responded (protocol is supported)
    Open,
    /// Target sent ICMP protocol unreachable
    Closed,
    /// No response received
    Filtered,
}

impl std::fmt::Display for ProtocolState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolState::Open => write!(f, "open"),
            ProtocolState::Closed => write!(f, "closed"),
            ProtocolState::Filtered => write!(f, "filtered"),
        }
    }
}

/// Result of probing a single IP protocol
#[derive(Debug, Clone)]
pub struct ProtocolProbeResult {
    pub protocol: IpProtocol,
    pub state: ProtocolState,
    pub response_info: Option<String>,
}

impl std::fmt::Display for ProtocolProbeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.protocol, self.state)
    }
}

/// IP Protocol scanner (-sO)
pub struct IpProtocolScanner {
    timeout_duration: Duration,
    use_raw_sockets: bool,
}

impl IpProtocolScanner {
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

    /// Get the list of default protocols to probe
    pub fn default_protocols() -> Vec<IpProtocol> {
        vec![
            IpProtocol::Icmp,
            IpProtocol::Igmp,
            IpProtocol::Tcp,
            IpProtocol::Udp,
            IpProtocol::Gre,
            IpProtocol::Esp,
            IpProtocol::Ah,
            IpProtocol::Sctp,
            IpProtocol::Ospf,
            IpProtocol::Rdp,
        ]
    }

    /// Probe a single IP protocol on the target
    pub async fn probe_protocol(
        &self,
        target: IpAddr,
        protocol: IpProtocol,
    ) -> Result<ProtocolProbeResult> {
        if self.use_raw_sockets {
            self.raw_probe(target, protocol).await
        } else {
            self.fallback_probe(target, protocol).await
        }
    }

    /// Probe all default IP protocols on the target
    pub async fn scan_all(&self, target: IpAddr) -> Result<Vec<ProtocolProbeResult>> {
        let protocols = Self::default_protocols();
        let mut results = Vec::with_capacity(protocols.len());

        for protocol in protocols {
            match self.probe_protocol(target, protocol).await {
                Ok(result) => results.push(result),
                Err(_) => results.push(ProtocolProbeResult {
                    protocol,
                    state: ProtocolState::Filtered,
                    response_info: None,
                }),
            }
        }

        Ok(results)
    }

    /// Probe specific IP protocols
    pub async fn scan_protocols(
        &self,
        target: IpAddr,
        protocols: &[IpProtocol],
    ) -> Result<Vec<ProtocolProbeResult>> {
        let mut results = Vec::with_capacity(protocols.len());

        for &protocol in protocols {
            match self.probe_protocol(target, protocol).await {
                Ok(result) => results.push(result),
                Err(_) => results.push(ProtocolProbeResult {
                    protocol,
                    state: ProtocolState::Filtered,
                    response_info: None,
                }),
            }
        }

        Ok(results)
    }

    /// Raw IP protocol probe using pnet
    async fn raw_probe(&self, target: IpAddr, protocol: IpProtocol) -> Result<ProtocolProbeResult> {
        let target_ipv4 = match target {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => return Err(anyhow!("IPv6 IP protocol scan not yet supported")),
        };

        let source_ip = self.get_source_ip()?;
        let packet = self.build_probe_packet(source_ip, target_ipv4, protocol)?;

        use pnet::datalink::{self, Channel};
        let interface = self.find_interface()?;
        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow!("Unsupported channel type")),
            Err(e) => return Err(anyhow!("Failed to create channel: {}", e)),
        };

        tx.send_to(&packet, None)
            .ok_or_else(|| anyhow!("Failed to send probe"))?
            .map_err(|e| anyhow!("Send error: {}", e))?;

        let state = match timeout(self.timeout_duration, async {
            loop {
                match rx.next() {
                    Ok(frame) => {
                        if frame.len() < 14 {
                            continue;
                        }
                        let ip_data = &frame[14..];
                        if let Some(ipv4) = Ipv4Packet::new(ip_data) {
                            if ipv4.get_source() != target_ipv4 {
                                continue;
                            }

                            let proto_num = ipv4.get_next_level_protocol().0;

                            // ICMP protocol unreachable (type 3, code 2)
                            if proto_num == 1 {
                                let offset = (ipv4.get_header_length() as usize) * 4;
                                if ip_data.len() > offset + 2 {
                                    let icmp_type = ip_data[offset];
                                    let icmp_code = ip_data[offset + 1];
                                    if icmp_type == 3 && icmp_code == 2 {
                                        return Ok(ProtocolState::Closed);
                                    }
                                }
                            }

                            // Response from the same protocol = open
                            if proto_num == protocol.number() {
                                return Ok(ProtocolState::Open);
                            }

                            // Any response from the target is interesting
                            return Ok(ProtocolState::Open);
                        }
                    }
                    Err(_) => break,
                }
            }
            Ok(ProtocolState::Filtered) as Result<ProtocolState>
        })
        .await
        {
            Ok(Ok(state)) => state,
            Ok(Err(e)) => return Err(e),
            Err(_) => ProtocolState::Filtered,
        };

        Ok(ProtocolProbeResult {
            protocol,
            state,
            response_info: None,
        })
    }

    /// Build a minimal IP packet with the specified protocol
    fn build_probe_packet(
        &self,
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        protocol: IpProtocol,
    ) -> Result<Vec<u8>> {
        let header_len = 20;
        let mut buffer = vec![0u8; header_len];

        {
            let mut ip = MutableIpv4Packet::new(&mut buffer)
                .ok_or_else(|| anyhow!("Failed to create IP packet"))?;
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(header_len as u16);
            ip.set_identification(rand::thread_rng().gen());
            ip.set_ttl(64);
            ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocol(protocol.number()));
            ip.set_source(source_ip);
            ip.set_destination(dest_ip);
            let checksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
            ip.set_checksum(checksum);
        }

        Ok(buffer)
    }

    /// Find a suitable network interface
    fn find_interface(&self) -> Result<pnet::datalink::NetworkInterface> {
        use pnet::datalink;
        datalink::interfaces()
            .into_iter()
            .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
            .ok_or_else(|| anyhow!("No suitable network interface found"))
    }

    /// Get source IP
    fn get_source_ip(&self) -> Result<Ipv4Addr> {
        let interface = self.find_interface()?;
        for ip_network in &interface.ips {
            if let IpAddr::V4(ipv4) = ip_network.ip() {
                return Ok(ipv4);
            }
        }
        Err(anyhow!("No IPv4 address found on interface"))
    }

    /// Fallback probe when raw sockets are not available
    async fn fallback_probe(
        &self,
        target: IpAddr,
        protocol: IpProtocol,
    ) -> Result<ProtocolProbeResult> {
        // Without raw sockets, we can only test TCP and UDP
        let state = match protocol {
            IpProtocol::Tcp => {
                use tokio::net::TcpStream;
                let addr = std::net::SocketAddr::new(target, 80);
                match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
                    Ok(Ok(_)) => ProtocolState::Open,
                    Ok(Err(_)) => ProtocolState::Closed,
                    Err(_) => ProtocolState::Filtered,
                }
            }
            IpProtocol::Udp => {
                use tokio::net::UdpSocket;
                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                let probe = vec![0u8; 4];
                match socket.send_to(&probe, (target, 33434)).await {
                    Ok(_) => ProtocolState::Open,
                    Err(_) => ProtocolState::Filtered,
                }
            }
            _ => {
                // Cannot probe other protocols without raw sockets
                ProtocolState::Filtered
            }
        };

        Ok(ProtocolProbeResult {
            protocol,
            state,
            response_info: if !self.use_raw_sockets
                && !matches!(protocol, IpProtocol::Tcp | IpProtocol::Udp)
            {
                Some("Requires raw sockets (-eR)".to_string())
            } else {
                None
            },
        })
    }
}

/// Convert protocol probe results to ScanResult format for integration
pub fn probe_to_scan_result(target: IpAddr, probe: &ProtocolProbeResult) -> ScanResult {
    use crate::scanner::{PortState, Protocol};

    let port_state = match probe.state {
        ProtocolState::Open => PortState::Open,
        ProtocolState::Closed => PortState::Closed,
        ProtocolState::Filtered => PortState::Filtered,
    };

    ScanResult {
        target,
        port: 0, // IP protocol scan doesn't use ports
        state: port_state,
        protocol: Protocol::TCP, // Placeholder; SCTP protocol variant not yet in enum
        service: Some(probe.protocol.name().to_string()),
        service_info: None,
        hostname: None,
        reason: Some(format!("ip-proto-{}", probe.protocol.number())),
        timestamp: chrono::Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::PortState;

    #[test]
    fn test_ip_protocol_number() {
        assert_eq!(IpProtocol::Icmp.number(), 1);
        assert_eq!(IpProtocol::Tcp.number(), 6);
        assert_eq!(IpProtocol::Udp.number(), 17);
        assert_eq!(IpProtocol::Gre.number(), 47);
        assert_eq!(IpProtocol::Esp.number(), 50);
        assert_eq!(IpProtocol::Sctp.number(), 132);
        assert_eq!(IpProtocol::Other(99).number(), 99);
    }

    #[test]
    fn test_ip_protocol_name() {
        assert_eq!(IpProtocol::Icmp.name(), "icmp");
        assert_eq!(IpProtocol::Tcp.name(), "tcp");
        assert_eq!(IpProtocol::Gre.name(), "gre");
        assert_eq!(IpProtocol::Sctp.name(), "sctp");
    }

    #[test]
    fn test_ip_protocol_from_number() {
        assert_eq!(IpProtocol::from_number(1), IpProtocol::Icmp);
        assert_eq!(IpProtocol::from_number(6), IpProtocol::Tcp);
        assert_eq!(IpProtocol::from_number(47), IpProtocol::Gre);
        assert_eq!(IpProtocol::from_number(200), IpProtocol::Other(200));
    }

    #[test]
    fn test_ip_protocol_display() {
        assert_eq!(IpProtocol::Tcp.to_string(), "tcp(6)");
        assert_eq!(IpProtocol::Gre.to_string(), "gre(47)");
    }

    #[test]
    fn test_protocol_state_display() {
        assert_eq!(ProtocolState::Open.to_string(), "open");
        assert_eq!(ProtocolState::Closed.to_string(), "closed");
        assert_eq!(ProtocolState::Filtered.to_string(), "filtered");
    }

    #[test]
    fn test_default_protocols() {
        let protocols = IpProtocolScanner::default_protocols();
        assert!(protocols.len() >= 10);
        assert!(protocols.contains(&IpProtocol::Tcp));
        assert!(protocols.contains(&IpProtocol::Udp));
        assert!(protocols.contains(&IpProtocol::Icmp));
        assert!(protocols.contains(&IpProtocol::Gre));
        assert!(protocols.contains(&IpProtocol::Sctp));
    }

    #[test]
    fn test_scanner_creation() {
        let scanner = IpProtocolScanner::new(2000);
        assert_eq!(scanner.timeout_duration, Duration::from_millis(2000));
        assert!(!scanner.use_raw_sockets);
    }

    #[test]
    fn test_probe_to_scan_result() {
        let probe = ProtocolProbeResult {
            protocol: IpProtocol::Tcp,
            state: ProtocolState::Open,
            response_info: None,
        };
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let result = probe_to_scan_result(target, &probe);
        assert_eq!(result.state, PortState::Open);
        assert_eq!(result.service, Some("tcp".to_string()));
    }

    #[tokio::test]
    async fn test_fallback_probe_tcp() {
        let scanner = IpProtocolScanner::new(500);
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let result = scanner.probe_protocol(target, IpProtocol::Tcp).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fallback_probe_unsupported() {
        let scanner = IpProtocolScanner::new(500);
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let result = scanner.probe_protocol(target, IpProtocol::Gre).await;
        assert!(result.is_ok());
        let probe = result.unwrap();
        assert_eq!(probe.state, ProtocolState::Filtered);
        assert!(probe.response_info.is_some());
    }
}
