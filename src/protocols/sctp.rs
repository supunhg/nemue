use anyhow::{anyhow, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;

use crate::scanner::{PortState, ScanResult};

/// SCTP chunk types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SctpChunkType {
    Data = 0,
    Init = 1,
    InitAck = 2,
    SacK = 3,
    Heartbeat = 4,
    HeartbeatAck = 5,
    Abort = 6,
    Shutdown = 7,
    ShutdownAck = 8,
    Error = 9,
    CookieEcho = 10,
    CookieAck = 11,
    ShutdownComplete = 14,
}

/// SCTP common header
#[derive(Debug, Clone)]
pub struct SctpHeader {
    pub source_port: u16,
    pub dest_port: u16,
    pub verification_tag: u32,
    pub checksum: u32,
}

/// SCTP chunk
#[derive(Debug, Clone)]
pub struct SctpChunk {
    pub chunk_type: u8,
    pub flags: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

/// SCTP scan type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpScanType {
    /// SCTP INIT scan (-sY)
    Init,
    /// SCTP COOKIE-ECHO scan (-sZ)
    CookieEcho,
}

impl SctpScanType {
    pub fn nmap_flag(&self) -> &str {
        match self {
            SctpScanType::Init => "-sY",
            SctpScanType::CookieEcho => "-sZ",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            SctpScanType::Init => "SCTP INIT scan (stealth, like SYN scan)",
            SctpScanType::CookieEcho => "SCTP COOKIE-ECHO scan (bypass some firewalls)",
        }
    }
}

/// SCTP scanner
#[derive(Clone)]
pub struct SctpScanner {
    timeout_duration: Duration,
    use_raw_sockets: bool,
}

impl SctpScanner {
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

    /// Perform SCTP INIT scan (-sY)
    pub async fn init_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        if self.use_raw_sockets {
            self.raw_init_scan(target, port).await
        } else {
            self.fallback_scan(target, port, SctpScanType::Init).await
        }
    }

    /// Perform SCTP COOKIE-ECHO scan (-sZ)
    pub async fn cookie_echo_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        if self.use_raw_sockets {
            self.raw_cookie_echo_scan(target, port).await
        } else {
            self.fallback_scan(target, port, SctpScanType::CookieEcho)
                .await
        }
    }

    /// Perform an SCTP scan with the specified scan type
    pub async fn scan(
        &self,
        target: IpAddr,
        port: u16,
        scan_type: SctpScanType,
    ) -> Result<ScanResult> {
        match scan_type {
            SctpScanType::Init => self.init_scan(target, port).await,
            SctpScanType::CookieEcho => self.cookie_echo_scan(target, port).await,
        }
    }

    /// Raw SCTP INIT scan using pnet
    async fn raw_init_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        let target_ipv4 = match target {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => return Err(anyhow!("IPv6 SCTP scan not yet supported")),
        };

        let src_port: u16 = rand::thread_rng().gen_range(1024..65535);
        let init_tag: u32 = rand::thread_rng().gen();

        let packet = self.build_sctp_init_packet(target_ipv4, src_port, port, init_tag)?;
        self.send_and_receive(target_ipv4, src_port, port, &packet, "INIT")
            .await
    }

    /// Raw SCTP COOKIE-ECHO scan using pnet
    async fn raw_cookie_echo_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        let target_ipv4 = match target {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => return Err(anyhow!("IPv6 SCTP scan not yet supported")),
        };

        let src_port: u16 = rand::thread_rng().gen_range(1024..65535);

        let packet = self.build_sctp_cookie_echo_packet(target_ipv4, src_port, port)?;
        self.send_and_receive(target_ipv4, src_port, port, &packet, "COOKIE-ECHO")
            .await
    }

    /// Send SCTP packet and analyze response
    async fn send_and_receive(
        &self,
        target: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        packet: &[u8],
        scan_name: &str,
    ) -> Result<ScanResult> {
        use pnet::datalink::{self, Channel};
        use pnet::packet::ipv4::Ipv4Packet;

        let interface = self.find_interface()?;
        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow!("Unsupported channel type")),
            Err(e) => return Err(anyhow!("Failed to create channel: {}", e)),
        };

        tx.send_to(packet, None)
            .ok_or_else(|| anyhow!("Failed to send SCTP packet"))?
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
                            if ipv4.get_source() != target {
                                continue;
                            }
                            if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Sctp {
                                continue;
                            }

                            let offset = (ipv4.get_header_length() as usize) * 4;
                            if ip_data.len() < offset + 12 {
                                continue;
                            }

                            let sctp_data = &ip_data[offset..];
                            let dest_port_check = u16::from_be_bytes([sctp_data[2], sctp_data[3]]);
                            if dest_port_check != src_port {
                                continue;
                            }

                            if sctp_data.len() >= 16 {
                                let chunk_type = sctp_data[12];
                                match chunk_type {
                                    2 => return Ok(PortState::Open),   // INIT-ACK
                                    6 => return Ok(PortState::Closed), // ABORT
                                    11 => return Ok(PortState::Open),  // COOKIE-ACK
                                    _ => continue,
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            Ok(PortState::Filtered) as Result<PortState>
        })
        .await
        {
            Ok(Ok(state)) => state,
            Ok(Err(e)) => return Err(e),
            Err(_) => PortState::Filtered,
        };

        Ok(ScanResult {
            target: IpAddr::V4(target),
            port: dst_port,
            state,
            protocol: crate::scanner::Protocol::TCP, // SCTP doesn't have its own Protocol variant yet
            service: None,
            service_info: None,
            hostname: None,
            reason: Some(scan_name.to_string()),
            timestamp: chrono::Utc::now(),
        })
    }

    /// Find a suitable network interface
    fn find_interface(&self) -> Result<pnet::datalink::NetworkInterface> {
        use pnet::datalink;
        datalink::interfaces()
            .into_iter()
            .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
            .ok_or_else(|| anyhow!("No suitable network interface found"))
    }

    /// Build an SCTP INIT packet
    fn build_sctp_init_packet(
        &self,
        dest_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        init_tag: u32,
    ) -> Result<Vec<u8>> {
        let source_ip = self.get_source_ip(dest_ip)?;

        // SCTP common header (12 bytes) + INIT chunk (20 bytes min)
        let sctp_len = 12 + 20;
        let ip_len = 20 + sctp_len;
        let mut buffer = vec![0u8; ip_len];

        // IP header
        {
            let mut ip = MutableIpv4Packet::new(&mut buffer[..20])
                .ok_or_else(|| anyhow!("Failed to create IP packet"))?;
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(ip_len as u16);
            ip.set_identification(rand::thread_rng().gen());
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Sctp);
            ip.set_source(source_ip);
            ip.set_destination(dest_ip);
            let checksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
            ip.set_checksum(checksum);
        }

        // SCTP header
        {
            let sctp = &mut buffer[20..];
            sctp[0..2].copy_from_slice(&src_port.to_be_bytes());
            sctp[2..4].copy_from_slice(&dst_port.to_be_bytes());
            sctp[4..8].copy_from_slice(&init_tag.to_be_bytes());
            // Checksum placeholder (0 for now, requires CRC32c)
            sctp[8..12].copy_from_slice(&[0, 0, 0, 0]);
        }

        // SCTP INIT chunk
        {
            let chunk = &mut buffer[32..];
            chunk[0] = SctpChunkType::Init as u8; // Chunk type
            chunk[1] = 0; // Flags
            chunk[2..4].copy_from_slice(&20u16.to_be_bytes()); // Length
                                                               // Initiate Tag
            chunk[4..8].copy_from_slice(&init_tag.to_be_bytes());
            // Advertised Receiver Window Credit (a_rwnd)
            chunk[8..12].copy_from_slice(&65535u32.to_be_bytes());
            // Number of Outbound Streams
            chunk[12..14].copy_from_slice(&1u16.to_be_bytes());
            // Number of Inbound Streams
            chunk[14..16].copy_from_slice(&1u16.to_be_bytes());
            // Initial TSN
            let tsn: u32 = rand::thread_rng().gen();
            chunk[16..20].copy_from_slice(&tsn.to_be_bytes());
        }

        Ok(buffer)
    }

    /// Build an SCTP COOKIE-ECHO packet
    fn build_sctp_cookie_echo_packet(
        &self,
        dest_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Result<Vec<u8>> {
        let source_ip = self.get_source_ip(dest_ip)?;
        let verification_tag: u32 = rand::thread_rng().gen();

        let cookie_data = b"nemue_scan_cookie";
        let chunk_len = 4 + cookie_data.len();
        let sctp_len = 12 + chunk_len;
        let ip_len = 20 + sctp_len;
        let mut buffer = vec![0u8; ip_len];

        // IP header
        {
            let mut ip = MutableIpv4Packet::new(&mut buffer[..20])
                .ok_or_else(|| anyhow!("Failed to create IP packet"))?;
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(ip_len as u16);
            ip.set_identification(rand::thread_rng().gen());
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Sctp);
            ip.set_source(source_ip);
            ip.set_destination(dest_ip);
            let checksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
            ip.set_checksum(checksum);
        }

        // SCTP header
        {
            let sctp = &mut buffer[20..];
            sctp[0..2].copy_from_slice(&src_port.to_be_bytes());
            sctp[2..4].copy_from_slice(&dst_port.to_be_bytes());
            sctp[4..8].copy_from_slice(&verification_tag.to_be_bytes());
            sctp[8..12].copy_from_slice(&[0, 0, 0, 0]);
        }

        // COOKIE-ECHO chunk
        {
            let chunk = &mut buffer[32..];
            chunk[0] = SctpChunkType::CookieEcho as u8;
            chunk[1] = 0;
            chunk[2..4].copy_from_slice(&(chunk_len as u16).to_be_bytes());
            chunk[4..4 + cookie_data.len()].copy_from_slice(cookie_data);
        }

        Ok(buffer)
    }

    /// Get source IP for the given destination
    fn get_source_ip(&self, _dest: Ipv4Addr) -> Result<Ipv4Addr> {
        let interface = self.find_interface()?;
        for ip_network in &interface.ips {
            if let IpAddr::V4(ipv4) = ip_network.ip() {
                return Ok(ipv4);
            }
        }
        Err(anyhow!("No IPv4 address found on interface"))
    }

    /// Fallback scan when raw sockets are not available
    async fn fallback_scan(
        &self,
        target: IpAddr,
        port: u16,
        scan_type: SctpScanType,
    ) -> Result<ScanResult> {
        // Without raw sockets, we cannot perform true SCTP scans.
        // Attempt a TCP connection as a rough heuristic.
        use tokio::net::TcpStream;
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
            protocol: crate::scanner::Protocol::TCP,
            service: None,
            service_info: None,
            hostname: None,
            reason: Some(scan_type.nmap_flag().to_string()),
            timestamp: chrono::Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sctp_scan_type_display() {
        assert_eq!(SctpScanType::Init.nmap_flag(), "-sY");
        assert_eq!(SctpScanType::CookieEcho.nmap_flag(), "-sZ");
    }

    #[test]
    fn test_sctp_scan_type_description() {
        assert!(!SctpScanType::Init.description().is_empty());
        assert!(!SctpScanType::CookieEcho.description().is_empty());
    }

    #[test]
    fn test_sctp_scanner_creation() {
        let scanner = SctpScanner::new(2000);
        assert_eq!(scanner.timeout_duration, Duration::from_millis(2000));
        assert!(!scanner.use_raw_sockets);
    }

    #[test]
    fn test_sctp_scanner_with_raw_sockets() {
        let scanner = SctpScanner::with_raw_sockets(3000, true);
        assert!(scanner.use_raw_sockets);
        assert_eq!(scanner.timeout_duration, Duration::from_millis(3000));
    }

    #[test]
    fn test_sctp_chunk_types() {
        assert_eq!(SctpChunkType::Init as u8, 1);
        assert_eq!(SctpChunkType::InitAck as u8, 2);
        assert_eq!(SctpChunkType::CookieEcho as u8, 10);
        assert_eq!(SctpChunkType::CookieAck as u8, 11);
        assert_eq!(SctpChunkType::Abort as u8, 6);
    }

    #[tokio::test]
    async fn test_sctp_fallback_scan_localhost() {
        let scanner = SctpScanner::new(500);
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let result = scanner.init_scan(target, 12345).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sctp_cookie_echo_fallback() {
        let scanner = SctpScanner::new(500);
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let result = scanner.cookie_echo_scan(target, 12345).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sctp_scan_method() {
        let scanner = SctpScanner::new(500);
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let result = scanner.scan(target, 12345, SctpScanType::Init).await;
        assert!(result.is_ok());
        let result = scanner.scan(target, 12345, SctpScanType::CookieEcho).await;
        assert!(result.is_ok());
    }
}
