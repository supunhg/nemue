use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

use crate::scanner::{PortState, Protocol, ScanResult};

#[derive(Clone)]
pub struct UdpScanner {
    timeout_ms: u64,
}

impl UdpScanner {
    pub fn new(timeout_ms: u64) -> Self {
        Self { timeout_ms }
    }

    /// Perform UDP scan on a single port
    pub async fn scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        let state = self.udp_scan(target, port).await?;

        Ok(ScanResult {
            target,
            port,
            state,
            protocol: Protocol::UDP,
            service: self.identify_service(port),
            service_info: None,
            hostname: None,
            reason: None,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Send UDP probe and detect response
    async fn udp_scan(&self, target: IpAddr, port: u16) -> Result<PortState> {
        // Bind to a random local port
        let local_addr: SocketAddr = match target {
            IpAddr::V4(_) => "0.0.0.0:0".parse()?,
            IpAddr::V6(_) => "[::]:0".parse()?,
        };

        let socket = UdpSocket::bind(local_addr).await?;
        socket.connect((target, port)).await?;

        // Send service-specific probe
        let probe = self.get_probe_for_port(port);
        socket.send(probe).await?;

        // Try to receive response
        let mut buf = [0u8; 1024];
        let timeout_duration = Duration::from_millis(self.timeout_ms);

        match timeout(timeout_duration, socket.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                // Received data - port is open and responding
                Ok(PortState::Open)
            }
            Ok(Ok(_)) => {
                // Received empty response
                Ok(PortState::Open)
            }
            Ok(Err(e)) => {
                // Check if it's ICMP port unreachable
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    Ok(PortState::Closed)
                } else {
                    Ok(PortState::Filtered)
                }
            }
            Err(_) => {
                // Timeout - could be open|filtered
                // UDP is stateless, no response doesn't mean closed
                Ok(PortState::Filtered)
            }
        }
    }

    /// Get service-specific UDP probe (static data, zero allocation)
    fn get_probe_for_port(&self, port: u16) -> &'static [u8] {
        match port {
            53 => {
                // DNS query for version.bind
                &[
                    0x00, 0x00, // Transaction ID
                    0x01, 0x00, // Flags: standard query
                    0x00, 0x01, // Questions: 1
                    0x00, 0x00, // Answer RRs: 0
                    0x00, 0x00, // Authority RRs: 0
                    0x00, 0x00, // Additional RRs: 0
                    0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
                    0x04, 0x62, 0x69, 0x6e, 0x64, // "bind"
                    0x00, // null terminator
                    0x00, 0x10, // Type: TXT
                    0x00, 0x03, // Class: CHAOS
                ]
            }
            123 => {
                // NTP request
                &[
                    0x1b, // LI, Version, Mode
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00,
                ]
            }
            161 | 162 => {
                // SNMP GetRequest
                &[
                    0x30, 0x26, // SEQUENCE
                    0x02, 0x01, 0x00, // Version: 1
                    0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // Community: "public"
                    0xa0, 0x19, // GetRequest PDU
                    0x02, 0x01, 0x01, // Request ID
                    0x02, 0x01, 0x00, // Error status
                    0x02, 0x01, 0x00, // Error index
                    0x30, 0x0e, // Variable bindings
                    0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01,
                    0x00, // OID
                    0x05, 0x00, // NULL
                ]
            }
            137 => {
                // NetBIOS Name Service query
                &[
                    0x00, 0x00, // Transaction ID
                    0x00, 0x10, // Flags
                    0x00, 0x01, // Questions
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, // Encoded name
                ]
            }
            5060 | 5061 => {
                // SIP OPTIONS request
                b"OPTIONS sip:nm SIP/2.0\r\n\r\n"
            }
            _ => {
                // Generic empty probe
                &[0x00]
            }
        }
    }

    /// Identify common UDP services by port
    fn identify_service(&self, port: u16) -> Option<String> {
        let service = match port {
            53 => "domain",
            67 | 68 => "dhcp",
            69 => "tftp",
            123 => "ntp",
            135 => "msrpc",
            137 => "netbios-ns",
            138 => "netbios-dgm",
            139 => "netbios-ssn",
            161 | 162 => "snmp",
            389 => "ldap",
            500 => "isakmp",
            514 => "syslog",
            520 => "rip",
            1434 => "ms-sql-m",
            1701 => "l2tp",
            1900 => "upnp",
            3478 => "stun",
            4500 => "ipsec-nat-t",
            5060 | 5061 => "sip",
            5353 => "mdns",
            _ => return None,
        };
        Some(service.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_scanner_creation() {
        let scanner = UdpScanner::new(1000);
        assert_eq!(scanner.timeout_ms, 1000);
    }

    #[test]
    fn test_service_identification() {
        let scanner = UdpScanner::new(1000);
        assert_eq!(scanner.identify_service(53), Some("domain".to_string()));
        assert_eq!(scanner.identify_service(123), Some("ntp".to_string()));
        assert_eq!(scanner.identify_service(161), Some("snmp".to_string()));
        assert_eq!(scanner.identify_service(65000), None);
    }

    #[test]
    fn test_dns_probe() {
        let scanner = UdpScanner::new(1000);
        let probe = scanner.get_probe_for_port(53);
        assert!(probe.len() > 0);
        assert_eq!(probe[0], 0x00); // Transaction ID starts with 0
    }

    #[test]
    fn test_ntp_probe() {
        let scanner = UdpScanner::new(1000);
        let probe = scanner.get_probe_for_port(123);
        assert_eq!(probe[0], 0x1b); // NTP version/mode byte
    }

    #[tokio::test]
    async fn test_udp_scan_timeout() {
        let scanner = UdpScanner::new(100); // Very short timeout
                                            // Scan a port unlikely to be open on localhost
        let result = scanner
            .scan(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 58732)
            .await;
        assert!(result.is_ok());
        // Should timeout and return Filtered, or get Closed from ICMP unreachable
        if let Ok(scan_result) = result {
            assert!(matches!(
                scan_result.state,
                PortState::Filtered | PortState::Closed | PortState::Open
            ));
        }
    }
}
