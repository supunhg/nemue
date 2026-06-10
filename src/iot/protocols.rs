use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IoTProtocol {
    MQTT,
    MQTTS,
    CoAP,
    AMQP,
    AMQPS,
    DDS,
}

impl IoTProtocol {
    pub fn default_port(&self) -> u16 {
        match self {
            IoTProtocol::MQTT => 1883,
            IoTProtocol::MQTTS => 8883,
            IoTProtocol::CoAP => 5683,
            IoTProtocol::AMQP => 5672,
            IoTProtocol::AMQPS => 5671,
            IoTProtocol::DDS => 7400,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            IoTProtocol::MQTT => "MQTT",
            IoTProtocol::MQTTS => "MQTTS",
            IoTProtocol::CoAP => "CoAP",
            IoTProtocol::AMQP => "AMQP",
            IoTProtocol::AMQPS => "AMQPS",
            IoTProtocol::DDS => "DDS",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolSecurityFinding {
    NoAuthentication,
    AnonymousAccess,
    NoEncryption,
    WeakCredentials,
    ExposedTopics,
    NoAccessControl,
    UnpatchedBroker,
    ExcessivePermissions,
    NoTlsCertificate,
    DefaultConfig,
}

impl ProtocolSecurityFinding {
    pub fn severity(&self) -> &str {
        match self {
            ProtocolSecurityFinding::NoAuthentication => "CRITICAL",
            ProtocolSecurityFinding::AnonymousAccess => "CRITICAL",
            ProtocolSecurityFinding::NoEncryption => "HIGH",
            ProtocolSecurityFinding::WeakCredentials => "HIGH",
            ProtocolSecurityFinding::ExposedTopics => "MEDIUM",
            ProtocolSecurityFinding::NoAccessControl => "HIGH",
            ProtocolSecurityFinding::UnpatchedBroker => "HIGH",
            ProtocolSecurityFinding::ExcessivePermissions => "MEDIUM",
            ProtocolSecurityFinding::NoTlsCertificate => "HIGH",
            ProtocolSecurityFinding::DefaultConfig => "MEDIUM",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            ProtocolSecurityFinding::NoAuthentication => "Protocol accepts connections without authentication",
            ProtocolSecurityFinding::AnonymousAccess => "Anonymous access is enabled on the broker",
            ProtocolSecurityFinding::NoEncryption => "Communication is not encrypted",
            ProtocolSecurityFinding::WeakCredentials => "Broker uses weak or default credentials",
            ProtocolSecurityFinding::ExposedTopics => "Topics are exposed without access control",
            ProtocolSecurityFinding::NoAccessControl => "No topic-level access control configured",
            ProtocolSecurityFinding::UnpatchedBroker => "Broker may be running an outdated version",
            ProtocolSecurityFinding::ExcessivePermissions => "Clients have excessive publish/subscribe permissions",
            ProtocolSecurityFinding::NoTlsCertificate => "TLS certificate is not configured",
            ProtocolSecurityFinding::DefaultConfig => "Broker is using default configuration",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolScanResult {
    pub protocol: IoTProtocol,
    pub target: IpAddr,
    pub port: u16,
    pub is_detected: bool,
    pub version: Option<String>,
    pub broker_name: Option<String>,
    pub findings: Vec<ProtocolSecurityFinding>,
    pub scan_duration: Duration,
}

#[derive(Debug, Clone)]
pub struct IoTProtocolScanner {
    timeout_duration: Duration,
}

impl IoTProtocolScanner {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
        }
    }

    pub async fn scan_mqtt(&self, target: IpAddr, port: Option<u16>) -> Result<ProtocolScanResult> {
        let start = std::time::Instant::now();
        let port = port.unwrap_or(IoTProtocol::MQTT.default_port());
        let addr = SocketAddr::new(target, port);

        let stream = timeout(self.timeout_duration, TcpStream::connect(addr)).await;
        let is_detected = match stream {
            Ok(Ok(mut s)) => {
                let connect = self.build_mqtt_connect("nemue_scan", None, None);
                let _ = s.write_all(&connect).await;
                let mut buf = [0u8; 256];
                match timeout(self.timeout_duration, s.read(&mut buf)).await {
                    Ok(Ok(n)) if n >= 4 => {
                        // CONNACK: byte 0 = 0x20, byte 1 = remaining length, byte 3 = return code
                        buf[0] == 0x20 && buf[3] == 0x00
                    }
                    _ => false,
                }
            }
            _ => false,
        };

        let mut findings = Vec::new();
        if is_detected {
            // Test anonymous access
            let anon_result = self.test_mqtt_anonymous(target, port).await;
            if anon_result {
                findings.push(ProtocolSecurityFinding::AnonymousAccess);
                findings.push(ProtocolSecurityFinding::NoAuthentication);
            }
            findings.push(ProtocolSecurityFinding::NoEncryption);
        }

        Ok(ProtocolScanResult {
            protocol: IoTProtocol::MQTT,
            target,
            port,
            is_detected,
            version: None,
            broker_name: None,
            findings,
            scan_duration: start.elapsed(),
        })
    }

    pub async fn scan_coap(&self, target: IpAddr, port: Option<u16>) -> Result<ProtocolScanResult> {
        let start = std::time::Instant::now();
        let port = port.unwrap_or(IoTProtocol::CoAP.default_port());
        let addr = SocketAddr::new(target, port);

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let coap_ping = self.build_coap_ping();
        let _ = socket.send_to(&coap_ping, addr).await;

        let mut buf = [0u8; 1024];
        let is_detected = match timeout(self.timeout_duration, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                // CoAP response: version (2 bits), type (2 bits), token length (4 bits)
                n >= 4 && (buf[0] >> 6) == 1 // CoAP version 1
            }
            _ => false,
        };

        let mut findings = Vec::new();
        if is_detected {
            findings.push(ProtocolSecurityFinding::NoEncryption);
            findings.push(ProtocolSecurityFinding::NoAuthentication);
        }

        Ok(ProtocolScanResult {
            protocol: IoTProtocol::CoAP,
            target,
            port,
            is_detected,
            version: None,
            broker_name: None,
            findings,
            scan_duration: start.elapsed(),
        })
    }

    pub async fn scan_amqp(&self, target: IpAddr, port: Option<u16>) -> Result<ProtocolScanResult> {
        let start = std::time::Instant::now();
        let port = port.unwrap_or(IoTProtocol::AMQP.default_port());
        let addr = SocketAddr::new(target, port);

        let stream = timeout(self.timeout_duration, TcpStream::connect(addr)).await;
        let is_detected = match stream {
            Ok(Ok(mut s)) => {
                // AMQP protocol header
                let amqp_header: [u8; 8] = [b'A', b'M', b'Q', b'P', 0, 1, 0, 0];
                let _ = s.write_all(&amqp_header).await;
                let mut buf = [0u8; 256];
                match timeout(self.timeout_duration, s.read(&mut buf)).await {
                    Ok(Ok(n)) if n >= 8 => {
                        &buf[0..4] == b"AMQP"
                    }
                    _ => false,
                }
            }
            _ => false,
        };

        let mut findings = Vec::new();
        if is_detected {
            findings.push(ProtocolSecurityFinding::NoEncryption);
        }

        Ok(ProtocolScanResult {
            protocol: IoTProtocol::AMQP,
            target,
            port,
            is_detected,
            version: None,
            broker_name: None,
            findings,
            scan_duration: start.elapsed(),
        })
    }

    pub async fn scan_dds(&self, target: IpAddr, port: Option<u16>) -> Result<ProtocolScanResult> {
        let start = std::time::Instant::now();
        let port = port.unwrap_or(IoTProtocol::DDS.default_port());
        let addr = SocketAddr::new(target, port);

        // DDS uses RTPS protocol; send a discovery ping
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let rtps_header = self.build_rtps_ping();
        let _ = socket.send_to(&rtps_header, addr).await;

        let mut buf = [0u8; 1024];
        let is_detected = match timeout(self.timeout_duration, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                n >= 4 && &buf[0..4] == b"RTPS"
            }
            _ => false,
        };

        let mut findings = Vec::new();
        if is_detected {
            findings.push(ProtocolSecurityFinding::NoAuthentication);
            findings.push(ProtocolSecurityFinding::NoAccessControl);
        }

        Ok(ProtocolScanResult {
            protocol: IoTProtocol::DDS,
            target,
            port,
            is_detected,
            version: None,
            broker_name: None,
            findings,
            scan_duration: start.elapsed(),
        })
    }

    pub async fn scan_all(&self, target: IpAddr) -> Vec<ProtocolScanResult> {
        let mut results = Vec::new();

        if let Ok(r) = self.scan_mqtt(target, None).await {
            results.push(r);
        }
        if let Ok(r) = self.scan_coap(target, None).await {
            results.push(r);
        }
        if let Ok(r) = self.scan_amqp(target, None).await {
            results.push(r);
        }
        if let Ok(r) = self.scan_dds(target, None).await {
            results.push(r);
        }

        results
    }

    fn build_mqtt_connect(&self, client_id: &str, username: Option<&str>, password: Option<&str>) -> Vec<u8> {
        let protocol_name = b"MQTT";
        let protocol_level: u8 = 4; // MQTT 3.1.1
        let mut connect_flags: u8 = 0x02; // Clean session

        if username.is_some() {
            connect_flags |= 0x80;
        }
        if password.is_some() {
            connect_flags |= 0x40;
        }

        let keep_alive: u16 = 60;

        let client_id_bytes = client_id.as_bytes();
        let username_bytes = username.map(|u| u.as_bytes());
        let password_bytes = password.map(|p| p.as_bytes());

        let mut payload = Vec::new();
        // Client ID
        payload.extend_from_slice(&(client_id_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(client_id_bytes);

        if let Some(u) = username_bytes {
            payload.extend_from_slice(&(u.len() as u16).to_be_bytes());
            payload.extend_from_slice(u);
        }
        if let Some(p) = password_bytes {
            payload.extend_from_slice(&(p.len() as u16).to_be_bytes());
            payload.extend_from_slice(p);
        }

        let variable_header_len = 2 + protocol_name.len() + 1 + 1 + 2; // name len + name + level + flags + keepalive
        let remaining_length = variable_header_len + payload.len();

        let mut packet = Vec::new();
        packet.push(0x10); // CONNECT packet type
        // Remaining length (variable length encoding)
        let mut rl = remaining_length;
        while rl > 0x7F {
            packet.push((rl & 0x7F) as u8 | 0x80);
            rl >>= 7;
        }
        packet.push(rl as u8);

        // Variable header
        packet.extend_from_slice(&(protocol_name.len() as u16).to_be_bytes());
        packet.extend_from_slice(protocol_name);
        packet.push(protocol_level);
        packet.push(connect_flags);
        packet.extend_from_slice(&keep_alive.to_be_bytes());

        // Payload
        packet.extend_from_slice(&payload);

        packet
    }

    async fn test_mqtt_anonymous(&self, target: IpAddr, port: u16) -> bool {
        let addr = SocketAddr::new(target, port);
        let stream = match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return false,
        };

        let (mut reader, mut writer) = stream.into_split();
        let connect = self.build_mqtt_connect("nemue_anon_test", None, None);
        let _ = writer.write_all(&connect).await;

        let mut buf = [0u8; 256];
        match timeout(self.timeout_duration, reader.read(&mut buf)).await {
            Ok(Ok(n)) if n >= 4 => buf[0] == 0x20 && buf[3] == 0x00,
            _ => false,
        }
    }

    fn build_coap_ping(&self) -> Vec<u8> {
        // CoAP header: Version=1, Type=0 (CON), Token Length=0, Code=0.00 (Empty), Message ID=1
        vec![0x40, 0x00, 0x00, 0x01]
    }

    fn build_rtps_ping(&self) -> Vec<u8> {
        // RTPS header: "RTPS" magic + protocol version + vendor ID + ...
        let mut packet = Vec::with_capacity(20);
        packet.extend_from_slice(b"RTPS");
        packet.push(2); // Protocol version major
        packet.push(1); // Protocol version minor
        packet.push(0x01); // Vendor ID high
        packet.push(0x00); // Vendor ID low
        // Pad with zeros for a minimal discovery message
        packet.resize(20, 0);
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_default_port() {
        assert_eq!(IoTProtocol::MQTT.default_port(), 1883);
        assert_eq!(IoTProtocol::MQTTS.default_port(), 8883);
        assert_eq!(IoTProtocol::CoAP.default_port(), 5683);
        assert_eq!(IoTProtocol::AMQP.default_port(), 5672);
        assert_eq!(IoTProtocol::AMQPS.default_port(), 5671);
        assert_eq!(IoTProtocol::DDS.default_port(), 7400);
    }

    #[test]
    fn test_protocol_as_str() {
        assert_eq!(IoTProtocol::MQTT.as_str(), "MQTT");
        assert_eq!(IoTProtocol::CoAP.as_str(), "CoAP");
        assert_eq!(IoTProtocol::AMQP.as_str(), "AMQP");
        assert_eq!(IoTProtocol::DDS.as_str(), "DDS");
    }

    #[test]
    fn test_finding_severity() {
        assert_eq!(
            ProtocolSecurityFinding::NoAuthentication.severity(),
            "CRITICAL"
        );
        assert_eq!(
            ProtocolSecurityFinding::AnonymousAccess.severity(),
            "CRITICAL"
        );
        assert_eq!(
            ProtocolSecurityFinding::NoEncryption.severity(),
            "HIGH"
        );
        assert_eq!(
            ProtocolSecurityFinding::ExposedTopics.severity(),
            "MEDIUM"
        );
        assert_eq!(
            ProtocolSecurityFinding::DefaultConfig.severity(),
            "MEDIUM"
        );
    }

    #[test]
    fn test_finding_description() {
        assert!(!ProtocolSecurityFinding::NoAuthentication.description().is_empty());
        assert!(!ProtocolSecurityFinding::AnonymousAccess.description().is_empty());
        assert!(!ProtocolSecurityFinding::NoEncryption.description().is_empty());
    }

    #[test]
    fn test_scanner_creation() {
        let scanner = IoTProtocolScanner::new(3000);
        assert_eq!(scanner.timeout_duration, Duration::from_millis(3000));
    }

    #[test]
    fn test_build_mqtt_connect() {
        let scanner = IoTProtocolScanner::new(1000);
        let packet = scanner.build_mqtt_connect("test_client", None, None);
        // First byte should be CONNECT (0x10)
        assert_eq!(packet[0], 0x10);
        // Should contain "MQTT" protocol name
        let packet_str = String::from_utf8_lossy(&packet);
        assert!(packet_str.contains("MQTT"));
    }

    #[test]
    fn test_build_mqtt_connect_with_auth() {
        let scanner = IoTProtocolScanner::new(1000);
        let packet = scanner.build_mqtt_connect("test", Some("user"), Some("pass"));
        assert_eq!(packet[0], 0x10);
        // Verify packet contains MQTT protocol
        let packet_str = String::from_utf8_lossy(&packet);
        assert!(packet_str.contains("MQTT"));
        // Verify packet has reasonable length (client id + username + password)
        assert!(packet.len() > 20);
    }

    #[test]
    fn test_build_coap_ping() {
        let scanner = IoTProtocolScanner::new(1000);
        let packet = scanner.build_coap_ping();
        assert_eq!(packet.len(), 4);
        // Version = 1 (bits 7-6)
        assert_eq!(packet[0] >> 6, 1);
        // Type = CON (0), so bits 5-4 = 0
        assert_eq!((packet[0] >> 4) & 0x03, 0);
    }

    #[test]
    fn test_build_rtps_ping() {
        let scanner = IoTProtocolScanner::new(1000);
        let packet = scanner.build_rtps_ping();
        assert_eq!(&packet[0..4], b"RTPS");
        assert_eq!(packet[4], 2); // Major version
        assert_eq!(packet[5], 1); // Minor version
    }

    #[test]
    fn test_protocol_serialization() {
        let protocol = IoTProtocol::MQTT;
        let json = serde_json::to_string(&protocol).unwrap();
        assert!(json.contains("MQTT"));
    }

    #[test]
    fn test_scan_result_serialization() {
        let result = ProtocolScanResult {
            protocol: IoTProtocol::MQTT,
            target: IpAddr::V4([192, 168, 1, 1].into()),
            port: 1883,
            is_detected: true,
            version: Some("3.1.1".to_string()),
            broker_name: Some("Mosquitto".to_string()),
            findings: vec![ProtocolSecurityFinding::NoAuthentication],
            scan_duration: Duration::from_millis(100),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("MQTT"));
        assert!(json.contains("1883"));
    }

    #[tokio::test]
    async fn test_scan_mqtt_on_closed_port() {
        let scanner = IoTProtocolScanner::new(200);
        let result = scanner
            .scan_mqtt(IpAddr::V4([127, 0, 0, 1].into()), Some(1))
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap().is_detected);
    }

    #[tokio::test]
    async fn test_scan_coap_on_closed_port() {
        let scanner = IoTProtocolScanner::new(200);
        let result = scanner
            .scan_coap(IpAddr::V4([127, 0, 0, 1].into()), Some(1))
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap().is_detected);
    }

    #[tokio::test]
    async fn test_scan_amqp_on_closed_port() {
        let scanner = IoTProtocolScanner::new(200);
        let result = scanner
            .scan_amqp(IpAddr::V4([127, 0, 0, 1].into()), Some(1))
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap().is_detected);
    }

    #[tokio::test]
    async fn test_scan_dds_on_closed_port() {
        let scanner = IoTProtocolScanner::new(200);
        let result = scanner
            .scan_dds(IpAddr::V4([127, 0, 0, 1].into()), Some(1))
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap().is_detected);
    }
}
