/// Protocol-specific parsers for service detection
///
/// This module contains parsers for SMB, RDP, database protocols, and other
/// application-layer protocols to extract detailed version and configuration information.
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// SMB (Server Message Block) parser for Windows file sharing
pub struct SmbParser {
    timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct SmbInfo {
    pub version: String,
    pub dialect: Option<String>,
    pub os_version: Option<String>,
    pub domain: Option<String>,
    pub workgroup: Option<String>,
    pub signing_required: bool,
    pub shares: Vec<String>,
}

impl SmbParser {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Detect SMB version and capabilities
    pub async fn detect(&self, target: IpAddr, port: u16) -> Result<SmbInfo> {
        let addr = SocketAddr::new(target, port);
        let mut stream = timeout(self.timeout, TcpStream::connect(addr)).await??;

        // Send SMB negotiate request
        let negotiate = self.build_negotiate_request();
        stream.write_all(&negotiate).await?;

        // Read response
        let mut buffer = vec![0u8; 4096];
        let n = timeout(self.timeout, stream.read(&mut buffer)).await??;

        if n < 4 {
            return Err(anyhow!("Invalid SMB response"));
        }

        self.parse_negotiate_response(&buffer[..n])
    }

    fn build_negotiate_request(&self) -> Vec<u8> {
        // SMB1 Negotiate Protocol Request
        let mut packet = vec![
            0x00, 0x00, 0x00, 0x85, // NetBIOS Session Service header
            0xff, 0x53, 0x4d, 0x42, // SMB header "\xffSMB"
            0x72, // Negotiate Protocol
            0x00, 0x00, 0x00, 0x00, // Status
            0x18, 0x53, 0xc8, 0x00, // Flags
            0x00, 0x00, // Flags2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Process ID
            0x00, 0x00, // Signature
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00, // Tree ID
            0xff, 0xfe, // User ID
            0x00, 0x00, // Multiplex ID
        ];

        // Dialect strings (SMB1, SMB2, SMB3)
        let dialects: Vec<&[u8]> = vec![
            b"\x02PC NETWORK PROGRAM 1.0\x00",
            b"\x02LANMAN1.0\x00",
            b"\x02Windows for Workgroups 3.1a\x00",
            b"\x02LM1.2X002\x00",
            b"\x02LANMAN2.1\x00",
            b"\x02NT LM 0.12\x00",
            b"\x02SMB 2.002\x00",
            b"\x02SMB 2.???\x00",
        ];

        for dialect in dialects {
            packet.extend_from_slice(dialect);
        }

        packet
    }

    fn parse_negotiate_response(&self, data: &[u8]) -> Result<SmbInfo> {
        if data.len() < 36 {
            return Err(anyhow!("Response too short"));
        }

        // Check for SMB signature
        if &data[4..8] != b"\xffSMB" && &data[4..8] != b"\xfeSMB" {
            return Err(anyhow!("Not an SMB response"));
        }

        let is_smb2 = &data[4..8] == b"\xfeSMB";
        let version = if is_smb2 { "SMB2/3" } else { "SMB1" };

        let mut info = SmbInfo {
            version: version.to_string(),
            dialect: None,
            os_version: None,
            domain: None,
            workgroup: None,
            signing_required: false,
            shares: Vec::new(),
        };

        if !is_smb2 {
            // Parse SMB1 response
            if data.len() > 43 {
                let dialect_index = u16::from_le_bytes([data[37], data[38]]);
                info.dialect = Some(format!("Dialect index: {}", dialect_index));

                // Check security mode
                if data.len() > 39 {
                    let security_mode = data[39];
                    info.signing_required = (security_mode & 0x08) != 0;
                }
            }
        } else {
            // Parse SMB2 response
            if data.len() > 70 {
                let dialect_revision = u16::from_le_bytes([data[36], data[37]]);
                info.dialect = Some(match dialect_revision {
                    0x0202 => "SMB 2.0.2".to_string(),
                    0x0210 => "SMB 2.1".to_string(),
                    0x0300 => "SMB 3.0".to_string(),
                    0x0302 => "SMB 3.0.2".to_string(),
                    0x0311 => "SMB 3.1.1".to_string(),
                    _ => format!("SMB 2/3 (0x{:04x})", dialect_revision),
                });

                // Check security mode
                if data.len() > 38 {
                    let security_mode = data[38];
                    info.signing_required = (security_mode & 0x02) != 0;
                }
            }
        }

        Ok(info)
    }
}

/// RDP (Remote Desktop Protocol) parser
pub struct RdpParser {
    timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct RdpInfo {
    pub version: String,
    pub encryption_level: String,
    pub encryption_methods: Vec<String>,
    pub nla_supported: bool,
    pub tls_supported: bool,
}

impl RdpParser {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Detect RDP version and encryption
    pub async fn detect(&self, target: IpAddr, port: u16) -> Result<RdpInfo> {
        let addr = SocketAddr::new(target, port);
        let mut stream = timeout(self.timeout, TcpStream::connect(addr)).await??;

        // Send X.224 Connection Request
        let request = self.build_connection_request();
        stream.write_all(&request).await?;

        // Read response
        let mut buffer = vec![0u8; 4096];
        let n = timeout(self.timeout, stream.read(&mut buffer)).await??;

        if n < 11 {
            return Err(anyhow!("Invalid RDP response"));
        }

        self.parse_connection_response(&buffer[..n])
    }

    fn build_connection_request(&self) -> Vec<u8> {
        vec![
            0x03, 0x00, // TPKT version
            0x00, 0x13, // Length (19 bytes)
            0x0e, // X.224 Length
            0xe0, // X.224 Type: Connection Request
            0x00, 0x00, // Destination reference
            0x00, 0x00, // Source reference
            0x00, // Class and options
            0x01, // RDP Negotiation Request
            0x00, // Flags
            0x08, 0x00, // Length
            0x03, 0x00, 0x00, 0x00, // Requested protocols (TLS, CredSSP, RDSTLS)
        ]
    }

    fn parse_connection_response(&self, data: &[u8]) -> Result<RdpInfo> {
        if data.len() < 11 {
            return Err(anyhow!("Response too short"));
        }

        // Check TPKT header
        if data[0] != 0x03 || data[1] != 0x00 {
            return Err(anyhow!("Invalid TPKT header"));
        }

        let mut info = RdpInfo {
            version: "RDP".to_string(),
            encryption_level: "Unknown".to_string(),
            encryption_methods: Vec::new(),
            nla_supported: false,
            tls_supported: false,
        };

        // Check for RDP Negotiation Response
        if data.len() > 19 {
            for i in 11..data.len() - 8 {
                if data[i] == 0x02 && data[i + 1] == 0x00 {
                    // Found negotiation response
                    if i + 7 < data.len() {
                        let selected_protocols = u32::from_le_bytes([
                            data[i + 4],
                            data[i + 5],
                            data[i + 6],
                            data[i + 7],
                        ]);

                        info.tls_supported = (selected_protocols & 0x01) != 0;
                        info.nla_supported = (selected_protocols & 0x02) != 0;

                        if info.nla_supported {
                            info.encryption_level =
                                "NLA (Network Level Authentication)".to_string();
                            info.encryption_methods.push("CredSSP".to_string());
                        } else if info.tls_supported {
                            info.encryption_level = "TLS".to_string();
                            info.encryption_methods.push("TLS 1.0+".to_string());
                        } else {
                            info.encryption_level = "Standard RDP".to_string();
                        }
                    }
                    break;
                }
            }
        }

        Ok(info)
    }
}

/// HTTP/2 and gRPC detector
pub struct Http2Parser {
    timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct Http2Info {
    pub version: String,
    pub supports_h2c: bool, // HTTP/2 cleartext
    pub supports_h2: bool,  // HTTP/2 over TLS
    pub grpc_supported: bool,
    pub settings: HashMap<String, u32>,
}

impl Http2Parser {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Detect HTTP/2 support using prior knowledge
    pub async fn detect(&self, target: IpAddr, port: u16) -> Result<Http2Info> {
        let addr = SocketAddr::new(target, port);
        let mut stream = timeout(self.timeout, TcpStream::connect(addr)).await??;

        // Send HTTP/2 connection preface (prior knowledge)
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        stream.write_all(preface).await?;

        // Send SETTINGS frame
        let settings_frame = vec![
            0x00, 0x00, 0x00, // Length: 0
            0x04, // Type: SETTINGS
            0x00, // Flags: none
            0x00, 0x00, 0x00, 0x00, // Stream ID: 0
        ];
        stream.write_all(&settings_frame).await?;

        // Read response
        let mut buffer = vec![0u8; 4096];
        let n = timeout(self.timeout, stream.read(&mut buffer)).await??;

        self.parse_http2_response(&buffer[..n])
    }

    fn parse_http2_response(&self, data: &[u8]) -> Result<Http2Info> {
        if data.len() < 9 {
            return Err(anyhow!("Response too short for HTTP/2"));
        }

        let mut info = Http2Info {
            version: "HTTP/2".to_string(),
            supports_h2c: false,
            supports_h2: false,
            grpc_supported: false,
            settings: HashMap::new(),
        };

        // Check if response starts with a valid HTTP/2 frame
        let mut pos = 0;
        while pos + 9 <= data.len() {
            let length = u32::from_be_bytes([0, data[pos], data[pos + 1], data[pos + 2]]) as usize;
            let frame_type = data[pos + 3];

            if frame_type == 0x04 {
                // SETTINGS frame
                info.supports_h2c = true;

                // Parse settings
                let settings_data = &data[pos + 9..pos + 9 + length.min(data.len() - pos - 9)];
                for chunk in settings_data.chunks_exact(6) {
                    let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                    let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);

                    let setting_name = match id {
                        1 => "HEADER_TABLE_SIZE",
                        2 => "ENABLE_PUSH",
                        3 => "MAX_CONCURRENT_STREAMS",
                        4 => "INITIAL_WINDOW_SIZE",
                        5 => "MAX_FRAME_SIZE",
                        6 => "MAX_HEADER_LIST_SIZE",
                        _ => "UNKNOWN",
                    };

                    info.settings.insert(setting_name.to_string(), value);
                }
            }

            pos += 9 + length;
            if pos >= data.len() {
                break;
            }
        }

        Ok(info)
    }
}

/// Database protocol parsers
pub struct DatabaseParser {
    timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct DatabaseInfo {
    pub database_type: String,
    pub version: Option<String>,
    pub auth_methods: Vec<String>,
    pub capabilities: Vec<String>,
    pub default_database: Option<String>,
}

impl DatabaseParser {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Parse MySQL greeting packet
    pub async fn detect_mysql(&self, target: IpAddr, port: u16) -> Result<DatabaseInfo> {
        let addr = SocketAddr::new(target, port);
        let mut stream = timeout(self.timeout, TcpStream::connect(addr)).await??;

        // Read server greeting
        let mut buffer = vec![0u8; 512];
        let n = timeout(self.timeout, stream.read(&mut buffer)).await??;

        self.parse_mysql_greeting(&buffer[..n])
    }

    fn parse_mysql_greeting(&self, data: &[u8]) -> Result<DatabaseInfo> {
        if data.len() < 10 {
            return Err(anyhow!("Invalid MySQL greeting"));
        }

        // Skip packet length (3 bytes) and sequence (1 byte)
        let protocol_version = data[4];
        if protocol_version != 10 {
            return Err(anyhow!(
                "Unsupported MySQL protocol version: {}",
                protocol_version
            ));
        }

        // Parse version string (null-terminated)
        let mut version_end = 5;
        while version_end < data.len() && data[version_end] != 0 {
            version_end += 1;
        }

        let version = String::from_utf8_lossy(&data[5..version_end]).to_string();

        let mut info = DatabaseInfo {
            database_type: "MySQL".to_string(),
            version: Some(version),
            auth_methods: Vec::new(),
            capabilities: Vec::new(),
            default_database: None,
        };

        // Parse capabilities (if enough data)
        if data.len() > version_end + 20 {
            let cap_flags = u16::from_le_bytes([data[version_end + 14], data[version_end + 15]]);

            if (cap_flags & 0x0001) != 0 {
                info.capabilities.push("LONG_PASSWORD".to_string());
            }
            if (cap_flags & 0x0008) != 0 {
                info.capabilities.push("CONNECT_WITH_DB".to_string());
            }
            if (cap_flags & 0x0200) != 0 {
                info.capabilities.push("LONG_FLAG".to_string());
            }
            if (cap_flags & 0x0800) != 0 {
                info.capabilities.push("PROTOCOL_41".to_string());
            }
            if (cap_flags & 0x8000) != 0 {
                info.capabilities.push("SECURE_CONNECTION".to_string());
            }
        }

        Ok(info)
    }

    /// Parse PostgreSQL startup response
    pub async fn detect_postgresql(&self, target: IpAddr, port: u16) -> Result<DatabaseInfo> {
        let addr = SocketAddr::new(target, port);
        let mut stream = timeout(self.timeout, TcpStream::connect(addr)).await??;

        // Send startup message
        let startup = vec![
            0x00, 0x00, 0x00, 0x08, // Length
            0x04, 0xd2, 0x16, 0x2f, // Protocol version 3.0
        ];
        stream.write_all(&startup).await?;

        // Read response
        let mut buffer = vec![0u8; 512];
        let n = timeout(self.timeout, stream.read(&mut buffer)).await??;

        self.parse_postgresql_response(&buffer[..n])
    }

    fn parse_postgresql_response(&self, data: &[u8]) -> Result<DatabaseInfo> {
        if data.is_empty() {
            return Err(anyhow!("Empty PostgreSQL response"));
        }

        let mut info = DatabaseInfo {
            database_type: "PostgreSQL".to_string(),
            version: None,
            auth_methods: Vec::new(),
            capabilities: Vec::new(),
            default_database: None,
        };

        // Parse authentication response
        let message_type = data[0] as char;
        match message_type {
            'R' => {
                // Authentication request
                if data.len() >= 9 {
                    let auth_type = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
                    info.auth_methods.push(match auth_type {
                        0 => "OK (no authentication)".to_string(),
                        3 => "Cleartext password".to_string(),
                        5 => "MD5 password".to_string(),
                        10 => "SASL".to_string(),
                        _ => format!("Unknown ({})", auth_type),
                    });
                }
            }
            'E' => {
                // Error message - still indicates PostgreSQL
                info.capabilities
                    .push("Authentication required".to_string());
            }
            _ => {}
        }

        Ok(info)
    }

    /// Detect Redis with INFO command
    pub async fn detect_redis(&self, target: IpAddr, port: u16) -> Result<DatabaseInfo> {
        let addr = SocketAddr::new(target, port);
        let mut stream = timeout(self.timeout, TcpStream::connect(addr)).await??;

        // Send INFO command
        stream.write_all(b"INFO\r\n").await?;

        // Read response
        let mut buffer = vec![0u8; 4096];
        let n = timeout(self.timeout, stream.read(&mut buffer)).await??;

        self.parse_redis_info(&buffer[..n])
    }

    fn parse_redis_info(&self, data: &[u8]) -> Result<DatabaseInfo> {
        let response = String::from_utf8_lossy(data);

        let mut info = DatabaseInfo {
            database_type: "Redis".to_string(),
            version: None,
            auth_methods: Vec::new(),
            capabilities: Vec::new(),
            default_database: None,
        };

        // Parse version from INFO response
        for line in response.lines() {
            if line.starts_with("redis_version:") {
                info.version = Some(line.split(':').nth(1).unwrap_or("").to_string());
            } else if line.starts_with("redis_mode:") {
                let mode = line.split(':').nth(1).unwrap_or("");
                info.capabilities.push(format!("Mode: {}", mode));
            } else if line.starts_with("role:") {
                let role = line.split(':').nth(1).unwrap_or("");
                info.capabilities.push(format!("Role: {}", role));
            }
        }

        // Check if authentication required
        if response.contains("NOAUTH") {
            info.auth_methods.push("Password required".to_string());
        }

        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb_parser_creation() {
        let parser = SmbParser::new(5000);
        assert_eq!(parser.timeout.as_millis(), 5000);
    }

    #[test]
    fn test_smb_build_negotiate_request() {
        let parser = SmbParser::new(5000);
        let request = parser.build_negotiate_request();

        // Check SMB signature
        assert_eq!(&request[4..8], b"\xffSMB");

        // Check command (Negotiate Protocol)
        assert_eq!(request[8], 0x72);
    }

    #[test]
    fn test_smb_parse_response_too_short() {
        let parser = SmbParser::new(5000);
        let result = parser.parse_negotiate_response(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_rdp_parser_creation() {
        let parser = RdpParser::new(5000);
        assert_eq!(parser.timeout.as_millis(), 5000);
    }

    #[test]
    fn test_rdp_build_connection_request() {
        let parser = RdpParser::new(5000);
        let request = parser.build_connection_request();

        // Check TPKT header
        assert_eq!(request[0], 0x03);
        assert_eq!(request[1], 0x00);

        // Check length
        assert_eq!(request[2], 0x00);
        assert_eq!(request[3], 0x13); // 19 bytes
    }

    #[test]
    fn test_http2_parser_creation() {
        let parser = Http2Parser::new(5000);
        assert_eq!(parser.timeout.as_millis(), 5000);
    }

    #[test]
    fn test_http2_parse_response_too_short() {
        let parser = Http2Parser::new(5000);
        let result = parser.parse_http2_response(&[0u8; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn test_database_parser_creation() {
        let parser = DatabaseParser::new(5000);
        assert_eq!(parser.timeout.as_millis(), 5000);
    }

    #[test]
    fn test_mysql_parse_greeting() {
        let parser = DatabaseParser::new(5000);

        // Simulate MySQL greeting packet
        let mut greeting = vec![
            0x4a, 0x00, 0x00, 0x00, // Packet length + sequence
            0x0a, // Protocol version 10
        ];
        greeting.extend_from_slice(b"8.0.28\x00"); // Version string
        greeting.extend_from_slice(&[0u8; 30]); // Padding

        let result = parser.parse_mysql_greeting(&greeting);
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.database_type, "MySQL");
        assert_eq!(info.version, Some("8.0.28".to_string()));
    }

    #[test]
    fn test_mysql_parse_invalid_protocol() {
        let parser = DatabaseParser::new(5000);

        let greeting = vec![
            0x0a, 0x00, 0x00, 0x00, 0x09, // Invalid protocol version
        ];

        let result = parser.parse_mysql_greeting(&greeting);
        assert!(result.is_err());
    }

    #[test]
    fn test_postgresql_parse_auth_ok() {
        let parser = DatabaseParser::new(5000);

        let response = vec![
            b'R', // Authentication request
            0x00, 0x00, 0x00, 0x08, // Length
            0x00, 0x00, 0x00, 0x00, // Auth OK
        ];

        let result = parser.parse_postgresql_response(&response);
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.database_type, "PostgreSQL");
        assert!(info
            .auth_methods
            .contains(&"OK (no authentication)".to_string()));
    }

    #[test]
    fn test_redis_parse_info() {
        let parser = DatabaseParser::new(5000);

        let response =
            b"# Server\r\nredis_version:6.2.6\r\nredis_mode:standalone\r\nrole:master\r\n";

        let result = parser.parse_redis_info(response);
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.database_type, "Redis");
        assert_eq!(info.version, Some("6.2.6".to_string()));
        assert!(info.capabilities.iter().any(|c| c.contains("standalone")));
        assert!(info.capabilities.iter().any(|c| c.contains("master")));
    }
}
