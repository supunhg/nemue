// FTP Bounce Scan Implementation
// Uses an FTP server to scan target ports via PORT commands
//
// How it works:
// 1. Connect to FTP server
// 2. Send PORT command with target IP and port
// 3. Send LIST command
// 4. If LIST succeeds, port is open
// 5. If LIST fails with "500" error, port is closed

use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info};

use super::{PortState, Protocol, ScanResult};

/// FTP Bounce scan configuration
pub struct FtpBounceConfig {
    /// FTP server address
    pub ftp_server: IpAddr,
    /// FTP server port
    pub ftp_port: u16,
    /// FTP username
    pub username: String,
    /// FTP password
    pub password: String,
    /// Connection timeout
    pub timeout_ms: u64,
}

impl FtpBounceConfig {
    pub fn new(ftp_server: IpAddr) -> Self {
        Self {
            ftp_server,
            ftp_port: 21,
            username: "anonymous".to_string(),
            password: "user@nemue.scan".to_string(),
            timeout_ms: 5000,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.ftp_port = port;
        self
    }

    pub fn with_credentials(mut self, username: &str, password: &str) -> Self {
        self.username = username.to_string();
        self.password = password.to_string();
        self
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }
}

/// Perform an FTP bounce scan
pub async fn ftp_bounce_scan(
    config: &FtpBounceConfig,
    target: Ipv4Addr,
    ports: &[u16],
) -> Result<Vec<ScanResult>> {
    info!(
        "Starting FTP bounce scan of {} ports via FTP server {}",
        ports.len(),
        config.ftp_server
    );

    // Connect to FTP server
    let stream = timeout(
        Duration::from_millis(config.timeout_ms),
        TcpStream::connect(SocketAddr::new(config.ftp_server, config.ftp_port)),
    )
    .await
    .map_err(|_| anyhow!("FTP connection timeout"))?
    .map_err(|e| anyhow!("FTP connection failed: {}", e))?;

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Read welcome message
    reader.read_line(&mut line).await?;
    debug!("FTP: {}", line.trim());

    // Login
    writer
        .write_all(format!("USER {}\r\n", config.username).as_bytes())
        .await?;
    reader.read_line(&mut line).await?;
    debug!("FTP: {}", line.trim());

    writer
        .write_all(format!("PASS {}\r\n", config.password).as_bytes())
        .await?;
    reader.read_line(&mut line).await?;
    debug!("FTP: {}", line.trim());

    if !line.starts_with("230") {
        return Err(anyhow!("FTP login failed: {}", line.trim()));
    }

    // Switch to binary mode
    writer.write_all(b"TYPE I\r\n").await?;
    reader.read_line(&mut line).await?;
    debug!("FTP: {}", line.trim());

    let mut results = Vec::new();

    for &port in ports {
        let result =
            check_port_via_ftp(&mut reader, &mut writer, target, port, config.timeout_ms).await;
        match result {
            Ok(state) => {
                results.push(ScanResult {
                    target: IpAddr::V4(target),
                    port,
                    state,
                    protocol: Protocol::TCP,
                    service: None,
                    service_info: None,
                    hostname: None,
                    reason: Some("ftp-bounce".to_string()),
                    timestamp: chrono::Utc::now(),
                });
            }
            Err(e) => {
                debug!("Port {} check failed: {}", port, e);
                results.push(ScanResult {
                    target: IpAddr::V4(target),
                    port,
                    state: PortState::Filtered,
                    protocol: Protocol::TCP,
                    service: None,
                    service_info: None,
                    hostname: None,
                    reason: Some(format!("ftp-bounce-error: {}", e)),
                    timestamp: chrono::Utc::now(),
                });
            }
        }
    }

    // Quit FTP session
    let _ = writer.write_all(b"QUIT\r\n").await;

    info!(
        "FTP bounce scan complete: {} open, {} closed, {} filtered",
        results
            .iter()
            .filter(|r| r.state == PortState::Open)
            .count(),
        results
            .iter()
            .filter(|r| r.state == PortState::Closed)
            .count(),
        results
            .iter()
            .filter(|r| r.state == PortState::Filtered)
            .count(),
    );

    Ok(results)
}

/// Check a single port via FTP bounce
async fn check_port_via_ftp(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    target: Ipv4Addr,
    port: u16,
    timeout_ms: u64,
) -> Result<PortState> {
    let mut line = String::new();

    // Format PORT command: h1,h2,h3,h4,p1,p2
    let octets = target.octets();
    let p1 = (port >> 8) as u8;
    let p2 = (port & 0xFF) as u8;
    let port_cmd = format!(
        "PORT {},{},{},{},{},{}\r\n",
        octets[0], octets[1], octets[2], octets[3], p1, p2
    );

    // Send PORT command
    writer.write_all(port_cmd.as_bytes()).await?;
    line.clear();
    reader.read_line(&mut line).await?;
    debug!("FTP PORT: {}", line.trim());

    if !line.starts_with("200") {
        // PORT command failed
        return Ok(PortState::Filtered);
    }

    // Send LIST command to attempt connection
    writer.write_all(b"LIST\r\n").await?;
    line.clear();

    // Read response with timeout
    let read_result = timeout(
        Duration::from_millis(timeout_ms),
        reader.read_line(&mut line),
    )
    .await;

    match read_result {
        Ok(Ok(_)) => {
            debug!("FTP LIST: {}", line.trim());
            if line.starts_with("150") || line.starts_with("125") {
                // Data connection opened - port is open
                // Read the listing data
                let mut dummy = String::new();
                let _ = timeout(Duration::from_millis(1000), reader.read_line(&mut dummy)).await;

                // Read transfer complete message
                line.clear();
                let _ = timeout(Duration::from_millis(1000), reader.read_line(&mut line)).await;

                Ok(PortState::Open)
            } else if line.starts_with("425") || line.starts_with("426") {
                // Connection refused - port is closed
                Ok(PortState::Closed)
            } else if line.starts_with("500") || line.starts_with("501") {
                // Command not understood - port might be closed
                Ok(PortState::Closed)
            } else {
                Ok(PortState::Filtered)
            }
        }
        Ok(Err(e)) => {
            debug!("FTP read error: {}", e);
            Ok(PortState::Filtered)
        }
        Err(_) => {
            // Timeout - port is likely filtered
            debug!("FTP timeout for port {}", port);
            Ok(PortState::Filtered)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ftp_bounce_config() {
        let config = FtpBounceConfig::new("192.168.1.1".parse().unwrap())
            .with_port(2121)
            .with_credentials("admin", "password")
            .with_timeout(10000);

        assert_eq!(config.ftp_server, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(config.ftp_port, 2121);
        assert_eq!(config.username, "admin");
        assert_eq!(config.password, "password");
        assert_eq!(config.timeout_ms, 10000);
    }

    #[test]
    fn test_default_config() {
        let config = FtpBounceConfig::new("10.0.0.1".parse().unwrap());
        assert_eq!(config.ftp_port, 21);
        assert_eq!(config.username, "anonymous");
    }
}
