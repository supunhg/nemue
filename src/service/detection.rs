use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    pub banner: Option<String>,
    pub confidence: u8, // 0-100
}

pub struct ServiceDetector {
    timeout_duration: Duration,
    probes: HashMap<String, ServiceProbe>,
}

#[derive(Clone)]
struct ServiceProbe {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    probe_data: Vec<u8>,
    patterns: Vec<ServicePattern>,
}

#[derive(Clone)]
struct ServicePattern {
    regex: String,
    service: String,
    product: Option<String>,
}

impl ServiceDetector {
    pub fn new(timeout_ms: u64) -> Self {
        let mut detector = Self {
            timeout_duration: Duration::from_millis(timeout_ms),
            probes: HashMap::new(),
        };
        detector.load_default_probes();
        detector
    }

    fn load_default_probes(&mut self) {
        // HTTP probe
        self.probes.insert(
            "HTTP".to_string(),
            ServiceProbe {
                name: "HTTP".to_string(),
                probe_data: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
                patterns: vec![
                    ServicePattern {
                        regex: "HTTP/".to_string(),
                        service: "http".to_string(),
                        product: None,
                    },
                    ServicePattern {
                        regex: "Server: nginx".to_string(),
                        service: "http".to_string(),
                        product: Some("nginx".to_string()),
                    },
                    ServicePattern {
                        regex: "Server: Apache".to_string(),
                        service: "http".to_string(),
                        product: Some("Apache".to_string()),
                    },
                ],
            },
        );

        // SSH probe
        self.probes.insert(
            "SSH".to_string(),
            ServiceProbe {
                name: "SSH".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "SSH-".to_string(),
                    service: "ssh".to_string(),
                    product: Some("OpenSSH".to_string()),
                }],
            },
        );

        // FTP probe
        self.probes.insert(
            "FTP".to_string(),
            ServiceProbe {
                name: "FTP".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "220".to_string(),
                    service: "ftp".to_string(),
                    product: None,
                }],
            },
        );

        // SMTP probe
        self.probes.insert(
            "SMTP".to_string(),
            ServiceProbe {
                name: "SMTP".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "220".to_string(),
                    service: "smtp".to_string(),
                    product: None,
                }],
            },
        );
    }

    /// Detect service on a specific port
    pub async fn detect(&self, target: IpAddr, port: u16) -> Result<ServiceInfo> {
        let addr = SocketAddr::new(target, port);

        // Try to connect and grab banner
        let banner = match timeout(self.timeout_duration, self.grab_banner(addr)).await {
            Ok(Ok(b)) => Some(b),
            _ => None,
        };

        // Analyze banner if we got one
        if let Some(ref b) = banner {
            if let Some(info) = self.analyze_banner(port, b) {
                return Ok(info);
            }
        }

        // Fallback to port-based detection
        Ok(self.detect_by_port(port, banner))
    }

    async fn grab_banner(&self, addr: SocketAddr) -> Result<String> {
        let mut stream = TcpStream::connect(addr).await?;
        let mut buffer = vec![0u8; 4096];

        // Try to read initial banner (some services send data immediately)
        // MySQL, SSH, FTP, SMTP send greeting immediately
        match timeout(Duration::from_millis(2000), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                debug!("Received initial banner from port {}: {}", addr.port(), banner.trim());
                
                // Check if this is a MySQL handshake (starts with packet length and protocol version)
                if n >= 5 && addr.port() == 3306 {
                    // MySQL handshake starts with: [packet_length: 3 bytes] [packet_number: 1 byte] [protocol_version: 1 byte]
                    if buffer[4] == 10 || buffer[4] == 9 {  // Protocol version 10 or 9
                        return Ok(format!("MYSQL_HANDSHAKE:{}", String::from_utf8_lossy(&buffer[5..n.min(100)])));
                    }
                }
                
                return Ok(banner);
            }
            _ => {}
        }

        // For RPC endpoints (port 135), send DCE/RPC bind request
        if addr.port() == 135 {
            // Simple DCE/RPC probe to trigger response
            let rpc_probe = vec![
                0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
                0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            let _ = stream.write_all(&rpc_probe).await;
            
            match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    // Check for DCE/RPC response
                    if n >= 10 && buffer[0] == 0x05 && buffer[1] == 0x00 {
                        return Ok("MSRPC".to_string());
                    }
                }
                _ => {}
            }
        }

        // If no immediate banner, try HTTP probe for web servers
        if addr.port() == 80 || addr.port() == 443 || addr.port() == 8080 || addr.port() == 8443 {
            stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
            
            match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                    debug!("Received HTTP response: {}", banner.trim());
                    return Ok(banner);
                }
                _ => {}
            }
        }
        
        Ok(String::new())
    }

    fn analyze_banner(&self, port: u16, banner: &str) -> Option<ServiceInfo> {
        let banner_lower = banner.to_lowercase();

        // Check for MySQL handshake
        if banner.starts_with("MYSQL_HANDSHAKE:") {
            let version_info = &banner[16..]; // Skip "MYSQL_HANDSHAKE:"
            let version = self.extract_mysql_version(version_info);
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "mysql".to_string(),
                product: Some("MySQL".to_string()),
                version,
                extra_info: None,
                banner: Some(version_info.trim().to_string()),
                confidence: 95,
            });
        }

        // Check for Microsoft RPC
        if banner == "MSRPC" || (port == 135 && !banner.is_empty()) {
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "msrpc".to_string(),
                product: Some("Microsoft Windows RPC".to_string()),
                version: None,
                extra_info: None,
                banner: None,
                confidence: 90,
            });
        }

        // Check against known patterns
        for probe in self.probes.values() {
            for pattern in &probe.patterns {
                if banner_lower.contains(&pattern.regex.to_lowercase()) {
                    return Some(ServiceInfo {
                        port,
                        protocol: "tcp".to_string(),
                        service: pattern.service.clone(),
                        product: pattern.product.clone(),
                        version: self.extract_version(banner),
                        extra_info: None,
                        banner: Some(banner.trim().to_string()),
                        confidence: 90,
                    });
                }
            }
        }

        // Check for common patterns
        if banner_lower.contains("http/") {
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "http".to_string(),
                product: self.extract_server(banner),
                version: self.extract_version(banner),
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 85,
            });
        }

        if banner_lower.contains("ssh-") {
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "ssh".to_string(),
                product: Some("OpenSSH".to_string()),
                version: self.extract_ssh_version(banner),
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 95,
            });
        }

        if banner_lower.starts_with("220") {
            let service = if port == 21 { "ftp" } else { "smtp" };
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: service.to_string(),
                product: None,
                version: None,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 75,
            });
        }

        None
    }

    fn detect_by_port(&self, port: u16, banner: Option<String>) -> ServiceInfo {
        let (service, product, confidence) = match port {
            // File transfer
            20 => ("ftp-data", None, 60),
            21 => ("ftp", None, 70),
            69 => ("tftp", None, 60),
            115 => ("sftp", None, 70),
            
            // SSH/Telnet
            22 => ("ssh", None, 80),
            23 => ("telnet", None, 70),
            
            // Mail
            25 => ("smtp", None, 70),
            110 => ("pop3", None, 70),
            143 => ("imap", None, 70),
            465 => ("smtps", None, 75),
            587 => ("submission", None, 70),
            993 => ("imaps", None, 75),
            995 => ("pop3s", None, 75),
            
            // DNS
            53 => ("domain", None, 80),
            
            // HTTP/Web
            80 => ("http", None, 85),
            443 => ("https", None, 85),
            8000 => ("http-alt", None, 70),
            8008 => ("http", None, 70),
            8080 => ("http-proxy", None, 75),
            8081 => ("http-alt", None, 70),
            8443 => ("https-alt", None, 80),
            8888 => ("http-alt", None, 70),
            
            // Windows RPC/DCOM
            135 => ("msrpc", Some("Microsoft Windows RPC"), 85),
            593 => ("http-rpc-epmap", Some("Microsoft DCOM"), 75),
            
            // SMB/NetBIOS
            137 => ("netbios-ns", Some("Microsoft Windows netbios-ns"), 75),
            138 => ("netbios-dgm", Some("Microsoft Windows netbios-dgm"), 75),
            139 => ("netbios-ssn", Some("Microsoft Windows netbios-ssn"), 75),
            445 => ("microsoft-ds", Some("Microsoft Windows SMB"), 80),
            
            // Directory
            88 => ("kerberos", Some("Microsoft Windows Kerberos"), 75),
            389 => ("ldap", None, 80),
            636 => ("ldaps", None, 80),
            3268 => ("ldap-gc", None, 75),
            3269 => ("ldap-gc-ssl", None, 75),
            
            // Databases
            1433 => ("ms-sql-s", Some("Microsoft SQL Server"), 80),
            1521 => ("oracle", Some("Oracle Database"), 80),
            3306 => ("mysql", Some("MySQL"), 85),
            5432 => ("postgresql", Some("PostgreSQL"), 85),
            6379 => ("redis", Some("Redis"), 85),
            7000 | 7001 => ("cassandra", Some("Apache Cassandra"), 75),
            9042 => ("cassandra-cql", Some("Apache Cassandra CQL"), 80),
            9200 => ("elasticsearch", Some("Elasticsearch"), 85),
            9300 => ("elasticsearch-cluster", Some("Elasticsearch"), 80),
            11211 => ("memcached", Some("Memcached"), 80),
            27017 => ("mongodb", Some("MongoDB"), 85),
            27018 => ("mongodb-shard", Some("MongoDB"), 80),
            27019 => ("mongodb-config", Some("MongoDB"), 80),
            5984 => ("couchdb", Some("Apache CouchDB"), 75),
            
            // Remote desktop/VNC
            3389 => ("rdp", Some("Microsoft Terminal Services"), 85),
            5900..=5910 => ("vnc", Some("VNC"), 80),
            
            // Message queues
            5672 => ("amqp", Some("RabbitMQ"), 75),
            1883 => ("mqtt", None, 75),
            8883 => ("mqtt-tls", None, 75),
            9092 => ("kafka", Some("Apache Kafka"), 80),
            61616 => ("activemq", Some("Apache ActiveMQ"), 75),
            
            // Monitoring/Management
            161 | 162 => ("snmp", None, 75),
            514 => ("syslog", None, 70),
            8086 => ("influxdb", Some("InfluxDB"), 75),
            9090 => ("prometheus", Some("Prometheus"), 75),
            
            // Container/Orchestration
            2375 => ("docker", Some("Docker"), 80),
            2376 => ("docker-tls", Some("Docker"), 80),
            2379 | 2380 => ("etcd", Some("etcd"), 75),
            6443 => ("kubernetes-api", Some("Kubernetes"), 80),
            8500 => ("consul", Some("HashiCorp Consul"), 75),
            
            // Web frameworks (common dev ports)
            3000 => ("node-http", Some("Node.js"), 65),
            4200 => ("angular-dev", Some("Angular Dev Server"), 65),
            5000 => ("flask", Some("Flask"), 65),
            9418 => ("git", Some("Git"), 70),
            
            // SIP/VoIP
            5060 | 5061 => ("sip", None, 75),
            
            _ => ("unknown", None, 25),
        };

        ServiceInfo {
            port,
            protocol: "tcp".to_string(),
            service: service.to_string(),
            product: product.map(String::from),
            version: None,
            extra_info: None,
            banner,
            confidence,
        }
    }

    fn extract_version(&self, banner: &str) -> Option<String> {
        // Simple version extraction (could be enhanced)
        for word in banner.split_whitespace() {
            if word.contains('/') {
                let parts: Vec<&str> = word.split('/').collect();
                if parts.len() == 2 && parts[1].chars().any(|c| c.is_numeric()) {
                    return Some(parts[1].to_string());
                }
            }
        }
        None
    }

    fn extract_server(&self, banner: &str) -> Option<String> {
        if let Some(server_line) = banner.lines().find(|l| l.to_lowercase().starts_with("server:")) {
            let server = server_line.split(':').nth(1)?.trim();
            return Some(server.split('/').next()?.to_string());
        }
        None
    }

    fn extract_ssh_version(&self, banner: &str) -> Option<String> {
        if let Some(ssh_line) = banner.lines().find(|l| l.starts_with("SSH-")) {
            // Format: SSH-2.0-OpenSSH_8.2p1
            let parts: Vec<&str> = ssh_line.split('-').collect();
            if parts.len() >= 3 {
                return Some(parts[2].split('_').nth(1)?.to_string());
            }
        }
        None
    }

    fn extract_mysql_version(&self, banner: &str) -> Option<String> {
        // MySQL handshake contains version string as null-terminated string
        // Format after protocol version: server_version\0
        if let Some(null_pos) = banner.bytes().position(|b| b == 0) {
            let version = &banner[..null_pos];
            // Extract version numbers (e.g., "8.0.33-0ubuntu0.22.04.2" -> "8.0.33")
            if let Some(first_part) = version.split('-').next() {
                if first_part.chars().any(|c| c.is_numeric()) {
                    return Some(first_part.to_string());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_by_port() {
        let detector = ServiceDetector::new(1000);
        
        let info = detector.detect_by_port(80, None);
        assert_eq!(info.service, "http");
        
        let info = detector.detect_by_port(22, None);
        assert_eq!(info.service, "ssh");
    }

    #[test]
    fn test_analyze_http_banner() {
        let detector = ServiceDetector::new(1000);
        let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n";
        
        let info = detector.analyze_banner(80, banner);
        assert!(info.is_some());
        
        let info = info.unwrap();
        assert_eq!(info.service, "http");
        assert!(info.confidence >= 80);
    }

    #[test]
    fn test_analyze_ssh_banner() {
        let detector = ServiceDetector::new(1000);
        let banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";
        
        let info = detector.analyze_banner(22, banner);
        assert!(info.is_some());
        
        let info = info.unwrap();
        assert_eq!(info.service, "ssh");
        assert_eq!(info.product, Some("OpenSSH".to_string()));
    }
}
