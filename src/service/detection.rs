use anyhow::Result;
use regex::bytes::Regex;
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
    pub service_family: Option<String>,
    pub os_hint: Option<String>,
    pub cpe: Option<String>,
}

pub struct ServiceDetector {
    timeout_duration: Duration,
    probes: HashMap<String, ServiceProbe>,
    signatures: Vec<CompiledSignature>,
}

struct CompiledSignature {
    service: String,
    regex: Regex,
    product: String,
    version_template: Option<String>,
    is_softmatch: bool,
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
            signatures: Vec::new(),
        };
        detector.load_default_probes();
        detector.load_signatures();
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

        // BGP probe
        self.probes.insert(
            "BGP".to_string(),
            ServiceProbe {
                name: "BGP".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "BGP".to_string(),
                    service: "bgp".to_string(),
                    product: None,
                }],
            },
        );

        // SNMP probe
        self.probes.insert(
            "SNMP".to_string(),
            ServiceProbe {
                name: "SNMP".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "SNMP".to_string(),
                    service: "snmp".to_string(),
                    product: None,
                }],
            },
        );

        // LDAP probe
        self.probes.insert(
            "LDAP".to_string(),
            ServiceProbe {
                name: "LDAP".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "LDAP".to_string(),
                    service: "ldap".to_string(),
                    product: None,
                }],
            },
        );

        // RDP probe
        self.probes.insert(
            "RDP".to_string(),
            ServiceProbe {
                name: "RDP".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "RDP".to_string(),
                    service: "rdp".to_string(),
                    product: None,
                }],
            },
        );

        // VNC probe
        self.probes.insert(
            "VNC".to_string(),
            ServiceProbe {
                name: "VNC".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "RFB".to_string(),
                    service: "vnc".to_string(),
                    product: None,
                }],
            },
        );

        // Telnet probe
        self.probes.insert(
            "Telnet".to_string(),
            ServiceProbe {
                name: "Telnet".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "Telnet".to_string(),
                    service: "telnet".to_string(),
                    product: None,
                }],
            },
        );

        // MySQL probe
        self.probes.insert(
            "MySQL".to_string(),
            ServiceProbe {
                name: "MySQL".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "mysql".to_string(),
                    service: "mysql".to_string(),
                    product: Some("MySQL".to_string()),
                }],
            },
        );

        // PostgreSQL probe
        self.probes.insert(
            "PostgreSQL".to_string(),
            ServiceProbe {
                name: "PostgreSQL".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "PostgreSQL".to_string(),
                    service: "postgresql".to_string(),
                    product: Some("PostgreSQL".to_string()),
                }],
            },
        );

        // Redis probe
        self.probes.insert(
            "Redis".to_string(),
            ServiceProbe {
                name: "Redis".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "redis".to_string(),
                    service: "redis".to_string(),
                    product: Some("Redis".to_string()),
                }],
            },
        );

        // SIP probe
        self.probes.insert(
            "SIP".to_string(),
            ServiceProbe {
                name: "SIP".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "SIP/".to_string(),
                    service: "sip".to_string(),
                    product: None,
                }],
            },
        );

        // MQTT probe
        self.probes.insert(
            "MQTT".to_string(),
            ServiceProbe {
                name: "MQTT".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "MQTT".to_string(),
                    service: "mqtt".to_string(),
                    product: None,
                }],
            },
        );

        // AMQP probe
        self.probes.insert(
            "AMQP".to_string(),
            ServiceProbe {
                name: "AMQP".to_string(),
                probe_data: vec![],
                patterns: vec![ServicePattern {
                    regex: "AMQP".to_string(),
                    service: "amqp".to_string(),
                    product: None,
                }],
            },
        );
    }

    /// Load compiled signatures from the signatures database
    fn load_signatures(&mut self) {
        let all_sigs = super::signatures::all_signatures();
        for sig in all_sigs {
            if let Ok(re) = Regex::new(&sig.pattern_str) {
                self.signatures.push(CompiledSignature {
                    service: sig.service,
                    regex: re,
                    product: sig.version_info.product.unwrap_or_default(),
                    version_template: sig.version_info.version_template,
                    is_softmatch: sig.is_softmatch,
                });
            }
        }
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
            stream.write_all(b"GET / HTTP/1.0\r\nHost: target\r\n\r\n").await?;
            
            // Read multiple chunks to get full response
            let mut full_response = Vec::new();
            loop {
                match timeout(Duration::from_millis(2000), stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        full_response.extend_from_slice(&buffer[..n]);
                        // Check if we have headers (look for \r\n\r\n)
                        if full_response.windows(4).any(|w| w == b"\r\n\r\n") {
                            // Got headers, read a bit more for body
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
                                Ok(Ok(m)) if m > 0 => full_response.extend_from_slice(&buffer[..m]),
                                _ => {}
                            }
                            break;
                        }
                        // If we've read enough, stop
                        if full_response.len() > 4096 {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            
            if !full_response.is_empty() {
                let banner = String::from_utf8_lossy(&full_response).to_string();
                debug!("Received HTTP response: {} bytes", banner.len());
                return Ok(banner);
            }
        }

        // Try generic probes for unknown ports
        if addr.port() == 9929 {
            // Nping echo service - send a probe
            let probe = b"NPING";
            let _ = stream.write_all(probe).await;
            match timeout(Duration::from_millis(2000), stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buffer[..n]).to_string();
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
                service_family: Some("database".to_string()),
                os_hint: None,
                cpe: Some("cpe:/a:mysql:mysql".to_string()),
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
                service_family: Some("rpc".to_string()),
                os_hint: Some("Windows".to_string()),
                cpe: Some("cpe:/o:microsoft:windows".to_string()),
            });
        }

        // Check against compiled signatures (regex-based matching)
        let banner_bytes = banner.as_bytes();
        let mut best_match: Option<ServiceInfo> = None;
        
        for sig in &self.signatures {
            if let Some(caps) = sig.regex.captures(banner_bytes) {
                let version = sig.version_template.as_ref().map(|tmpl| {
                    let mut result = tmpl.clone();
                    for i in 1..caps.len() {
                        if let Some(m) = caps.get(i) {
                            result = result.replace(
                                &format!("${}", i),
                                &String::from_utf8_lossy(m.as_bytes()),
                            );
                        }
                    }
                    result
                });
                
                let confidence = if sig.is_softmatch { 60 } else { 90 };
                let service_family = self.detect_service_family(&sig.service, banner);
                let os_hint = self.detect_os_hint(banner);
                let cpe = self.generate_cpe(&sig.service, Some(&sig.product), version.as_deref());
                
                let info = ServiceInfo {
                    port,
                    protocol: "tcp".to_string(),
                    service: sig.service.clone(),
                    product: Some(sig.product.clone()),
                    version,
                    extra_info: None,
                    banner: Some(banner.trim().to_string()),
                    confidence,
                    service_family,
                    os_hint,
                    cpe,
                };
                
                // Hard match wins over soft match
                if !sig.is_softmatch {
                    return Some(info);
                }
                
                // Keep best soft match as fallback
                if best_match.is_none() || confidence > best_match.as_ref().unwrap().confidence {
                    best_match = Some(info);
                }
            }
        }
        
        if let Some(info) = best_match {
            return Some(info);
        }

        // Check against known patterns (legacy substring matching)
        for probe in self.probes.values() {
            for pattern in &probe.patterns {
                if banner_lower.contains(&pattern.regex.to_lowercase()) {
                    let service_family = self.detect_service_family(&pattern.service, banner);
                    let os_hint = self.detect_os_hint(banner);
                    let version = self.extract_version(banner);
                    let cpe = self.generate_cpe(&pattern.service, pattern.product.as_deref(), version.as_deref());
                    return Some(ServiceInfo {
                        port,
                        protocol: "tcp".to_string(),
                        service: pattern.service.clone(),
                        product: pattern.product.clone(),
                        version,
                        extra_info: None,
                        banner: Some(banner.trim().to_string()),
                        confidence: 90,
                        service_family,
                        os_hint,
                        cpe,
                    });
                }
            }
        }

        // Check for common patterns
        if banner_lower.contains("http/") {
            let version = self.extract_version(banner);
            let product = self.extract_server(banner);
            let cpe = self.generate_cpe("http", product.as_deref(), version.as_deref());
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "http".to_string(),
                product,
                version,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 85,
                service_family: Some("web".to_string()),
                os_hint: self.detect_os_hint(banner),
                cpe,
            });
        }

        if banner_lower.contains("ssh-") {
            let version = self.extract_ssh_version(banner);
            let cpe = self.generate_cpe("ssh", Some("OpenSSH"), version.as_deref());
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "ssh".to_string(),
                product: Some("OpenSSH".to_string()),
                version,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 95,
                service_family: Some("remote-access".to_string()),
                os_hint: self.detect_os_hint(banner),
                cpe,
            });
        }

        if banner_lower.starts_with("220") {
            let service = if port == 21 { "ftp" } else { "smtp" };
            let service_family = if port == 21 { "file-transfer" } else { "mail" };
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: service.to_string(),
                product: None,
                version: None,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 75,
                service_family: Some(service_family.to_string()),
                os_hint: None,
                cpe: None,
            });
        }

        // BGP detection
        if banner_lower.contains("bgp") || (port == 179 && !banner.is_empty()) {
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "bgp".to_string(),
                product: None,
                version: None,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 85,
                service_family: Some("routing".to_string()),
                os_hint: None,
                cpe: None,
            });
        }

        // SNMP detection
        if banner_lower.contains("snmp") || (port == 161 && !banner.is_empty()) {
            return Some(ServiceInfo {
                port,
                protocol: "udp".to_string(),
                service: "snmp".to_string(),
                product: None,
                version: None,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 85,
                service_family: Some("management".to_string()),
                os_hint: None,
                cpe: None,
            });
        }

        // LDAP detection
        if banner_lower.contains("ldap") || (port == 389 && !banner.is_empty()) {
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "ldap".to_string(),
                product: None,
                version: None,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 85,
                service_family: Some("directory".to_string()),
                os_hint: None,
                cpe: None,
            });
        }

        // RDP detection
        if banner_lower.contains("rdp") || banner_lower.contains("terminal services") || (port == 3389 && !banner.is_empty()) {
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "rdp".to_string(),
                product: Some("Microsoft Terminal Services".to_string()),
                version: None,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 90,
                service_family: Some("remote-access".to_string()),
                os_hint: Some("Windows".to_string()),
                cpe: Some("cpe:/o:microsoft:windows".to_string()),
            });
        }

        // VNC detection
        if banner_lower.contains("rfb") || (port >= 5900 && port <= 5910 && !banner.is_empty()) {
            let version = self.extract_vnc_version(banner);
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "vnc".to_string(),
                product: Some("VNC".to_string()),
                version,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 90,
                service_family: Some("remote-access".to_string()),
                os_hint: None,
                cpe: None,
            });
        }

        // Telnet detection
        if banner_lower.contains("telnet") || banner_lower.contains("login:") || banner_lower.contains("password:") {
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "telnet".to_string(),
                product: None,
                version: None,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 80,
                service_family: Some("remote-access".to_string()),
                os_hint: self.detect_os_hint(banner),
                cpe: None,
            });
        }

        // Redis detection
        if banner_lower.contains("redis_version") || banner_lower.contains("+ok") || banner_lower.contains("$-1") {
            let version = self.extract_redis_version(banner);
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "redis".to_string(),
                product: Some("Redis".to_string()),
                version,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 90,
                service_family: Some("database".to_string()),
                os_hint: None,
                cpe: Some("cpe:/a:redis:redis".to_string()),
            });
        }

        // PostgreSQL detection
        if banner_lower.contains("postgresql") || banner_lower.contains("pgbouncer") {
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "postgresql".to_string(),
                product: Some("PostgreSQL".to_string()),
                version: None,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 85,
                service_family: Some("database".to_string()),
                os_hint: None,
                cpe: Some("cpe:/a:postgresql:postgresql".to_string()),
            });
        }

        // MongoDB detection
        if banner_lower.contains("mongodb") || banner_lower.contains("ismaster") {
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "mongodb".to_string(),
                product: Some("MongoDB".to_string()),
                version: None,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 85,
                service_family: Some("database".to_string()),
                os_hint: None,
                cpe: Some("cpe:/a:mongodb:mongodb".to_string()),
            });
        }

        // Elasticsearch detection
        if banner_lower.contains("elasticsearch") || banner_lower.contains("cluster_name") {
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "elasticsearch".to_string(),
                product: Some("Elasticsearch".to_string()),
                version: None,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 85,
                service_family: Some("search".to_string()),
                os_hint: None,
                cpe: Some("cpe:/a:elastic:elasticsearch".to_string()),
            });
        }

        // Docker detection
        if banner_lower.contains("docker") {
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "docker".to_string(),
                product: Some("Docker".to_string()),
                version: None,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 85,
                service_family: Some("container".to_string()),
                os_hint: None,
                cpe: Some("cpe:/a:docker:docker".to_string()),
            });
        }

        // Kubernetes detection
        if banner_lower.contains("kubernetes") || banner_lower.contains("k8s") {
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "kubernetes".to_string(),
                product: Some("Kubernetes".to_string()),
                version: None,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 85,
                service_family: Some("container".to_string()),
                os_hint: None,
                cpe: Some("cpe:/a:kubernetes:kubernetes".to_string()),
            });
        }

        None
    }

    fn detect_by_port(&self, port: u16, banner: Option<String>) -> ServiceInfo {
        let (service, product, confidence, service_family, os_hint, cpe) = match port {
            // File transfer
            20 => ("ftp-data", None, 60, "file-transfer", None, None),
            21 => ("ftp", None, 70, "file-transfer", None, None),
            69 => ("tftp", None, 60, "file-transfer", None, None),
            115 => ("sftp", None, 70, "file-transfer", None, None),
            
            // SSH/Telnet
            22 => ("ssh", None, 80, "remote-access", None, None),
            23 => ("telnet", None, 70, "remote-access", None, None),
            
            // Mail
            25 => ("smtp", None, 70, "mail", None, None),
            110 => ("pop3", None, 70, "mail", None, None),
            143 => ("imap", None, 70, "mail", None, None),
            465 => ("smtps", None, 75, "mail", None, None),
            587 => ("submission", None, 70, "mail", None, None),
            993 => ("imaps", None, 75, "mail", None, None),
            995 => ("pop3s", None, 75, "mail", None, None),
            
            // DNS
            53 => ("domain", None, 80, "dns", None, None),
            
            // HTTP/Web
            80 => ("http", None, 85, "web", None, None),
            443 => ("https", None, 85, "web", None, None),
            8000 => ("http-alt", None, 70, "web", None, None),
            8008 => ("http", None, 70, "web", None, None),
            8080 => ("http-proxy", None, 75, "web", None, None),
            8081 => ("http-alt", None, 70, "web", None, None),
            8443 => ("https-alt", None, 80, "web", None, None),
            8888 => ("http-alt", None, 70, "web", None, None),
            
            // Windows RPC/DCOM
            135 => ("msrpc", Some("Microsoft Windows RPC"), 85, "rpc", Some("Windows"), Some("cpe:/o:microsoft:windows")),
            593 => ("http-rpc-epmap", Some("Microsoft DCOM"), 75, "rpc", Some("Windows"), Some("cpe:/o:microsoft:windows")),
            
            // SMB/NetBIOS
            137 => ("netbios-ns", Some("Microsoft Windows netbios-ns"), 75, "netbios", Some("Windows"), Some("cpe:/o:microsoft:windows")),
            138 => ("netbios-dgm", Some("Microsoft Windows netbios-dgm"), 75, "netbios", Some("Windows"), Some("cpe:/o:microsoft:windows")),
            139 => ("netbios-ssn", Some("Microsoft Windows netbios-ssn"), 75, "netbios", Some("Windows"), Some("cpe:/o:microsoft:windows")),
            445 => ("microsoft-ds", Some("Microsoft Windows SMB"), 80, "netbios", Some("Windows"), Some("cpe:/o:microsoft:windows")),
            
            // Directory
            88 => ("kerberos", Some("Microsoft Windows Kerberos"), 75, "directory", Some("Windows"), Some("cpe:/o:microsoft:windows")),
            389 => ("ldap", None, 80, "directory", None, None),
            636 => ("ldaps", None, 80, "directory", None, None),
            3268 => ("ldap-gc", None, 75, "directory", None, None),
            3269 => ("ldap-gc-ssl", None, 75, "directory", None, None),
            
            // Databases
            1433 => ("ms-sql-s", Some("Microsoft SQL Server"), 80, "database", None, Some("cpe:/a:microsoft:sql_server")),
            1521 => ("oracle", Some("Oracle Database"), 80, "database", None, Some("cpe:/a:oracle:database")),
            3306 => ("mysql", Some("MySQL"), 85, "database", None, Some("cpe:/a:mysql:mysql")),
            5432 => ("postgresql", Some("PostgreSQL"), 85, "database", None, Some("cpe:/a:postgresql:postgresql")),
            6379 => ("redis", Some("Redis"), 85, "database", None, Some("cpe:/a:redis:redis")),
            7000 | 7001 => ("cassandra", Some("Apache Cassandra"), 75, "database", None, None),
            9042 => ("cassandra-cql", Some("Apache Cassandra CQL"), 80, "database", None, None),
            9200 => ("elasticsearch", Some("Elasticsearch"), 85, "search", None, Some("cpe:/a:elastic:elasticsearch")),
            9300 => ("elasticsearch-cluster", Some("Elasticsearch"), 80, "search", None, Some("cpe:/a:elastic:elasticsearch")),
            11211 => ("memcached", Some("Memcached"), 80, "database", None, None),
            27017 => ("mongodb", Some("MongoDB"), 85, "database", None, Some("cpe:/a:mongodb:mongodb")),
            27018 => ("mongodb-shard", Some("MongoDB"), 80, "database", None, Some("cpe:/a:mongodb:mongodb")),
            27019 => ("mongodb-config", Some("MongoDB"), 80, "database", None, Some("cpe:/a:mongodb:mongodb")),
            5984 => ("couchdb", Some("Apache CouchDB"), 75, "database", None, None),
            
            // Remote desktop/VNC
            3389 => ("rdp", Some("Microsoft Terminal Services"), 85, "remote-access", Some("Windows"), Some("cpe:/o:microsoft:windows")),
            5900..=5910 => ("vnc", Some("VNC"), 80, "remote-access", None, None),
            
            // Message queues
            5672 => ("amqp", Some("RabbitMQ"), 75, "messaging", None, None),
            1883 => ("mqtt", None, 75, "messaging", None, None),
            8883 => ("mqtt-tls", None, 75, "messaging", None, None),
            9092 => ("kafka", Some("Apache Kafka"), 80, "messaging", None, None),
            61616 => ("activemq", Some("Apache ActiveMQ"), 75, "messaging", None, None),
            
            // Monitoring/Management
            161 | 162 => ("snmp", None, 75, "management", None, None),
            514 => ("syslog", None, 70, "management", None, None),
            8086 => ("influxdb", Some("InfluxDB"), 75, "monitoring", None, None),
            9090 => ("prometheus", Some("Prometheus"), 75, "monitoring", None, None),
            
            // Container/Orchestration
            2375 => ("docker", Some("Docker"), 80, "container", None, Some("cpe:/a:docker:docker")),
            2376 => ("docker-tls", Some("Docker"), 80, "container", None, Some("cpe:/a:docker:docker")),
            2379 | 2380 => ("etcd", Some("etcd"), 75, "container", None, None),
            6443 => ("kubernetes-api", Some("Kubernetes"), 80, "container", None, Some("cpe:/a:kubernetes:kubernetes")),
            8500 => ("consul", Some("HashiCorp Consul"), 75, "container", None, None),
            
            // Web frameworks (common dev ports)
            3000 => ("node-http", Some("Node.js"), 65, "web", None, None),
            4200 => ("angular-dev", Some("Angular Dev Server"), 65, "web", None, None),
            5000 => ("flask", Some("Flask"), 65, "web", None, None),
            9418 => ("git", Some("Git"), 70, "vcs", None, None),
            
            // SIP/VoIP
            5060 | 5061 => ("sip", None, 75, "voip", None, None),
            
            // Routing
            179 => ("bgp", None, 80, "routing", None, None),
            
            // RPC
            111 => ("rpcbind", None, 75, "rpc", None, None),
            
            // Printing
            515 => ("printer", None, 70, "printing", None, None),
            631 => ("ipp", None, 75, "printing", None, None),
            
            // NTP
            123 => ("ntp", None, 75, "time", None, None),
            
            // DHCP
            67 | 68 => ("dhcp", None, 75, "network", None, None),
            
            // Tor
            9001 | 9030 => ("tor", None, 70, "anonymity", None, None),
            
            _ => ("unknown", None, 25, "unknown", None, None),
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
            service_family: Some(service_family.to_string()),
            os_hint: os_hint.map(String::from),
            cpe: cpe.map(String::from),
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

    fn extract_vnc_version(&self, banner: &str) -> Option<String> {
        // VNC RFB protocol version: RFB xxx.yyy
        if let Some(rfb_pos) = banner.find("RFB ") {
            let version_str = &banner[rfb_pos + 4..];
            let version: String = version_str.chars().take(7).collect();
            if version.contains('.') {
                return Some(version);
            }
        }
        None
    }

    fn extract_redis_version(&self, banner: &str) -> Option<String> {
        // Redis INFO response: redis_version:X.Y.Z
        for line in banner.lines() {
            if line.starts_with("redis_version:") {
                return line.split(':').nth(1).map(|v| v.trim().to_string());
            }
        }
        None
    }

    fn detect_service_family(&self, service: &str, banner: &str) -> Option<String> {
        let service_lower = service.to_lowercase();
        let banner_lower = banner.to_lowercase();

        // Database services
        if service_lower.contains("mysql") || service_lower.contains("postgres") 
            || service_lower.contains("redis") || service_lower.contains("mongo")
            || service_lower.contains("cassandra") || service_lower.contains("elasticsearch")
            || service_lower.contains("memcached") || service_lower.contains("couchdb")
            || service_lower.contains("influxdb") || service_lower.contains("mssql")
            || service_lower.contains("oracle") || service_lower.contains("database") {
            return Some("database".to_string());
        }

        // Web services
        if service_lower.contains("http") || service_lower.contains("web")
            || banner_lower.contains("server:") || banner_lower.contains("http/") {
            return Some("web".to_string());
        }

        // Mail services
        if service_lower.contains("smtp") || service_lower.contains("imap")
            || service_lower.contains("pop3") || service_lower.contains("mail")
            || service_lower.contains("exchange") {
            return Some("mail".to_string());
        }

        // Remote access
        if service_lower.contains("ssh") || service_lower.contains("telnet")
            || service_lower.contains("rdp") || service_lower.contains("vnc")
            || service_lower.contains("remote") {
            return Some("remote-access".to_string());
        }

        // File transfer
        if service_lower.contains("ftp") || service_lower.contains("sftp")
            || service_lower.contains("tftp") || service_lower.contains("smb")
            || service_lower.contains("netbios") || service_lower.contains("nfs") {
            return Some("file-transfer".to_string());
        }

        // Directory services
        if service_lower.contains("ldap") || service_lower.contains("kerberos")
            || service_lower.contains("active-directory") || service_lower.contains("dns") {
            return Some("directory".to_string());
        }

        // Messaging
        if service_lower.contains("amqp") || service_lower.contains("mqtt")
            || service_lower.contains("kafka") || service_lower.contains("activemq")
            || service_lower.contains("rabbitmq") || service_lower.contains("stomp") {
            return Some("messaging".to_string());
        }

        // Container/Orchestration
        if service_lower.contains("docker") || service_lower.contains("kubernetes")
            || service_lower.contains("etcd") || service_lower.contains("consul") {
            return Some("container".to_string());
        }

        // Monitoring
        if service_lower.contains("snmp") || service_lower.contains("prometheus")
            || service_lower.contains("grafana") || service_lower.contains("zabbix")
            || service_lower.contains("nagios") || service_lower.contains("syslog") {
            return Some("monitoring".to_string());
        }

        // Routing
        if service_lower.contains("bgp") || service_lower.contains("ospf")
            || service_lower.contains("eigrp") || service_lower.contains("rip") {
            return Some("routing".to_string());
        }

        // VoIP
        if service_lower.contains("sip") || service_lower.contains("h.323")
            || service_lower.contains("rtp") || service_lower.contains("voip") {
            return Some("voip".to_string());
        }

        Some("other".to_string())
    }

    fn detect_os_hint(&self, banner: &str) -> Option<String> {
        let banner_lower = banner.to_lowercase();

        // Windows indicators
        if banner_lower.contains("windows") || banner_lower.contains("microsoft")
            || banner_lower.contains("iis") || banner_lower.contains("asp.net")
            || banner_lower.contains("win32") || banner_lower.contains("win64") {
            return Some("Windows".to_string());
        }

        // Linux indicators
        if banner_lower.contains("ubuntu") || banner_lower.contains("debian")
            || banner_lower.contains("centos") || banner_lower.contains("rhel")
            || banner_lower.contains("fedora") || banner_lower.contains("suse")
            || banner_lower.contains("linux") || banner_lower.contains("apache")
            || banner_lower.contains("nginx") || banner_lower.contains("php/") {
            return Some("Linux".to_string());
        }

        // macOS indicators
        if banner_lower.contains("macos") || banner_lower.contains("darwin")
            || banner_lower.contains("mac os") || banner_lower.contains("apple") {
            return Some("macOS".to_string());
        }

        // BSD indicators
        if banner_lower.contains("freebsd") || banner_lower.contains("openbsd")
            || banner_lower.contains("netbsd") || banner_lower.contains("bsd") {
            return Some("BSD".to_string());
        }

        // Solaris indicators
        if banner_lower.contains("solaris") || banner_lower.contains("sunos")
            || banner_lower.contains("sun os") {
            return Some("Solaris".to_string());
        }

        // Cisco indicators
        if banner_lower.contains("cisco") || banner_lower.contains("ios")
            || banner_lower.contains("nx-os") || banner_lower.contains("asa") {
            return Some("Cisco IOS".to_string());
        }

        // Network device indicators
        if banner_lower.contains("juniper") || banner_lower.contains("fortinet")
            || banner_lower.contains("palo alto") || banner_lower.contains("mikrotik")
            || banner_lower.contains("aruba") || banner_lower.contains("arista") {
            return Some("Network Device".to_string());
        }

        None
    }

    fn generate_cpe(&self, service: &str, product: Option<&str>, version: Option<&str>) -> Option<String> {
        let service_lower = service.to_lowercase();
        
        // Map service to CPE vendor:product
        let (vendor, product_name) = if service_lower.contains("mysql") {
            ("mysql", "mysql")
        } else if service_lower.contains("postgres") {
            ("postgresql", "postgresql")
        } else if service_lower.contains("redis") {
            ("redis", "redis")
        } else if service_lower.contains("mongo") {
            ("mongodb", "mongodb")
        } else if service_lower.contains("elasticsearch") {
            ("elastic", "elasticsearch")
        } else if service_lower.contains("apache") || product.map_or(false, |p| p.to_lowercase().contains("apache")) {
            ("apache", "http_server")
        } else if service_lower.contains("nginx") || product.map_or(false, |p| p.to_lowercase().contains("nginx")) {
            ("nginx", "nginx")
        } else if service_lower.contains("iis") || product.map_or(false, |p| p.to_lowercase().contains("iis")) {
            ("microsoft", "iis")
        } else if service_lower.contains("ssh") || service_lower.contains("openssh") {
            ("openbsd", "openssh")
        } else if service_lower.contains("docker") {
            ("docker", "docker")
        } else if service_lower.contains("kubernetes") {
            ("kubernetes", "kubernetes")
        } else if service_lower.contains("tomcat") {
            ("apache", "tomcat")
        } else if service_lower.contains("lighttpd") {
            ("lighttpd", "lighttpd")
        } else if service_lower.contains("caddy") {
            ("caddyserver", "caddy")
        } else {
            return None;
        };

        let mut cpe = format!("cpe:/a:{}:{}", vendor, product_name);
        if let Some(v) = version {
            cpe.push_str(&format!(":{}", v));
        }
        Some(cpe)
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
        assert_eq!(info.service_family, Some("web".to_string()));
        
        let info = detector.detect_by_port(22, None);
        assert_eq!(info.service, "ssh");
        assert_eq!(info.service_family, Some("remote-access".to_string()));
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
        assert_eq!(info.service_family, Some("web".to_string()));
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
        assert_eq!(info.service_family, Some("remote-access".to_string()));
        assert!(info.os_hint.is_some());
    }

    #[test]
    fn test_detect_service_family() {
        let detector = ServiceDetector::new(1000);
        
        assert_eq!(detector.detect_service_family("mysql", ""), Some("database".to_string()));
        assert_eq!(detector.detect_service_family("http", ""), Some("web".to_string()));
        assert_eq!(detector.detect_service_family("smtp", ""), Some("mail".to_string()));
        assert_eq!(detector.detect_service_family("ssh", ""), Some("remote-access".to_string()));
        assert_eq!(detector.detect_service_family("ftp", ""), Some("file-transfer".to_string()));
        assert_eq!(detector.detect_service_family("ldap", ""), Some("directory".to_string()));
        assert_eq!(detector.detect_service_family("amqp", ""), Some("messaging".to_string()));
        assert_eq!(detector.detect_service_family("docker", ""), Some("container".to_string()));
        assert_eq!(detector.detect_service_family("snmp", ""), Some("monitoring".to_string()));
        assert_eq!(detector.detect_service_family("bgp", ""), Some("routing".to_string()));
        assert_eq!(detector.detect_service_family("sip", ""), Some("voip".to_string()));
    }

    #[test]
    fn test_detect_os_hint() {
        let detector = ServiceDetector::new(1000);
        
        assert_eq!(detector.detect_os_hint("Server: Microsoft-IIS/10.0"), Some("Windows".to_string()));
        assert_eq!(detector.detect_os_hint("Server: nginx/1.18.0 (Ubuntu)"), Some("Linux".to_string()));
        assert_eq!(detector.detect_os_hint("Server: Apache/2.4.41 (Ubuntu)"), Some("Linux".to_string()));
        assert_eq!(detector.detect_os_hint("SSH-2.0-OpenSSH_8.2p1 Ubuntu"), Some("Linux".to_string()));
        assert_eq!(detector.detect_os_hint("SSH-2.0-Cisco-1.25"), Some("Cisco IOS".to_string()));
    }

    #[test]
    fn test_generate_cpe() {
        let detector = ServiceDetector::new(1000);
        
        let cpe = detector.generate_cpe("mysql", None, Some("8.0.28"));
        assert_eq!(cpe, Some("cpe:/a:mysql:mysql:8.0.28".to_string()));
        
        let cpe = detector.generate_cpe("http", Some("nginx"), Some("1.18.0"));
        assert_eq!(cpe, Some("cpe:/a:nginx:nginx:1.18.0".to_string()));
        
        let cpe = detector.generate_cpe("ssh", None, Some("8.2p1"));
        assert_eq!(cpe, Some("cpe:/a:openbsd:openssh:8.2p1".to_string()));
        
        let cpe = detector.generate_cpe("unknown_service", None, None);
        assert_eq!(cpe, None);
    }

    #[test]
    fn test_detect_by_port_database_services() {
        let detector = ServiceDetector::new(1000);
        
        let info = detector.detect_by_port(3306, None);
        assert_eq!(info.service, "mysql");
        assert_eq!(info.service_family, Some("database".to_string()));
        assert!(info.cpe.is_some());
        
        let info = detector.detect_by_port(5432, None);
        assert_eq!(info.service, "postgresql");
        assert_eq!(info.service_family, Some("database".to_string()));
        
        let info = detector.detect_by_port(6379, None);
        assert_eq!(info.service, "redis");
        assert_eq!(info.service_family, Some("database".to_string()));
    }

    #[test]
    fn test_detect_by_port_routing() {
        let detector = ServiceDetector::new(1000);
        
        let info = detector.detect_by_port(179, None);
        assert_eq!(info.service, "bgp");
        assert_eq!(info.service_family, Some("routing".to_string()));
    }

    #[test]
    fn test_detect_by_port_management() {
        let detector = ServiceDetector::new(1000);
        
        let info = detector.detect_by_port(161, None);
        assert_eq!(info.service, "snmp");
        assert_eq!(info.service_family, Some("management".to_string()));
    }

    #[test]
    fn test_extract_vnc_version() {
        let detector = ServiceDetector::new(1000);
        
        let version = detector.extract_vnc_version("RFB 003.008");
        assert_eq!(version, Some("003.008".to_string()));
        
        let version = detector.extract_vnc_version("RFB 003.007");
        assert_eq!(version, Some("003.007".to_string()));
    }

    #[test]
    fn test_extract_redis_version() {
        let detector = ServiceDetector::new(1000);
        
        let version = detector.extract_redis_version("# Server\r\nredis_version:6.2.6\r\nredis_mode:standalone");
        assert_eq!(version, Some("6.2.6".to_string()));
    }

    #[test]
    fn test_service_info_has_new_fields() {
        let detector = ServiceDetector::new(1000);
        let info = detector.detect_by_port(80, Some("test banner".to_string()));
        
        assert!(info.service_family.is_some());
        assert!(info.banner.is_some());
        assert!(info.confidence > 0);
    }

    #[test]
    fn test_detect_by_port_windows_services() {
        let detector = ServiceDetector::new(1000);
        
        let info = detector.detect_by_port(135, None);
        assert_eq!(info.service, "msrpc");
        assert_eq!(info.os_hint, Some("Windows".to_string()));
        assert!(info.cpe.is_some());
        
        let info = detector.detect_by_port(445, None);
        assert_eq!(info.service, "microsoft-ds");
        assert_eq!(info.os_hint, Some("Windows".to_string()));
    }
}
