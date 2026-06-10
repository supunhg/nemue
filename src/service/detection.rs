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

        // Try to connect and grab banner (use longer timeout for service detection)
        let detect_timeout = Duration::from_millis(self.timeout_duration.as_millis().max(5000) as u64);
        let banner = match timeout(detect_timeout, self.grab_banner(addr)).await {
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

        // SSH detection (before generic probes)
        if banner_lower.contains("ssh-") {
            let version = self.extract_ssh_version(banner);
            let extra_info = self.extract_ssh_extra(banner);
            let protocol = self.extract_ssh_protocol(banner);
            let mut os_hint = self.detect_os_hint(banner);
            if os_hint.is_none() {
                if let Some(ref extra) = extra_info {
                    os_hint = self.detect_os_hint(extra);
                }
            }
            let product = Some("OpenSSH".to_string());
            let cpe = self.generate_cpe("ssh", product.as_deref(), version.as_deref());
            let extra_display = match (extra_info, protocol) {
                (Some(e), Some(p)) => Some(format!("{}; {}", p, e)),
                (Some(e), None) => Some(e),
                (None, Some(p)) => Some(p),
                (None, None) => None,
            };
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "ssh".to_string(),
                product,
                version,
                extra_info: extra_display,
                banner: Some(banner.trim().to_string()),
                confidence: 95,
                service_family: Some("remote-access".to_string()),
                os_hint,
                cpe,
            });
        }

        // HTTP detection (before generic probes)
        if banner_lower.contains("http/") {
            let version = self.extract_server_version(banner).or_else(|| self.extract_version(banner));
            let mut product = self.extract_server(banner);
            let extra_info = self.extract_server_extra(banner);
            let mut os_hint = self.detect_os_hint(banner);

            if product.is_none() {
                if let Some((powered_by, powered_ver)) = self.extract_x_powered_by(banner) {
                    product = Some(powered_by);
                    return Some(ServiceInfo {
                        port,
                        protocol: "tcp".to_string(),
                        service: "http".to_string(),
                        product,
                        version: powered_ver,
                        extra_info,
                        banner: Some(banner.trim().to_string()),
                        confidence: 85,
                        service_family: Some("web".to_string()),
                        os_hint,
                        cpe: None,
                    });
                }
            }

            if let Some(ref p) = product {
                if p.eq_ignore_ascii_case("apache") {
                    product = Some("Apache httpd".to_string());
                }
            }

            let cpe = self.generate_cpe("http", product.as_deref(), version.as_deref());
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "http".to_string(),
                product,
                version,
                extra_info,
                banner: Some(banner.trim().to_string()),
                confidence: 85,
                service_family: Some("web".to_string()),
                os_hint,
                cpe,
            });
        }

        // FTP detection (before generic probes)
        if banner_lower.starts_with("220") && (port == 21 || self.extract_ftp_product(banner).is_some()) {
            let product = self.extract_ftp_product(banner);
            let version = self.extract_ftp_version(banner);
            let cpe = self.generate_cpe("ftp", product.as_deref(), version.as_deref());
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "ftp".to_string(),
                product,
                version,
                extra_info: None,
                banner: Some(banner.trim().to_string()),
                confidence: 85,
                service_family: Some("file-transfer".to_string()),
                os_hint: self.detect_os_hint(banner),
                cpe,
            });
        }

        // SMTP detection (before generic probes)
        if banner_lower.starts_with("220") {
            let product = self.extract_smtp_product(banner);
            let extra_info = self.extract_smtp_extra(banner);
            let cpe = self.generate_cpe("smtp", product.as_deref(), None);
            return Some(ServiceInfo {
                port,
                protocol: "tcp".to_string(),
                service: "smtp".to_string(),
                product,
                version: None,
                extra_info,
                banner: Some(banner.trim().to_string()),
                confidence: 80,
                service_family: Some("mail".to_string()),
                os_hint: self.detect_os_hint(banner),
                cpe,
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
        for line in banner.lines() {
            let line = line.trim();
            // Pattern: word/X.Y.Z (e.g., "Apache/2.4.7", "nginx/1.18.0")
            for word in line.split_whitespace() {
                if word.contains('/') {
                    let parts: Vec<&str> = word.splitn(2, '/').collect();
                    if parts.len() == 2 {
                        let ver = parts[1].trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_');
                        if ver.chars().any(|c| c.is_numeric()) && ver.len() < 64 {
                            return Some(ver.to_string());
                        }
                    }
                }
                // Pattern: word version X.Y.Z (e.g., "Postfix version 3.6.4")
                if word.eq_ignore_ascii_case("version") {
                    let rest = line[line.find(word).unwrap() + word.len()..].trim();
                    if let Some(v) = rest.split_whitespace().next() {
                        if v.chars().any(|c| c.is_numeric()) && v.len() < 64 {
                            return Some(v.to_string());
                        }
                    }
                }
                // Pattern: word vX.Y.Z (e.g., "ProFTPD v1.3.5e")
                if word.starts_with('v') && word.len() > 1 {
                    let ver = &word[1..];
                    if ver.chars().next().map_or(false, |c| c.is_numeric()) && ver.len() < 64 {
                        return Some(ver.to_string());
                    }
                }
            }
        }
        None
    }

    fn extract_server(&self, banner: &str) -> Option<String> {
        if let Some(server_line) = banner.lines().find(|l| l.to_lowercase().starts_with("server:")) {
            let server = server_line.splitn(2, ':').nth(1)?.trim();
            // "Apache/2.4.7 (Ubuntu)" -> "Apache"
            if let Some(name) = server.split('/').next() {
                let name = name.trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
            // "nginx" (no version)
            if !server.contains('/') {
                let name = server.split('(').next().unwrap_or(server).trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    fn extract_server_version(&self, banner: &str) -> Option<String> {
        if let Some(server_line) = banner.lines().find(|l| l.to_lowercase().starts_with("server:")) {
            let server = server_line.splitn(2, ':').nth(1)?.trim();
            // "Apache/2.4.7 (Ubuntu)" -> "2.4.7"
            if server.contains('/') {
                let after_slash = server.splitn(2, '/').nth(1)?.trim();
                let ver = after_slash.split_whitespace().next()
                    .unwrap_or(after_slash)
                    .trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_');
                if ver.chars().any(|c| c.is_numeric()) {
                    return Some(ver.to_string());
                }
            }
        }
        None
    }

    fn extract_server_extra(&self, banner: &str) -> Option<String> {
        if let Some(server_line) = banner.lines().find(|l| l.to_lowercase().starts_with("server:")) {
            let server = server_line.splitn(2, ':').nth(1)?.trim();
            // "Apache/2.4.7 (Ubuntu)" -> "Ubuntu"
            if let Some(start) = server.find('(') {
                if let Some(end) = server[start..].find(')') {
                    let extra = server[start + 1..start + end].trim();
                    if !extra.is_empty() {
                        return Some(extra.to_string());
                    }
                }
            }
        }
        None
    }

    fn extract_x_powered_by(&self, banner: &str) -> Option<(String, Option<String>)> {
        if let Some(line) = banner.lines().find(|l| l.to_lowercase().starts_with("x-powered-by:")) {
            let value = line.splitn(2, ':').nth(1)?.trim();
            // "PHP/7.4.3" -> ("PHP", Some("7.4.3"))
            if let Some(idx) = value.find('/') {
                let product = value[..idx].trim().to_string();
                let ver = value[idx + 1..].trim();
                let ver = if ver.chars().any(|c| c.is_numeric()) {
                    Some(ver.to_string())
                } else {
                    None
                };
                return Some((product, ver));
            }
            // "Express" (no version)
            if !value.is_empty() {
                return Some((value.to_string(), None));
            }
        }
        None
    }

    fn extract_ssh_version(&self, banner: &str) -> Option<String> {
        if let Some(ssh_line) = banner.lines().find(|l| l.starts_with("SSH-")) {
            // Format: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
            // or: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
            let after_proto = ssh_line.splitn(3, '-').nth(2)?;
            // after_proto = "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
            let parts: Vec<&str> = after_proto.splitn(2, |c: char| c == '_' || c == ' ').collect();
            if parts.len() >= 2 {
                let version_part = parts[1];
                // version_part = "8.2p1 Ubuntu-4ubuntu0.5" or "8.2p1"
                let ver = version_part.split_whitespace().next().unwrap_or(version_part);
                return Some(ver.to_string());
            }
            // Fallback: try to find version in the line
            if let Some(idx) = after_proto.find('_') {
                let rest = &after_proto[idx + 1..];
                let ver = rest.split_whitespace().next().unwrap_or(rest);
                if ver.chars().any(|c| c.is_numeric()) {
                    return Some(ver.to_string());
                }
            }
        }
        None
    }

    fn extract_ssh_extra(&self, banner: &str) -> Option<String> {
        if let Some(ssh_line) = banner.lines().find(|l| l.starts_with("SSH-")) {
            // Format: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
            let after_proto = ssh_line.splitn(3, '-').nth(2)?;
            // Find the version part (after underscore), then take the rest
            if let Some(idx) = after_proto.find('_') {
                let rest = &after_proto[idx + 1..];
                // rest = "8.2p1 Ubuntu-4ubuntu0.5"
                if let Some(space_idx) = rest.find(' ') {
                    let extra = rest[space_idx + 1..].trim();
                    if !extra.is_empty() {
                        return Some(extra.to_string());
                    }
                }
            }
        }
        None
    }

    fn extract_ssh_protocol(&self, banner: &str) -> Option<String> {
        if let Some(ssh_line) = banner.lines().find(|l| l.starts_with("SSH-")) {
            // Format: SSH-2.0-...
            let parts: Vec<&str> = ssh_line.splitn(3, '-').collect();
            if parts.len() >= 2 {
                let proto = parts[1];
                if !proto.is_empty() {
                    return Some(format!("SSH-{}", proto));
                }
            }
        }
        None
    }

    fn extract_ftp_version(&self, banner: &str) -> Option<String> {
        // Pattern: 220 ProFTPD 1.3.5e Server
        // Pattern: 220 vsFTPd 3.0.3
        // Pattern: 220 FileZilla Server 0.9.60
        let line = banner.lines().find(|l| l.starts_with("220"))?;
        let content = line.strip_prefix("220").unwrap_or(line).trim();
        for server_name in &["ProFTPD", "vsFTPd", "FileZilla Server", "FileZilla", "Pure-FTPd", "WU-FTPD", "NcFTP", "Serv-U"] {
            if let Some(idx) = content.find(server_name) {
                let rest = &content[idx + server_name.len()..].trim();
                if let Some(word) = rest.split_whitespace().next() {
                    if word.chars().any(|c| c.is_numeric()) {
                        return Some(word.to_string());
                    }
                }
            }
        }
        None
    }

    fn extract_ftp_product(&self, banner: &str) -> Option<String> {
        let line = banner.lines().find(|l| l.starts_with("220"))?;
        let content = line.strip_prefix("220").unwrap_or(line).trim();
        for server_name in &["ProFTPD", "vsFTPd", "FileZilla Server", "FileZilla", "Pure-FTPd", "WU-FTPD", "NcFTP", "Serv-U"] {
            if content.contains(server_name) {
                return Some(server_name.to_string());
            }
        }
        None
    }

    fn extract_smtp_product(&self, banner: &str) -> Option<String> {
        let line = banner.lines().find(|l| l.starts_with("220"))?;
        let content = line.strip_prefix("220").unwrap_or(line).trim();
        // Pattern: 220 mail.example.com ESMTP Postfix (Ubuntu)
        // Pattern: 220 mail.example.com ESMTP Sendmail
        // Pattern: 220 mail.example.com Microsoft ESMTP MAIL Service
        for server_name in &["Postfix", "Sendmail", "Exim", "Microsoft ESMTP", "Exchange", "Dovecot", "qmail"] {
            if content.contains(server_name) {
                return Some(server_name.to_string());
            }
        }
        None
    }

    fn extract_smtp_extra(&self, banner: &str) -> Option<String> {
        let line = banner.lines().find(|l| l.starts_with("220"))?;
        // Extract parenthetical info: (Ubuntu), (Debian), etc.
        if let Some(start) = line.find('(') {
            if let Some(end) = line[start..].find(')') {
                let extra = line[start + 1..start + end].trim();
                if !extra.is_empty() {
                    return Some(extra.to_string());
                }
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

    #[test]
    fn test_extract_ssh_version_with_extra() {
        let detector = ServiceDetector::new(1000);
        let banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1";
        
        assert_eq!(detector.extract_ssh_version(banner), Some("8.9p1".to_string()));
        assert_eq!(detector.extract_ssh_extra(banner), Some("Ubuntu-3ubuntu0.1".to_string()));
        assert_eq!(detector.extract_ssh_protocol(banner), Some("SSH-2.0".to_string()));
    }

    #[test]
    fn test_extract_ssh_version_no_extra() {
        let detector = ServiceDetector::new(1000);
        let banner = "SSH-2.0-OpenSSH_8.2p1";
        
        assert_eq!(detector.extract_ssh_version(banner), Some("8.2p1".to_string()));
        assert_eq!(detector.extract_ssh_extra(banner), None);
        assert_eq!(detector.extract_ssh_protocol(banner), Some("SSH-2.0".to_string()));
    }

    #[test]
    fn test_analyze_ssh_banner_with_extra() {
        let detector = ServiceDetector::new(1000);
        let banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1";
        
        let info = detector.analyze_banner(22, banner).unwrap();
        assert_eq!(info.service, "ssh");
        assert_eq!(info.product, Some("OpenSSH".to_string()));
        assert_eq!(info.version, Some("8.9p1".to_string()));
        assert_eq!(info.extra_info, Some("SSH-2.0; Ubuntu-3ubuntu0.1".to_string()));
        assert_eq!(info.os_hint, Some("Linux".to_string()));
    }

    #[test]
    fn test_extract_server_version() {
        let detector = ServiceDetector::new(1000);
        let banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.7 (Ubuntu)\r\n";
        
        assert_eq!(detector.extract_server(banner), Some("Apache".to_string()));
        assert_eq!(detector.extract_server_version(banner), Some("2.4.7".to_string()));
        assert_eq!(detector.extract_server_extra(banner), Some("Ubuntu".to_string()));
    }

    #[test]
    fn test_extract_server_nginx() {
        let detector = ServiceDetector::new(1000);
        let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n";
        
        assert_eq!(detector.extract_server(banner), Some("nginx".to_string()));
        assert_eq!(detector.extract_server_version(banner), Some("1.18.0".to_string()));
        assert_eq!(detector.extract_server_extra(banner), Some("Ubuntu".to_string()));
    }

    #[test]
    fn test_extract_x_powered_by() {
        let detector = ServiceDetector::new(1000);
        let banner = "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/7.4.3\r\n";
        
        let result = detector.extract_x_powered_by(banner);
        assert_eq!(result, Some(("PHP".to_string(), Some("7.4.3".to_string()))));
    }

    #[test]
    fn test_analyze_http_apache_banner() {
        let detector = ServiceDetector::new(1000);
        let banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.7 (Ubuntu)\r\n";
        
        let info = detector.analyze_banner(80, banner).unwrap();
        assert_eq!(info.service, "http");
        assert_eq!(info.product, Some("Apache httpd".to_string()));
        assert_eq!(info.version, Some("2.4.7".to_string()));
        assert_eq!(info.extra_info, Some("Ubuntu".to_string()));
        assert_eq!(info.os_hint, Some("Linux".to_string()));
    }

    #[test]
    fn test_extract_ftp_version() {
        let detector = ServiceDetector::new(1000);
        let banner = "220 ProFTPD 1.3.5e Server";
        
        assert_eq!(detector.extract_ftp_product(banner), Some("ProFTPD".to_string()));
        assert_eq!(detector.extract_ftp_version(banner), Some("1.3.5e".to_string()));
    }

    #[test]
    fn test_analyze_ftp_banner() {
        let detector = ServiceDetector::new(1000);
        let banner = "220 ProFTPD 1.3.5e Server";
        
        let info = detector.analyze_banner(21, banner).unwrap();
        assert_eq!(info.service, "ftp");
        assert_eq!(info.product, Some("ProFTPD".to_string()));
        assert_eq!(info.version, Some("1.3.5e".to_string()));
    }

    #[test]
    fn test_extract_smtp_product() {
        let detector = ServiceDetector::new(1000);
        let banner = "220 mail.example.com ESMTP Postfix (Ubuntu)";
        
        assert_eq!(detector.extract_smtp_product(banner), Some("Postfix".to_string()));
        assert_eq!(detector.extract_smtp_extra(banner), Some("Ubuntu".to_string()));
    }

    #[test]
    fn test_analyze_smtp_banner() {
        let detector = ServiceDetector::new(1000);
        let banner = "220 mail.example.com ESMTP Postfix (Ubuntu)";
        
        let info = detector.analyze_banner(25, banner).unwrap();
        assert_eq!(info.service, "smtp");
        assert_eq!(info.product, Some("Postfix".to_string()));
        assert_eq!(info.extra_info, Some("Ubuntu".to_string()));
    }

    #[test]
    fn test_extract_version_word_version_pattern() {
        let detector = ServiceDetector::new(1000);
        assert_eq!(detector.extract_version("Postfix version 3.6.4"), Some("3.6.4".to_string()));
    }

    #[test]
    fn test_extract_version_v_prefix_pattern() {
        let detector = ServiceDetector::new(1000);
        assert_eq!(detector.extract_version("ProFTPD v1.3.5e Server"), Some("1.3.5e".to_string()));
    }

    #[test]
    fn test_extract_version_slash_pattern() {
        let detector = ServiceDetector::new(1000);
        assert_eq!(detector.extract_version("Apache/2.4.7 (Ubuntu)"), Some("2.4.7".to_string()));
    }
}
