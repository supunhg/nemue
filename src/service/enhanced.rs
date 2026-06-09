/// Enhanced service detection integrating multi-probe scanning with protocol-specific parsers
///
/// This module combines the probe database with protocol parsers for comprehensive
/// service detection and version identification.

use super::detection::{ServiceDetector, ServiceInfo};
use super::intensity::{DetectionConfig, MatchPattern};
use super::parsers::{DatabaseParser, Http2Parser, RdpParser, SmbParser};
use super::probes::ProbeDatabase;
use super::signatures::all_signatures;
use anyhow::Result;
use regex::bytes::Regex;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info};

/// Enhanced service detector with multi-probe and protocol analysis
pub struct EnhancedServiceDetector {
    basic_detector: ServiceDetector,
    probe_db: ProbeDatabase,
    config: DetectionConfig,
    smb_parser: SmbParser,
    rdp_parser: RdpParser,
    http2_parser: Http2Parser,
    db_parser: DatabaseParser,
}

impl EnhancedServiceDetector {
    pub fn new(config: DetectionConfig) -> Self {
        let timeout_ms = config.probe_timeout_ms;
        
        Self {
            basic_detector: ServiceDetector::new(timeout_ms),
            probe_db: ProbeDatabase::new(),
            config,
            smb_parser: SmbParser::new(timeout_ms),
            rdp_parser: RdpParser::new(timeout_ms),
            http2_parser: Http2Parser::new(timeout_ms),
            db_parser: DatabaseParser::new(timeout_ms),
        }
    }

    /// Detect service with enhanced multi-probe scanning
    pub async fn detect(&self, target: IpAddr, port: u16) -> Result<ServiceInfo> {
        info!("Enhanced detection for {}:{}", target, port);

        // Start with basic detection
        let mut service_info = self.basic_detector.detect(target, port).await?;

        // If confidence is low, try protocol-specific detection
        if service_info.confidence < 80 {
            service_info = self.try_protocol_specific(target, port, service_info).await;
        }

        // Multi-probe detection based on intensity
        if self.config.intensity.value() >= 5 {
            service_info = self.multi_probe_detection(target, port, service_info).await;
        }

        if self.config.trace {
            debug!("Final detection: {:?}", service_info);
        }

        Ok(service_info)
    }

    /// Try protocol-specific parsers based on port
    async fn try_protocol_specific(
        &self,
        target: IpAddr,
        port: u16,
        mut service_info: ServiceInfo,
    ) -> ServiceInfo {
        match port {
            // SMB/NetBIOS
            139 | 445 => {
                if let Ok(smb_info) = self.smb_parser.detect(target, port).await {
                    service_info.service = "microsoft-ds".to_string();
                    service_info.product = Some(format!(
                        "Windows SMB ({})",
                        smb_info.dialect.clone().unwrap_or_else(|| "unknown".to_string())
                    ));
                    let version = smb_info.version.clone();
                    service_info.version = Some(version.clone());
                    service_info.extra_info = Some(format!(
                        "Signing: {}",
                        if smb_info.signing_required {
                            "required"
                        } else {
                            "optional"
                        }
                    ));
                    service_info.confidence = 95;
                    info!("SMB detected: {}", version);
                }
            }

            // RDP
            3389 => {
                if let Ok(rdp_info) = self.rdp_parser.detect(target, port).await {
                    service_info.service = "rdp".to_string();
                    service_info.product = Some("Microsoft Terminal Services".to_string());
                    service_info.version = Some(rdp_info.version);
                    service_info.extra_info = Some(format!(
                        "Encryption: {}, NLA: {}",
                        rdp_info.encryption_level,
                        if rdp_info.nla_supported {
                            "enabled"
                        } else {
                            "disabled"
                        }
                    ));
                    service_info.confidence = 95;
                    info!("RDP detected with {}", rdp_info.encryption_level);
                }
            }

            // MySQL
            3306 => {
                if let Ok(db_info) = self.db_parser.detect_mysql(target, port).await {
                    service_info.service = "mysql".to_string();
                    service_info.product = Some("MySQL".to_string());
                    let version = db_info.version.clone();
                    service_info.version = version.clone();
                    if !db_info.capabilities.is_empty() {
                        service_info.extra_info =
                            Some(db_info.capabilities.join(", "));
                    }
                    service_info.confidence = 95;
                    info!("MySQL detected: {:?}", version);
                }
            }

            // PostgreSQL
            5432 => {
                if let Ok(db_info) = self.db_parser.detect_postgresql(target, port).await {
                    service_info.service = "postgresql".to_string();
                    service_info.product = Some("PostgreSQL".to_string());
                    if !db_info.auth_methods.is_empty() {
                        service_info.extra_info = Some(format!(
                            "Auth: {}",
                            db_info.auth_methods.join(", ")
                        ));
                    }
                    service_info.confidence = 90;
                    info!("PostgreSQL detected");
                }
            }

            // Redis
            6379 => {
                if let Ok(db_info) = self.db_parser.detect_redis(target, port).await {
                    service_info.service = "redis".to_string();
                    service_info.product = Some("Redis".to_string());
                    let version = db_info.version.clone();
                    service_info.version = version.clone();
                    if !db_info.capabilities.is_empty() {
                        service_info.extra_info =
                            Some(db_info.capabilities.join(", "));
                    }
                    service_info.confidence = 95;
                    info!("Redis detected: {:?}", version);
                }
            }

            // HTTP/2 ports
            80 | 443 | 8080 | 8443 => {
                if let Ok(http2_info) = self.http2_parser.detect(target, port).await {
                    if http2_info.supports_h2c || http2_info.supports_h2 {
                        service_info.extra_info = Some(format!(
                            "HTTP/2 supported, h2c: {}, h2: {}",
                            http2_info.supports_h2c, http2_info.supports_h2
                        ));
                        service_info.confidence = service_info.confidence.max(90);
                        info!("HTTP/2 support detected");
                    }
                }
            }

            _ => {}
        }

        service_info
    }

    /// Multi-probe detection for higher intensity levels
    async fn multi_probe_detection(
        &self,
        target: IpAddr,
        port: u16,
        service_info: ServiceInfo,
    ) -> ServiceInfo {
        // Get applicable probes for this port
        let probes = self.probe_db.probes_for_port(port);
        
        if self.config.trace {
            debug!(
                "Running {} probes for port {} at intensity {}",
                probes.len(),
                port,
                self.config.intensity.value()
            );
        }

        // Filter probes by intensity
        let applicable_probes: Vec<_> = probes
            .iter()
            .filter(|p| p.should_use(&self.config.intensity))
            .collect();

        info!(
            "Multi-probe detection: {} probes applicable",
            applicable_probes.len()
        );

        // Load all signatures for matching
        let signatures = all_signatures();
        let mut best_info = service_info;

        // Try each probe
        for probe in &applicable_probes {
            // Send probe and get response
            let response = match self.send_probe(target, port, probe).await {
                Ok(data) if !data.is_empty() => data,
                _ => continue,
            };

            // Try to match response against signatures
            if let Some(matched) = self.match_response(&response, &signatures, port) {
                if matched.confidence > best_info.confidence {
                    best_info = matched;
                    // If we got a high-confidence match, stop probing
                    if best_info.confidence >= 90 {
                        break;
                    }
                }
            }
        }

        best_info
    }

    /// Send a probe to a target port and capture the response
    async fn send_probe(&self, target: IpAddr, port: u16, probe: &super::intensity::ServiceProbe) -> Result<Vec<u8>> {
        let addr = SocketAddr::new(target, port);
        let connect_timeout = Duration::from_millis(self.config.probe_timeout_ms);
        
        let mut stream = match timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(Vec::new()),
        };

        // Send probe data (empty for NULL/banner-only probes)
        if !probe.probe_data.is_empty() {
            let _ = timeout(
                Duration::from_millis(1000),
                stream.write_all(&probe.probe_data),
            ).await;
        }

        // Read response
        let mut buffer = vec![0u8; 65536];
        let read_timeout = Duration::from_millis(2000);
        let n = match timeout(read_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            _ => 0,
        };

        buffer.truncate(n);
        Ok(buffer)
    }

    /// Match a response against signatures
    fn match_response(&self, data: &[u8], signatures: &[MatchPattern], port: u16) -> Option<ServiceInfo> {
        let mut best_match: Option<ServiceInfo> = None;

        for sig in signatures {
            // Compile regex and try to match
            let pattern = if sig.case_insensitive {
                format!("(?i){}", sig.pattern_str)
            } else {
                sig.pattern_str.clone()
            };

            let re = match Regex::new(&pattern) {
                Ok(r) => r,
                Err(_) => continue,
            };

            if let Some(caps) = re.captures(data) {
                // Extract version from capture groups
                let version = sig.version_info.version_template.as_ref().map(|tmpl| {
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

                let info = ServiceInfo {
                    port,
                    protocol: "tcp".to_string(),
                    service: sig.service.clone(),
                    product: sig.version_info.product.clone(),
                    version,
                    extra_info: None,
                    banner: Some(String::from_utf8_lossy(data).to_string()),
                    confidence,
                };

                // Hard match wins immediately
                if !sig.is_softmatch {
                    return Some(info);
                }

                // Keep best soft match as fallback
                if best_match.is_none() || confidence > best_match.as_ref().unwrap().confidence {
                    best_match = Some(info);
                }
            }
        }

        best_match
    }

    /// Get statistics about available probes
    pub fn probe_statistics(&self) -> ProbeStatistics {
        let all_probes = self.probe_db.all_probes();
        let applicable = all_probes
            .iter()
            .filter(|p| p.should_use(&self.config.intensity))
            .count();

        ProbeStatistics {
            total_probes: all_probes.len(),
            applicable_probes: applicable,
            intensity: self.config.intensity.value(),
        }
    }
}

/// Statistics about probe database
#[derive(Debug, Clone)]
pub struct ProbeStatistics {
    pub total_probes: usize,
    pub applicable_probes: usize,
    pub intensity: u8,
}

impl Default for EnhancedServiceDetector {
    fn default() -> Self {
        Self::new(DetectionConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enhanced_detector_creation() {
        let detector = EnhancedServiceDetector::new(DetectionConfig::default());
        let stats = detector.probe_statistics();
        
        assert!(stats.total_probes > 0);
        assert!(stats.applicable_probes > 0);
        assert_eq!(stats.intensity, 7); // default
    }

    #[test]
    fn test_enhanced_detector_light_mode() {
        let detector = EnhancedServiceDetector::new(DetectionConfig::light());
        let stats = detector.probe_statistics();
        
        assert_eq!(stats.intensity, 2);
        assert!(stats.applicable_probes < stats.total_probes);
    }

    #[test]
    fn test_enhanced_detector_all_mode() {
        let detector = EnhancedServiceDetector::new(DetectionConfig::all());
        let stats = detector.probe_statistics();
        
        assert_eq!(stats.intensity, 9);
        assert_eq!(stats.applicable_probes, stats.total_probes);
    }

    #[test]
    fn test_probe_statistics_intensity_filtering() {
        let light = EnhancedServiceDetector::new(DetectionConfig::light());
        let default = EnhancedServiceDetector::new(DetectionConfig::default());
        let all = EnhancedServiceDetector::new(DetectionConfig::all());

        let light_stats = light.probe_statistics();
        let default_stats = default.probe_statistics();
        let all_stats = all.probe_statistics();

        // Higher intensity should have more or equal probes
        assert!(light_stats.applicable_probes <= default_stats.applicable_probes);
        assert!(default_stats.applicable_probes <= all_stats.applicable_probes);
    }
}
