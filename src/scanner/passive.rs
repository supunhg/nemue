// Passive network discovery module
// Monitors network traffic to discover hosts and services without sending probes

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Passive discovery configuration
#[derive(Debug, Clone)]
pub struct PassiveConfig {
    /// Duration to monitor traffic
    pub monitor_duration: Duration,
    /// Whether to capture DNS responses
    pub capture_dns: bool,
    /// Whether to capture ARP traffic
    pub capture_arp: bool,
    /// Whether to capture DHCP traffic
    pub capture_dhcp: bool,
    /// Whether to capture service banners
    pub capture_banners: bool,
    /// Maximum number of hosts to track
    pub max_hosts: usize,
    /// Maximum number of services per host
    pub max_services_per_host: usize,
}

impl Default for PassiveConfig {
    fn default() -> Self {
        Self {
            monitor_duration: Duration::from_secs(300), // 5 minutes
            capture_dns: true,
            capture_arp: true,
            capture_dhcp: true,
            capture_banners: true,
            max_hosts: 10000,
            max_services_per_host: 100,
        }
    }
}

/// Passive host information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveHost {
    pub ip_address: IpAddr,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub packet_count: u64,
    pub byte_count: u64,
    pub services: Vec<PassiveService>,
    pub os_fingerprint: Option<String>,
}

/// Passive service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveService {
    pub port: u16,
    pub protocol: String,
    pub service_name: Option<String>,
    pub banner: Option<String>,
    pub version: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub connection_count: u64,
}

/// Passive discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveResult {
    pub hosts: Vec<PassiveHost>,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub duration: Duration,
    pub services_discovered: usize,
}

/// Traffic statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: String,
    pub port: u16,
    pub packet_count: u64,
    pub byte_count: u64,
    pub duration: Duration,
}

/// DNS observation
#[derive(Debug, Clone)]
pub struct DnsObservation {
    pub query: String,
    pub response: IpAddr,
    pub ttl: u32,
    pub timestamp: DateTime<Utc>,
}

/// ARP observation
#[derive(Debug, Clone)]
pub struct ArpObservation {
    pub ip: IpAddr,
    pub mac: String,
    pub is_request: bool,
    pub timestamp: DateTime<Utc>,
}

/// DHCP observation
#[derive(Debug, Clone)]
pub struct DhcpObservation {
    pub client_mac: String,
    pub assigned_ip: IpAddr,
    pub hostname: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Passive discovery engine
pub struct PassiveDiscovery {
    config: PassiveConfig,
    hosts: Arc<Mutex<HashMap<IpAddr, PassiveHost>>>,
    dns_observations: Arc<Mutex<Vec<DnsObservation>>>,
    arp_observations: Arc<Mutex<Vec<ArpObservation>>>,
    dhcp_observations: Arc<Mutex<Vec<DhcpObservation>>>,
    traffic_stats: Arc<Mutex<HashMap<(IpAddr, IpAddr, u16), TrafficStats>>>,
    total_packets: Arc<Mutex<u64>>,
    total_bytes: Arc<Mutex<u64>>,
}

impl PassiveDiscovery {
    /// Create a new passive discovery engine
    pub fn new(config: PassiveConfig) -> Self {
        Self {
            config,
            hosts: Arc::new(Mutex::new(HashMap::new())),
            dns_observations: Arc::new(Mutex::new(Vec::new())),
            arp_observations: Arc::new(Mutex::new(Vec::new())),
            dhcp_observations: Arc::new(Mutex::new(Vec::new())),
            traffic_stats: Arc::new(Mutex::new(HashMap::new())),
            total_packets: Arc::new(Mutex::new(0)),
            total_bytes: Arc::new(Mutex::new(0)),
        }
    }

    /// Start passive monitoring
    pub async fn start_monitoring(&self) -> Result<(), String> {
        // In production, this would:
        // 1. Open a raw socket or use pcap
        // 2. Capture packets in promiscuous mode
        // 3. Parse DNS, ARP, DHCP, and service banners
        // 4. Update host and service information

        // For now, return Ok as placeholder
        Ok(())
    }

    /// Process a captured packet
    pub fn process_packet(&self, packet_data: &[u8]) -> Result<(), String> {
        // Parse packet headers
        // Extract IP addresses, ports, and payload
        // Update statistics

        let mut total_packets = self.total_packets.lock().unwrap();
        *total_packets += 1;

        let mut total_bytes = self.total_bytes.lock().unwrap();
        *total_bytes += packet_data.len() as u64;

        Ok(())
    }

    /// Record DNS observation
    pub fn record_dns(&self, observation: DnsObservation) {
        if self.config.capture_dns {
            let mut dns_obs = self.dns_observations.lock().unwrap();
            dns_obs.push(observation);
        }
    }

    /// Record ARP observation
    pub fn record_arp(&self, observation: ArpObservation) {
        if self.config.capture_arp {
            let mac = observation.mac.clone();
            let ip = observation.ip;
            let timestamp = observation.timestamp;

            let mut arp_obs = self.arp_observations.lock().unwrap();
            arp_obs.push(observation);

            // Update host information
            let mut hosts = self.hosts.lock().unwrap();
            let host = hosts.entry(ip).or_insert_with(|| PassiveHost {
                ip_address: ip,
                mac_address: Some(mac.clone()),
                hostname: None,
                vendor: None,
                first_seen: timestamp,
                last_seen: timestamp,
                packet_count: 0,
                byte_count: 0,
                services: Vec::new(),
                os_fingerprint: None,
            });

            host.last_seen = timestamp;
            host.mac_address = Some(mac);
        }
    }

    /// Record DHCP observation
    pub fn record_dhcp(&self, observation: DhcpObservation) {
        if self.config.capture_dhcp {
            let mut dhcp_obs = self.dhcp_observations.lock().unwrap();
            dhcp_obs.push(observation.clone());

            // Update host information
            let mut hosts = self.hosts.lock().unwrap();
            let host = hosts
                .entry(observation.assigned_ip)
                .or_insert_with(|| PassiveHost {
                    ip_address: observation.assigned_ip,
                    mac_address: Some(observation.client_mac.clone()),
                    hostname: observation.hostname.clone(),
                    vendor: None,
                    first_seen: observation.timestamp,
                    last_seen: observation.timestamp,
                    packet_count: 0,
                    byte_count: 0,
                    services: Vec::new(),
                    os_fingerprint: None,
                });

            host.last_seen = observation.timestamp;
            host.mac_address = Some(observation.client_mac);
            if observation.hostname.is_some() {
                host.hostname = observation.hostname;
            }
        }
    }

    /// Record service banner
    pub fn record_banner(&self, ip: IpAddr, port: u16, protocol: &str, banner: &str) {
        if self.config.capture_banners {
            let mut hosts = self.hosts.lock().unwrap();
            if let Some(host) = hosts.get_mut(&ip) {
                if host.services.len() < self.config.max_services_per_host {
                    let service = PassiveService {
                        port,
                        protocol: protocol.to_string(),
                        service_name: Self::identify_service(port, banner),
                        banner: Some(banner.to_string()),
                        version: Self::extract_version(banner),
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                        connection_count: 1,
                    };
                    host.services.push(service);
                }
            }
        }
    }

    /// Identify service from port and banner
    fn identify_service(port: u16, banner: &str) -> Option<String> {
        let banner_lower = banner.to_lowercase();

        match port {
            21 => Some("ftp".to_string()),
            22 => Some("ssh".to_string()),
            23 => Some("telnet".to_string()),
            25 => Some("smtp".to_string()),
            53 => Some("dns".to_string()),
            80 => Some("http".to_string()),
            110 => Some("pop3".to_string()),
            143 => Some("imap".to_string()),
            443 => Some("https".to_string()),
            993 => Some("imaps".to_string()),
            995 => Some("pop3s".to_string()),
            3306 => Some("mysql".to_string()),
            3389 => Some("rdp".to_string()),
            5432 => Some("postgresql".to_string()),
            8080 => Some("http-proxy".to_string()),
            _ => {
                if banner_lower.contains("ssh") {
                    Some("ssh".to_string())
                } else if banner_lower.contains("http") {
                    Some("http".to_string())
                } else if banner_lower.contains("ftp") {
                    Some("ftp".to_string())
                } else {
                    None
                }
            }
        }
    }

    /// Extract version from banner
    fn extract_version(banner: &str) -> Option<String> {
        // Try to extract version information from banner
        // Common patterns: "Apache/2.4.41", "OpenSSH_8.0", "nginx/1.18.0", etc.

        let patterns = [
            r"(\d+\.\d+\.\d+)",
            r"v(\d+\.\d+\.\d+)",
            r"version\s+(\d+\.\d+)",
            r"[_/](\d+\.\d+)",
            r"[_/](\d+\.\d+\.\d+)",
        ];

        for pattern in &patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(captures) = re.captures(banner) {
                    if let Some(version) = captures.get(1) {
                        return Some(version.as_str().to_string());
                    }
                }
            }
        }

        None
    }

    /// Get discovered hosts
    pub fn get_hosts(&self) -> Vec<PassiveHost> {
        let hosts = self.hosts.lock().unwrap();
        hosts.values().cloned().collect()
    }

    /// Get DNS observations
    pub fn get_dns_observations(&self) -> Vec<DnsObservation> {
        let dns_obs = self.dns_observations.lock().unwrap();
        dns_obs.clone()
    }

    /// Get ARP observations
    pub fn get_arp_observations(&self) -> Vec<ArpObservation> {
        let arp_obs = self.arp_observations.lock().unwrap();
        arp_obs.clone()
    }

    /// Get DHCP observations
    pub fn get_dhcp_observations(&self) -> Vec<DhcpObservation> {
        let dhcp_obs = self.dhcp_observations.lock().unwrap();
        dhcp_obs.clone()
    }

    /// Get traffic statistics
    pub fn get_traffic_stats(&self) -> Vec<TrafficStats> {
        let stats = self.traffic_stats.lock().unwrap();
        stats.values().cloned().collect()
    }

    /// Get passive discovery result
    pub fn get_result(&self) -> PassiveResult {
        let hosts = self.get_hosts();
        let total_packets = *self.total_packets.lock().unwrap();
        let total_bytes = *self.total_bytes.lock().unwrap();

        let services_discovered = hosts.iter().map(|h| h.services.len()).sum();

        PassiveResult {
            hosts,
            total_packets,
            total_bytes,
            duration: Duration::from_secs(0), // Would be calculated from start time
            services_discovered,
        }
    }

    /// Merge with active scan results
    pub fn merge_with_active(
        &self,
        active_hosts: &mut HashMap<IpAddr, crate::scanner::DiscoveryResult>,
    ) {
        let passive_hosts = self.get_hosts();

        for passive_host in passive_hosts {
            let active_entry = active_hosts
                .entry(passive_host.ip_address)
                .or_insert_with(|| crate::scanner::DiscoveryResult {
                    target: passive_host.ip_address,
                    is_up: true,
                    responding_methods: vec![],
                    rtt_ms: None,
                    hostname: passive_host.hostname.clone(),
                    mac_address: passive_host.mac_address.clone(),
                    vendor: passive_host.vendor.clone(),
                    distance: None,
                });

            // Merge information
            if passive_host.hostname.is_some() && active_entry.hostname.is_none() {
                active_entry.hostname = passive_host.hostname;
            }
            if passive_host.mac_address.is_some() && active_entry.mac_address.is_none() {
                active_entry.mac_address = passive_host.mac_address;
            }
            if passive_host.vendor.is_some() && active_entry.vendor.is_none() {
                active_entry.vendor = passive_host.vendor;
            }
        }
    }

    /// Clear all observations
    pub fn clear(&self) {
        self.hosts.lock().unwrap().clear();
        self.dns_observations.lock().unwrap().clear();
        self.arp_observations.lock().unwrap().clear();
        self.dhcp_observations.lock().unwrap().clear();
        self.traffic_stats.lock().unwrap().clear();
        *self.total_packets.lock().unwrap() = 0;
        *self.total_bytes.lock().unwrap() = 0;
    }
}

/// Passive discovery builder
pub struct PassiveDiscoveryBuilder {
    config: PassiveConfig,
}

impl PassiveDiscoveryBuilder {
    pub fn new() -> Self {
        Self {
            config: PassiveConfig::default(),
        }
    }

    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.config.monitor_duration = duration;
        self
    }

    pub fn with_dns_capture(mut self, enabled: bool) -> Self {
        self.config.capture_dns = enabled;
        self
    }

    pub fn with_arp_capture(mut self, enabled: bool) -> Self {
        self.config.capture_arp = enabled;
        self
    }

    pub fn with_dhcp_capture(mut self, enabled: bool) -> Self {
        self.config.capture_dhcp = enabled;
        self
    }

    pub fn with_banner_capture(mut self, enabled: bool) -> Self {
        self.config.capture_banners = enabled;
        self
    }

    pub fn with_max_hosts(mut self, max: usize) -> Self {
        self.config.max_hosts = max;
        self
    }

    pub fn build(self) -> PassiveDiscovery {
        PassiveDiscovery::new(self.config)
    }
}

impl Default for PassiveDiscoveryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_passive_config_default() {
        let config = PassiveConfig::default();
        assert!(config.capture_dns);
        assert!(config.capture_arp);
        assert!(config.capture_dhcp);
        assert!(config.capture_banners);
        assert_eq!(config.max_hosts, 10000);
    }

    #[test]
    fn test_passive_discovery_creation() {
        let discovery = PassiveDiscovery::new(PassiveConfig::default());
        let hosts = discovery.get_hosts();
        assert_eq!(hosts.len(), 0);
    }

    #[test]
    fn test_record_dns_observation() {
        let discovery = PassiveDiscovery::new(PassiveConfig::default());
        let observation = DnsObservation {
            query: "example.com".to_string(),
            response: IpAddr::from_str("93.184.216.34").unwrap(),
            ttl: 3600,
            timestamp: Utc::now(),
        };

        discovery.record_dns(observation);
        let dns_obs = discovery.get_dns_observations();
        assert_eq!(dns_obs.len(), 1);
        assert_eq!(dns_obs[0].query, "example.com");
    }

    #[test]
    fn test_record_arp_observation() {
        let discovery = PassiveDiscovery::new(PassiveConfig::default());
        let observation = ArpObservation {
            ip: IpAddr::from_str("192.168.1.1").unwrap(),
            mac: "00:11:22:33:44:55".to_string(),
            is_request: true,
            timestamp: Utc::now(),
        };

        discovery.record_arp(observation);
        let hosts = discovery.get_hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].mac_address, Some("00:11:22:33:44:55".to_string()));
    }

    #[test]
    fn test_record_dhcp_observation() {
        let discovery = PassiveDiscovery::new(PassiveConfig::default());
        let observation = DhcpObservation {
            client_mac: "00:11:22:33:44:55".to_string(),
            assigned_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            hostname: Some("my-laptop".to_string()),
            timestamp: Utc::now(),
        };

        discovery.record_dhcp(observation);
        let hosts = discovery.get_hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, Some("my-laptop".to_string()));
    }

    #[test]
    fn test_identify_service() {
        assert_eq!(
            PassiveDiscovery::identify_service(22, ""),
            Some("ssh".to_string())
        );
        assert_eq!(
            PassiveDiscovery::identify_service(80, ""),
            Some("http".to_string())
        );
        assert_eq!(
            PassiveDiscovery::identify_service(443, ""),
            Some("https".to_string())
        );
        assert_eq!(PassiveDiscovery::identify_service(12345, ""), None);
    }

    #[test]
    fn test_identify_service_from_banner() {
        assert_eq!(
            PassiveDiscovery::identify_service(0, "SSH-2.0-OpenSSH_8.0"),
            Some("ssh".to_string())
        );
        assert_eq!(
            PassiveDiscovery::identify_service(0, "HTTP/1.1 200 OK"),
            Some("http".to_string())
        );
    }

    #[test]
    fn test_extract_version() {
        assert_eq!(
            PassiveDiscovery::extract_version("Apache/2.4.41"),
            Some("2.4.41".to_string())
        );
        assert_eq!(
            PassiveDiscovery::extract_version("OpenSSH_8.0"),
            Some("8.0".to_string())
        );
        assert_eq!(PassiveDiscovery::extract_version("no version here"), None);
    }

    #[test]
    fn test_record_banner() {
        let discovery = PassiveDiscovery::new(PassiveConfig::default());
        let ip = IpAddr::from_str("192.168.1.100").unwrap();

        // First add host via ARP
        discovery.record_arp(ArpObservation {
            ip,
            mac: "00:11:22:33:44:55".to_string(),
            is_request: true,
            timestamp: Utc::now(),
        });

        // Then record banner
        discovery.record_banner(ip, 22, "tcp", "SSH-2.0-OpenSSH_8.0");

        let hosts = discovery.get_hosts();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].services.len(), 1);
        assert_eq!(hosts[0].services[0].service_name, Some("ssh".to_string()));
    }

    #[test]
    fn test_passive_result() {
        let discovery = PassiveDiscovery::new(PassiveConfig::default());

        // Add some test data
        discovery.record_arp(ArpObservation {
            ip: IpAddr::from_str("192.168.1.1").unwrap(),
            mac: "00:11:22:33:44:55".to_string(),
            is_request: true,
            timestamp: Utc::now(),
        });

        let result = discovery.get_result();
        assert_eq!(result.hosts.len(), 1);
        assert_eq!(result.services_discovered, 0);
    }

    #[test]
    fn test_builder() {
        let discovery = PassiveDiscoveryBuilder::new()
            .with_duration(Duration::from_secs(60))
            .with_dns_capture(false)
            .with_arp_capture(true)
            .with_max_hosts(1000)
            .build();

        assert_eq!(discovery.config.monitor_duration, Duration::from_secs(60));
        assert!(!discovery.config.capture_dns);
        assert!(discovery.config.capture_arp);
        assert_eq!(discovery.config.max_hosts, 1000);
    }

    #[test]
    fn test_clear() {
        let discovery = PassiveDiscovery::new(PassiveConfig::default());

        discovery.record_arp(ArpObservation {
            ip: IpAddr::from_str("192.168.1.1").unwrap(),
            mac: "00:11:22:33:44:55".to_string(),
            is_request: true,
            timestamp: Utc::now(),
        });

        assert_eq!(discovery.get_hosts().len(), 1);

        discovery.clear();

        assert_eq!(discovery.get_hosts().len(), 0);
        assert_eq!(discovery.get_arp_observations().len(), 0);
    }
}
