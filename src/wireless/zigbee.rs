use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ZigbeeSecurityLevel {
    None,
    Residential,
    Standard,
    High,
}

impl ZigbeeSecurityLevel {
    pub fn is_secure(&self) -> bool {
        matches!(
            self,
            ZigbeeSecurityLevel::Standard | ZigbeeSecurityLevel::High
        )
    }

    pub fn as_str(&self) -> &str {
        match self {
            ZigbeeSecurityLevel::None => "None",
            ZigbeeSecurityLevel::Residential => "Residential",
            ZigbeeSecurityLevel::Standard => "Standard",
            ZigbeeSecurityLevel::High => "High",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ZigbeeDeviceType {
    Coordinator,
    Router,
    EndDevice,
}

impl ZigbeeDeviceType {
    pub fn as_str(&self) -> &str {
        match self {
            ZigbeeDeviceType::Coordinator => "Coordinator",
            ZigbeeDeviceType::Router => "Router",
            ZigbeeDeviceType::EndDevice => "End Device",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZigbeeNetwork {
    pub pan_id: u16,
    pub extended_pan_id: u64,
    pub channel: u8,
    pub coordinator_addr: u16,
    pub permit_joining: bool,
    pub security_level: ZigbeeSecurityLevel,
    pub network_key_known: bool,
    pub devices: Vec<ZigbeeDevice>,
    pub stack_profile: u8,
    pub vulnerabilities: Vec<String>,
}

impl ZigbeeNetwork {
    pub fn assess_security(&mut self) {
        self.vulnerabilities.clear();

        if self.security_level == ZigbeeSecurityLevel::None {
            self.vulnerabilities
                .push("Network has no security enabled".to_string());
        }

        if self.security_level == ZigbeeSecurityLevel::Residential {
            self.vulnerabilities
                .push("Residential security uses well-known default key".to_string());
        }

        if self.permit_joining {
            self.vulnerabilities
                .push("Network permit-joining is enabled (allows new device joins)".to_string());
        }

        if self.network_key_known {
            self.vulnerabilities
                .push("Network key is known/default - should be rotated".to_string());
        }

        if self.channel > 26 {
            self.vulnerabilities
                .push("Invalid Zigbee channel detected".to_string());
        }
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn router_count(&self) -> usize {
        self.devices
            .iter()
            .filter(|d| d.device_type == ZigbeeDeviceType::Router)
            .count()
    }

    pub fn end_device_count(&self) -> usize {
        self.devices
            .iter()
            .filter(|d| d.device_type == ZigbeeDeviceType::EndDevice)
            .count()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZigbeeDevice {
    pub network_addr: u16,
    pub ieee_addr: u64,
    pub device_type: ZigbeeDeviceType,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub power_source: PowerSource,
    pub rx_on_when_idle: bool,
    pub endpoints: Vec<ZigbeeEndpoint>,
    pub last_seen: Option<String>,
    pub signal_strength: Option<i8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PowerSource {
    Mains,
    Battery,
    Unknown,
}

impl PowerSource {
    pub fn as_str(&self) -> &str {
        match self {
            PowerSource::Mains => "Mains",
            PowerSource::Battery => "Battery",
            PowerSource::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZigbeeEndpoint {
    pub endpoint_id: u8,
    pub profile_id: u16,
    pub device_id: u16,
    pub clusters: Vec<ZigbeeCluster>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZigbeeCluster {
    pub cluster_id: u16,
    pub name: String,
    pub is_server: bool,
    pub attributes: Vec<u16>,
}

impl ZigbeeCluster {
    pub fn name_for_id(cluster_id: u16) -> &'static str {
        match cluster_id {
            0x0000 => "Basic",
            0x0001 => "Power Configuration",
            0x0003 => "Identify",
            0x0004 => "Groups",
            0x0005 => "Scenes",
            0x0006 => "On/Off",
            0x0008 => "Level Control",
            0x0019 => "OTA Upgrade",
            0x0020 => "Poll Control",
            0x0101 => "Door Lock",
            0x0201 => "Thermostat",
            0x0301 => "Color Control",
            0x0400 => "Illuminance",
            0x0402 => "Temperature",
            0x0405 => "Humidity",
            0x0406 => "Occupancy",
            0x0500 => "IAS Zone",
            0x0702 => "Metering",
            0x0B04 => "Electrical Measurement",
            _ => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZigbeeScanConfig {
    pub channel: Option<u8>,
    pub channels: Option<Vec<u8>>,
    pub scan_duration_secs: u64,
    pub passive_scan: bool,
    pub include_end_devices: bool,
    pub enumerate_endpoints: bool,
}

impl Default for ZigbeeScanConfig {
    fn default() -> Self {
        Self {
            channel: None,
            channels: None,
            scan_duration_secs: 30,
            passive_scan: true,
            include_end_devices: true,
            enumerate_endpoints: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZigbeeScanResult {
    pub networks: Vec<ZigbeeNetwork>,
    pub scan_duration_secs: u64,
    pub total_networks: usize,
    pub total_devices: usize,
    pub open_networks: usize,
    pub networks_with_join_enabled: usize,
}

impl ZigbeeScanResult {
    pub fn security_summary(&self) -> ZigbeeSecuritySummary {
        let mut summary = ZigbeeSecuritySummary::default();
        summary.total_networks = self.networks.len();
        summary.total_devices = self.total_devices;

        for network in &self.networks {
            match network.security_level {
                ZigbeeSecurityLevel::None => summary.no_security += 1,
                ZigbeeSecurityLevel::Residential => summary.residential += 1,
                ZigbeeSecurityLevel::Standard => summary.standard += 1,
                ZigbeeSecurityLevel::High => summary.high_security += 1,
            }

            if network.permit_joining {
                summary.join_enabled += 1;
            }

            if !network.vulnerabilities.is_empty() {
                summary.vulnerable += 1;
            }
        }

        summary
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZigbeeSecuritySummary {
    pub total_networks: usize,
    pub total_devices: usize,
    pub no_security: usize,
    pub residential: usize,
    pub standard: usize,
    pub high_security: usize,
    pub join_enabled: usize,
    pub vulnerable: usize,
}

pub struct ZigbeeScanner {
    config: ZigbeeScanConfig,
}

impl ZigbeeScanner {
    pub fn new(config: ZigbeeScanConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &ZigbeeScanConfig {
        &self.config
    }

    pub fn protocol_analysis(network: &ZigbeeNetwork) -> ProtocolAnalysis {
        let mut analysis = ProtocolAnalysis {
            pan_id: network.pan_id,
            channel: network.channel,
            security_level: network.security_level.as_str().to_string(),
            topology_type: Self::determine_topology(network),
            device_breakdown: DeviceBreakdown {
                coordinators: network
                    .devices
                    .iter()
                    .filter(|d| d.device_type == ZigbeeDeviceType::Coordinator)
                    .count(),
                routers: network.router_count(),
                end_devices: network.end_device_count(),
            },
            cluster_summary: Self::summarize_clusters(network),
            recommendations: Vec::new(),
        };

        if network.security_level == ZigbeeSecurityLevel::None {
            analysis
                .recommendations
                .push("Enable network security with at least Standard level".to_string());
        }
        if network.permit_joining {
            analysis
                .recommendations
                .push("Disable permit-joining when not adding new devices".to_string());
        }
        if network.router_count() < 2 && network.device_count() > 5 {
            analysis
                .recommendations
                .push("Add more router devices to improve mesh reliability".to_string());
        }

        analysis
    }

    fn determine_topology(network: &ZigbeeNetwork) -> String {
        let has_coordinator = network
            .devices
            .iter()
            .any(|d| d.device_type == ZigbeeDeviceType::Coordinator);
        let has_router = network
            .devices
            .iter()
            .any(|d| d.device_type == ZigbeeDeviceType::Router);

        if has_coordinator && has_router {
            "Star/Mesh".to_string()
        } else if has_coordinator {
            "Star".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    fn summarize_clusters(network: &ZigbeeNetwork) -> Vec<ClusterSummary> {
        let mut cluster_counts: std::collections::HashMap<u16, usize> =
            std::collections::HashMap::new();

        for device in &network.devices {
            for endpoint in &device.endpoints {
                for cluster in &endpoint.clusters {
                    *cluster_counts.entry(cluster.cluster_id).or_insert(0) += 1;
                }
            }
        }

        let mut summaries: Vec<ClusterSummary> = cluster_counts
            .into_iter()
            .map(|(id, count)| ClusterSummary {
                cluster_id: id,
                name: ZigbeeCluster::name_for_id(id).to_string(),
                device_count: count,
            })
            .collect();

        summaries.sort_by(|a, b| b.device_count.cmp(&a.device_count));
        summaries
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolAnalysis {
    pub pan_id: u16,
    pub channel: u8,
    pub security_level: String,
    pub topology_type: String,
    pub device_breakdown: DeviceBreakdown,
    pub cluster_summary: Vec<ClusterSummary>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceBreakdown {
    pub coordinators: usize,
    pub routers: usize,
    pub end_devices: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSummary {
    pub cluster_id: u16,
    pub name: String,
    pub device_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_network(security: ZigbeeSecurityLevel) -> ZigbeeNetwork {
        ZigbeeNetwork {
            pan_id: 0x1234,
            extended_pan_id: 0x0011223344556677,
            channel: 15,
            coordinator_addr: 0x0000,
            permit_joining: false,
            security_level: security,
            network_key_known: false,
            devices: vec![
                ZigbeeDevice {
                    network_addr: 0x0000,
                    ieee_addr: 0x0011223344556677,
                    device_type: ZigbeeDeviceType::Coordinator,
                    manufacturer: Some("TestCo".to_string()),
                    model: Some("Coordinator".to_string()),
                    power_source: PowerSource::Mains,
                    rx_on_when_idle: true,
                    endpoints: vec![ZigbeeEndpoint {
                        endpoint_id: 1,
                        profile_id: 0x0104,
                        device_id: 0x0005,
                        clusters: vec![ZigbeeCluster {
                            cluster_id: 0x0000,
                            name: "Basic".to_string(),
                            is_server: true,
                            attributes: vec![],
                        }],
                    }],
                    last_seen: None,
                    signal_strength: Some(-40),
                },
                ZigbeeDevice {
                    network_addr: 0x0001,
                    ieee_addr: 0xAABBCCDDEEFF0011,
                    device_type: ZigbeeDeviceType::Router,
                    manufacturer: Some("SmartHome".to_string()),
                    model: Some("Bulb".to_string()),
                    power_source: PowerSource::Mains,
                    rx_on_when_idle: true,
                    endpoints: vec![ZigbeeEndpoint {
                        endpoint_id: 1,
                        profile_id: 0x0104,
                        device_id: 0x0100,
                        clusters: vec![ZigbeeCluster {
                            cluster_id: 0x0006,
                            name: "On/Off".to_string(),
                            is_server: true,
                            attributes: vec![],
                        }],
                    }],
                    last_seen: None,
                    signal_strength: Some(-55),
                },
            ],
            stack_profile: 2,
            vulnerabilities: Vec::new(),
        }
    }

    #[test]
    fn test_zigbee_security_level() {
        assert!(!ZigbeeSecurityLevel::None.is_secure());
        assert!(!ZigbeeSecurityLevel::Residential.is_secure());
        assert!(ZigbeeSecurityLevel::Standard.is_secure());
        assert!(ZigbeeSecurityLevel::High.is_secure());
    }

    #[test]
    fn test_network_security_assessment() {
        let mut network = create_test_network(ZigbeeSecurityLevel::None);
        network.assess_security();
        assert!(!network.vulnerabilities.is_empty());
        assert!(network
            .vulnerabilities
            .iter()
            .any(|v| v.contains("no security")));
    }

    #[test]
    fn test_network_permit_joining() {
        let mut network = create_test_network(ZigbeeSecurityLevel::Standard);
        network.permit_joining = true;
        network.assess_security();
        assert!(network
            .vulnerabilities
            .iter()
            .any(|v| v.contains("permit-joining")));
    }

    #[test]
    fn test_residential_security_warning() {
        let mut network = create_test_network(ZigbeeSecurityLevel::Residential);
        network.assess_security();
        assert!(network
            .vulnerabilities
            .iter()
            .any(|v| v.contains("default key")));
    }

    #[test]
    fn test_device_counts() {
        let network = create_test_network(ZigbeeSecurityLevel::Standard);
        assert_eq!(network.device_count(), 2);
        assert_eq!(network.router_count(), 1);
        assert_eq!(network.end_device_count(), 0);
    }

    #[test]
    fn test_protocol_analysis() {
        let network = create_test_network(ZigbeeSecurityLevel::Standard);
        let analysis = ZigbeeScanner::protocol_analysis(&network);

        assert_eq!(analysis.pan_id, 0x1234);
        assert_eq!(analysis.channel, 15);
        assert_eq!(analysis.device_breakdown.coordinators, 1);
        assert_eq!(analysis.device_breakdown.routers, 1);
    }

    #[test]
    fn test_cluster_name_lookup() {
        assert_eq!(ZigbeeCluster::name_for_id(0x0006), "On/Off");
        assert_eq!(ZigbeeCluster::name_for_id(0x0402), "Temperature");
        assert_eq!(ZigbeeCluster::name_for_id(0xFFFF), "Unknown");
    }

    #[test]
    fn test_security_summary() {
        let networks = vec![
            create_test_network(ZigbeeSecurityLevel::None),
            create_test_network(ZigbeeSecurityLevel::Standard),
        ];

        let result = ZigbeeScanResult {
            networks,
            scan_duration_secs: 30,
            total_networks: 2,
            total_devices: 4,
            open_networks: 1,
            networks_with_join_enabled: 0,
        };

        let summary = result.security_summary();
        assert_eq!(summary.total_networks, 2);
        assert_eq!(summary.no_security, 1);
        assert_eq!(summary.standard, 1);
    }

    #[test]
    fn test_default_scan_config() {
        let config = ZigbeeScanConfig::default();
        assert_eq!(config.scan_duration_secs, 30);
        assert!(config.passive_scan);
    }

    #[test]
    fn test_cluster_summary_generation() {
        let network = create_test_network(ZigbeeSecurityLevel::Standard);
        let analysis = ZigbeeScanner::protocol_analysis(&network);
        assert!(!analysis.cluster_summary.is_empty());
    }
}
