// Network topology mapping and visualization
use std::net::IpAddr;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::topology::{TracerouteResult, DeviceInfo, DeviceType};

/// Network segment (subnet)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSegment {
    pub network: String,
    pub cidr: Option<u8>,
    pub devices: Vec<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub vlan_id: Option<u16>,
    pub segment_type: SegmentType,
}

/// Segment type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SegmentType {
    Core,
    Distribution,
    Access,
    Dmz,
    Guest,
    Management,
    Unknown,
}

impl std::fmt::Display for SegmentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SegmentType::Core => write!(f, "Core"),
            SegmentType::Distribution => write!(f, "Distribution"),
            SegmentType::Access => write!(f, "Access"),
            SegmentType::Dmz => write!(f, "DMZ"),
            SegmentType::Guest => write!(f, "Guest"),
            SegmentType::Management => write!(f, "Management"),
            SegmentType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Connection between devices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConnection {
    pub from: IpAddr,
    pub to: IpAddr,
    pub latency: Option<std::time::Duration>,
    pub bandwidth: Option<u64>,
    pub connection_type: ConnectionType,
}

/// Connection type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConnectionType {
    Wired,
    Wireless,
    Vpn,
    Tunnel,
    Virtual,
    Unknown,
}

/// Service mapping information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceMapping {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub service_name: String,
    pub version: Option<String>,
    pub state: MappingServiceState,
}

/// Service state for mapping
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MappingServiceState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

/// Complete topology map
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyMap {
    pub target: IpAddr,
    pub segments: Vec<NetworkSegment>,
    pub devices: HashMap<IpAddr, DeviceInfo>,
    pub path_to_target: Vec<IpAddr>,
    pub connections: Vec<DeviceConnection>,
    pub services: Vec<ServiceMapping>,
    pub scan_time: String,
    pub metadata: TopologyMetadata,
}

/// Topology metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyMetadata {
    pub total_devices: usize,
    pub total_segments: usize,
    pub total_connections: usize,
    pub total_services: usize,
    pub device_type_distribution: HashMap<String, usize>,
    pub os_distribution: HashMap<String, usize>,
}

impl TopologyMap {
    /// Export topology as DOT (Graphviz) format
    pub fn to_dot(&self) -> String {
        let mut dot = String::from("digraph NetworkTopology {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box];\n\n");

        // Add nodes with cluster by segment
        for segment in &self.segments {
            dot.push_str(&format!("  subgraph cluster_{} {{\n", segment.network.replace('.', "_").replace('/', "_")));
            dot.push_str(&format!("    label=\"{} ({})\";\n", segment.network, segment.segment_type));
            dot.push_str("    style=dashed;\n");
            
            for addr in &segment.devices {
                if let Some(info) = self.devices.get(addr) {
                    let label = format!("{}\\n{}", addr, info.device_type);
                    let color = Self::get_device_color(&info.device_type);
                    dot.push_str(&format!(
                        "    \"{}\" [label=\"{}\", style=filled, fillcolor={}];\n",
                        addr, label, color
                    ));
                }
            }
            dot.push_str("  }\n\n");
        }

        // Add connections
        for conn in &self.connections {
            let style = match conn.connection_type {
                ConnectionType::Wired => "solid",
                ConnectionType::Wireless => "dashed",
                ConnectionType::Vpn => "dotted",
                ConnectionType::Tunnel => "bold",
                ConnectionType::Virtual => "dashed",
                ConnectionType::Unknown => "solid",
            };
            dot.push_str(&format!(
                "  \"{}\" -> \"{}\" [style={}];\n",
                conn.from, conn.to, style
            ));
        }

        // Add path edges
        for i in 0..self.path_to_target.len().saturating_sub(1) {
            let from = &self.path_to_target[i];
            let to = &self.path_to_target[i + 1];
            dot.push_str(&format!("  \"{}\" -> \"{}\" [color=red, penwidth=2];\n", from, to));
        }

        dot.push_str("}\n");
        dot
    }

    /// Export as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Export as HTML with interactive visualization
    pub fn to_html(&self) -> String {
        crate::topology::visualization::VisualizationEngine::generate_html(self)
    }

    /// Export as SVG diagram
    pub fn to_svg(&self) -> String {
        crate::topology::visualization::VisualizationEngine::generate_svg(self)
    }

    /// Get color for device type
    fn get_device_color(device_type: &DeviceType) -> &'static str {
        match device_type {
            DeviceType::Router => "lightblue",
            DeviceType::Switch => "lightgreen",
            DeviceType::Firewall => "orange",
            DeviceType::Server => "yellow",
            DeviceType::Workstation => "plum",
            DeviceType::Printer => "pink",
            DeviceType::IoT => "cyan",
            DeviceType::Mobile => "lavender",
            DeviceType::Camera => "salmon",
            DeviceType::VoIP => "gold",
            DeviceType::Unknown => "white",
        }
    }

    /// Get topology statistics
    pub fn get_statistics(&self) -> TopologyStatistics {
        let mut device_counts: HashMap<String, usize> = HashMap::new();
        for info in self.devices.values() {
            *device_counts.entry(info.device_type.to_string()).or_insert(0) += 1;
        }

        let mut os_counts: HashMap<String, usize> = HashMap::new();
        for info in self.devices.values() {
            if let Some(os) = &info.os_family {
                *os_counts.entry(os.clone()).or_insert(0) += 1;
            }
        }

        TopologyStatistics {
            total_devices: self.devices.len(),
            total_segments: self.segments.len(),
            total_connections: self.connections.len(),
            total_services: self.services.len(),
            device_type_distribution: device_counts,
            os_distribution: os_counts,
        }
    }

    /// Find devices by type
    pub fn find_devices_by_type(&self, device_type: DeviceType) -> Vec<&IpAddr> {
        self.devices.iter()
            .filter(|(_, info)| info.device_type == device_type)
            .map(|(addr, _)| addr)
            .collect()
    }

    /// Find devices by OS
    pub fn find_devices_by_os(&self, os: &str) -> Vec<&IpAddr> {
        self.devices.iter()
            .filter(|(_, info)| {
                info.os_family.as_ref().map(|os_family| os_family.contains(os)).unwrap_or(false)
            })
            .map(|(addr, _)| addr)
            .collect()
    }

    /// Get segment for device
    pub fn get_segment_for_device(&self, device: &IpAddr) -> Option<&NetworkSegment> {
        self.segments.iter().find(|s| s.devices.contains(device))
    }
}

/// Topology statistics
#[derive(Debug, Serialize)]
pub struct TopologyStatistics {
    pub total_devices: usize,
    pub total_segments: usize,
    pub total_connections: usize,
    pub total_services: usize,
    pub device_type_distribution: HashMap<String, usize>,
    pub os_distribution: HashMap<String, usize>,
}

/// Network topology mapper
pub struct NetworkMapper {
    devices: HashMap<IpAddr, DeviceInfo>,
    connections: Vec<DeviceConnection>,
    services: Vec<ServiceMapping>,
}

impl NetworkMapper {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
            connections: Vec::new(),
            services: Vec::new(),
        }
    }

    /// Add a device to the topology
    pub fn add_device(&mut self, address: IpAddr, info: DeviceInfo) {
        self.devices.insert(address, info);
    }

    /// Add a connection between devices
    pub fn add_connection(&mut self, connection: DeviceConnection) {
        self.connections.push(connection);
    }

    /// Add a service mapping
    pub fn add_service(&mut self, service: ServiceMapping) {
        self.services.push(service);
    }

    /// Classify device based on open ports
    pub fn classify_device_by_ports(&self, ports: &[u16]) -> DeviceType {
        let has_http = ports.contains(&80);
        let has_https = ports.contains(&443);
        let has_ssh = ports.contains(&22);
        let has_telnet = ports.contains(&23);
        let has_smtp = ports.contains(&25);
        let has_dns = ports.contains(&53);
        let has_dhcp = ports.contains(&67) || ports.contains(&68);
        let has_snmp = ports.contains(&161);
        let has_ldap = ports.contains(&389);
        let has_smb = ports.contains(&445) || ports.contains(&139);
        let has_printer = ports.contains(&515) || ports.contains(&631);
        let has_voip = ports.contains(&5060) || ports.contains(&5061);
        let has_camera = ports.contains(&554) || ports.contains(&8554);

        if has_dns || has_dhcp || has_snmp {
            DeviceType::Router
        } else if has_telnet && !has_http {
            DeviceType::Switch
        } else if has_printer {
            DeviceType::Printer
        } else if has_voip {
            DeviceType::VoIP
        } else if has_camera {
            DeviceType::Camera
        } else if has_ldap || has_smb || (has_http && has_ssh) {
            DeviceType::Server
        } else if has_http || has_https {
            DeviceType::Workstation
        } else if has_ssh {
            DeviceType::Workstation
        } else {
            DeviceType::Unknown
        }
    }

    /// Build topology map from traceroute results
    pub fn build_topology(&self, trace_result: &TracerouteResult) -> Result<TopologyMap, String> {
        let mut path = Vec::new();
        let mut segments = Vec::new();

        // Extract path from hops
        for hop in &trace_result.hops {
            if let Some(addr) = hop.address {
                path.push(addr);
            }
        }

        // Group devices by network segment
        let mut current_segment = NetworkSegment {
            network: "0.0.0.0/0".to_string(),
            cidr: None,
            devices: Vec::new(),
            gateway: path.first().copied(),
            vlan_id: None,
            segment_type: SegmentType::Unknown,
        };

        for addr in &path {
            current_segment.devices.push(*addr);
        }

        if !current_segment.devices.is_empty() {
            segments.push(current_segment);
        }

        // Generate metadata
        let mut device_type_distribution = HashMap::new();
        for info in self.devices.values() {
            *device_type_distribution.entry(info.device_type.to_string()).or_insert(0) += 1;
        }

        let mut os_distribution = HashMap::new();
        for info in self.devices.values() {
            if let Some(os) = &info.os_family {
                *os_distribution.entry(os.clone()).or_insert(0) += 1;
            }
        }

        let now = chrono::Utc::now();

        let total_segments = segments.len();

        Ok(TopologyMap {
            target: trace_result.target,
            segments,
            devices: self.devices.clone(),
            path_to_target: path,
            connections: self.connections.clone(),
            services: self.services.clone(),
            scan_time: now.to_rfc3339(),
            metadata: TopologyMetadata {
                total_devices: self.devices.len(),
                total_segments,
                total_connections: self.connections.len(),
                total_services: self.services.len(),
                device_type_distribution,
                os_distribution,
            },
        })
    }

    /// Build topology from multiple traceroutes
    pub fn build_multi_topology(&self, trace_results: &[TracerouteResult]) -> Result<TopologyMap, String> {
        if trace_results.is_empty() {
            return Err("No traceroute results provided".to_string());
        }

        let target = trace_results[0].target;
        let mut path = Vec::new();
        let mut segments = Vec::new();
        let mut seen_addrs = std::collections::HashSet::new();

        // Merge paths from all traceroutes
        for result in trace_results {
            for hop in &result.hops {
                if let Some(addr) = hop.address {
                    if !seen_addrs.contains(&addr) {
                        seen_addrs.insert(addr);
                        path.push(addr);
                    }
                }
            }
        }

        // Create segments based on IP ranges
        let mut segment_map: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for addr in &path {
            let network = Self::get_network_prefix(*addr);
            segment_map.entry(network.clone()).or_insert_with(Vec::new).push(*addr);
        }

        for (network, devices) in segment_map {
            segments.push(NetworkSegment {
                network: network.clone(),
                cidr: None,
                devices,
                gateway: None,
                vlan_id: None,
                segment_type: SegmentType::Unknown,
            });
        }

        // Generate metadata
        let mut device_type_distribution = HashMap::new();
        for info in self.devices.values() {
            *device_type_distribution.entry(info.device_type.to_string()).or_insert(0) += 1;
        }

        let mut os_distribution = HashMap::new();
        for info in self.devices.values() {
            if let Some(os) = &info.os_family {
                *os_distribution.entry(os.clone()).or_insert(0) += 1;
            }
        }

        let now = chrono::Utc::now();

        let total_segments = segments.len();

        Ok(TopologyMap {
            target,
            segments,
            devices: self.devices.clone(),
            path_to_target: path,
            connections: self.connections.clone(),
            services: self.services.clone(),
            scan_time: now.to_rfc3339(),
            metadata: TopologyMetadata {
                total_devices: self.devices.len(),
                total_segments,
                total_connections: self.connections.len(),
                total_services: self.services.len(),
                device_type_distribution,
                os_distribution,
            },
        })
    }

    /// Get network prefix from IP address
    fn get_network_prefix(addr: IpAddr) -> String {
        match addr {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(_) => "::/0".to_string(),
        }
    }
}

impl Default for NetworkMapper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use crate::topology::DeviceType;

    #[test]
    fn test_network_mapper_creation() {
        let mapper = NetworkMapper::new();
        assert_eq!(mapper.devices.len(), 0);
        assert_eq!(mapper.connections.len(), 0);
        assert_eq!(mapper.services.len(), 0);
    }

    #[test]
    fn test_add_device() {
        let mut mapper = NetworkMapper::new();
        let addr = IpAddr::from_str("192.168.1.1").unwrap();
        let info = DeviceInfo {
            device_type: DeviceType::Router,
            os_family: Some("Linux".to_string()),
            vendor: None,
            hostname: None,
        };
        mapper.add_device(addr, info);
        assert_eq!(mapper.devices.len(), 1);
    }

    #[test]
    fn test_add_connection() {
        let mut mapper = NetworkMapper::new();
        let conn = DeviceConnection {
            from: IpAddr::from_str("192.168.1.1").unwrap(),
            to: IpAddr::from_str("192.168.1.2").unwrap(),
            latency: Some(std::time::Duration::from_millis(5)),
            bandwidth: Some(1000),
            connection_type: ConnectionType::Wired,
        };
        mapper.add_connection(conn);
        assert_eq!(mapper.connections.len(), 1);
    }

    #[test]
    fn test_add_service() {
        let mut mapper = NetworkMapper::new();
        let service = ServiceMapping {
            ip: IpAddr::from_str("192.168.1.100").unwrap(),
            port: 80,
            protocol: "tcp".to_string(),
            service_name: "http".to_string(),
            version: Some("nginx".to_string()),
            state: MappingServiceState::Open,
        };
        mapper.add_service(service);
        assert_eq!(mapper.services.len(), 1);
    }

    #[test]
    fn test_classify_device_by_ports() {
        let mapper = NetworkMapper::new();
        
        // Router (DNS, DHCP, SNMP)
        assert_eq!(mapper.classify_device_by_ports(&[53, 67, 161]), DeviceType::Router);
        
        // Switch (Telnet without HTTP)
        assert_eq!(mapper.classify_device_by_ports(&[23]), DeviceType::Switch);
        
        // Printer
        assert_eq!(mapper.classify_device_by_ports(&[515, 631]), DeviceType::Printer);
        
        // VoIP
        assert_eq!(mapper.classify_device_by_ports(&[5060, 5061]), DeviceType::VoIP);
        
        // Camera
        assert_eq!(mapper.classify_device_by_ports(&[554, 8554]), DeviceType::Camera);
        
        // Server (LDAP, SMB)
        assert_eq!(mapper.classify_device_by_ports(&[389, 445]), DeviceType::Server);
    }

    #[test]
    fn test_topology_map_to_dot() {
        let mut devices = HashMap::new();
        let router = IpAddr::from_str("192.168.1.1").unwrap();
        devices.insert(router, DeviceInfo {
            device_type: DeviceType::Router,
            os_family: Some("Cisco IOS".to_string()),
            vendor: Some("Cisco".to_string()),
            hostname: Some("gw1".to_string()),
        });

        let map = TopologyMap {
            target: IpAddr::from_str("8.8.8.8").unwrap(),
            segments: vec![NetworkSegment {
                network: "192.168.1.0/24".to_string(),
                cidr: Some(24),
                devices: vec![router],
                gateway: Some(router),
                vlan_id: None,
                segment_type: SegmentType::Access,
            }],
            devices,
            path_to_target: vec![router],
            connections: vec![],
            services: vec![],
            scan_time: chrono::Utc::now().to_rfc3339(),
            metadata: TopologyMetadata {
                total_devices: 1,
                total_segments: 1,
                total_connections: 0,
                total_services: 0,
                device_type_distribution: HashMap::new(),
                os_distribution: HashMap::new(),
            },
        };

        let dot = map.to_dot();
        assert!(dot.contains("digraph NetworkTopology"));
        assert!(dot.contains("192.168.1.1"));
        assert!(dot.contains("Router"));
        assert!(dot.contains("Access"));
    }

    #[test]
    fn test_topology_statistics() {
        let mut devices = HashMap::new();
        devices.insert(IpAddr::from_str("192.168.1.1").unwrap(), DeviceInfo {
            device_type: DeviceType::Router,
            os_family: Some("Linux".to_string()),
            vendor: None,
            hostname: None,
        });
        devices.insert(IpAddr::from_str("192.168.1.2").unwrap(), DeviceInfo {
            device_type: DeviceType::Switch,
            os_family: Some("Cisco".to_string()),
            vendor: None,
            hostname: None,
        });

        let map = TopologyMap {
            target: IpAddr::from_str("8.8.8.8").unwrap(),
            segments: vec![],
            devices,
            path_to_target: vec![],
            connections: vec![],
            services: vec![],
            scan_time: chrono::Utc::now().to_rfc3339(),
            metadata: TopologyMetadata {
                total_devices: 2,
                total_segments: 0,
                total_connections: 0,
                total_services: 0,
                device_type_distribution: HashMap::new(),
                os_distribution: HashMap::new(),
            },
        };

        let stats = map.get_statistics();
        assert_eq!(stats.total_devices, 2);
        assert!(stats.device_type_distribution.contains_key("Router"));
        assert!(stats.os_distribution.contains_key("Linux"));
    }

    #[test]
    fn test_find_devices_by_type() {
        let mut devices = HashMap::new();
        devices.insert(IpAddr::from_str("192.168.1.1").unwrap(), DeviceInfo {
            device_type: DeviceType::Router,
            os_family: None,
            vendor: None,
            hostname: None,
        });
        devices.insert(IpAddr::from_str("192.168.1.2").unwrap(), DeviceInfo {
            device_type: DeviceType::Switch,
            os_family: None,
            vendor: None,
            hostname: None,
        });

        let map = TopologyMap {
            target: IpAddr::from_str("8.8.8.8").unwrap(),
            segments: vec![],
            devices,
            path_to_target: vec![],
            connections: vec![],
            services: vec![],
            scan_time: chrono::Utc::now().to_rfc3339(),
            metadata: TopologyMetadata {
                total_devices: 2,
                total_segments: 0,
                total_connections: 0,
                total_services: 0,
                device_type_distribution: HashMap::new(),
                os_distribution: HashMap::new(),
            },
        };

        let routers = map.find_devices_by_type(DeviceType::Router);
        assert_eq!(routers.len(), 1);
        assert_eq!(*routers[0], IpAddr::from_str("192.168.1.1").unwrap());
    }

    #[test]
    fn test_segment_type_display() {
        assert_eq!(SegmentType::Core.to_string(), "Core");
        assert_eq!(SegmentType::Dmz.to_string(), "DMZ");
        assert_eq!(SegmentType::Management.to_string(), "Management");
    }

    #[test]
    fn test_connection_type() {
        let conn = DeviceConnection {
            from: IpAddr::from_str("192.168.1.1").unwrap(),
            to: IpAddr::from_str("192.168.1.2").unwrap(),
            latency: None,
            bandwidth: None,
            connection_type: ConnectionType::Wireless,
        };
        assert_eq!(conn.connection_type, ConnectionType::Wireless);
    }
}
