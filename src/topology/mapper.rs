// Network topology mapping and visualization
use std::net::IpAddr;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::topology::{TracerouteResult, DeviceInfo};

/// Network segment (subnet)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSegment {
    pub network: String,
    pub devices: Vec<IpAddr>,
    pub gateway: Option<IpAddr>,
}

/// Complete topology map
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyMap {
    pub target: IpAddr,
    pub segments: Vec<NetworkSegment>,
    pub devices: HashMap<IpAddr, DeviceInfo>,
    pub path_to_target: Vec<IpAddr>,
}

impl TopologyMap {
    /// Export topology as DOT (Graphviz) format
    pub fn to_dot(&self) -> String {
        let mut dot = String::from("digraph NetworkTopology {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box];\n\n");

        // Add nodes
        for (addr, info) in &self.devices {
            let label = format!("{}\\n{}", addr, info.device_type);
            let color = match info.device_type {
                crate::topology::DeviceType::Router => "lightblue",
                crate::topology::DeviceType::Switch => "lightgreen",
                crate::topology::DeviceType::Firewall => "orange",
                crate::topology::DeviceType::Server => "yellow",
                _ => "white",
            };
            dot.push_str(&format!(
                "  \"{}\" [label=\"{}\", style=filled, fillcolor={}];\n",
                addr, label, color
            ));
        }

        // Add edges (path)
        for i in 0..self.path_to_target.len().saturating_sub(1) {
            let from = &self.path_to_target[i];
            let to = &self.path_to_target[i + 1];
            dot.push_str(&format!("  \"{}\" -> \"{}\";\n", from, to));
        }

        dot.push_str("}\n");
        dot
    }

    /// Export as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

/// Network topology mapper
pub struct NetworkMapper {
    devices: HashMap<IpAddr, DeviceInfo>,
}

impl NetworkMapper {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }

    /// Add a device to the topology
    pub fn add_device(&mut self, address: IpAddr, info: DeviceInfo) {
        self.devices.insert(address, info);
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
            devices: Vec::new(),
            gateway: path.first().copied(),
        };

        for addr in &path {
            current_segment.devices.push(*addr);
        }

        if !current_segment.devices.is_empty() {
            segments.push(current_segment);
        }

        Ok(TopologyMap {
            target: trace_result.target,
            segments,
            devices: self.devices.clone(),
            path_to_target: path,
        })
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
            segments: vec![],
            devices,
            path_to_target: vec![router],
        };

        let dot = map.to_dot();
        assert!(dot.contains("digraph NetworkTopology"));
        assert!(dot.contains("192.168.1.1"));
        assert!(dot.contains("Router"));
    }
}
