// Network Topology Discovery Module
// Implements traceroute, network mapping, and device classification

pub mod traceroute;
pub mod mapper;
pub mod device;
pub mod visualization;
pub mod mac_lookup;
pub mod inventory;

pub use traceroute::{
    Traceroute, TracerouteConfig, TracerouteResult, HopInfo, TracerouteProtocol,
    IcmpTraceroute, UdpTraceroute, TcpTraceroute, ParallelTraceroute,
};
pub use mapper::{
    NetworkMapper, TopologyMap, NetworkSegment, SegmentType,
    DeviceConnection, ConnectionType, ServiceMapping, MappingServiceState,
    TopologyMetadata, TopologyStatistics,
};
pub use device::{DeviceClassifier, DeviceType, DeviceInfo};
pub use visualization::VisualizationEngine;
pub use mac_lookup::{MacVendorLookup, DeviceCategory};
pub use inventory::{ServiceCatalog, AssetInfo, ServiceInfo};

use std::net::IpAddr;

/// Network topology discovery engine
pub struct TopologyDiscovery {
    traceroute: Traceroute,
    mapper: NetworkMapper,
    classifier: DeviceClassifier,
}

impl TopologyDiscovery {
    pub fn new() -> Self {
        Self {
            traceroute: Traceroute::new(TracerouteConfig::default()),
            mapper: NetworkMapper::new(),
            classifier: DeviceClassifier::new(),
        }
    }

    /// Discover network topology for a target
    pub async fn discover(&mut self, target: IpAddr) -> Result<TopologyMap, String> {
        // Run traceroute to discover path
        let trace_result = self.traceroute.trace(target).await?;
        
        // Classify devices along the path
        for hop in &trace_result.hops {
            if let Some(addr) = hop.address {
                let device_info = self.classifier.classify(addr).await;
                self.mapper.add_device(addr, device_info);
            }
        }
        
        // Build topology map
        self.mapper.build_topology(&trace_result)
    }
}

impl Default for TopologyDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_topology_discovery_creation() {
        let discovery = TopologyDiscovery::new();
        assert!(discovery.traceroute.config().max_hops > 0);
    }
}
