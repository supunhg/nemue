// Network Topology Discovery Module
// Implements traceroute, network mapping, and device classification

pub mod device;
pub mod inventory;
pub mod mac_lookup;
pub mod mapper;
pub mod traceroute;
pub mod visualization;

pub use device::{DeviceClassifier, DeviceInfo, DeviceType};
pub use inventory::{AssetInfo, ServiceCatalog, ServiceInfo};
pub use mac_lookup::{DeviceCategory, MacVendorLookup};
pub use mapper::{
    ConnectionType, DeviceConnection, MappingServiceState, NetworkMapper, NetworkSegment,
    SegmentType, ServiceMapping, TopologyMap, TopologyMetadata, TopologyStatistics,
};
pub use traceroute::{
    HopInfo, IcmpTraceroute, ParallelTraceroute, TcpTraceroute, Traceroute, TracerouteConfig,
    TracerouteProtocol, TracerouteResult, UdpTraceroute,
};
pub use visualization::VisualizationEngine;

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
