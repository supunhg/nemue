// Shared AF_PACKET channel manager for high-performance scanning
// Provides kernel-level BPF filtering and async receive

use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Shared packet I/O manager - one per interface
pub struct PacketIO {
    interface: String,
    local_ip: Ipv4Addr,
}

impl PacketIO {
    /// Create a new PacketIO for the given interface
    pub fn new(interface: String, local_ip: Ipv4Addr) -> Self {
        Self { interface, local_ip }
    }

    /// Get the local IP address
    pub fn local_ip(&self) -> Ipv4Addr {
        self.local_ip
    }

    /// Get the interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Build a BPF filter string for target-specific filtering
    pub fn build_bpf_filter(target_ip: Ipv4Addr, port: u16) -> String {
        format!("tcp port {} and src host {}", port, target_ip)
    }

    /// Build a BPF filter for multiple ports
    pub fn build_multi_port_filter(target_ip: Ipv4Addr, ports: &[u16]) -> String {
        if ports.is_empty() {
            return format!("src host {}", target_ip);
        }
        let port_filters: Vec<String> = ports.iter().map(|p| format!("tcp port {}", p)).collect();
        format!("({}) and src host {}", port_filters.join(" or "), target_ip)
    }
}

/// Find the best network interface for scanning
pub fn find_best_interface() -> Option<(String, Ipv4Addr)> {
    use pnet::datalink;

    for iface in datalink::interfaces() {
        if iface.is_up() && !iface.is_loopback() {
            for ip in &iface.ips {
                if let std::net::IpAddr::V4(ipv4) = ip.ip() {
                    if !ipv4.is_loopback() && !ipv4.is_link_local() {
                        return Some((iface.name.clone(), ipv4));
                    }
                }
            }
        }
    }
    None
}

/// Shared interface cache - avoids repeated interface lookups
pub struct InterfaceCache {
    cached: Arc<Mutex<Option<(String, Ipv4Addr)>>>,
}

impl InterfaceCache {
    pub fn new() -> Self {
        Self {
            cached: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn get_or_discover(&self) -> Option<(String, Ipv4Addr)> {
        let mut cache = self.cached.lock().await;
        if cache.is_none() {
            *cache = find_best_interface();
        }
        cache.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_filter() {
        let filter = PacketIO::build_bpf_filter("192.168.1.1".parse().unwrap(), 80);
        assert_eq!(filter, "tcp port 80 and src host 192.168.1.1");
    }

    #[test]
    fn test_multi_port_filter() {
        let filter = PacketIO::build_multi_port_filter(
            "10.0.0.1".parse().unwrap(),
            &[22, 80, 443],
        );
        assert!(filter.contains("tcp port 22"));
        assert!(filter.contains("tcp port 80"));
        assert!(filter.contains("tcp port 443"));
        assert!(filter.contains("src host 10.0.0.1"));
    }

    #[test]
    fn test_empty_ports_filter() {
        let filter = PacketIO::build_multi_port_filter("10.0.0.1".parse().unwrap(), &[]);
        assert_eq!(filter, "src host 10.0.0.1");
    }
}
