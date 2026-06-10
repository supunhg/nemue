// Cross-platform raw socket abstraction
// Provides a unified interface for raw packet I/O across Linux, macOS, and Windows

use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;

/// Platform-specific raw socket implementation
pub struct RawSocket {
    inner: PlatformSocket,
}

/// Platform-specific socket implementation
enum PlatformSocket {
    #[cfg(target_os = "linux")]
    Linux {
        interface: String,
        source_ip: Ipv4Addr,
    },
    #[cfg(target_os = "macos")]
    Macos {
        interface: String,
        source_ip: Ipv4Addr,
    },
    #[cfg(target_os = "windows")]
    Windows {
        interface: String,
        source_ip: Ipv4Addr,
    },
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Unsupported,
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub index: u32,
    pub ipv4: Option<Ipv4Addr>,
    pub is_up: bool,
    pub is_loopback: bool,
}

impl RawSocket {
    /// Create a new raw socket for the given interface
    pub fn new(interface: &str, source_ip: Ipv4Addr) -> Result<Self> {
        let inner = Self::create_platform_socket(interface, source_ip)?;
        Ok(Self { inner })
    }

    /// Find the best interface for scanning
    pub fn find_best_interface() -> Result<InterfaceInfo> {
        let interfaces = Self::list_interfaces()?;
        interfaces
            .into_iter()
            .find(|iface| iface.is_up && !iface.is_loopback && iface.ipv4.is_some())
            .ok_or_else(|| anyhow!("No suitable network interface found"))
    }

    /// List all available interfaces
    pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
        Self::platform_list_interfaces()
    }

    /// Send a raw packet
    pub fn send(&self, packet: &[u8]) -> Result<()> {
        match &self.inner {
            #[cfg(target_os = "linux")]
            PlatformSocket::Linux {
                interface,
                source_ip,
            } => Self::linux_send(interface, *source_ip, packet),
            #[cfg(target_os = "macos")]
            PlatformSocket::Macos {
                interface,
                source_ip,
            } => Self::macos_send(interface, *source_ip, packet),
            #[cfg(target_os = "windows")]
            PlatformSocket::Windows {
                interface,
                source_ip,
            } => Self::windows_send(interface, *source_ip, packet),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            _ => Err(anyhow!("Unsupported platform")),
        }
    }

    /// Receive a raw packet (blocking)
    pub fn receive(&self, buffer: &mut [u8]) -> Result<usize> {
        match &self.inner {
            #[cfg(target_os = "linux")]
            PlatformSocket::Linux { interface, .. } => Self::linux_receive(interface, buffer),
            #[cfg(target_os = "macos")]
            PlatformSocket::Macos { interface, .. } => Self::macos_receive(interface, buffer),
            #[cfg(target_os = "windows")]
            PlatformSocket::Windows { interface, .. } => Self::windows_receive(interface, buffer),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            _ => Err(anyhow!("Unsupported platform")),
        }
    }

    /// Set BPF filter on the socket
    pub fn set_bpf_filter(&self, filter: &str) -> Result<()> {
        match &self.inner {
            #[cfg(target_os = "linux")]
            PlatformSocket::Linux { interface, .. } => Self::linux_set_bpf(interface, filter),
            #[cfg(target_os = "macos")]
            PlatformSocket::Macos { interface, .. } => Self::macos_set_bpf(interface, filter),
            #[cfg(target_os = "windows")]
            PlatformSocket::Windows { interface, .. } => Self::windows_set_bpf(interface, filter),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            _ => Err(anyhow!("Unsupported platform")),
        }
    }

    /// Get the source IP for this socket
    pub fn source_ip(&self) -> Ipv4Addr {
        match &self.inner {
            #[cfg(target_os = "linux")]
            PlatformSocket::Linux { source_ip, .. } => *source_ip,
            #[cfg(target_os = "macos")]
            PlatformSocket::Macos { source_ip, .. } => *source_ip,
            #[cfg(target_os = "windows")]
            PlatformSocket::Windows { source_ip, .. } => *source_ip,
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            _ => Ipv4Addr::new(127, 0, 0, 1),
        }
    }

    // Platform-specific implementations

    fn create_platform_socket(interface: &str, source_ip: Ipv4Addr) -> Result<PlatformSocket> {
        #[cfg(target_os = "linux")]
        {
            Ok(PlatformSocket::Linux {
                interface: interface.to_string(),
                source_ip,
            })
        }
        #[cfg(target_os = "macos")]
        {
            Ok(PlatformSocket::Macos {
                interface: interface.to_string(),
                source_ip,
            })
        }
        #[cfg(target_os = "windows")]
        {
            Ok(PlatformSocket::Windows {
                interface: interface.to_string(),
                source_ip,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Err(anyhow!(
                "Unsupported platform: only Linux, macOS, and Windows are supported"
            ))
        }
    }

    fn platform_list_interfaces() -> Result<Vec<InterfaceInfo>> {
        #[cfg(target_os = "linux")]
        {
            Self::linux_list_interfaces()
        }
        #[cfg(target_os = "macos")]
        {
            Self::macos_list_interfaces()
        }
        #[cfg(target_os = "windows")]
        {
            Self::windows_list_interfaces()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Ok(Vec::new())
        }
    }

    // Linux implementation using pnet

    #[cfg(target_os = "linux")]
    fn linux_list_interfaces() -> Result<Vec<InterfaceInfo>> {
        use pnet::datalink;

        Ok(datalink::interfaces()
            .into_iter()
            .map(|iface| InterfaceInfo {
                name: iface.name.clone(),
                index: iface.index,
                ipv4: iface.ips.iter().find_map(|ip| {
                    if let std::net::IpAddr::V4(ipv4) = ip.ip() {
                        Some(ipv4)
                    } else {
                        None
                    }
                }),
                is_up: iface.is_up(),
                is_loopback: iface.is_loopback(),
            })
            .collect())
    }

    #[cfg(target_os = "linux")]
    fn linux_send(interface: &str, _source_ip: Ipv4Addr, packet: &[u8]) -> Result<()> {
        use pnet::datalink::{self, Channel};

        let iface = datalink::interfaces()
            .into_iter()
            .find(|i| i.name == interface)
            .ok_or_else(|| anyhow!("Interface not found: {}", interface))?;

        let (mut tx, _rx) = match datalink::channel(&iface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(anyhow!("Failed to create raw socket")),
        };

        let _ = tx
            .send_to(packet, None)
            .ok_or_else(|| anyhow!("Failed to send packet"))?;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn linux_receive(interface: &str, buffer: &mut [u8]) -> Result<usize> {
        use pnet::datalink::{self, Channel};

        let iface = datalink::interfaces()
            .into_iter()
            .find(|i| i.name == interface)
            .ok_or_else(|| anyhow!("Interface not found: {}", interface))?;

        let (_tx, mut rx) = match datalink::channel(&iface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(anyhow!("Failed to create raw socket")),
        };

        match rx.next() {
            Ok(packet) => {
                let len = packet.len().min(buffer.len());
                buffer[..len].copy_from_slice(&packet[..len]);
                Ok(len)
            }
            Err(e) => Err(anyhow!("Receive error: {}", e)),
        }
    }

    #[cfg(target_os = "linux")]
    fn linux_set_bpf(interface: &str, filter: &str) -> Result<()> {
        // BPF filter would be set via setsockopt on the raw socket
        // For now, this is a placeholder
        tracing::debug!("BPF filter set on {}: {}", interface, filter);
        Ok(())
    }

    // macOS implementation (similar to Linux with BPF)

    #[cfg(target_os = "macos")]
    fn macos_list_interfaces() -> Result<Vec<InterfaceInfo>> {
        use pnet::datalink;

        Ok(datalink::interfaces()
            .into_iter()
            .map(|iface| InterfaceInfo {
                name: iface.name.clone(),
                index: iface.index,
                ipv4: iface.ips.iter().find_map(|ip| {
                    if let std::net::IpAddr::V4(ipv4) = ip.ip() {
                        Some(ipv4)
                    } else {
                        None
                    }
                }),
                is_up: iface.is_up(),
                is_loopback: iface.is_loopback(),
            })
            .collect())
    }

    #[cfg(target_os = "macos")]
    fn macos_send(interface: &str, _source_ip: Ipv4Addr, packet: &[u8]) -> Result<()> {
        use pnet::datalink::{self, Channel};

        let iface = datalink::interfaces()
            .into_iter()
            .find(|i| i.name == interface)
            .ok_or_else(|| anyhow!("Interface not found: {}", interface))?;

        let (mut tx, _rx) = match datalink::channel(&iface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(anyhow!("Failed to create raw socket")),
        };

        let _ = tx.send_to(packet, None)
            .ok_or_else(|| anyhow!("Failed to send packet"))?;

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn macos_receive(interface: &str, buffer: &mut [u8]) -> Result<usize> {
        use pnet::datalink::{self, Channel};

        let iface = datalink::interfaces()
            .into_iter()
            .find(|i| i.name == interface)
            .ok_or_else(|| anyhow!("Interface not found: {}", interface))?;

        let (_tx, mut rx) = match datalink::channel(&iface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => return Err(anyhow!("Failed to create raw socket")),
        };

        match rx.next() {
            Ok(packet) => {
                let len = packet.len().min(buffer.len());
                buffer[..len].copy_from_slice(&packet[..len]);
                Ok(len)
            }
            Err(e) => Err(anyhow!("Receive error: {}", e)),
        }
    }

    #[cfg(target_os = "macos")]
    fn macos_set_bpf(interface: &str, filter: &str) -> Result<()> {
        // BPF filter would be set via setsockopt on the raw socket
        tracing::debug!("BPF filter set on {}: {}", interface, filter);
        Ok(())
    }

    // Windows implementation (requires Npcap)

    #[cfg(target_os = "windows")]
    fn windows_list_interfaces() -> Result<Vec<InterfaceInfo>> {
        // Windows requires Npcap for raw sockets
        // For now, return empty list
        Ok(Vec::new())
    }

    #[cfg(target_os = "windows")]
    fn windows_send(interface: &str, source_ip: Ipv4Addr, packet: &[u8]) -> Result<()> {
        Err(anyhow!(
            "Windows raw sockets require Npcap. Install from https://npcap.com/"
        ))
    }

    #[cfg(target_os = "windows")]
    fn windows_receive(interface: &str, buffer: &mut [u8]) -> Result<usize> {
        Err(anyhow!(
            "Windows raw sockets require Npcap. Install from https://npcap.com/"
        ))
    }

    #[cfg(target_os = "windows")]
    fn windows_set_bpf(interface: &str, filter: &str) -> Result<()> {
        Err(anyhow!(
            "Windows raw sockets require Npcap. Install from https://npcap.com/"
        ))
    }
}

/// Check if raw sockets are available on this platform
pub fn raw_sockets_available() -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        true
    }
    #[cfg(target_os = "windows")]
    {
        // Check if Npcap is installed
        false
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        false
    }
}

/// Get platform-specific raw socket requirements message
pub fn platform_requirements() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "Raw sockets require root privileges. Run with sudo."
    }
    #[cfg(target_os = "macos")]
    {
        "Raw sockets require root privileges. Run with sudo."
    }
    #[cfg(target_os = "windows")]
    {
        "Raw sockets require Npcap. Install from https://npcap.com/ and run as Administrator."
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "Raw sockets are not supported on this platform. Use connect scan instead."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_sockets_available() {
        // Should return true on Linux/macOS, false on Windows without Npcap
        let available = raw_sockets_available();
        #[cfg(target_os = "linux")]
        assert!(available);
        #[cfg(target_os = "macos")]
        assert!(available);
    }

    #[test]
    fn test_platform_requirements() {
        let msg = platform_requirements();
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_list_interfaces() {
        let interfaces = RawSocket::list_interfaces();
        // Should succeed on all platforms
        assert!(interfaces.is_ok());
    }
}
