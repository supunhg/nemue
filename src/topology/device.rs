// Device classification and fingerprinting
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Device type classification
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum DeviceType {
    Router,
    Switch,
    Firewall,
    Server,
    Workstation,
    Printer,
    IoT,
    Mobile,
    Camera,
    VoIP,
    Unknown,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Router => write!(f, "Router"),
            DeviceType::Switch => write!(f, "Switch"),
            DeviceType::Firewall => write!(f, "Firewall"),
            DeviceType::Server => write!(f, "Server"),
            DeviceType::Workstation => write!(f, "Workstation"),
            DeviceType::Printer => write!(f, "Printer"),
            DeviceType::IoT => write!(f, "IoT Device"),
            DeviceType::Mobile => write!(f, "Mobile Device"),
            DeviceType::Camera => write!(f, "IP Camera"),
            DeviceType::VoIP => write!(f, "VoIP Phone"),
            DeviceType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_type: DeviceType,
    pub os_family: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
}

/// Device classifier
pub struct DeviceClassifier {
    // Could add ML model or rules here
}

impl DeviceClassifier {
    pub fn new() -> Self {
        Self {}
    }

    /// Classify device based on IP and scanned characteristics
    pub async fn classify(&self, address: IpAddr) -> DeviceInfo {
        // In production: perform service detection, TTL analysis, etc.
        // For now, return basic classification based on IP

        let device_type = if Self::is_private_ip(address) {
            // Could be gateway/router
            if Self::is_likely_gateway(address) {
                DeviceType::Router
            } else {
                DeviceType::Workstation
            }
        } else {
            DeviceType::Server
        };

        DeviceInfo {
            device_type,
            os_family: None,
            vendor: None,
            hostname: None,
        }
    }

    /// Check if IP is in private range
    fn is_private_ip(addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                octets[0] == 10
                    || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                    || (octets[0] == 192 && octets[1] == 168)
            }
            IpAddr::V6(_) => false, // Simplified
        }
    }

    /// Check if IP is likely a gateway (.1, .254, etc.)
    fn is_likely_gateway(addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                octets[3] == 1 || octets[3] == 254
            }
            IpAddr::V6(_) => false,
        }
    }

    /// Classify based on open ports and services
    pub fn classify_by_services(&self, _services: &[u16]) -> DeviceType {
        // In production: analyze service patterns
        // e.g., port 515 (LPD) = Printer
        // ports 80,443,3306 = Server
        // ports 23,22,161 = Network device
        DeviceType::Unknown
    }
}

impl Default for DeviceClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_device_type_display() {
        assert_eq!(DeviceType::Router.to_string(), "Router");
        assert_eq!(DeviceType::Server.to_string(), "Server");
        assert_eq!(DeviceType::IoT.to_string(), "IoT Device");
    }

    #[test]
    fn test_is_private_ip() {
        let private = IpAddr::from_str("192.168.1.1").unwrap();
        let public = IpAddr::from_str("8.8.8.8").unwrap();

        assert!(DeviceClassifier::is_private_ip(private));
        assert!(!DeviceClassifier::is_private_ip(public));
    }

    #[test]
    fn test_is_likely_gateway() {
        let gateway1 = IpAddr::from_str("192.168.1.1").unwrap();
        let gateway2 = IpAddr::from_str("10.0.0.254").unwrap();
        let host = IpAddr::from_str("192.168.1.100").unwrap();

        assert!(DeviceClassifier::is_likely_gateway(gateway1));
        assert!(DeviceClassifier::is_likely_gateway(gateway2));
        assert!(!DeviceClassifier::is_likely_gateway(host));
    }

    #[tokio::test]
    async fn test_classify_device() {
        let classifier = DeviceClassifier::new();
        let router_ip = IpAddr::from_str("192.168.1.1").unwrap();

        let info = classifier.classify(router_ip).await;
        assert_eq!(info.device_type, DeviceType::Router);
    }

    #[test]
    fn test_classify_by_services() {
        let classifier = DeviceClassifier::new();
        let services = vec![80, 443, 3306];
        let device_type = classifier.classify_by_services(&services);
        assert_eq!(device_type, DeviceType::Unknown); // Placeholder
    }
}
