// Service catalog and asset inventory management
use std::net::IpAddr;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Service information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceInfo {
    pub port: u16,
    pub protocol: String,
    pub service_name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub state: ServiceState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServiceState {
    Open,
    Filtered,
    Closed,
}

/// Asset information with comprehensive details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetInfo {
    pub ip_address: IpAddr,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub vendor: Option<String>,
    pub device_type: String,
    pub os_family: Option<String>,
    pub services: Vec<ServiceInfo>,
    pub importance_score: u8,
    pub last_seen: String,
    pub first_seen: String,
}

impl AssetInfo {
    /// Calculate importance score based on services and device type
    pub fn calculate_importance(&self) -> u8 {
        let mut score = 0u8;

        // Base score from device type
        score += match self.device_type.as_str() {
            "Firewall" => 5,
            "Router" => 4,
            "Server" => 4,
            "Switch" => 3,
            "Workstation" => 2,
            _ => 1,
        };

        // Add points for critical services
        for service in &self.services {
            score = score.saturating_add(match service.service_name.as_str() {
                "ssh" | "https" | "rdp" => 1,
                "domain" | "ldap" | "kerberos" => 2,
                "smb" | "netbios" | "msrpc" => 1,
                _ => 0,
            });
        }

        // Cap at 10
        score.min(10)
    }

    /// Check if asset has vulnerable services
    pub fn has_vulnerable_services(&self) -> bool {
        self.services.iter().any(|s| {
            // Check for commonly vulnerable services
            matches!(s.service_name.as_str(), 
                "telnet" | "ftp" | "rexec" | "rlogin" | "rsh" | "tftp"
            ) || (s.service_name == "smb" && s.version.as_ref()
                .map(|v| v.contains("1.0") || v.contains("2.0"))
                .unwrap_or(false))
        })
    }

    /// Get risk level
    pub fn risk_level(&self) -> RiskLevel {
        if self.has_vulnerable_services() {
            return RiskLevel::High;
        }

        let open_count = self.services.iter()
            .filter(|s| s.state == ServiceState::Open)
            .count();

        match (self.importance_score, open_count) {
            (8..=10, _) => RiskLevel::High,
            (5..=7, 10..) => RiskLevel::High,
            (5..=7, _) => RiskLevel::Medium,
            (3..=4, 20..) => RiskLevel::Medium,
            _ => RiskLevel::Low,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

/// Service catalog manager
pub struct ServiceCatalog {
    assets: HashMap<IpAddr, AssetInfo>,
}

impl ServiceCatalog {
    pub fn new() -> Self {
        Self {
            assets: HashMap::new(),
        }
    }

    /// Add or update an asset
    pub fn add_asset(&mut self, asset: AssetInfo) {
        self.assets.insert(asset.ip_address, asset);
    }

    /// Get asset by IP
    pub fn get_asset(&self, ip: &IpAddr) -> Option<&AssetInfo> {
        self.assets.get(ip)
    }

    /// Get all assets
    pub fn get_all_assets(&self) -> Vec<&AssetInfo> {
        self.assets.values().collect()
    }

    /// Get high-risk assets
    pub fn get_high_risk_assets(&self) -> Vec<&AssetInfo> {
        self.assets
            .values()
            .filter(|a| matches!(a.risk_level(), RiskLevel::High | RiskLevel::Critical))
            .collect()
    }

    /// Get assets by service
    pub fn get_assets_by_service(&self, service_name: &str) -> Vec<&AssetInfo> {
        self.assets
            .values()
            .filter(|a| a.services.iter().any(|s| s.service_name == service_name))
            .collect()
    }

    /// Generate service catalog report
    pub fn generate_catalog(&self) -> ServiceCatalogReport {
        let mut service_distribution: HashMap<String, usize> = HashMap::new();
        let mut os_distribution: HashMap<String, usize> = HashMap::new();

        for asset in self.assets.values() {
            // Count services
            for service in &asset.services {
                *service_distribution.entry(service.service_name.clone()).or_insert(0) += 1;
            }

            // Count OS families
            if let Some(os) = &asset.os_family {
                *os_distribution.entry(os.clone()).or_insert(0) += 1;
            }
        }

        ServiceCatalogReport {
            total_assets: self.assets.len(),
            total_services: self.assets.values().map(|a| a.services.len()).sum(),
            service_distribution,
            os_distribution,
            high_risk_count: self.get_high_risk_assets().len(),
        }
    }

    /// Export as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.assets).unwrap_or_default()
    }

    /// Export as CSV
    pub fn to_csv(&self) -> String {
        let mut csv = String::from("IP,Hostname,MAC,Vendor,Type,OS,Services,Importance,Risk\n");
        
        for asset in self.assets.values() {
            let services: Vec<String> = asset.services
                .iter()
                .map(|s| format!("{}:{}", s.service_name, s.port))
                .collect();
            
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{:?}\n",
                asset.ip_address,
                asset.hostname.as_ref().unwrap_or(&"-".to_string()),
                asset.mac_address.as_ref().unwrap_or(&"-".to_string()),
                asset.vendor.as_ref().unwrap_or(&"-".to_string()),
                asset.device_type,
                asset.os_family.as_ref().unwrap_or(&"-".to_string()),
                services.join(";"),
                asset.importance_score,
                asset.risk_level()
            ));
        }
        
        csv
    }
}

impl Default for ServiceCatalog {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize)]
pub struct ServiceCatalogReport {
    pub total_assets: usize,
    pub total_services: usize,
    pub service_distribution: HashMap<String, usize>,
    pub os_distribution: HashMap<String, usize>,
    pub high_risk_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn create_test_asset() -> AssetInfo {
        AssetInfo {
            ip_address: IpAddr::from_str("192.168.1.100").unwrap(),
            hostname: Some("web-server-01".to_string()),
            mac_address: Some("00:50:56:ab:cd:ef".to_string()),
            vendor: Some("VMware".to_string()),
            device_type: "Server".to_string(),
            os_family: Some("Linux".to_string()),
            services: vec![
                ServiceInfo {
                    port: 22,
                    protocol: "tcp".to_string(),
                    service_name: "ssh".to_string(),
                    version: Some("OpenSSH 8.0".to_string()),
                    banner: None,
                    state: ServiceState::Open,
                },
                ServiceInfo {
                    port: 443,
                    protocol: "tcp".to_string(),
                    service_name: "https".to_string(),
                    version: Some("nginx 1.18".to_string()),
                    banner: None,
                    state: ServiceState::Open,
                },
            ],
            importance_score: 0,
            last_seen: "2025-11-25T12:00:00Z".to_string(),
            first_seen: "2025-11-01T08:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_calculate_importance() {
        let mut asset = create_test_asset();
        let score = asset.calculate_importance();
        assert!(score >= 4); // Server (4) + ssh (1) + https (1)
        asset.importance_score = score;
        assert_eq!(asset.importance_score, 6);
    }

    #[test]
    fn test_vulnerable_services_telnet() {
        let mut asset = create_test_asset();
        asset.services.push(ServiceInfo {
            port: 23,
            protocol: "tcp".to_string(),
            service_name: "telnet".to_string(),
            version: None,
            banner: None,
            state: ServiceState::Open,
        });
        assert!(asset.has_vulnerable_services());
    }

    #[test]
    fn test_no_vulnerable_services() {
        let asset = create_test_asset();
        assert!(!asset.has_vulnerable_services());
    }

    #[test]
    fn test_risk_level_calculation() {
        let mut asset = create_test_asset();
        asset.importance_score = asset.calculate_importance();
        let risk = asset.risk_level();
        assert_eq!(risk, RiskLevel::Medium);
    }

    #[test]
    fn test_service_catalog_add() {
        let mut catalog = ServiceCatalog::new();
        let asset = create_test_asset();
        let ip = asset.ip_address;
        catalog.add_asset(asset);
        
        assert_eq!(catalog.assets.len(), 1);
        assert!(catalog.get_asset(&ip).is_some());
    }

    #[test]
    fn test_get_assets_by_service() {
        let mut catalog = ServiceCatalog::new();
        catalog.add_asset(create_test_asset());
        
        let ssh_assets = catalog.get_assets_by_service("ssh");
        assert_eq!(ssh_assets.len(), 1);
        
        let http_assets = catalog.get_assets_by_service("http");
        assert_eq!(http_assets.len(), 0);
    }

    #[test]
    fn test_generate_catalog_report() {
        let mut catalog = ServiceCatalog::new();
        catalog.add_asset(create_test_asset());
        
        let report = catalog.generate_catalog();
        assert_eq!(report.total_assets, 1);
        assert_eq!(report.total_services, 2);
        assert!(report.service_distribution.contains_key("ssh"));
    }

    #[test]
    fn test_export_csv() {
        let mut catalog = ServiceCatalog::new();
        catalog.add_asset(create_test_asset());
        
        let csv = catalog.to_csv();
        assert!(csv.contains("IP,Hostname,MAC"));
        assert!(csv.contains("192.168.1.100"));
        assert!(csv.contains("web-server-01"));
    }
}
