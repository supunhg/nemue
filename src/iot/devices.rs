use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceType {
    Camera,
    Router,
    SmartHome,
    Industrial,
    Unknown,
}

impl DeviceType {
    pub fn as_str(&self) -> &str {
        match self {
            DeviceType::Camera => "Camera",
            DeviceType::Router => "Router",
            DeviceType::SmartHome => "Smart Home",
            DeviceType::Industrial => "Industrial",
            DeviceType::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceVendor {
    Hikvision,
    Dahua,
    Axis,
    TPLink,
    Netgear,
    Cisco,
    Xiaomi,
    Philips,
    Nest,
    Siemens,
    Schneider,
    ABB,
    Unknown(String),
}

impl DeviceVendor {
    pub fn as_str(&self) -> &str {
        match self {
            DeviceVendor::Hikvision => "Hikvision",
            DeviceVendor::Dahua => "Dahua",
            DeviceVendor::Axis => "Axis",
            DeviceVendor::TPLink => "TP-Link",
            DeviceVendor::Netgear => "Netgear",
            DeviceVendor::Cisco => "Cisco",
            DeviceVendor::Xiaomi => "Xiaomi",
            DeviceVendor::Philips => "Philips",
            DeviceVendor::Nest => "Nest",
            DeviceVendor::Siemens => "Siemens",
            DeviceVendor::Schneider => "Schneider Electric",
            DeviceVendor::ABB => "ABB",
            DeviceVendor::Unknown(s) => s,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityRisk {
    DefaultCredentials,
    OpenTelnet,
    OpenRTSP,
    OpenONVIF,
    UnencryptedFirmware,
    ExposedAPI,
    WeakAuthentication,
    NoFirmwareUpdate,
    VulnerableFirmware,
    ExposedDebugInterface,
}

impl SecurityRisk {
    pub fn severity(&self) -> &str {
        match self {
            SecurityRisk::DefaultCredentials => "CRITICAL",
            SecurityRisk::OpenTelnet => "HIGH",
            SecurityRisk::OpenRTSP => "MEDIUM",
            SecurityRisk::OpenONVIF => "MEDIUM",
            SecurityRisk::UnencryptedFirmware => "HIGH",
            SecurityRisk::ExposedAPI => "HIGH",
            SecurityRisk::WeakAuthentication => "HIGH",
            SecurityRisk::NoFirmwareUpdate => "MEDIUM",
            SecurityRisk::VulnerableFirmware => "CRITICAL",
            SecurityRisk::ExposedDebugInterface => "HIGH",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            SecurityRisk::DefaultCredentials => "Device uses default or well-known credentials",
            SecurityRisk::OpenTelnet => "Telnet port (23) is open and accessible",
            SecurityRisk::OpenRTSP => "RTSP streaming port (554) is open",
            SecurityRisk::OpenONVIF => "ONVIF service (port 80/8080) is accessible",
            SecurityRisk::UnencryptedFirmware => "Firmware can be retrieved without encryption",
            SecurityRisk::ExposedAPI => "Device API is exposed without authentication",
            SecurityRisk::WeakAuthentication => "Device uses weak authentication mechanism",
            SecurityRisk::NoFirmwareUpdate => "Device firmware may be outdated",
            SecurityRisk::VulnerableFirmware => "Device runs known vulnerable firmware version",
            SecurityRisk::ExposedDebugInterface => "Debug or diagnostic interface is accessible",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoTDevice {
    pub ip: IpAddr,
    pub device_type: DeviceType,
    pub vendor: DeviceVendor,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub open_ports: Vec<u16>,
    pub mac_address: Option<String>,
    pub services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceScanResult {
    pub device: IoTDevice,
    pub risks: Vec<SecurityRisk>,
    pub scan_duration: Duration,
}

#[derive(Debug, Clone)]
pub struct IoTDeviceScanner {
    timeout_duration: Duration,
    common_ports: Vec<u16>,
}

impl IoTDeviceScanner {
    pub const CAMERA_PORTS: [u16; 6] = [80, 443, 554, 8000, 8080, 8443];
    pub const ROUTER_PORTS: [u16; 6] = [22, 23, 80, 443, 8080, 8443];
    pub const SMART_HOME_PORTS: [u16; 5] = [80, 443, 8080, 8883, 1883];
    pub const INDUSTRIAL_PORTS: [u16; 6] = [80, 443, 502, 47808, 44818, 2222];

    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
            common_ports: vec![22, 23, 80, 443, 554, 1883, 8000, 8080, 8443, 8883],
        }
    }

    pub fn with_ports(timeout_ms: u64, ports: Vec<u16>) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
            common_ports: ports,
        }
    }

    pub async fn scan_device(&self, target: IpAddr) -> Result<DeviceScanResult> {
        let start = std::time::Instant::now();

        let open_ports = self.scan_ports(target, &self.common_ports).await;
        let device_type = self.identify_device_type(target, &open_ports).await;
        let vendor = self.identify_vendor(target, &open_ports).await;
        let services = self.identify_services(target, &open_ports).await;

        let device = IoTDevice {
            ip: target,
            device_type,
            vendor,
            model: None,
            firmware_version: None,
            open_ports,
            mac_address: None,
            services,
        };

        let risks = self.assess_risks(&device).await;

        Ok(DeviceScanResult {
            device,
            risks,
            scan_duration: start.elapsed(),
        })
    }

    pub async fn enumerate_cameras(&self, targets: &[IpAddr]) -> Vec<DeviceScanResult> {
        let mut results = Vec::new();
        for target in targets {
            let ports = Self::CAMERA_PORTS.to_vec();
            let scanner =
                IoTDeviceScanner::with_ports(self.timeout_duration.as_millis() as u64, ports);
            if let Ok(result) = scanner.scan_device(*target).await {
                if result.device.device_type == DeviceType::Camera
                    || result
                        .device
                        .services
                        .iter()
                        .any(|s| s.contains("RTSP") || s.contains("ONVIF"))
                {
                    results.push(result);
                }
            }
        }
        results
    }

    pub async fn enumerate_routers(&self, targets: &[IpAddr]) -> Vec<DeviceScanResult> {
        let mut results = Vec::new();
        for target in targets {
            let ports = Self::ROUTER_PORTS.to_vec();
            let scanner =
                IoTDeviceScanner::with_ports(self.timeout_duration.as_millis() as u64, ports);
            if let Ok(result) = scanner.scan_device(*target).await {
                if result.device.device_type == DeviceType::Router
                    || result
                        .device
                        .services
                        .iter()
                        .any(|s| s.contains("HTTP") || s.contains("SSH"))
                {
                    results.push(result);
                }
            }
        }
        results
    }

    pub async fn enumerate_smart_home(&self, targets: &[IpAddr]) -> Vec<DeviceScanResult> {
        let mut results = Vec::new();
        for target in targets {
            let ports = Self::SMART_HOME_PORTS.to_vec();
            let scanner =
                IoTDeviceScanner::with_ports(self.timeout_duration.as_millis() as u64, ports);
            if let Ok(result) = scanner.scan_device(*target).await {
                if result.device.device_type == DeviceType::SmartHome
                    || result
                        .device
                        .services
                        .iter()
                        .any(|s| s.contains("MQTT") || s.contains("CoAP"))
                {
                    results.push(result);
                }
            }
        }
        results
    }

    pub async fn enumerate_industrial(&self, targets: &[IpAddr]) -> Vec<DeviceScanResult> {
        let mut results = Vec::new();
        for target in targets {
            let ports = Self::INDUSTRIAL_PORTS.to_vec();
            let scanner =
                IoTDeviceScanner::with_ports(self.timeout_duration.as_millis() as u64, ports);
            if let Ok(result) = scanner.scan_device(*target).await {
                if result.device.device_type == DeviceType::Industrial
                    || result
                        .device
                        .services
                        .iter()
                        .any(|s| s.contains("Modbus") || s.contains("BACnet"))
                {
                    results.push(result);
                }
            }
        }
        results
    }

    async fn scan_ports(&self, target: IpAddr, ports: &[u16]) -> Vec<u16> {
        let mut open_ports = Vec::new();
        for &port in ports {
            let addr = SocketAddr::new(target, port);
            if timeout(self.timeout_duration, TcpStream::connect(addr))
                .await
                .ok()
                .and_then(|r| r.ok())
                .is_some()
            {
                open_ports.push(port);
            }
        }
        open_ports
    }

    async fn identify_device_type(&self, _target: IpAddr, open_ports: &[u16]) -> DeviceType {
        let has_rtsp = open_ports.contains(&554);
        let has_onvif = open_ports.contains(&80) || open_ports.contains(&8080);
        let has_modbus = open_ports.contains(&502);
        let has_bacnet = open_ports.contains(&47808);
        let has_mqtt = open_ports.contains(&1883) || open_ports.contains(&8883);
        let has_telnet = open_ports.contains(&23);

        if has_rtsp || (has_onvif && open_ports.contains(&8000)) {
            DeviceType::Camera
        } else if has_modbus || has_bacnet || open_ports.contains(&44818) {
            DeviceType::Industrial
        } else if has_mqtt {
            DeviceType::SmartHome
        } else if has_telnet && (open_ports.contains(&80) || open_ports.contains(&443)) {
            DeviceType::Router
        } else {
            DeviceType::Unknown
        }
    }

    async fn identify_vendor(&self, target: IpAddr, open_ports: &[u16]) -> DeviceVendor {
        if open_ports.contains(&80) || open_ports.contains(&443) {
            let port = if open_ports.contains(&80) { 80 } else { 443 };
            if let Ok(banner) = self.grab_http_banner(target, port).await {
                let lower = banner.to_lowercase();
                if lower.contains("hikvision") {
                    return DeviceVendor::Hikvision;
                } else if lower.contains("dahua") {
                    return DeviceVendor::Dahua;
                } else if lower.contains("axis") {
                    return DeviceVendor::Axis;
                } else if lower.contains("tp-link") {
                    return DeviceVendor::TPLink;
                } else if lower.contains("netgear") {
                    return DeviceVendor::Netgear;
                } else if lower.contains("cisco") {
                    return DeviceVendor::Cisco;
                } else if lower.contains("xiaomi") {
                    return DeviceVendor::Xiaomi;
                } else if lower.contains("philips") {
                    return DeviceVendor::Philips;
                } else if lower.contains("nest") || lower.contains("google") {
                    return DeviceVendor::Nest;
                } else if lower.contains("siemens") {
                    return DeviceVendor::Siemens;
                } else if lower.contains("schneider") {
                    return DeviceVendor::Schneider;
                } else if lower.contains("abb") {
                    return DeviceVendor::ABB;
                }
            }
        }
        DeviceVendor::Unknown("Unknown".to_string())
    }

    async fn identify_services(&self, _target: IpAddr, open_ports: &[u16]) -> Vec<String> {
        let mut services = Vec::new();
        for &port in open_ports {
            let service = match port {
                22 => "SSH",
                23 => "Telnet",
                80 => "HTTP",
                443 => "HTTPS",
                502 => "Modbus",
                554 => "RTSP",
                1883 => "MQTT",
                8000 => "HTTP-Alt",
                8080 => "HTTP-Proxy",
                8443 => "HTTPS-Alt",
                8883 => "MQTTS",
                47808 => "BACnet",
                44818 => "EtherNet/IP",
                _ => continue,
            };
            services.push(service.to_string());
        }
        services
    }

    async fn assess_risks(&self, device: &IoTDevice) -> Vec<SecurityRisk> {
        let mut risks = Vec::new();

        if device.open_ports.contains(&23) {
            risks.push(SecurityRisk::OpenTelnet);
        }
        if device.open_ports.contains(&554) {
            risks.push(SecurityRisk::OpenRTSP);
        }
        if device.open_ports.contains(&80) || device.open_ports.contains(&8080) {
            risks.push(SecurityRisk::OpenONVIF);
        }

        match device.device_type {
            DeviceType::Camera => {
                if device.vendor == DeviceVendor::Hikvision || device.vendor == DeviceVendor::Dahua
                {
                    risks.push(SecurityRisk::DefaultCredentials);
                }
                if device.firmware_version.is_none() {
                    risks.push(SecurityRisk::NoFirmwareUpdate);
                }
            }
            DeviceType::Router => {
                if device.vendor == DeviceVendor::TPLink || device.vendor == DeviceVendor::Netgear {
                    risks.push(SecurityRisk::DefaultCredentials);
                }
            }
            DeviceType::SmartHome => {
                risks.push(SecurityRisk::WeakAuthentication);
            }
            DeviceType::Industrial => {
                risks.push(SecurityRisk::ExposedDebugInterface);
                if device.open_ports.contains(&502) {
                    risks.push(SecurityRisk::ExposedAPI);
                }
            }
            DeviceType::Unknown => {}
        }

        risks
    }

    async fn grab_http_banner(&self, target: IpAddr, port: u16) -> Result<String> {
        let addr = SocketAddr::new(target, port);
        let stream = timeout(self.timeout_duration, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("Connection timeout"))?
            .map_err(|e| anyhow!("Connection failed: {}", e))?;

        let (mut reader, mut writer) = stream.into_split();

        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Nemue-IoT-Scanner\r\nConnection: close\r\n\r\n",
            target
        );

        writer.write_all(request.as_bytes()).await?;

        let mut response = vec![0u8; 4096];
        let n = timeout(self.timeout_duration, reader.read(&mut response))
            .await
            .map_err(|_| anyhow!("Read timeout"))?
            .map_err(|e| anyhow!("Read failed: {}", e))?;

        Ok(String::from_utf8_lossy(&response[..n]).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_type_as_str() {
        assert_eq!(DeviceType::Camera.as_str(), "Camera");
        assert_eq!(DeviceType::Router.as_str(), "Router");
        assert_eq!(DeviceType::SmartHome.as_str(), "Smart Home");
        assert_eq!(DeviceType::Industrial.as_str(), "Industrial");
        assert_eq!(DeviceType::Unknown.as_str(), "Unknown");
    }

    #[test]
    fn test_device_vendor_as_str() {
        assert_eq!(DeviceVendor::Hikvision.as_str(), "Hikvision");
        assert_eq!(DeviceVendor::Dahua.as_str(), "Dahua");
        assert_eq!(DeviceVendor::TPLink.as_str(), "TP-Link");
        assert_eq!(
            DeviceVendor::Unknown("Custom".to_string()).as_str(),
            "Custom"
        );
    }

    #[test]
    fn test_security_risk_severity() {
        assert_eq!(SecurityRisk::DefaultCredentials.severity(), "CRITICAL");
        assert_eq!(SecurityRisk::OpenTelnet.severity(), "HIGH");
        assert_eq!(SecurityRisk::OpenRTSP.severity(), "MEDIUM");
        assert_eq!(SecurityRisk::VulnerableFirmware.severity(), "CRITICAL");
        assert_eq!(SecurityRisk::ExposedDebugInterface.severity(), "HIGH");
    }

    #[test]
    fn test_security_risk_description() {
        assert!(!SecurityRisk::DefaultCredentials.description().is_empty());
        assert!(!SecurityRisk::OpenTelnet.description().is_empty());
        assert!(!SecurityRisk::WeakAuthentication.description().is_empty());
    }

    #[test]
    fn test_camera_ports() {
        assert!(IoTDeviceScanner::CAMERA_PORTS.contains(&554));
        assert!(IoTDeviceScanner::CAMERA_PORTS.contains(&80));
        assert!(IoTDeviceScanner::CAMERA_PORTS.contains(&8080));
    }

    #[test]
    fn test_router_ports() {
        assert!(IoTDeviceScanner::ROUTER_PORTS.contains(&22));
        assert!(IoTDeviceScanner::ROUTER_PORTS.contains(&23));
        assert!(IoTDeviceScanner::ROUTER_PORTS.contains(&80));
    }

    #[test]
    fn test_smart_home_ports() {
        assert!(IoTDeviceScanner::SMART_HOME_PORTS.contains(&1883));
        assert!(IoTDeviceScanner::SMART_HOME_PORTS.contains(&8883));
    }

    #[test]
    fn test_industrial_ports() {
        assert!(IoTDeviceScanner::INDUSTRIAL_PORTS.contains(&502));
        assert!(IoTDeviceScanner::INDUSTRIAL_PORTS.contains(&47808));
    }

    #[test]
    fn test_scanner_creation() {
        let scanner = IoTDeviceScanner::new(2000);
        assert_eq!(scanner.timeout_duration, Duration::from_millis(2000));
        assert!(!scanner.common_ports.is_empty());
    }

    #[test]
    fn test_scanner_with_ports() {
        let scanner = IoTDeviceScanner::with_ports(1000, vec![80, 443]);
        assert_eq!(scanner.common_ports, vec![80, 443]);
    }

    #[test]
    fn test_device_type_serialization() {
        let device_type = DeviceType::Camera;
        let json = serde_json::to_string(&device_type).unwrap();
        assert!(json.contains("Camera"));
    }

    #[test]
    fn test_security_risk_serialization() {
        let risk = SecurityRisk::DefaultCredentials;
        let json = serde_json::to_string(&risk).unwrap();
        assert!(json.contains("DefaultCredentials"));
    }

    #[tokio::test]
    async fn test_scan_ports_on_closed() {
        let scanner = IoTDeviceScanner::new(200);
        let ports = scanner
            .scan_ports(IpAddr::V4([127, 0, 0, 1].into()), &[1])
            .await;
        assert!(ports.is_empty());
    }

    #[tokio::test]
    async fn test_identify_device_type_camera() {
        let scanner = IoTDeviceScanner::new(500);
        let ports = vec![80, 554, 8000];
        let dt = scanner
            .identify_device_type(IpAddr::V4([192, 168, 1, 1].into()), &ports)
            .await;
        assert_eq!(dt, DeviceType::Camera);
    }

    #[tokio::test]
    async fn test_identify_device_type_industrial() {
        let scanner = IoTDeviceScanner::new(500);
        let ports = vec![502, 47808];
        let dt = scanner
            .identify_device_type(IpAddr::V4([192, 168, 1, 1].into()), &ports)
            .await;
        assert_eq!(dt, DeviceType::Industrial);
    }

    #[tokio::test]
    async fn test_identify_device_type_smarthome() {
        let scanner = IoTDeviceScanner::new(500);
        let ports = vec![1883, 8080];
        let dt = scanner
            .identify_device_type(IpAddr::V4([192, 168, 1, 1].into()), &ports)
            .await;
        assert_eq!(dt, DeviceType::SmartHome);
    }

    #[tokio::test]
    async fn test_identify_device_type_router() {
        let scanner = IoTDeviceScanner::new(500);
        let ports = vec![23, 80, 443];
        let dt = scanner
            .identify_device_type(IpAddr::V4([192, 168, 1, 1].into()), &ports)
            .await;
        assert_eq!(dt, DeviceType::Router);
    }

    #[tokio::test]
    async fn test_identify_device_type_unknown() {
        let scanner = IoTDeviceScanner::new(500);
        let ports = vec![12345];
        let dt = scanner
            .identify_device_type(IpAddr::V4([192, 168, 1, 1].into()), &ports)
            .await;
        assert_eq!(dt, DeviceType::Unknown);
    }

    #[tokio::test]
    async fn test_assess_risks_camera_telnet() {
        let scanner = IoTDeviceScanner::new(500);
        let device = IoTDevice {
            ip: IpAddr::V4([192, 168, 1, 10].into()),
            device_type: DeviceType::Camera,
            vendor: DeviceVendor::Hikvision,
            model: None,
            firmware_version: None,
            open_ports: vec![23, 554, 80],
            mac_address: None,
            services: vec!["Telnet".to_string(), "RTSP".to_string()],
        };
        let risks = scanner.assess_risks(&device).await;
        assert!(risks.contains(&SecurityRisk::OpenTelnet));
        assert!(risks.contains(&SecurityRisk::OpenRTSP));
        assert!(risks.contains(&SecurityRisk::DefaultCredentials));
    }

    #[tokio::test]
    async fn test_assess_risks_industrial() {
        let scanner = IoTDeviceScanner::new(500);
        let device = IoTDevice {
            ip: IpAddr::V4([10, 0, 0, 1].into()),
            device_type: DeviceType::Industrial,
            vendor: DeviceVendor::Siemens,
            model: None,
            firmware_version: None,
            open_ports: vec![502],
            mac_address: None,
            services: vec!["Modbus".to_string()],
        };
        let risks = scanner.assess_risks(&device).await;
        assert!(risks.contains(&SecurityRisk::ExposedDebugInterface));
        assert!(risks.contains(&SecurityRisk::ExposedAPI));
    }

    #[tokio::test]
    async fn test_identify_services() {
        let scanner = IoTDeviceScanner::new(500);
        let services = scanner
            .identify_services(IpAddr::V4([1, 2, 3, 4].into()), &[22, 80, 554, 1883, 502])
            .await;
        assert!(services.contains(&"SSH".to_string()));
        assert!(services.contains(&"HTTP".to_string()));
        assert!(services.contains(&"RTSP".to_string()));
        assert!(services.contains(&"MQTT".to_string()));
        assert!(services.contains(&"Modbus".to_string()));
    }
}
