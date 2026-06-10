#![allow(dead_code)]
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceCategory {
    IPCamera,
    NetworkRouter,
    SmartSpeaker,
    SmartThermostat,
    SmartLock,
    SmartLight,
    IndustrialController,
    SmartTV,
    NAS,
    Printer,
    VoIPPhone,
    Wearable,
    Unknown,
}

impl DeviceCategory {
    pub fn as_str(&self) -> &str {
        match self {
            DeviceCategory::IPCamera => "IP Camera",
            DeviceCategory::NetworkRouter => "Network Router",
            DeviceCategory::SmartSpeaker => "Smart Speaker",
            DeviceCategory::SmartThermostat => "Smart Thermostat",
            DeviceCategory::SmartLock => "Smart Lock",
            DeviceCategory::SmartLight => "Smart Light",
            DeviceCategory::IndustrialController => "Industrial Controller",
            DeviceCategory::SmartTV => "Smart TV",
            DeviceCategory::NAS => "Network Attached Storage",
            DeviceCategory::Printer => "Network Printer",
            DeviceCategory::VoIPPhone => "VoIP Phone",
            DeviceCategory::Wearable => "Wearable Device",
            DeviceCategory::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintResult {
    pub ip: IpAddr,
    pub category: DeviceCategory,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware_version: Option<String>,
    pub os: Option<String>,
    pub mac_vendor: Option<String>,
    pub open_ports: Vec<u16>,
    pub banner_info: HashMap<String, String>,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    pub confidence: f64,
    pub scan_duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub affected_versions: Vec<String>,
    pub fixed_version: Option<String>,
}

impl VulnerabilityInfo {
    pub fn new(id: &str, severity: &str, title: &str, description: &str) -> Self {
        Self {
            id: id.to_string(),
            severity: severity.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            affected_versions: Vec::new(),
            fixed_version: None,
        }
    }

    pub fn with_versions(mut self, affected: Vec<&str>, fixed: Option<&str>) -> Self {
        self.affected_versions = affected.into_iter().map(|s| s.to_string()).collect();
        self.fixed_version = fixed.map(|s| s.to_string());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortBanner {
    pub port: u16,
    pub service: String,
    pub banner: String,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct IoTDeviceFingerprinter {
    timeout_duration: Duration,
    fingerprint_db: Vec<FingerprintSignature>,
}

#[derive(Debug, Clone)]
struct FingerprintSignature {
    vendor: String,
    model: String,
    category: DeviceCategory,
    banner_patterns: Vec<String>,
    port_combinations: Vec<Vec<u16>>,
    os_pattern: Option<String>,
}

impl IoTDeviceFingerprinter {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
            fingerprint_db: Self::build_fingerprint_db(),
        }
    }

    pub async fn fingerprint(&self, target: IpAddr, ports: &[u16]) -> Result<FingerprintResult> {
        let start = std::time::Instant::now();

        let mut open_ports = Vec::new();
        let mut banner_info = HashMap::new();

        for &port in ports {
            if let Ok(banner) = self.grab_banner(target, port).await {
                if !banner.is_empty() {
                    open_ports.push(port);
                    banner_info.insert(format!("port_{}", port), banner);
                }
            }
        }

        let (category, vendor, model, confidence) =
            self.match_fingerprint(&open_ports, &banner_info);
        let firmware_version = self.detect_firmware_version(&banner_info);
        let os = self.detect_os(&banner_info);
        let vulnerabilities = self.check_vulnerabilities(&vendor, &model, &firmware_version);

        Ok(FingerprintResult {
            ip: target,
            category,
            vendor,
            model,
            firmware_version,
            os,
            mac_vendor: None,
            open_ports,
            banner_info,
            vulnerabilities,
            confidence,
            scan_duration: start.elapsed(),
        })
    }

    pub async fn identify_device_type(
        &self,
        target: IpAddr,
        ports: &[u16],
    ) -> Result<DeviceCategory> {
        let result = self.fingerprint(target, ports).await?;
        Ok(result.category)
    }

    pub async fn identify_vendor(&self, target: IpAddr, ports: &[u16]) -> Result<Option<String>> {
        let result = self.fingerprint(target, ports).await?;
        Ok(result.vendor)
    }

    pub async fn detect_firmware(&self, target: IpAddr, ports: &[u16]) -> Result<Option<String>> {
        let result = self.fingerprint(target, ports).await?;
        Ok(result.firmware_version)
    }

    pub async fn assess_vulnerabilities(
        &self,
        target: IpAddr,
        ports: &[u16],
    ) -> Result<Vec<VulnerabilityInfo>> {
        let result = self.fingerprint(target, ports).await?;
        Ok(result.vulnerabilities)
    }

    fn match_fingerprint(
        &self,
        open_ports: &[u16],
        banner_info: &HashMap<String, String>,
    ) -> (DeviceCategory, Option<String>, Option<String>, f64) {
        // Check banners for known patterns
        for banner in banner_info.values() {
            let lower = banner.to_lowercase();

            for sig in &self.fingerprint_db {
                for pattern in &sig.banner_patterns {
                    if lower.contains(&pattern.to_lowercase()) {
                        return (
                            sig.category.clone(),
                            Some(sig.vendor.clone()),
                            Some(sig.model.clone()),
                            0.9,
                        );
                    }
                }
            }

            // Generic detection based on banner content
            if lower.contains("hikvision") {
                return (
                    DeviceCategory::IPCamera,
                    Some("Hikvision".to_string()),
                    None,
                    0.8,
                );
            } else if lower.contains("dahua") {
                return (
                    DeviceCategory::IPCamera,
                    Some("Dahua".to_string()),
                    None,
                    0.8,
                );
            } else if lower.contains("ubnt") || lower.contains("ubiquiti") {
                return (
                    DeviceCategory::NetworkRouter,
                    Some("Ubiquiti".to_string()),
                    None,
                    0.8,
                );
            } else if lower.contains("mikrotik") {
                return (
                    DeviceCategory::NetworkRouter,
                    Some("MikroTik".to_string()),
                    None,
                    0.8,
                );
            } else if lower.contains("openwrt") {
                return (
                    DeviceCategory::NetworkRouter,
                    Some("OpenWrt".to_string()),
                    None,
                    0.7,
                );
            } else if lower.contains("samsung") && (lower.contains("tv") || lower.contains("smart"))
            {
                return (
                    DeviceCategory::SmartTV,
                    Some("Samsung".to_string()),
                    None,
                    0.8,
                );
            } else if lower.contains("synology") {
                return (DeviceCategory::NAS, Some("Synology".to_string()), None, 0.8);
            } else if lower.contains("qnap") {
                return (DeviceCategory::NAS, Some("QNAP".to_string()), None, 0.8);
            }
        }

        // Port-based heuristics
        if open_ports.contains(&554) {
            return (DeviceCategory::IPCamera, None, None, 0.5);
        }
        if open_ports.contains(&502) || open_ports.contains(&47808) {
            return (DeviceCategory::IndustrialController, None, None, 0.6);
        }
        if open_ports.contains(&5060) {
            return (DeviceCategory::VoIPPhone, None, None, 0.5);
        }
        if open_ports.contains(&9100) {
            return (DeviceCategory::Printer, None, None, 0.6);
        }
        if open_ports.contains(&8080) && open_ports.contains(&22) {
            return (DeviceCategory::NetworkRouter, None, None, 0.4);
        }

        (DeviceCategory::Unknown, None, None, 0.1)
    }

    fn detect_firmware_version(&self, banner_info: &HashMap<String, String>) -> Option<String> {
        for banner in banner_info.values() {
            let lower = banner.to_lowercase();

            // Common firmware version patterns
            if let Some(ver) = Self::extract_version(&lower, "firmware") {
                return Some(ver);
            }
            if let Some(ver) = Self::extract_version(&lower, "version") {
                return Some(ver);
            }
            if let Some(ver) = Self::extract_version(&lower, "ver") {
                return Some(ver);
            }
            if let Some(ver) = Self::extract_version(&lower, "fw") {
                return Some(ver);
            }
        }
        None
    }

    fn extract_version(text: &str, prefix: &str) -> Option<String> {
        if let Some(pos) = text.find(prefix) {
            let after = &text[pos + prefix.len()..];
            // Look for version-like patterns: digits.digits.digits
            let chars: Vec<char> = after.chars().collect();
            let mut version = String::new();
            let mut started = false;
            for ch in chars.iter().take(20) {
                if ch.is_ascii_digit() || (*ch == '.' && started) {
                    version.push(*ch);
                    started = true;
                } else if started && !ch.is_ascii_whitespace() && *ch != ':' && *ch != '=' {
                    break;
                }
            }
            if !version.is_empty() && version.contains('.') {
                return Some(version);
            }
        }
        None
    }

    fn detect_os(&self, banner_info: &HashMap<String, String>) -> Option<String> {
        for banner in banner_info.values() {
            let lower = banner.to_lowercase();
            if lower.contains("linux") {
                return Some("Linux".to_string());
            } else if lower.contains("windows") {
                return Some("Windows".to_string());
            } else if lower.contains("vxworks") {
                return Some("VxWorks".to_string());
            } else if lower.contains("rtos") {
                return Some("RTOS".to_string());
            } else if lower.contains("freertos") {
                return Some("FreeRTOS".to_string());
            } else if lower.contains("openwrt") {
                return Some("OpenWrt".to_string());
            }
        }
        None
    }

    fn check_vulnerabilities(
        &self,
        vendor: &Option<String>,
        _model: &Option<String>,
        _firmware: &Option<String>,
    ) -> Vec<VulnerabilityInfo> {
        let mut vulns = Vec::new();

        // Check known vulnerability patterns
        if let Some(v) = vendor {
            let v_lower = v.to_lowercase();

            if v_lower.contains("hikvision") {
                vulns.push(
                    VulnerabilityInfo::new(
                        "CVE-2017-7921",
                        "CRITICAL",
                        "Hikvision Authentication Bypass",
                        "Authentication bypass vulnerability in Hikvision cameras allowing unauthorized access",
                    )
                    .with_versions(
                        vec!["5.2.0", "5.3.0", "5.3.5", "5.3.6", "5.3.7", "5.3.8", "5.3.9", "5.4.0"],
                        Some("5.4.5"),
                    ),
                );
                vulns.push(
                    VulnerabilityInfo::new(
                        "CVE-2021-36260",
                        "CRITICAL",
                        "Hikvision Command Injection",
                        "Command injection vulnerability via malicious HTTP messages",
                    )
                    .with_versions(
                        vec![
                            "5.3.0", "5.3.5", "5.3.6", "5.3.7", "5.3.8", "5.3.9", "5.4.0", "5.4.5",
                            "5.5.0",
                        ],
                        Some("5.6.0"),
                    ),
                );
            } else if v_lower.contains("dahua") {
                vulns.push(
                    VulnerabilityInfo::new(
                        "CVE-2021-33044",
                        "CRITICAL",
                        "Dahua Authentication Bypass",
                        "Authentication bypass allowing access to device configuration",
                    )
                    .with_versions(vec![], Some("Latest")),
                );
            } else if v_lower.contains("mikrotik") {
                vulns.push(
                    VulnerabilityInfo::new(
                        "CVE-2018-14847",
                        "CRITICAL",
                        "MikroTik Winbox File Read",
                        "Vulnerability allowing unauthenticated file read via Winbox",
                    )
                    .with_versions(
                        vec![
                            "6.29", "6.30", "6.31", "6.32", "6.33", "6.34", "6.35", "6.36", "6.37",
                            "6.38", "6.39", "6.40",
                        ],
                        Some("6.40.5"),
                    ),
                );
            } else if v_lower.contains("ubiquiti") || v_lower.contains("ubnt") {
                vulns.push(
                    VulnerabilityInfo::new(
                        "CVE-2019-5018",
                        "HIGH",
                        "Ubiquiti EdgeRouter XSS",
                        "Cross-site scripting vulnerability in EdgeRouter web interface",
                    )
                    .with_versions(vec!["1.10.6", "1.10.7", "1.10.8", "1.10.9"], Some("2.0.0")),
                );
            }
        }

        vulns
    }

    async fn grab_banner(&self, target: IpAddr, port: u16) -> Result<String> {
        let addr = SocketAddr::new(target, port);
        let stream = timeout(self.timeout_duration, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("Connection timeout"))?
            .map_err(|e| anyhow!("Connection failed: {}", e))?;

        let (mut reader, mut writer) = stream.into_split();

        // Send HTTP request for web ports, or just read for other ports
        if port == 80 || port == 8080 || port == 8000 {
            let request = format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Nemue-Fingerprint\r\nConnection: close\r\n\r\n",
                target
            );
            let _ = writer.write_all(request.as_bytes()).await;
        } else if port == 443 || port == 8443 {
            // For HTTPS, just try to grab what we can from the TCP layer
            let probe = format!("HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n", target);
            let _ = writer.write_all(probe.as_bytes()).await;
        }

        let mut response = vec![0u8; 4096];
        let n = match timeout(self.timeout_duration, reader.read(&mut response)).await {
            Ok(Ok(n)) => n,
            _ => return Ok(String::new()),
        };

        Ok(String::from_utf8_lossy(&response[..n]).to_string())
    }

    fn build_fingerprint_db() -> Vec<FingerprintSignature> {
        vec![
            FingerprintSignature {
                vendor: "Hikvision".to_string(),
                model: "IP Camera".to_string(),
                category: DeviceCategory::IPCamera,
                banner_patterns: vec!["hikvision".to_string(), "HIKVISION".to_string()],
                port_combinations: vec![vec![80, 554, 8000]],
                os_pattern: Some("Linux".to_string()),
            },
            FingerprintSignature {
                vendor: "Dahua".to_string(),
                model: "IP Camera".to_string(),
                category: DeviceCategory::IPCamera,
                banner_patterns: vec!["dahua".to_string(), "DAHUA".to_string()],
                port_combinations: vec![vec![80, 554, 37777]],
                os_pattern: Some("Linux".to_string()),
            },
            FingerprintSignature {
                vendor: "Axis".to_string(),
                model: "IP Camera".to_string(),
                category: DeviceCategory::IPCamera,
                banner_patterns: vec!["axis".to_string(), "AXIS".to_string()],
                port_combinations: vec![vec![80, 443, 554]],
                os_pattern: Some("Linux".to_string()),
            },
            FingerprintSignature {
                vendor: "MikroTik".to_string(),
                model: "Router".to_string(),
                category: DeviceCategory::NetworkRouter,
                banner_patterns: vec!["mikrotik".to_string(), "routeros".to_string()],
                port_combinations: vec![vec![22, 80, 8291]],
                os_pattern: Some("RouterOS".to_string()),
            },
            FingerprintSignature {
                vendor: "Ubiquiti".to_string(),
                model: "UniFi".to_string(),
                category: DeviceCategory::NetworkRouter,
                banner_patterns: vec![
                    "ubnt".to_string(),
                    "ubiquiti".to_string(),
                    "unifi".to_string(),
                ],
                port_combinations: vec![vec![22, 80, 443, 8080, 8443]],
                os_pattern: Some("Linux".to_string()),
            },
            FingerprintSignature {
                vendor: "Synology".to_string(),
                model: "DiskStation".to_string(),
                category: DeviceCategory::NAS,
                banner_patterns: vec!["synology".to_string()],
                port_combinations: vec![vec![5000, 5001]],
                os_pattern: Some("DSM".to_string()),
            },
            FingerprintSignature {
                vendor: "QNAP".to_string(),
                model: "TurboNAS".to_string(),
                category: DeviceCategory::NAS,
                banner_patterns: vec!["qnap".to_string()],
                port_combinations: vec![vec![8080, 8443]],
                os_pattern: Some("QTS".to_string()),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_category_as_str() {
        assert_eq!(DeviceCategory::IPCamera.as_str(), "IP Camera");
        assert_eq!(DeviceCategory::NetworkRouter.as_str(), "Network Router");
        assert_eq!(DeviceCategory::SmartSpeaker.as_str(), "Smart Speaker");
        assert_eq!(
            DeviceCategory::IndustrialController.as_str(),
            "Industrial Controller"
        );
        assert_eq!(DeviceCategory::NAS.as_str(), "Network Attached Storage");
        assert_eq!(DeviceCategory::Unknown.as_str(), "Unknown");
    }

    #[test]
    fn test_fingerprinter_creation() {
        let fp = IoTDeviceFingerprinter::new(2000);
        assert_eq!(fp.timeout_duration, Duration::from_millis(2000));
        assert!(!fp.fingerprint_db.is_empty());
    }

    #[test]
    fn test_vulnerability_info_new() {
        let vuln = VulnerabilityInfo::new("CVE-2021-1234", "HIGH", "Test Vuln", "Test description");
        assert_eq!(vuln.id, "CVE-2021-1234");
        assert_eq!(vuln.severity, "HIGH");
        assert!(vuln.affected_versions.is_empty());
        assert!(vuln.fixed_version.is_none());
    }

    #[test]
    fn test_vulnerability_info_with_versions() {
        let vuln = VulnerabilityInfo::new("CVE-2021-1234", "HIGH", "Test", "Desc")
            .with_versions(vec!["1.0", "2.0"], Some("3.0"));
        assert_eq!(vuln.affected_versions.len(), 2);
        assert_eq!(vuln.fixed_version, Some("3.0".to_string()));
    }

    #[test]
    fn test_fingerprint_db_has_entries() {
        let fp = IoTDeviceFingerprinter::new(1000);
        assert!(fp.fingerprint_db.len() >= 5);
        assert!(fp.fingerprint_db.iter().any(|s| s.vendor == "Hikvision"));
        assert!(fp.fingerprint_db.iter().any(|s| s.vendor == "MikroTik"));
    }

    #[test]
    fn test_extract_version() {
        let text = "firmware version 2.1.3 build 1234";
        let ver = IoTDeviceFingerprinter::extract_version(text, "firmware");
        assert_eq!(ver, Some("2.1.3".to_string()));
    }

    #[test]
    fn test_extract_version_simple() {
        let text = "ver: 1.0.5";
        let ver = IoTDeviceFingerprinter::extract_version(text, "ver");
        assert_eq!(ver, Some("1.0.5".to_string()));
    }

    #[test]
    fn test_extract_version_not_found() {
        let text = "no version info here";
        let ver = IoTDeviceFingerprinter::extract_version(text, "firmware");
        assert!(ver.is_none());
    }

    #[test]
    fn test_detect_os_linux() {
        let fp = IoTDeviceFingerprinter::new(1000);
        let mut banners = HashMap::new();
        banners.insert(
            "port_80".to_string(),
            "Server: Apache/2.4 (Linux)".to_string(),
        );
        let os = fp.detect_os(&banners);
        assert_eq!(os, Some("Linux".to_string()));
    }

    #[test]
    fn test_detect_os_none() {
        let fp = IoTDeviceFingerprinter::new(1000);
        let banners = HashMap::new();
        let os = fp.detect_os(&banners);
        assert!(os.is_none());
    }

    #[test]
    fn test_match_fingerprint_hikvision() {
        let fp = IoTDeviceFingerprinter::new(1000);
        let mut banners = HashMap::new();
        banners.insert(
            "port_80".to_string(),
            "HTTP/1.1 200 OK\r\nServer: Hikvision-Webs".to_string(),
        );
        let (cat, vendor, _model, conf) = fp.match_fingerprint(&[80, 554], &banners);
        assert_eq!(cat, DeviceCategory::IPCamera);
        assert_eq!(vendor, Some("Hikvision".to_string()));
        assert!(conf > 0.5);
    }

    #[test]
    fn test_match_fingerprint_camera_ports() {
        let fp = IoTDeviceFingerprinter::new(1000);
        let banners = HashMap::new();
        let (cat, _, _, conf) = fp.match_fingerprint(&[554], &banners);
        assert_eq!(cat, DeviceCategory::IPCamera);
        assert!(conf > 0.0);
    }

    #[test]
    fn test_match_fingerprint_industrial_ports() {
        let fp = IoTDeviceFingerprinter::new(1000);
        let banners = HashMap::new();
        let (cat, _, _, _) = fp.match_fingerprint(&[502, 47808], &banners);
        assert_eq!(cat, DeviceCategory::IndustrialController);
    }

    #[test]
    fn test_match_fingerprint_unknown() {
        let fp = IoTDeviceFingerprinter::new(1000);
        let banners = HashMap::new();
        let (cat, _, _, conf) = fp.match_fingerprint(&[12345], &banners);
        assert_eq!(cat, DeviceCategory::Unknown);
        assert!(conf < 0.5);
    }

    #[test]
    fn test_check_vulnerabilities_hikvision() {
        let fp = IoTDeviceFingerprinter::new(1000);
        let vulns = fp.check_vulnerabilities(
            &Some("Hikvision".to_string()),
            &None,
            &Some("5.3.0".to_string()),
        );
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.id == "CVE-2017-7921"));
        assert!(vulns.iter().any(|v| v.id == "CVE-2021-36260"));
    }

    #[test]
    fn test_check_vulnerabilities_mikrotik() {
        let fp = IoTDeviceFingerprinter::new(1000);
        let vulns = fp.check_vulnerabilities(&Some("MikroTik".to_string()), &None, &None);
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.id == "CVE-2018-14847"));
    }

    #[test]
    fn test_check_vulnerabilities_unknown() {
        let fp = IoTDeviceFingerprinter::new(1000);
        let vulns = fp.check_vulnerabilities(&Some("UnknownVendor".to_string()), &None, &None);
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_fingerprint_result_serialization() {
        let result = FingerprintResult {
            ip: IpAddr::V4([192, 168, 1, 1].into()),
            category: DeviceCategory::IPCamera,
            vendor: Some("Hikvision".to_string()),
            model: Some("DS-2CD2042".to_string()),
            firmware_version: Some("5.4.5".to_string()),
            os: Some("Linux".to_string()),
            mac_vendor: None,
            open_ports: vec![80, 554],
            banner_info: HashMap::new(),
            vulnerabilities: vec![],
            confidence: 0.9,
            scan_duration: Duration::from_millis(100),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("IPCamera"));
        assert!(json.contains("Hikvision"));
    }

    #[test]
    fn test_detect_firmware_from_banner() {
        let fp = IoTDeviceFingerprinter::new(1000);
        let mut banners = HashMap::new();
        banners.insert(
            "port_80".to_string(),
            "Server: Device/1.0\r\nFirmware: 3.2.1 build 1234".to_string(),
        );
        let fw = fp.detect_firmware_version(&banners);
        assert_eq!(fw, Some("3.2.1".to_string()));
    }

    #[tokio::test]
    async fn test_grab_banner_closed_port() {
        let fp = IoTDeviceFingerprinter::new(200);
        let result = fp.grab_banner(IpAddr::V4([127, 0, 0, 1].into()), 1).await;
        assert!(result.is_err());
    }
}
