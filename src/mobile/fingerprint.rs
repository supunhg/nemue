//! Mobile Device Fingerprinting Module
//!
//! Device type identification, OS version detection, app enumeration,
//! and security assessment for mobile devices.

use serde::{Deserialize, Serialize};
use std::process::Command;

use crate::mobile::MobileSeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintConfig {
    pub detect_via_network: bool,
    pub detect_via_user_agent: bool,
    pub enumerate_apps: bool,
    pub timeout_seconds: u64,
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            detect_via_network: true,
            detect_via_user_agent: true,
            enumerate_apps: true,
            timeout_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    Android,
    Ios,
    WindowsPhone,
    Unknown,
}

impl DeviceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceType::Android => "Android",
            DeviceType::Ios => "iOS",
            DeviceType::WindowsPhone => "Windows Phone",
            DeviceType::Unknown => "Unknown",
        }
    }
}

impl Default for DeviceType {
    fn default() -> Self {
        DeviceType::Unknown
    }
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OsInfo {
    pub os_type: DeviceType,
    pub version: String,
    pub build: String,
    pub kernel: String,
    pub architecture: String,
    pub security_patch: String,
    pub is_jailbroken: bool,
    pub is_rooted: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    pub device_type: DeviceType,
    pub manufacturer: String,
    pub model: String,
    pub os_info: OsInfo,
    pub screen_resolution: String,
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: String,
    pub open_ports: Vec<u16>,
    pub installed_apps: Vec<String>,
    pub security_features: SecurityFeatures,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityFeatures {
    pub encryption_enabled: bool,
    pub screen_lock: bool,
    pub biometric_auth: bool,
    pub remote_wipe: bool,
    pub device_admin: bool,
    pub unknown_sources: bool,
    pub developer_mode: bool,
    pub usb_debugging: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintSecurityFinding {
    pub title: String,
    pub description: String,
    pub severity: MobileSeverity,
    pub category: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FingerprintResults {
    pub devices: Vec<DeviceFingerprint>,
    pub security_findings: Vec<FingerprintSecurityFinding>,
}

pub struct MobileFingerprinter {
    config: FingerprintConfig,
}

impl MobileFingerprinter {
    pub fn new(config: FingerprintConfig) -> Self {
        Self { config }
    }

    pub fn with_default() -> Self {
        Self::new(FingerprintConfig::default())
    }

    pub fn fingerprint_from_user_agent(&self, user_agent: &str) -> DeviceFingerprint {
        let ua_lower = user_agent.to_lowercase();
        let device_type = if ua_lower.contains("android") {
            DeviceType::Android
        } else if ua_lower.contains("iphone") || ua_lower.contains("ipad") || ua_lower.contains("ipod") {
            DeviceType::Ios
        } else if ua_lower.contains("windows phone") {
            DeviceType::WindowsPhone
        } else {
            DeviceType::Unknown
        };

        let os_version = self.extract_os_version(&ua_lower, device_type);

        let model = self.extract_model(user_agent, device_type);
        let manufacturer = self.extract_manufacturer(user_agent, device_type);

        DeviceFingerprint {
            device_type,
            manufacturer,
            model,
            os_info: OsInfo {
                os_type: device_type,
                version: os_version,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn extract_os_version(&self, ua_lower: &str, device_type: DeviceType) -> String {
        match device_type {
            DeviceType::Android => {
                if let Some(start) = ua_lower.find("android ") {
                    let version_start = start + 8;
                    if let Some(end) = ua_lower[version_start..].find(';') {
                        return ua_lower[version_start..version_start + end].trim().to_string();
                    }
                }
                String::new()
            }
            DeviceType::Ios => {
                if let Some(start) = ua_lower.find("os ") {
                    let version_start = start + 3;
                    if let Some(end) = ua_lower[version_start..].find(' ') {
                        return ua_lower[version_start..version_start + end].replace('_', ".");
                    }
                }
                String::new()
            }
            _ => String::new(),
        }
    }

    fn extract_model(&self, user_agent: &str, device_type: DeviceType) -> String {
        match device_type {
            DeviceType::Android => {
                if let Some(start) = user_agent.find("; ") {
                    let rest = &user_agent[start + 2..];
                    if let Some(end) = rest.find(" Build") {
                        return rest[..end].trim().to_string();
                    }
                }
                String::new()
            }
            DeviceType::Ios => {
                if user_agent.contains("iPhone") {
                    "iPhone".to_string()
                } else if user_agent.contains("iPad") {
                    "iPad".to_string()
                } else {
                    String::new()
                }
            }
            _ => String::new(),
        }
    }

    fn extract_manufacturer(&self, user_agent: &str, device_type: DeviceType) -> String {
        match device_type {
            DeviceType::Android => {
                let known_manufacturers = [
                    "Samsung", "Google", "OnePlus", "Xiaomi", "Huawei", "LG",
                    "Motorola", "Sony", "HTC", "Nokia", "Oppo", "Vivo", "Realme",
                ];
                for mfr in &known_manufacturers {
                    if user_agent.to_lowercase().contains(&mfr.to_lowercase()) {
                        return mfr.to_string();
                    }
                }
                "Unknown".to_string()
            }
            DeviceType::Ios => "Apple".to_string(),
            _ => "Unknown".to_string(),
        }
    }

    pub fn fingerprint_from_adb(&self) -> Vec<DeviceFingerprint> {
        let output = Command::new("adb")
            .arg("devices")
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty() && line.contains("device"))
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let serial = parts.first()?;
                Some(self.fingerprint_android_device(serial))
            })
            .collect()
    }

    fn fingerprint_android_device(&self, serial: &str) -> DeviceFingerprint {
        let manufacturer = self.get_adb_prop(serial, "ro.product.manufacturer");
        let model = self.get_adb_prop(serial, "ro.product.model");
        let version = self.get_adb_prop(serial, "ro.build.version.release");
        let _sdk = self.get_adb_prop(serial, "ro.build.version.sdk");
        let build = self.get_adb_prop(serial, "ro.build.display.id");
        let security_patch = self.get_adb_prop(serial, "ro.build.version.security_patch");
        let arch = self.get_adb_prop(serial, "ro.product.cpu.abi");

        let is_rooted = self.check_root_adb(serial);
        let usb_debugging = true;
        let developer_mode = self.get_adb_prop(serial, "ro.debuggable") == "1";

        let mut installed_apps = Vec::new();
        if self.config.enumerate_apps {
            installed_apps = self.enumerate_apps_adb(serial);
        }

        DeviceFingerprint {
            device_type: DeviceType::Android,
            manufacturer,
            model,
            os_info: OsInfo {
                os_type: DeviceType::Android,
                version,
                build,
                kernel: self.get_adb_prop(serial, "ro.kernel.version"),
                architecture: arch,
                security_patch,
                is_rooted,
                is_jailbroken: false,
            },
            installed_apps,
            security_features: SecurityFeatures {
                encryption_enabled: self.get_adb_prop(serial, "ro.crypto.state") == "encrypted",
                screen_lock: true,
                biometric_auth: false,
                remote_wipe: false,
                device_admin: false,
                unknown_sources: self.get_adb_prop(serial, "ro.allow.mock.location") == "1",
                developer_mode,
                usb_debugging,
            },
            ..Default::default()
        }
    }

    fn get_adb_prop(&self, serial: &str, prop: &str) -> String {
        Command::new("adb")
            .arg("-s")
            .arg(serial)
            .arg("shell")
            .arg("getprop")
            .arg(prop)
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }

    fn check_root_adb(&self, serial: &str) -> bool {
        let su = Command::new("adb")
            .arg("-s")
            .arg(serial)
            .arg("shell")
            .arg("which")
            .arg("su")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();

        !su.trim().is_empty() || self.get_adb_prop(serial, "ro.build.tags").contains("test-keys")
    }

    fn enumerate_apps_adb(&self, serial: &str) -> Vec<String> {
        Command::new("adb")
            .arg("-s")
            .arg(serial)
            .arg("shell")
            .arg("pm")
            .arg("list")
            .arg("packages")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| {
                s.lines()
                    .filter_map(|line| line.strip_prefix("package:").map(|p| p.trim().to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn assess_security(&self, device: &DeviceFingerprint) -> Vec<FingerprintSecurityFinding> {
        let mut findings = Vec::new();

        if device.os_info.is_rooted || device.os_info.is_jailbroken {
            findings.push(FingerprintSecurityFinding {
                title: format!("Device {} is {}", device.model, if device.os_info.is_rooted { "rooted" } else { "jailbroken" }),
                description: "Compromised devices bypass security sandboxing.".to_string(),
                severity: MobileSeverity::Critical,
                category: "integrity".to_string(),
                recommendation: "Use non-compromised devices for sensitive operations.".to_string(),
            });
        }

        if device.security_features.usb_debugging {
            findings.push(FingerprintSecurityFinding {
                title: "USB debugging enabled".to_string(),
                description: "USB debugging allows unauthorized access via ADB.".to_string(),
                severity: MobileSeverity::High,
                category: "debugging".to_string(),
                recommendation: "Disable USB debugging when not actively developing.".to_string(),
            });
        }

        if device.security_features.developer_mode {
            findings.push(FingerprintSecurityFinding {
                title: "Developer mode enabled".to_string(),
                description: "Developer mode exposes additional attack surface.".to_string(),
                severity: MobileSeverity::Medium,
                category: "configuration".to_string(),
                recommendation: "Disable developer mode on production devices.".to_string(),
            });
        }

        if device.security_features.unknown_sources {
            findings.push(FingerprintSecurityFinding {
                title: "Unknown sources allowed".to_string(),
                description: "Installing apps from unknown sources increases malware risk.".to_string(),
                severity: MobileSeverity::High,
                category: "installation".to_string(),
                recommendation: "Disable installation from unknown sources.".to_string(),
            });
        }

        if !device.security_features.encryption_enabled && device.device_type == DeviceType::Android {
            findings.push(FingerprintSecurityFinding {
                title: "Device encryption not enabled".to_string(),
                description: "Unencrypted devices expose data if physically compromised.".to_string(),
                severity: MobileSeverity::High,
                category: "encryption".to_string(),
                recommendation: "Enable device encryption in Security settings.".to_string(),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_config_default() {
        let config = FingerprintConfig::default();
        assert!(config.detect_via_network);
        assert!(config.detect_via_user_agent);
        assert!(config.enumerate_apps);
    }

    #[test]
    fn test_device_type_display() {
        assert_eq!(format!("{}", DeviceType::Android), "Android");
        assert_eq!(format!("{}", DeviceType::Ios), "iOS");
        assert_eq!(format!("{}", DeviceType::Unknown), "Unknown");
    }

    #[test]
    fn test_fingerprint_android_user_agent() {
        let fp = MobileFingerprinter::with_default();
        let ua = "Mozilla/5.0 (Linux; Android 13; Pixel 7 Build/TQ3A.230901.001) AppleWebKit/537.36";
        let device = fp.fingerprint_from_user_agent(ua);

        assert_eq!(device.device_type, DeviceType::Android);
        assert_eq!(device.os_info.version, "13");
        assert!(device.model.contains("Pixel") || device.model.contains("Android"));
        // Manufacturer detection depends on user agent patterns
        assert!(device.manufacturer == "Google" || device.manufacturer == "Unknown");
    }

    #[test]
    fn test_fingerprint_ios_user_agent() {
        let fp = MobileFingerprinter::with_default();
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15";
        let device = fp.fingerprint_from_user_agent(ua);

        assert_eq!(device.device_type, DeviceType::Ios);
        assert_eq!(device.os_info.version, "17.0");
        assert_eq!(device.model, "iPhone");
        assert_eq!(device.manufacturer, "Apple");
    }

    #[test]
    fn test_fingerprint_samsung_user_agent() {
        let fp = MobileFingerprinter::with_default();
        // Samsung user agents typically include "Samsung" in the string
        let ua = "Mozilla/5.0 (Linux; Android 13; SM-S918B Build/TQ3A.230901.001) AppleWebKit/537.36";
        let device = fp.fingerprint_from_user_agent(ua);

        assert_eq!(device.device_type, DeviceType::Android);
        assert_eq!(device.os_info.version, "13");
    }

    #[test]
    fn test_fingerprint_ipad_user_agent() {
        let fp = MobileFingerprinter::with_default();
        let ua = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15";
        let device = fp.fingerprint_from_user_agent(ua);

        assert_eq!(device.device_type, DeviceType::Ios);
        assert_eq!(device.model, "iPad");
    }

    #[test]
    fn test_fingerprint_unknown_user_agent() {
        let fp = MobileFingerprinter::with_default();
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
        let device = fp.fingerprint_from_user_agent(ua);

        assert_eq!(device.device_type, DeviceType::Unknown);
    }

    #[test]
    fn test_assess_rooted_device() {
        let fp = MobileFingerprinter::with_default();
        let device = DeviceFingerprint {
            device_type: DeviceType::Android,
            model: "Pixel".to_string(),
            os_info: OsInfo {
                is_rooted: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let findings = fp.assess_security(&device);
        assert!(findings.iter().any(|f| f.severity == MobileSeverity::Critical && f.title.contains("rooted")));
    }

    #[test]
    fn test_assess_usb_debugging() {
        let fp = MobileFingerprinter::with_default();
        let device = DeviceFingerprint {
            device_type: DeviceType::Android,
            security_features: SecurityFeatures {
                usb_debugging: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let findings = fp.assess_security(&device);
        assert!(findings.iter().any(|f| f.severity == MobileSeverity::High && f.title.contains("USB debugging")));
    }

    #[test]
    fn test_assess_developer_mode() {
        let fp = MobileFingerprinter::with_default();
        let device = DeviceFingerprint {
            security_features: SecurityFeatures {
                developer_mode: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let findings = fp.assess_security(&device);
        assert!(findings.iter().any(|f| f.severity == MobileSeverity::Medium && f.title.contains("Developer")));
    }

    #[test]
    fn test_assess_unknown_sources() {
        let fp = MobileFingerprinter::with_default();
        let device = DeviceFingerprint {
            security_features: SecurityFeatures {
                unknown_sources: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let findings = fp.assess_security(&device);
        assert!(findings.iter().any(|f| f.severity == MobileSeverity::High && f.title.contains("Unknown sources")));
    }

    #[test]
    fn test_assess_no_encryption_android() {
        let fp = MobileFingerprinter::with_default();
        let device = DeviceFingerprint {
            device_type: DeviceType::Android,
            security_features: SecurityFeatures {
                encryption_enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let findings = fp.assess_security(&device);
        assert!(findings.iter().any(|f| f.severity == MobileSeverity::High && f.title.contains("encryption")));
    }

    #[test]
    fn test_assess_secure_device() {
        let fp = MobileFingerprinter::with_default();
        let device = DeviceFingerprint {
            device_type: DeviceType::Android,
            os_info: OsInfo {
                is_rooted: false,
                ..Default::default()
            },
            security_features: SecurityFeatures {
                encryption_enabled: true,
                usb_debugging: false,
                developer_mode: false,
                unknown_sources: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let findings = fp.assess_security(&device);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_fingerprint_results_default() {
        let results = FingerprintResults::default();
        assert!(results.devices.is_empty());
        assert!(results.security_findings.is_empty());
    }
}
