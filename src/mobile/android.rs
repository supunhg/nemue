//! Android Security Scanning Module
//!
//! Provides ADB device enumeration, service discovery, security assessment,
//! and vulnerability detection for Android devices.

use serde::{Deserialize, Serialize};
use std::process::Command;

use crate::mobile::MobileSeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidConfig {
    pub adb_path: String,
    pub enumerate_packages: bool,
    pub check_permissions: bool,
    pub scan_ports: bool,
    pub timeout_seconds: u64,
}

impl Default for AndroidConfig {
    fn default() -> Self {
        Self {
            adb_path: "adb".to_string(),
            enumerate_packages: true,
            check_permissions: true,
            scan_ports: true,
            timeout_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdbDevice {
    pub serial: String,
    pub state: String,
    pub transport: String,
    pub model: String,
    pub product: String,
    pub device: String,
    pub android_version: String,
    pub sdk_version: String,
    pub build_id: String,
    pub security_patch: String,
    pub is_rooted: bool,
    pub usb_debugging: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AndroidService {
    pub name: String,
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub description: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AndroidVulnerability {
    pub id: String,
    pub title: String,
    pub severity: MobileSeverity,
    pub description: String,
    pub affected_component: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidSecurityFinding {
    pub title: String,
    pub description: String,
    pub severity: MobileSeverity,
    pub category: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub version_code: String,
    pub is_system: bool,
    pub permissions: Vec<String>,
    pub exported_activities: Vec<String>,
    pub debuggable: bool,
    pub allow_backup: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AndroidResults {
    pub devices: Vec<AdbDevice>,
    pub services: Vec<AndroidService>,
    pub packages: Vec<InstalledPackage>,
    pub vulnerabilities: Vec<AndroidVulnerability>,
    pub security_findings: Vec<AndroidSecurityFinding>,
    pub adb_available: bool,
}

pub struct AndroidScanner {
    config: AndroidConfig,
}

impl AndroidScanner {
    pub fn new(config: AndroidConfig) -> Self {
        Self { config }
    }

    pub fn with_default() -> Self {
        Self::new(AndroidConfig::default())
    }

    pub fn scan(&self) -> AndroidResults {
        let mut results = AndroidResults::default();

        results.adb_available = self.is_adb_available();
        if !results.adb_available {
            results.security_findings.push(AndroidSecurityFinding {
                title: "ADB not available".to_string(),
                description: "Android Debug Bridge is not installed or not in PATH.".to_string(),
                severity: MobileSeverity::Info,
                category: "tooling".to_string(),
                recommendation: "Install Android SDK Platform Tools to enable ADB scanning.".to_string(),
            });
            return results;
        }

        results.devices = self.enumerate_devices();

        if results.devices.is_empty() {
            results.security_findings.push(AndroidSecurityFinding {
                title: "No Android devices found".to_string(),
                description: "No connected Android devices detected via ADB.".to_string(),
                severity: MobileSeverity::Info,
                category: "connectivity".to_string(),
                recommendation: "Ensure USB debugging is enabled and the device is connected.".to_string(),
            });
            return results;
        }

        for device in &results.devices {
            results.services.extend(self.discover_services(&device.serial));

            if self.config.enumerate_packages {
                results.packages.extend(self.enumerate_packages(&device.serial));
            }
        }

        results.vulnerabilities = self.detect_vulnerabilities(&results);
        results.security_findings.extend(self.assess_security(&results));

        results
    }

    fn is_adb_available(&self) -> bool {
        Command::new(&self.config.adb_path)
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    pub fn enumerate_devices(&self) -> Vec<AdbDevice> {
        let output = Command::new(&self.config.adb_path)
            .arg("devices")
            .arg("-l")
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty() && !line.contains("List of devices"))
            .filter_map(|line| self.parse_device_line(line))
            .collect()
    }

    fn parse_device_line(&self, line: &str) -> Option<AdbDevice> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let serial = parts[0].to_string();
        let state = parts[1].to_string();

        let mut device_info = AdbDevice {
            serial: serial.clone(),
            state: state.clone(),
            transport: "usb".to_string(),
            ..Default::default()
        };

        for part in &parts[2..] {
            if let Some(val) = part.strip_prefix("model:") {
                device_info.model = val.to_string();
            } else if let Some(val) = part.strip_prefix("product:") {
                device_info.product = val.to_string();
            } else if let Some(val) = part.strip_prefix("device:") {
                device_info.device = val.to_string();
            } else if let Some(val) = part.strip_prefix("transport_id:") {
                device_info.transport = format!("transport_{}", val);
            }
        }

        if state == "device" {
            device_info.android_version = self.get_prop(&serial, "ro.build.version.release");
            device_info.sdk_version = self.get_prop(&serial, "ro.build.version.sdk");
            device_info.build_id = self.get_prop(&serial, "ro.build.display.id");
            device_info.security_patch = self.get_prop(&serial, "ro.build.version.security_patch");
            device_info.is_rooted = self.check_root(&serial);
            device_info.usb_debugging = true;
        }

        Some(device_info)
    }

    fn get_prop(&self, serial: &str, prop: &str) -> String {
        Command::new(&self.config.adb_path)
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

    fn check_root(&self, serial: &str) -> bool {
        let su_check = Command::new(&self.config.adb_path)
            .arg("-s")
            .arg(serial)
            .arg("shell")
            .arg("which")
            .arg("su")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();

        if !su_check.trim().is_empty() {
            return true;
        }

        let test_keys = self.get_prop(serial, "ro.build.tags");
        test_keys.contains("test-keys")
    }

    pub fn discover_services(&self, serial: &str) -> Vec<AndroidService> {
        let mut services = Vec::new();

        let known_services = vec![
            (5555, "adb", "ADB over TCP"),
            (5554, "emulator", "Android Emulator Console"),
            (5037, "adb-server", "ADB Server"),
            (8080, "http", "HTTP Proxy"),
            (8443, "https", "HTTPS"),
            (5000, "upnp", "UPnP Service"),
            (6200, "qsb", "Quick Search Box"),
            (7272, "dlna", "DLNA Service"),
            (9000, "mdns", "mDNS/Bonjour"),
        ];

        for (port, name, desc) in &known_services {
            let is_open = self.check_port(serial, *port);
            if is_open {
                services.push(AndroidService {
                    name: name.to_string(),
                    port: *port,
                    protocol: "tcp".to_string(),
                    state: "open".to_string(),
                    description: desc.to_string(),
                });
            }
        }

        let netstat_output = Command::new(&self.config.adb_path)
            .arg("-s")
            .arg(serial)
            .arg("shell")
            .arg("netstat")
            .arg("-tlnp")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();

        for line in netstat_output.lines() {
            if line.contains("LISTEN") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(addr) = parts.get(3) {
                    if let Some(port_str) = addr.rsplit(':').next() {
                        if let Ok(port) = port_str.parse::<u16>() {
                            if !services.iter().any(|s| s.port == port) {
                                services.push(AndroidService {
                                    name: format!("unknown-{}", port),
                                    port,
                                    protocol: "tcp".to_string(),
                                    state: "open".to_string(),
                                    description: "Discovered via netstat".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        services
    }

    fn check_port(&self, serial: &str, port: u16) -> bool {
        Command::new(&self.config.adb_path)
            .arg("-s")
            .arg(serial)
            .arg("shell")
            .arg("nc")
            .arg("-z")
            .arg("-w")
            .arg("1")
            .arg("127.0.0.1")
            .arg(port.to_string())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    pub fn enumerate_packages(&self, serial: &str) -> Vec<InstalledPackage> {
        let output = Command::new(&self.config.adb_path)
            .arg("-s")
            .arg(serial)
            .arg("shell")
            .arg("pm")
            .arg("list")
            .arg("packages")
            .arg("-f")
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .filter(|line| line.starts_with("package:"))
            .filter_map(|line| {
                let path_name = line.strip_prefix("package:")?;
                let parts: Vec<&str> = path_name.rsplitn(2, '=').collect();
                let name = parts.first()?.to_string();
                let path = parts.get(1).unwrap_or(&"").to_string();
                let is_system = path.starts_with("/system/") || path.starts_with("/vendor/");

                Some(InstalledPackage {
                    name,
                    version: String::new(),
                    version_code: String::new(),
                    is_system,
                    permissions: Vec::new(),
                    exported_activities: Vec::new(),
                    debuggable: false,
                    allow_backup: false,
                })
            })
            .collect()
    }

    fn detect_vulnerabilities(&self, results: &AndroidResults) -> Vec<AndroidVulnerability> {
        let mut vulns = Vec::new();

        for device in &results.devices {
            if let Ok(sdk) = device.sdk_version.parse::<u32>() {
                if sdk < 28 {
                    vulns.push(AndroidVulnerability {
                        id: "ANDROID-OLD-SDK".to_string(),
                        title: "Outdated Android SDK version".to_string(),
                        severity: MobileSeverity::High,
                        description: format!("Device running SDK {} (Android {}). Older versions lack critical security patches.", sdk, device.android_version),
                        affected_component: "OS".to_string(),
                        remediation: "Update device to Android 10 (SDK 29) or later.".to_string(),
                    });
                }
            }

            if device.is_rooted {
                vulns.push(AndroidVulnerability {
                    id: "ANDROID-ROOTED".to_string(),
                    title: "Device is rooted".to_string(),
                    severity: MobileSeverity::Critical,
                    description: "Root access bypasses Android's application sandbox and security model.".to_string(),
                    affected_component: "OS".to_string(),
                    remediation: "Unroot the device or use a non-rooted device for sensitive operations.".to_string(),
                });
            }
        }

        for pkg in &results.packages {
            if pkg.debuggable {
                vulns.push(AndroidVulnerability {
                    id: "ANDROID-DEBUGGABLE".to_string(),
                    title: format!("Debuggable application: {}", pkg.name),
                    severity: MobileSeverity::High,
                    description: "Debuggable apps expose internal state and allow arbitrary code execution.".to_string(),
                    affected_component: pkg.name.clone(),
                    remediation: "Remove android:debuggable=true from the application manifest.".to_string(),
                });
            }

            if pkg.allow_backup && !pkg.is_system {
                vulns.push(AndroidVulnerability {
                    id: "ANDROID-BACKUP".to_string(),
                    title: format!("Backup enabled: {}", pkg.name),
                    severity: MobileSeverity::Medium,
                    description: "Apps with allowBackup=true can have their data extracted via adb backup.".to_string(),
                    affected_component: pkg.name.clone(),
                    remediation: "Set android:allowBackup=false in the application manifest.".to_string(),
                });
            }
        }

        vulns
    }

    pub fn assess_security(&self, results: &AndroidResults) -> Vec<AndroidSecurityFinding> {
        let mut findings = Vec::new();

        for device in &results.devices {
            if device.security_patch.is_empty() {
                findings.push(AndroidSecurityFinding {
                    title: "Security patch level unknown".to_string(),
                    description: format!("Device {} has no security patch information.", device.serial),
                    severity: MobileSeverity::Medium,
                    category: "patching".to_string(),
                    recommendation: "Verify the device has the latest security patches installed.".to_string(),
                });
            }

            if results.services.iter().any(|s| s.port == 5555 && s.state == "open") {
                findings.push(AndroidSecurityFinding {
                    title: "ADB over TCP enabled".to_string(),
                    description: "ADB debugging over network is enabled, allowing remote access.".to_string(),
                    severity: MobileSeverity::High,
                    category: "network".to_string(),
                    recommendation: "Disable ADB over TCP and use USB debugging only when needed.".to_string(),
                });
            }

            let debuggable_count = results.packages.iter().filter(|p| p.debuggable).count();
            if debuggable_count > 0 {
                findings.push(AndroidSecurityFinding {
                    title: format!("{} debuggable applications found", debuggable_count),
                    description: "Debuggable applications can be inspected and modified at runtime.".to_string(),
                    severity: MobileSeverity::High,
                    category: "application".to_string(),
                    recommendation: "Ensure release builds have android:debuggable=false.".to_string(),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_android_config_default() {
        let config = AndroidConfig::default();
        assert_eq!(config.adb_path, "adb");
        assert!(config.enumerate_packages);
        assert!(config.check_permissions);
        assert!(config.scan_ports);
    }

    #[test]
    fn test_android_scanner_creation() {
        let scanner = AndroidScanner::with_default();
        assert_eq!(scanner.config.adb_path, "adb");
    }

    #[test]
    fn test_adb_device_default() {
        let device = AdbDevice::default();
        assert!(device.serial.is_empty());
        assert!(device.state.is_empty());
        assert!(!device.is_rooted);
    }

    #[test]
    fn test_android_results_default() {
        let results = AndroidResults::default();
        assert!(results.devices.is_empty());
        assert!(results.services.is_empty());
        assert!(results.packages.is_empty());
        assert!(results.vulnerabilities.is_empty());
        assert!(results.security_findings.is_empty());
        assert!(!results.adb_available);
    }

    #[test]
    fn test_installed_package_default() {
        let pkg = InstalledPackage::default();
        assert!(pkg.name.is_empty());
        assert!(!pkg.is_system);
        assert!(!pkg.debuggable);
        assert!(!pkg.allow_backup);
    }

    #[test]
    fn test_detect_rooted_device_vulnerability() {
        let scanner = AndroidScanner::with_default();
        let mut results = AndroidResults::default();
        results.devices.push(AdbDevice {
            serial: "test123".to_string(),
            state: "device".to_string(),
            android_version: "11".to_string(),
            sdk_version: "30".to_string(),
            is_rooted: true,
            ..Default::default()
        });

        let vulns = scanner.detect_vulnerabilities(&results);
        assert!(vulns.iter().any(|v| v.id == "ANDROID-ROOTED" && v.severity == MobileSeverity::Critical));
    }

    #[test]
    fn test_detect_old_sdk_vulnerability() {
        let scanner = AndroidScanner::with_default();
        let mut results = AndroidResults::default();
        results.devices.push(AdbDevice {
            serial: "test123".to_string(),
            state: "device".to_string(),
            android_version: "7".to_string(),
            sdk_version: "24".to_string(),
            ..Default::default()
        });

        let vulns = scanner.detect_vulnerabilities(&results);
        assert!(vulns.iter().any(|v| v.id == "ANDROID-OLD-SDK" && v.severity == MobileSeverity::High));
    }

    #[test]
    fn test_detect_debuggable_app_vulnerability() {
        let scanner = AndroidScanner::with_default();
        let mut results = AndroidResults::default();
        results.packages.push(InstalledPackage {
            name: "com.example.app".to_string(),
            debuggable: true,
            ..Default::default()
        });

        let vulns = scanner.detect_vulnerabilities(&results);
        assert!(vulns.iter().any(|v| v.id == "ANDROID-DEBUGGABLE"));
    }

    #[test]
    fn test_detect_backup_enabled_vulnerability() {
        let scanner = AndroidScanner::with_default();
        let mut results = AndroidResults::default();
        results.packages.push(InstalledPackage {
            name: "com.example.app".to_string(),
            allow_backup: true,
            is_system: false,
            ..Default::default()
        });

        let vulns = scanner.detect_vulnerabilities(&results);
        assert!(vulns.iter().any(|v| v.id == "ANDROID-BACKUP"));
    }

    #[test]
    fn test_assess_adb_over_tcp() {
        let scanner = AndroidScanner::with_default();
        let mut results = AndroidResults::default();
        results.devices.push(AdbDevice {
            serial: "test123".to_string(),
            state: "device".to_string(),
            ..Default::default()
        });
        results.services.push(AndroidService {
            name: "adb".to_string(),
            port: 5555,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            description: "ADB over TCP".to_string(),
        });

        let findings = scanner.assess_security(&results);
        assert!(findings.iter().any(|f| f.title.contains("ADB over TCP") && f.severity == MobileSeverity::High));
    }

    #[test]
    fn test_assess_security_empty() {
        let scanner = AndroidScanner::with_default();
        let results = AndroidResults::default();
        let findings = scanner.assess_security(&results);
        assert!(findings.is_empty());
    }
}
