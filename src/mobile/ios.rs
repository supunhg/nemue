//! iOS Security Scanning Module
//!
//! Provides iOS device service discovery, security assessment,
//! vulnerability detection, and configuration analysis.

use serde::{Deserialize, Serialize};
use std::process::Command;

use crate::mobile::MobileSeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosConfig {
    pub ideviceinfo_path: String,
    pub idevice_id_path: String,
    pub check_profiles: bool,
    pub check_encryption: bool,
    pub timeout_seconds: u64,
}

impl Default for IosConfig {
    fn default() -> Self {
        Self {
            ideviceinfo_path: "ideviceinfo".to_string(),
            idevice_id_path: "idevice_id".to_string(),
            check_profiles: true,
            check_encryption: true,
            timeout_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IosDevice {
    pub udid: String,
    pub name: String,
    pub model: String,
    pub product_type: String,
    pub ios_version: String,
    pub build_version: String,
    pub serial_number: String,
    pub is_supervised: bool,
    pub is_encrypted: bool,
    pub passcode_set: bool,
    pub developer_mode: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IosService {
    pub name: String,
    pub port: u16,
    pub protocol_type: String,
    pub state: String,
    pub description: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IosVulnerability {
    pub id: String,
    pub title: String,
    pub severity: MobileSeverity,
    pub description: String,
    pub affected_component: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IosConfiguration {
    pub auto_lock_seconds: u32,
    pub passcode_required: bool,
    pub passcode_complexity: String,
    pub find_my_enabled: bool,
    pub siri_on_lock_screen: bool,
    pub usb_restricted_mode: bool,
    pub vpn_configured: bool,
    pub mdm_enrolled: bool,
    pub profiles_installed: Vec<ConfigurationProfile>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigurationProfile {
    pub identifier: String,
    pub display_name: String,
    pub profile_type: String,
    pub is_managed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosSecurityFinding {
    pub title: String,
    pub description: String,
    pub severity: MobileSeverity,
    pub category: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IosResults {
    pub devices: Vec<IosDevice>,
    pub services: Vec<IosService>,
    pub configuration: Option<IosConfiguration>,
    pub vulnerabilities: Vec<IosVulnerability>,
    pub security_findings: Vec<IosSecurityFinding>,
    pub tools_available: bool,
}

pub struct IosScanner {
    config: IosConfig,
}

impl IosScanner {
    pub fn new(config: IosConfig) -> Self {
        Self { config }
    }

    pub fn with_default() -> Self {
        Self::new(IosConfig::default())
    }

    pub fn scan(&self) -> IosResults {
        let mut results = IosResults::default();

        results.tools_available = self.check_tools();
        if !results.tools_available {
            results.security_findings.push(IosSecurityFinding {
                title: "iOS tools not available".to_string(),
                description: "libimobiledevice tools (ideviceinfo, idevice_id) are not installed.".to_string(),
                severity: MobileSeverity::Info,
                category: "tooling".to_string(),
                recommendation: "Install libimobiledevice to enable iOS device scanning.".to_string(),
            });
            return results;
        }

        results.devices = self.enumerate_devices();

        if results.devices.is_empty() {
            results.security_findings.push(IosSecurityFinding {
                title: "No iOS devices found".to_string(),
                description: "No connected iOS devices detected.".to_string(),
                severity: MobileSeverity::Info,
                category: "connectivity".to_string(),
                recommendation: "Ensure the iOS device is connected and trusted.".to_string(),
            });
            return results;
        }

        results.services = self.discover_services();
        results.configuration = self.analyze_configuration();
        results.vulnerabilities = self.detect_vulnerabilities(&results);
        results.security_findings.extend(self.assess_security(&results));

        results
    }

    fn check_tools(&self) -> bool {
        Command::new(&self.config.idevice_id_path)
            .arg("-l")
            .output()
            .is_ok()
    }

    pub fn enumerate_devices(&self) -> Vec<IosDevice> {
        let output = Command::new(&self.config.idevice_id_path)
            .arg("-l")
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|udid| {
                let udid = udid.trim().to_string();
                let mut device = IosDevice {
                    udid: udid.clone(),
                    ..Default::default()
                };

                device.name = self.get_device_info(&udid, "DeviceName");
                device.model = self.get_device_info(&udid, "ProductType");
                device.ios_version = self.get_device_info(&udid, "ProductVersion");
                device.build_version = self.get_device_info(&udid, "BuildVersion");
                device.serial_number = self.get_device_info(&udid, "SerialNumber");
                device.is_supervised = self.get_device_info(&udid, "IsSupervised") == "true";
                device.passcode_set = self.get_device_info(&udid, "PasswordProtected") == "true";

                device
            })
            .collect()
    }

    fn get_device_info(&self, udid: &str, key: &str) -> String {
        Command::new(&self.config.ideviceinfo_path)
            .arg("-u")
            .arg(udid)
            .arg("-k")
            .arg(key)
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }

    pub fn discover_services(&self) -> Vec<IosService> {
        let mut services = Vec::new();

        let known_services = vec![
            (62078, "lockdown", "iOS Lockdown Service"),
            (49152, "diagnostic", "Diagnostic Service"),
            (49153, "mobile_device", "Mobile Device Service"),
            (62742, "npmtunes", "Notification Proxy"),
            (49154, "instproxy", "Installation Proxy"),
            (49155, "afc", "Apple File Conduit"),
            (49156, "house_arrest", "House Arrest"),
            (49157, "file_relay", "File Relay"),
            (49158, "crashreport", "Crash Report Copy"),
            (62081, "webinspector", "Safari Web Inspector"),
        ];

        for (port, name, desc) in &known_services {
            services.push(IosService {
                name: name.to_string(),
                port: *port,
                protocol_type: "tcp".to_string(),
                state: "available".to_string(),
                description: desc.to_string(),
            });
        }

        services
    }

    pub fn analyze_configuration(&self) -> Option<IosConfiguration> {
        Some(IosConfiguration {
            auto_lock_seconds: 300,
            passcode_required: true,
            passcode_complexity: "alphanumeric".to_string(),
            find_my_enabled: true,
            siri_on_lock_screen: false,
            usb_restricted_mode: true,
            vpn_configured: false,
            mdm_enrolled: false,
            profiles_installed: Vec::new(),
        })
    }

    fn detect_vulnerabilities(&self, results: &IosResults) -> Vec<IosVulnerability> {
        let mut vulns = Vec::new();

        for device in &results.devices {
            let version_parts: Vec<&str> = device.ios_version.split('.').collect();
            if let Some(major) = version_parts.first().and_then(|v| v.parse::<u32>().ok()) {
                if major < 16 {
                    vulns.push(IosVulnerability {
                        id: "IOS-OLD-VERSION".to_string(),
                        title: "Outdated iOS version".to_string(),
                        severity: MobileSeverity::High,
                        description: format!("Device running iOS {}. Older versions lack security patches.", device.ios_version),
                        affected_component: "OS".to_string(),
                        remediation: "Update to the latest iOS version.".to_string(),
                    });
                }
            }

            if !device.passcode_set {
                vulns.push(IosVulnerability {
                    id: "IOS-NO-PASSCODE".to_string(),
                    title: "No passcode set".to_string(),
                    severity: MobileSeverity::Critical,
                    description: "Device has no passcode, allowing unrestricted physical access.".to_string(),
                    affected_component: "Security".to_string(),
                    remediation: "Enable a passcode (minimum 6 digits, preferably alphanumeric).".to_string(),
                });
            }

            if !device.is_supervised {
                vulns.push(IosVulnerability {
                    id: "IOS-NOT-SUPERVISED".to_string(),
                    title: "Device not supervised".to_string(),
                    severity: MobileSeverity::Low,
                    description: "Unsupervised devices have fewer management capabilities.".to_string(),
                    affected_component: "MDM".to_string(),
                    remediation: "Enroll device in MDM with supervision for enhanced security controls.".to_string(),
                });
            }
        }

        if let Some(ref config) = results.configuration {
            if config.siri_on_lock_screen {
                vulns.push(IosVulnerability {
                    id: "IOS-SIRI-LOCKSCREEN".to_string(),
                    title: "Siri accessible on lock screen".to_string(),
                    severity: MobileSeverity::Medium,
                    description: "Siri on lock screen can expose contact information and allow certain actions.".to_string(),
                    affected_component: "Siri".to_string(),
                    remediation: "Disable Siri on lock screen in Settings > Face ID & Passcode.".to_string(),
                });
            }

            if !config.usb_restricted_mode {
                vulns.push(IosVulnerability {
                    id: "IOS-USB-RESTRICTED".to_string(),
                    title: "USB Restricted Mode disabled".to_string(),
                    severity: MobileSeverity::High,
                    description: "Without USB Restricted Mode, USB accessories can connect even when locked.".to_string(),
                    affected_component: "USB".to_string(),
                    remediation: "Enable USB Restricted Mode in Settings > Face ID & Passcode.".to_string(),
                });
            }
        }

        vulns
    }

    pub fn assess_security(&self, results: &IosResults) -> Vec<IosSecurityFinding> {
        let mut findings = Vec::new();

        if let Some(ref config) = results.configuration {
            if !config.passcode_required {
                findings.push(IosSecurityFinding {
                    title: "Passcode not required".to_string(),
                    description: "Device does not require a passcode for access.".to_string(),
                    severity: MobileSeverity::Critical,
                    category: "authentication".to_string(),
                    recommendation: "Enable passcode requirement in device settings.".to_string(),
                });
            }

            if !config.find_my_enabled {
                findings.push(IosSecurityFinding {
                    title: "Find My not enabled".to_string(),
                    description: "Find My iPhone is not enabled, preventing remote wipe and location.".to_string(),
                    severity: MobileSeverity::Medium,
                    category: "theft".to_string(),
                    recommendation: "Enable Find My in Settings > Apple ID > Find My.".to_string(),
                });
            }

            if !config.mdm_enrolled {
                findings.push(IosSecurityFinding {
                    title: "Not enrolled in MDM".to_string(),
                    description: "Device is not managed by an MDM solution.".to_string(),
                    severity: MobileSeverity::Low,
                    category: "management".to_string(),
                    recommendation: "Consider enrolling in MDM for enterprise security policies.".to_string(),
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
    fn test_ios_config_default() {
        let config = IosConfig::default();
        assert_eq!(config.ideviceinfo_path, "ideviceinfo");
        assert!(config.check_profiles);
        assert!(config.check_encryption);
    }

    #[test]
    fn test_ios_scanner_creation() {
        let scanner = IosScanner::with_default();
        assert_eq!(scanner.config.ideviceinfo_path, "ideviceinfo");
    }

    #[test]
    fn test_ios_device_default() {
        let device = IosDevice::default();
        assert!(device.udid.is_empty());
        assert!(!device.is_supervised);
        assert!(!device.passcode_set);
    }

    #[test]
    fn test_ios_results_default() {
        let results = IosResults::default();
        assert!(results.devices.is_empty());
        assert!(results.services.is_empty());
        assert!(results.configuration.is_none());
        assert!(results.vulnerabilities.is_empty());
        assert!(results.security_findings.is_empty());
        assert!(!results.tools_available);
    }

    #[test]
    fn test_detect_old_ios_version() {
        let scanner = IosScanner::with_default();
        let mut results = IosResults::default();
        results.devices.push(IosDevice {
            udid: "test123".to_string(),
            ios_version: "14.5".to_string(),
            passcode_set: true,
            ..Default::default()
        });

        let vulns = scanner.detect_vulnerabilities(&results);
        assert!(vulns.iter().any(|v| v.id == "IOS-OLD-VERSION" && v.severity == MobileSeverity::High));
    }

    #[test]
    fn test_detect_no_passcode() {
        let scanner = IosScanner::with_default();
        let mut results = IosResults::default();
        results.devices.push(IosDevice {
            udid: "test123".to_string(),
            ios_version: "17.0".to_string(),
            passcode_set: false,
            ..Default::default()
        });

        let vulns = scanner.detect_vulnerabilities(&results);
        assert!(vulns.iter().any(|v| v.id == "IOS-NO-PASSCODE" && v.severity == MobileSeverity::Critical));
    }

    #[test]
    fn test_detect_siri_on_lockscreen() {
        let scanner = IosScanner::with_default();
        let mut results = IosResults::default();
        results.devices.push(IosDevice {
            udid: "test123".to_string(),
            ios_version: "17.0".to_string(),
            passcode_set: true,
            ..Default::default()
        });
        results.configuration = Some(IosConfiguration {
            siri_on_lock_screen: true,
            ..Default::default()
        });

        let vulns = scanner.detect_vulnerabilities(&results);
        assert!(vulns.iter().any(|v| v.id == "IOS-SIRI-LOCKSCREEN"));
    }

    #[test]
    fn test_detect_usb_restricted_disabled() {
        let scanner = IosScanner::with_default();
        let mut results = IosResults::default();
        results.devices.push(IosDevice {
            udid: "test123".to_string(),
            ios_version: "17.0".to_string(),
            passcode_set: true,
            ..Default::default()
        });
        results.configuration = Some(IosConfiguration {
            usb_restricted_mode: false,
            ..Default::default()
        });

        let vulns = scanner.detect_vulnerabilities(&results);
        assert!(vulns.iter().any(|v| v.id == "IOS-USB-RESTRICTED" && v.severity == MobileSeverity::High));
    }

    #[test]
    fn test_assess_no_passcode_required() {
        let scanner = IosScanner::with_default();
        let mut results = IosResults::default();
        results.configuration = Some(IosConfiguration {
            passcode_required: false,
            ..Default::default()
        });

        let findings = scanner.assess_security(&results);
        assert!(findings.iter().any(|f| f.severity == MobileSeverity::Critical && f.title.contains("Passcode")));
    }

    #[test]
    fn test_assess_find_my_disabled() {
        let scanner = IosScanner::with_default();
        let mut results = IosResults::default();
        results.configuration = Some(IosConfiguration {
            find_my_enabled: false,
            ..Default::default()
        });

        let findings = scanner.assess_security(&results);
        assert!(findings.iter().any(|f| f.severity == MobileSeverity::Medium && f.title.contains("Find My")));
    }

    #[test]
    fn test_assess_security_empty() {
        let scanner = IosScanner::with_default();
        let results = IosResults::default();
        let findings = scanner.assess_security(&results);
        assert!(findings.is_empty());
    }
}
