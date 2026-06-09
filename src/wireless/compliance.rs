use serde::{Deserialize, Serialize};

use super::wifi::{AccessPoint, EncryptionType, WifiScanResult};
use super::bluetooth::{BluetoothDevice, BluetoothSecurityLevel, BluetoothScanResult};
use super::zigbee::{ZigbeeNetwork, ZigbeeScanResult, ZigbeeSecurityLevel};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WirelessStandard {
    Nist80097,
    OwaspWireless,
    CisWireless,
    PciDssWireless,
    Custom(String),
}

impl WirelessStandard {
    pub fn as_str(&self) -> &str {
        match self {
            WirelessStandard::Nist80097 => "NIST SP 800-97",
            WirelessStandard::OwaspWireless => "OWASP Wireless Security",
            WirelessStandard::CisWireless => "CIS Wireless Benchmark",
            WirelessStandard::PciDssWireless => "PCI-DSS Wireless",
            WirelessStandard::Custom(name) => name,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum WirelessSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl WirelessSeverity {
    pub fn as_str(&self) -> &str {
        match self {
            WirelessSeverity::Info => "INFO",
            WirelessSeverity::Low => "LOW",
            WirelessSeverity::Medium => "MEDIUM",
            WirelessSeverity::High => "HIGH",
            WirelessSeverity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessFinding {
    pub standard: WirelessStandard,
    pub control_id: String,
    pub title: String,
    pub description: String,
    pub severity: WirelessSeverity,
    pub affected_resource: String,
    pub recommendation: WirelessRecommendation,
    pub compliance_status: ComplianceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    PartiallyCompliant,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessRecommendation {
    pub title: String,
    pub description: String,
    pub priority: u8,
    pub effort: EffortLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EffortLevel {
    Low,
    Medium,
    High,
}

impl EffortLevel {
    pub fn as_str(&self) -> &str {
        match self {
            EffortLevel::Low => "Low",
            EffortLevel::Medium => "Medium",
            EffortLevel::High => "High",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessComplianceReport {
    pub timestamp: String,
    pub standards_checked: Vec<WirelessStandard>,
    pub wifi_findings: Vec<WirelessFinding>,
    pub bluetooth_findings: Vec<WirelessFinding>,
    pub zigbee_findings: Vec<WirelessFinding>,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub compliance_score: f64,
}

impl WirelessComplianceReport {
    pub fn summary(&self) -> String {
        format!(
            "Wireless Compliance Report: {} findings ({} critical, {} high, {} medium, {} low) - Score: {:.1}%",
            self.total_findings, self.critical_count, self.high_count, self.medium_count, self.low_count, self.compliance_score
        )
    }
}

pub struct WirelessComplianceChecker {
    standards: Vec<WirelessStandard>,
}

impl WirelessComplianceChecker {
    pub fn new() -> Self {
        Self {
            standards: vec![
                WirelessStandard::Nist80097,
                WirelessStandard::OwaspWireless,
                WirelessStandard::CisWireless,
                WirelessStandard::PciDssWireless,
            ],
        }
    }

    pub fn with_standards(standards: Vec<WirelessStandard>) -> Self {
        Self { standards }
    }

    pub fn check_wifi(&self, scan_result: &WifiScanResult) -> Vec<WirelessFinding> {
        let mut findings = Vec::new();

        for ap in &scan_result.access_points {
            findings.extend(self.check_ap_wifi_security(ap));
        }

        if !scan_result.access_points.is_empty() {
            let open_count = scan_result.access_points.iter().filter(|ap| ap.security.encryption == EncryptionType::Open).count();
            if open_count > 0 {
                findings.push(WirelessFinding {
                    standard: WirelessStandard::Nist80097,
                    control_id: "WLAN-SEC-01".to_string(),
                    title: "Open Wireless Networks Detected".to_string(),
                    description: format!("{} open wireless network(s) detected", open_count),
                    severity: WirelessSeverity::High,
                    affected_resource: "WiFi Infrastructure".to_string(),
                    recommendation: WirelessRecommendation {
                        title: "Eliminate Open Networks".to_string(),
                        description: "Enable WPA3 or WPA2-Enterprise on all wireless networks. Open networks should only be used for guest access with proper isolation.".to_string(),
                        priority: 1,
                        effort: EffortLevel::Medium,
                    },
                    compliance_status: ComplianceStatus::NonCompliant,
                });
            }

            let wps_count = scan_result.access_points.iter().filter(|ap| ap.wps_enabled).count();
            if wps_count > 0 {
                findings.push(WirelessFinding {
                    standard: WirelessStandard::CisWireless,
                    control_id: "CIS-WLAN-4.1".to_string(),
                    title: "WPS Enabled on Access Points".to_string(),
                    description: format!("{} access point(s) have WPS enabled", wps_count),
                    severity: WirelessSeverity::Medium,
                    affected_resource: "WiFi Infrastructure".to_string(),
                    recommendation: WirelessRecommendation {
                        title: "Disable WPS".to_string(),
                        description: "Disable Wi-Fi Protected Setup (WPS) on all access points to prevent brute-force PIN attacks.".to_string(),
                        priority: 2,
                        effort: EffortLevel::Low,
                    },
                    compliance_status: ComplianceStatus::NonCompliant,
                });
            }

            let weak_encryption = scan_result.access_points.iter().any(|ap| {
                matches!(ap.security.encryption, EncryptionType::Wep | EncryptionType::Wpa)
            });
            if weak_encryption {
                findings.push(WirelessFinding {
                    standard: WirelessStandard::PciDssWireless,
                    control_id: "PCI-WLAN-4.2".to_string(),
                    title: "Weak Encryption Protocols in Use".to_string(),
                    description: "Access points using WEP or WPA (TKIP) encryption detected".to_string(),
                    severity: WirelessSeverity::Critical,
                    affected_resource: "WiFi Infrastructure".to_string(),
                    recommendation: WirelessRecommendation {
                        title: "Upgrade Encryption".to_string(),
                        description: "Immediately upgrade all access points to WPA3 or minimum WPA2 with AES-CCMP. WEP and WPA-TKIP are cryptographically broken.".to_string(),
                        priority: 1,
                        effort: EffortLevel::Medium,
                    },
                    compliance_status: ComplianceStatus::NonCompliant,
                });
            }
        }

        findings
    }

    pub fn check_bluetooth(&self, scan_result: &BluetoothScanResult) -> Vec<WirelessFinding> {
        let mut findings = Vec::new();

        for device in &scan_result.devices {
            findings.extend(self.check_bt_device_security(device));
        }

        let insecure_count = scan_result.devices.iter().filter(|d| d.security_level == BluetoothSecurityLevel::None).count();
        if insecure_count > 0 {
            findings.push(WirelessFinding {
                standard: WirelessStandard::OwaspWireless,
                control_id: "BT-SEC-01".to_string(),
                title: "Insecure Bluetooth Devices Detected".to_string(),
                description: format!("{} device(s) with no Bluetooth security", insecure_count),
                severity: WirelessSeverity::High,
                affected_resource: "Bluetooth Infrastructure".to_string(),
                recommendation: WirelessRecommendation {
                    title: "Enforce Bluetooth Security".to_string(),
                    description: "Ensure all Bluetooth devices use Secure Connections pairing mode. Disable or remove devices that cannot be secured.".to_string(),
                    priority: 1,
                    effort: EffortLevel::Medium,
                },
                compliance_status: ComplianceStatus::NonCompliant,
            });
        }

        let legacy_count = scan_result.devices.iter().filter(|d| d.security_level == BluetoothSecurityLevel::LegacyPairing).count();
        if legacy_count > 0 {
            findings.push(WirelessFinding {
                standard: WirelessStandard::Nist80097,
                control_id: "BT-SEC-02".to_string(),
                title: "Legacy Bluetooth Pairing in Use".to_string(),
                description: format!("{} device(s) using legacy pairing", legacy_count),
                severity: WirelessSeverity::Medium,
                affected_resource: "Bluetooth Infrastructure".to_string(),
                recommendation: WirelessRecommendation {
                    title: "Upgrade to Secure Simple Pairing".to_string(),
                    description: "Replace devices that only support legacy pairing. Enable SSP on devices that support it.".to_string(),
                    priority: 2,
                    effort: EffortLevel::Medium,
                },
                compliance_status: ComplianceStatus::NonCompliant,
            });
        }

        findings
    }

    pub fn check_zigbee(&self, scan_result: &ZigbeeScanResult) -> Vec<WirelessFinding> {
        let mut findings = Vec::new();

        for network in &scan_result.networks {
            findings.extend(self.check_zigbee_network(network));
        }

        let open_count = scan_result.networks.iter().filter(|n| n.security_level == ZigbeeSecurityLevel::None).count();
        if open_count > 0 {
            findings.push(WirelessFinding {
                standard: WirelessStandard::OwaspWireless,
                control_id: "ZB-SEC-01".to_string(),
                title: "Unsecured Zigbee Networks".to_string(),
                description: format!("{} Zigbee network(s) with no security", open_count),
                severity: WirelessSeverity::Critical,
                affected_resource: "Zigbee Infrastructure".to_string(),
                recommendation: WirelessRecommendation {
                    title: "Enable Zigbee Security".to_string(),
                    description: "Enable at least Standard security level on all Zigbee networks. Use install codes for device joining.".to_string(),
                    priority: 1,
                    effort: EffortLevel::Low,
                },
                compliance_status: ComplianceStatus::NonCompliant,
            });
        }

        findings
    }

    pub fn generate_report(
        &self,
        wifi: Option<&WifiScanResult>,
        bluetooth: Option<&BluetoothScanResult>,
        zigbee: Option<&ZigbeeScanResult>,
    ) -> WirelessComplianceReport {
        let wifi_findings = wifi.map(|w| self.check_wifi(w)).unwrap_or_default();
        let bt_findings = bluetooth.map(|b| self.check_bluetooth(b)).unwrap_or_default();
        let zb_findings = zigbee.map(|z| self.check_zigbee(z)).unwrap_or_default();

        let all_findings: Vec<&WirelessFinding> = wifi_findings.iter()
            .chain(bt_findings.iter())
            .chain(zb_findings.iter())
            .collect();

        let total = all_findings.len();
        let critical = all_findings.iter().filter(|f| f.severity == WirelessSeverity::Critical).count();
        let high = all_findings.iter().filter(|f| f.severity == WirelessSeverity::High).count();
        let medium = all_findings.iter().filter(|f| f.severity == WirelessSeverity::Medium).count();
        let low = all_findings.iter().filter(|f| f.severity == WirelessSeverity::Low).count();

        let compliance_score = if total > 0 {
            let compliant = all_findings.iter().filter(|f| f.compliance_status == ComplianceStatus::Compliant).count();
            (compliant as f64 / total as f64) * 100.0
        } else {
            100.0
        };

        WirelessComplianceReport {
            timestamp: chrono::Utc::now().to_rfc3339(),
            standards_checked: self.standards.clone(),
            wifi_findings,
            bluetooth_findings: bt_findings,
            zigbee_findings: zb_findings,
            total_findings: total,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            compliance_score,
        }
    }

    fn check_ap_wifi_security(&self, ap: &AccessPoint) -> Vec<WirelessFinding> {
        let mut findings = Vec::new();

        match ap.security.encryption {
            EncryptionType::Open => {
                findings.push(WirelessFinding {
                    standard: WirelessStandard::OwaspWireless,
                    control_id: "OWASP-WIFI-01".to_string(),
                    title: "Open Access Point".to_string(),
                    description: format!("AP '{}' ({}) has no encryption", ap.ssid, ap.bssid),
                    severity: WirelessSeverity::High,
                    affected_resource: format!("AP: {}", ap.ssid),
                    recommendation: WirelessRecommendation {
                        title: "Enable Encryption".to_string(),
                        description: "Enable WPA3-SAE or minimum WPA2-PSK with strong passphrase".to_string(),
                        priority: 1,
                        effort: EffortLevel::Low,
                    },
                    compliance_status: ComplianceStatus::NonCompliant,
                });
            }
            EncryptionType::Wep => {
                findings.push(WirelessFinding {
                    standard: WirelessStandard::PciDssWireless,
                    control_id: "PCI-WLAN-01".to_string(),
                    title: "WEP Encryption on AP".to_string(),
                    description: format!("AP '{}' uses WEP encryption which can be cracked in minutes", ap.ssid),
                    severity: WirelessSeverity::Critical,
                    affected_resource: format!("AP: {}", ap.ssid),
                    recommendation: WirelessRecommendation {
                        title: "Replace WEP Immediately".to_string(),
                        description: "WEP is fundamentally broken. Upgrade to WPA3 or WPA2-AES immediately.".to_string(),
                        priority: 1,
                        effort: EffortLevel::Low,
                    },
                    compliance_status: ComplianceStatus::NonCompliant,
                });
            }
            EncryptionType::Wpa => {
                findings.push(WirelessFinding {
                    standard: WirelessStandard::Nist80097,
                    control_id: "NIST-WLAN-02".to_string(),
                    title: "Deprecated WPA Protocol".to_string(),
                    description: format!("AP '{}' uses WPA with TKIP cipher", ap.ssid),
                    severity: WirelessSeverity::High,
                    affected_resource: format!("AP: {}", ap.ssid),
                    recommendation: WirelessRecommendation {
                        title: "Upgrade to WPA2/WPA3".to_string(),
                        description: "WPA-TKIP has known vulnerabilities. Migrate to WPA3 or WPA2-CCMP.".to_string(),
                        priority: 1,
                        effort: EffortLevel::Low,
                    },
                    compliance_status: ComplianceStatus::NonCompliant,
                });
            }
            EncryptionType::Wpa2 | EncryptionType::Wpa2Wpa3Mixed => {
                findings.push(WirelessFinding {
                    standard: WirelessStandard::CisWireless,
                    control_id: "CIS-WLAN-01".to_string(),
                    title: "WPA2/WPA3 Access Point".to_string(),
                    description: format!("AP '{}' uses acceptable encryption", ap.ssid),
                    severity: WirelessSeverity::Info,
                    affected_resource: format!("AP: {}", ap.ssid),
                    recommendation: WirelessRecommendation {
                        title: "Consider WPA3-Only".to_string(),
                        description: "While WPA2 is acceptable, consider upgrading to WPA3-only when all clients support it.".to_string(),
                        priority: 4,
                        effort: EffortLevel::Low,
                    },
                    compliance_status: ComplianceStatus::Compliant,
                });
            }
            EncryptionType::Wpa3 | EncryptionType::EnhancedOpen => {
                findings.push(WirelessFinding {
                    standard: WirelessStandard::Nist80097,
                    control_id: "NIST-WLAN-01".to_string(),
                    title: "Modern Encryption in Use".to_string(),
                    description: format!("AP '{}' uses current-gen encryption", ap.ssid),
                    severity: WirelessSeverity::Info,
                    affected_resource: format!("AP: {}", ap.ssid),
                    recommendation: WirelessRecommendation {
                        title: "Maintain Current Configuration".to_string(),
                        description: "WPA3 meets current security standards. Monitor for firmware updates.".to_string(),
                        priority: 5,
                        effort: EffortLevel::Low,
                    },
                    compliance_status: ComplianceStatus::Compliant,
                });
            }
        }

        findings
    }

    fn check_bt_device_security(&self, device: &BluetoothDevice) -> Vec<WirelessFinding> {
        let mut findings = Vec::new();

        match device.security_level {
            BluetoothSecurityLevel::None => {
                findings.push(WirelessFinding {
                    standard: WirelessStandard::OwaspWireless,
                    control_id: "OWASP-BT-01".to_string(),
                    title: "Unsecured Bluetooth Device".to_string(),
                    description: format!("Device '{}' ({}) has no security", device.name.as_deref().unwrap_or("Unknown"), device.address),
                    severity: WirelessSeverity::High,
                    affected_resource: format!("BT: {}", device.address),
                    recommendation: WirelessRecommendation {
                        title: "Enable Device Security".to_string(),
                        description: "Enable Secure Simple Pairing and require authentication for connections.".to_string(),
                        priority: 1,
                        effort: EffortLevel::Low,
                    },
                    compliance_status: ComplianceStatus::NonCompliant,
                });
            }
            BluetoothSecurityLevel::LegacyPairing => {
                findings.push(WirelessFinding {
                    standard: WirelessStandard::Nist80097,
                    control_id: "NIST-BT-01".to_string(),
                    title: "Legacy Bluetooth Pairing".to_string(),
                    description: format!("Device '{}' uses legacy pairing vulnerable to eavesdropping", device.name.as_deref().unwrap_or("Unknown")),
                    severity: WirelessSeverity::Medium,
                    affected_resource: format!("BT: {}", device.address),
                    recommendation: WirelessRecommendation {
                        title: "Upgrade Pairing Method".to_string(),
                        description: "Use Secure Simple Pairing (SSP) or Secure Connections mode.".to_string(),
                        priority: 2,
                        effort: EffortLevel::Low,
                    },
                    compliance_status: ComplianceStatus::PartiallyCompliant,
                });
            }
            BluetoothSecurityLevel::SecureSimplePairing | BluetoothSecurityLevel::SecureConnections | BluetoothSecurityLevel::OutOfBand => {
                findings.push(WirelessFinding {
                    standard: WirelessStandard::CisWireless,
                    control_id: "CIS-BT-01".to_string(),
                    title: "Secure Bluetooth Pairing".to_string(),
                    description: format!("Device '{}' uses secure pairing", device.name.as_deref().unwrap_or("Unknown")),
                    severity: WirelessSeverity::Info,
                    affected_resource: format!("BT: {}", device.address),
                    recommendation: WirelessRecommendation {
                        title: "Maintain Secure Configuration".to_string(),
                        description: "Device uses acceptable security. Monitor for firmware updates.".to_string(),
                        priority: 5,
                        effort: EffortLevel::Low,
                    },
                    compliance_status: ComplianceStatus::Compliant,
                });
            }
        }

        findings
    }

    fn check_zigbee_network(&self, network: &ZigbeeNetwork) -> Vec<WirelessFinding> {
        let mut findings = Vec::new();

        match network.security_level {
            ZigbeeSecurityLevel::None => {
                findings.push(WirelessFinding {
                    standard: WirelessStandard::OwaspWireless,
                    control_id: "OWASP-ZB-01".to_string(),
                    title: "Unsecured Zigbee Network".to_string(),
                    description: format!("Zigbee PAN 0x{:04X} has no security enabled", network.pan_id),
                    severity: WirelessSeverity::Critical,
                    affected_resource: format!("Zigbee PAN: 0x{:04X}", network.pan_id),
                    recommendation: WirelessRecommendation {
                        title: "Enable Zigbee Network Security".to_string(),
                        description: "Enable AES-CCM* encryption with Standard or High security level.".to_string(),
                        priority: 1,
                        effort: EffortLevel::Low,
                    },
                    compliance_status: ComplianceStatus::NonCompliant,
                });
            }
            ZigbeeSecurityLevel::Residential => {
                findings.push(WirelessFinding {
                    standard: WirelessStandard::Nist80097,
                    control_id: "NIST-ZB-01".to_string(),
                    title: "Zigbee Residential Security".to_string(),
                    description: format!("Zigbee PAN 0x{:04X} uses Residential security with default keys", network.pan_id),
                    severity: WirelessSeverity::Medium,
                    affected_resource: format!("Zigbee PAN: 0x{:04X}", network.pan_id),
                    recommendation: WirelessRecommendation {
                        title: "Upgrade Security Level".to_string(),
                        description: "Upgrade to Standard security level with unique network keys.".to_string(),
                        priority: 2,
                        effort: EffortLevel::Low,
                    },
                    compliance_status: ComplianceStatus::PartiallyCompliant,
                });
            }
            ZigbeeSecurityLevel::Standard | ZigbeeSecurityLevel::High => {
                findings.push(WirelessFinding {
                    standard: WirelessStandard::CisWireless,
                    control_id: "CIS-ZB-01".to_string(),
                    title: "Zigbee Network Secured".to_string(),
                    description: format!("Zigbee PAN 0x{:04X} uses adequate security", network.pan_id),
                    severity: WirelessSeverity::Info,
                    affected_resource: format!("Zigbee PAN: 0x{:04X}", network.pan_id),
                    recommendation: WirelessRecommendation {
                        title: "Maintain Security".to_string(),
                        description: "Network security configuration is acceptable. Rotate keys periodically.".to_string(),
                        priority: 5,
                        effort: EffortLevel::Low,
                    },
                    compliance_status: ComplianceStatus::Compliant,
                });
            }
        }

        if network.permit_joining {
            findings.push(WirelessFinding {
                standard: WirelessStandard::CisWireless,
                control_id: "CIS-ZB-02".to_string(),
                title: "Zigbee Permit Join Enabled".to_string(),
                description: format!("Zigbee PAN 0x{:04X} allows new device joins", network.pan_id),
                severity: WirelessSeverity::Medium,
                affected_resource: format!("Zigbee PAN: 0x{:04X}", network.pan_id),
                recommendation: WirelessRecommendation {
                    title: "Disable Open Joining".to_string(),
                    description: "Disable permit-joining when not actively adding new devices to prevent unauthorized access.".to_string(),
                    priority: 2,
                    effort: EffortLevel::Low,
                },
                compliance_status: ComplianceStatus::NonCompliant,
            });
        }

        findings
    }
}

impl Default for WirelessComplianceChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireless::wifi::{AccessPoint, WifiSecurity, WifiBand, AuthenticationMode, WifiClient, ChannelInfo, InterferenceLevel};
    use crate::wireless::bluetooth::{BluetoothDevice, DeviceClass, BluetoothService, ServiceUuid, BleDevice};

    fn create_test_ap(ssid: &str, encryption: EncryptionType) -> AccessPoint {
        AccessPoint {
            bssid: "AA:BB:CC:DD:EE:FF".to_string(),
            ssid: ssid.to_string(),
            channel: 1,
            frequency_mhz: 2412,
            band: WifiBand::Band2GHz,
            signal_dbm: -50,
            security: WifiSecurity::new(encryption, AuthenticationMode::PSK),
            wps_enabled: false,
            vendor: None,
            beacon_interval_ms: 100,
            connected_clients: Vec::new(),
            hidden: false,
        }
    }

    fn create_test_bt_device(security: BluetoothSecurityLevel) -> BluetoothDevice {
        BluetoothDevice {
            address: "AA:BB:CC:DD:EE:FF".to_string(),
            name: Some("TestDevice".to_string()),
            device_class: DeviceClass::Phone,
            class_code: 0x020104,
            rssi: Some(-60),
            tx_power: None,
            manufacturer: None,
            is_paired: false,
            is_connectable: true,
            is_bonded: false,
            security_level: security,
            services: Vec::new(),
            vulnerabilities: Vec::new(),
            is_ble: false,
            firmware_version: None,
        }
    }

    fn create_test_zigbee_network(security: ZigbeeSecurityLevel) -> super::super::zigbee::ZigbeeNetwork {
        super::super::zigbee::ZigbeeNetwork {
            pan_id: 0x1234,
            extended_pan_id: 0x0011223344556677,
            channel: 15,
            coordinator_addr: 0x0000,
            permit_joining: false,
            security_level: security,
            network_key_known: false,
            devices: Vec::new(),
            stack_profile: 2,
            vulnerabilities: Vec::new(),
        }
    }

    #[test]
    fn test_checker_creation() {
        let checker = WirelessComplianceChecker::new();
        assert_eq!(checker.standards.len(), 4);
    }

    #[test]
    fn test_wifi_open_network_finding() {
        let checker = WirelessComplianceChecker::new();
        let scan = WifiScanResult {
            access_points: vec![create_test_ap("OpenNet", EncryptionType::Open)],
            clients: Vec::new(),
            channels: Vec::new(),
            scan_duration_secs: 10,
            total_networks: 1,
            open_networks: 1,
            encrypted_networks: 0,
            wps_enabled_count: 0,
            rogue_suspects: 1,
        };

        let findings = checker.check_wifi(&scan);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == WirelessSeverity::High));
    }

    #[test]
    fn test_wifi_wep_critical() {
        let checker = WirelessComplianceChecker::new();
        let scan = WifiScanResult {
            access_points: vec![create_test_ap("WepNet", EncryptionType::Wep)],
            clients: Vec::new(),
            channels: Vec::new(),
            scan_duration_secs: 10,
            total_networks: 1,
            open_networks: 0,
            encrypted_networks: 1,
            wps_enabled_count: 0,
            rogue_suspects: 0,
        };

        let findings = checker.check_wifi(&scan);
        assert!(findings.iter().any(|f| f.severity == WirelessSeverity::Critical));
    }

    #[test]
    fn test_wifi_wpa3_compliant() {
        let checker = WirelessComplianceChecker::new();
        let scan = WifiScanResult {
            access_points: vec![create_test_ap("SecureNet", EncryptionType::Wpa3)],
            clients: Vec::new(),
            channels: Vec::new(),
            scan_duration_secs: 10,
            total_networks: 1,
            open_networks: 0,
            encrypted_networks: 1,
            wps_enabled_count: 0,
            rogue_suspects: 0,
        };

        let findings = checker.check_wifi(&scan);
        assert!(findings.iter().any(|f| f.compliance_status == ComplianceStatus::Compliant));
    }

    #[test]
    fn test_bluetooth_no_security() {
        let checker = WirelessComplianceChecker::new();
        let scan = BluetoothScanResult {
            devices: vec![create_test_bt_device(BluetoothSecurityLevel::None)],
            ble_devices: Vec::new(),
            scan_duration_secs: 15,
            total_devices: 1,
            vulnerable_devices: 1,
            connectable_devices: 1,
            ble_only_devices: 0,
        };

        let findings = checker.check_bluetooth(&scan);
        assert!(findings.iter().any(|f| f.severity == WirelessSeverity::High));
    }

    #[test]
    fn test_zigbee_no_security() {
        let checker = WirelessComplianceChecker::new();
        let scan = ZigbeeScanResult {
            networks: vec![create_test_zigbee_network(ZigbeeSecurityLevel::None)],
            scan_duration_secs: 30,
            total_networks: 1,
            total_devices: 0,
            open_networks: 1,
            networks_with_join_enabled: 0,
        };

        let findings = checker.check_zigbee(&scan);
        assert!(findings.iter().any(|f| f.severity == WirelessSeverity::Critical));
    }

    #[test]
    fn test_full_report_generation() {
        let checker = WirelessComplianceChecker::new();

        let wifi = WifiScanResult {
            access_points: vec![
                create_test_ap("Open", EncryptionType::Open),
                create_test_ap("Wpa3", EncryptionType::Wpa3),
            ],
            clients: Vec::new(),
            channels: Vec::new(),
            scan_duration_secs: 10,
            total_networks: 2,
            open_networks: 1,
            encrypted_networks: 1,
            wps_enabled_count: 0,
            rogue_suspects: 1,
        };

        let report = checker.generate_report(Some(&wifi), None, None);
        assert!(report.total_findings > 0);
        assert!(report.compliance_score < 100.0);
    }

    #[test]
    fn test_report_summary() {
        let report = WirelessComplianceReport {
            timestamp: chrono::Utc::now().to_rfc3339(),
            standards_checked: vec![WirelessStandard::Nist80097],
            wifi_findings: Vec::new(),
            bluetooth_findings: Vec::new(),
            zigbee_findings: Vec::new(),
            total_findings: 5,
            critical_count: 1,
            high_count: 2,
            medium_count: 1,
            low_count: 1,
            compliance_score: 60.0,
        };

        let summary = report.summary();
        assert!(summary.contains("5 findings"));
        assert!(summary.contains("60.0%"));
    }

    #[test]
    fn test_wireless_severity_ordering() {
        assert!(WirelessSeverity::Critical > WirelessSeverity::High);
        assert!(WirelessSeverity::High > WirelessSeverity::Medium);
        assert!(WirelessSeverity::Medium > WirelessSeverity::Low);
    }

    #[test]
    fn test_compliance_status_values() {
        assert_ne!(ComplianceStatus::Compliant, ComplianceStatus::NonCompliant);
        assert_ne!(ComplianceStatus::PartiallyCompliant, ComplianceStatus::NotApplicable);
    }
}
