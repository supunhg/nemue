use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WifiBand {
    Band2GHz,
    Band5GHz,
    Band6GHz,
}

impl WifiBand {
    pub fn as_str(&self) -> &str {
        match self {
            WifiBand::Band2GHz => "2.4GHz",
            WifiBand::Band5GHz => "5GHz",
            WifiBand::Band6GHz => "6GHz",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionType {
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
    Wpa2Wpa3Mixed,
    EnhancedOpen,
}

impl EncryptionType {
    pub fn as_str(&self) -> &str {
        match self {
            EncryptionType::Open => "Open",
            EncryptionType::Wep => "WEP",
            EncryptionType::Wpa => "WPA",
            EncryptionType::Wpa2 => "WPA2",
            EncryptionType::Wpa3 => "WPA3",
            EncryptionType::Wpa2Wpa3Mixed => "WPA2/WPA3",
            EncryptionType::EnhancedOpen => "Enhanced Open (OWE)",
        }
    }

    pub fn is_secure(&self) -> bool {
        matches!(
            self,
            EncryptionType::Wpa2
                | EncryptionType::Wpa3
                | EncryptionType::Wpa2Wpa3Mixed
                | EncryptionType::EnhancedOpen
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthenticationMode {
    Open,
    PSK,
    EAP,
    SAE,
    OWE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiSecurity {
    pub encryption: EncryptionType,
    pub authentication: AuthenticationMode,
    pub cipher: String,
    pub pmf_required: bool,
    pub pmf_capable: bool,
    pub vulnerabilities: Vec<String>,
}

impl WifiSecurity {
    pub fn new(encryption: EncryptionType, authentication: AuthenticationMode) -> Self {
        let cipher = match &encryption {
            EncryptionType::Wep => "RC4".to_string(),
            EncryptionType::Wpa => "TKIP".to_string(),
            EncryptionType::Wpa2 | EncryptionType::Wpa3 => "CCMP".to_string(),
            _ => "None".to_string(),
        };

        let pmf_required = matches!(encryption, EncryptionType::Wpa3);
        let pmf_capable = matches!(
            encryption,
            EncryptionType::Wpa2 | EncryptionType::Wpa3 | EncryptionType::Wpa2Wpa3Mixed
        );

        Self {
            encryption,
            authentication,
            cipher,
            pmf_required,
            pmf_capable,
            vulnerabilities: Vec::new(),
        }
    }

    pub fn assess(&mut self) {
        self.vulnerabilities.clear();

        if self.encryption == EncryptionType::Open {
            self.vulnerabilities
                .push("Network is open with no encryption".to_string());
        }
        if self.encryption == EncryptionType::Wep {
            self.vulnerabilities
                .push("WEP encryption is trivially crackable".to_string());
        }
        if self.encryption == EncryptionType::Wpa {
            self.vulnerabilities
                .push("WPA uses deprecated TKIP cipher".to_string());
        }
        if !self.pmf_capable && self.encryption != EncryptionType::Open {
            self.vulnerabilities
                .push("Protected Management Frames (802.11w) not supported".to_string());
        }
        if self.cipher == "TKIP" {
            self.vulnerabilities
                .push("TKIP cipher is vulnerable to fragmentation attacks".to_string());
        }
    }

    pub fn is_secure(&self) -> bool {
        self.vulnerabilities.is_empty() && self.encryption.is_secure()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPoint {
    pub bssid: String,
    pub ssid: String,
    pub channel: u32,
    pub frequency_mhz: u32,
    pub band: WifiBand,
    pub signal_dbm: i32,
    pub security: WifiSecurity,
    pub wps_enabled: bool,
    pub vendor: Option<String>,
    pub beacon_interval_ms: u32,
    pub connected_clients: Vec<WifiClient>,
    pub hidden: bool,
}

impl AccessPoint {
    pub fn signal_quality(&self) -> u32 {
        match self.signal_dbm {
            s if s >= -30 => 100,
            s if s >= -50 => 80,
            s if s >= -60 => 60,
            s if s >= -70 => 40,
            s if s >= -80 => 20,
            _ => 0,
        }
    }

    pub fn is_rogue(&self) -> bool {
        self.security.encryption == EncryptionType::Open && !self.hidden
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiClient {
    pub mac_address: String,
    pub vendor: Option<String>,
    pub signal_dbm: i32,
    pub connected_ap: Option<String>,
    pub probed_ssids: Vec<String>,
    pub data_rate_mbps: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub channel: u32,
    pub frequency_mhz: u32,
    pub band: WifiBand,
    pub ap_count: usize,
    pub client_count: usize,
    pub utilization_percent: f64,
    pub interference_level: InterferenceLevel,
    pub overlapping_aps: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InterferenceLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl InterferenceLevel {
    pub fn from_ap_count(count: usize) -> Self {
        match count {
            0 => InterferenceLevel::None,
            1..=2 => InterferenceLevel::Low,
            3..=5 => InterferenceLevel::Medium,
            6..=10 => InterferenceLevel::High,
            _ => InterferenceLevel::Critical,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiScanConfig {
    pub interface: String,
    pub channels: Option<Vec<u32>>,
    pub band: Option<WifiBand>,
    pub passive_only: bool,
    pub scan_duration_secs: u64,
    pub include_hidden: bool,
    pub probe_clients: bool,
}

impl Default for WifiScanConfig {
    fn default() -> Self {
        Self {
            interface: "wlan0".to_string(),
            channels: None,
            band: None,
            passive_only: false,
            scan_duration_secs: 10,
            include_hidden: true,
            probe_clients: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiScanResult {
    pub access_points: Vec<AccessPoint>,
    pub clients: Vec<WifiClient>,
    pub channels: Vec<ChannelInfo>,
    pub scan_duration_secs: u64,
    pub total_networks: usize,
    pub open_networks: usize,
    pub encrypted_networks: usize,
    pub wps_enabled_count: usize,
    pub rogue_suspects: usize,
}

impl WifiScanResult {
    pub fn security_summary(&self) -> WifiSecuritySummary {
        let mut summary = WifiSecuritySummary::default();
        summary.total_aps = self.access_points.len();

        for ap in &self.access_points {
            match ap.security.encryption {
                EncryptionType::Open => summary.open += 1,
                EncryptionType::Wep => summary.wep += 1,
                EncryptionType::Wpa => summary.wpa += 1,
                EncryptionType::Wpa2 => summary.wpa2 += 1,
                EncryptionType::Wpa3 => summary.wpa3 += 1,
                EncryptionType::Wpa2Wpa3Mixed => summary.wpa2_wpa3_mixed += 1,
                EncryptionType::EnhancedOpen => summary.enhanced_open += 1,
            }
            if ap.wps_enabled {
                summary.wps_enabled += 1;
            }
            if !ap.security.vulnerabilities.is_empty() {
                summary.vulnerable += 1;
            }
        }
        summary
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WifiSecuritySummary {
    pub total_aps: usize,
    pub open: usize,
    pub wep: usize,
    pub wpa: usize,
    pub wpa2: usize,
    pub wpa3: usize,
    pub wpa2_wpa3_mixed: usize,
    pub enhanced_open: usize,
    pub wps_enabled: usize,
    pub vulnerable: usize,
}

pub struct WifiScanner {
    config: WifiScanConfig,
}

impl WifiScanner {
    pub fn new(config: WifiScanConfig) -> Self {
        Self { config }
    }

    pub fn with_default_config(interface: &str) -> Self {
        Self {
            config: WifiScanConfig {
                interface: interface.to_string(),
                ..Default::default()
            },
        }
    }

    pub fn config(&self) -> &WifiScanConfig {
        &self.config
    }

    pub fn channel_analysis(aps: &[AccessPoint]) -> Vec<ChannelInfo> {
        let mut channel_map: HashMap<u32, Vec<&AccessPoint>> = HashMap::new();

        for ap in aps {
            channel_map.entry(ap.channel).or_default().push(ap);
        }

        let mut channels: Vec<ChannelInfo> = channel_map
            .into_iter()
            .map(|(channel, aps_on_channel)| {
                let frequency = Self::channel_to_frequency(channel, &aps_on_channel[0].band);
                let client_count: usize = aps_on_channel
                    .iter()
                    .map(|ap| ap.connected_clients.len())
                    .sum();
                let ap_count = aps_on_channel.len();

                ChannelInfo {
                    channel,
                    frequency_mhz: frequency,
                    band: aps_on_channel[0].band.clone(),
                    ap_count,
                    client_count,
                    utilization_percent: Self::estimate_utilization(ap_count),
                    interference_level: InterferenceLevel::from_ap_count(ap_count),
                    overlapping_aps: Self::count_overlapping(channel, aps),
                }
            })
            .collect();

        channels.sort_by_key(|c| c.channel);
        channels
    }

    pub fn security_assessment(aps: &[AccessPoint]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        for ap in aps {
            if ap.security.encryption == EncryptionType::Open {
                findings.push(SecurityFinding {
                    ap_ssid: ap.ssid.clone(),
                    ap_bssid: ap.bssid.clone(),
                    finding_type: SecurityFindingType::OpenNetwork,
                    severity: FindingSeverity::High,
                    description: format!("Network '{}' is open with no encryption", ap.ssid),
                    recommendation: "Enable WPA3 or WPA2 encryption".to_string(),
                });
            }

            if ap.security.encryption == EncryptionType::Wep {
                findings.push(SecurityFinding {
                    ap_ssid: ap.ssid.clone(),
                    ap_bssid: ap.bssid.clone(),
                    finding_type: SecurityFindingType::WeakEncryption,
                    severity: FindingSeverity::Critical,
                    description: format!("Network '{}' uses deprecated WEP encryption", ap.ssid),
                    recommendation: "Upgrade to WPA3 immediately".to_string(),
                });
            }

            if ap.wps_enabled {
                findings.push(SecurityFinding {
                    ap_ssid: ap.ssid.clone(),
                    ap_bssid: ap.bssid.clone(),
                    finding_type: SecurityFindingType::WpsEnabled,
                    severity: FindingSeverity::Medium,
                    description: format!("Network '{}' has WPS enabled", ap.ssid),
                    recommendation: "Disable WPS to prevent brute-force attacks".to_string(),
                });
            }

            if !ap.security.pmf_capable && ap.security.encryption != EncryptionType::Open {
                findings.push(SecurityFinding {
                    ap_ssid: ap.ssid.clone(),
                    ap_bssid: ap.bssid.clone(),
                    finding_type: SecurityFindingType::NoPmf,
                    severity: FindingSeverity::Medium,
                    description: format!("Network '{}' does not support 802.11w (PMF)", ap.ssid),
                    recommendation: "Enable Protected Management Frames".to_string(),
                });
            }

            if ap.is_rogue() {
                findings.push(SecurityFinding {
                    ap_ssid: ap.ssid.clone(),
                    ap_bssid: ap.bssid.clone(),
                    finding_type: SecurityFindingType::RogueAp,
                    severity: FindingSeverity::Critical,
                    description: format!("Suspected rogue AP: '{}' ({})", ap.ssid, ap.bssid),
                    recommendation: "Investigate and remove unauthorized access point".to_string(),
                });
            }
        }

        findings
    }

    fn channel_to_frequency(channel: u32, band: &WifiBand) -> u32 {
        match band {
            WifiBand::Band2GHz => {
                if channel == 14 {
                    2484
                } else {
                    2407 + channel * 5
                }
            }
            WifiBand::Band5GHz => 5000 + channel * 5,
            WifiBand::Band6GHz => 5950 + channel * 5,
        }
    }

    fn estimate_utilization(ap_count: usize) -> f64 {
        (ap_count as f64 * 15.0).min(100.0)
    }

    fn count_overlapping(channel: u32, aps: &[AccessPoint]) -> usize {
        aps.iter()
            .filter(|ap| {
                let diff = ap.channel.abs_diff(channel);
                diff <= 4 && diff > 0
            })
            .count()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub ap_ssid: String,
    pub ap_bssid: String,
    pub finding_type: SecurityFindingType,
    pub severity: FindingSeverity,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityFindingType {
    OpenNetwork,
    WeakEncryption,
    WpsEnabled,
    NoPmf,
    RogueAp,
    DefaultSsid,
    ChannelOverlap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub fn as_str(&self) -> &str {
        match self {
            FindingSeverity::Info => "INFO",
            FindingSeverity::Low => "LOW",
            FindingSeverity::Medium => "MEDIUM",
            FindingSeverity::High => "HIGH",
            FindingSeverity::Critical => "CRITICAL",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_ap(ssid: &str, encryption: EncryptionType, channel: u32) -> AccessPoint {
        AccessPoint {
            bssid: format!("AA:BB:CC:DD:EE:{:02X}", channel),
            ssid: ssid.to_string(),
            channel,
            frequency_mhz: 2412 + (channel - 1) * 5,
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

    #[test]
    fn test_encryption_type_security() {
        assert!(!EncryptionType::Open.is_secure());
        assert!(!EncryptionType::Wep.is_secure());
        assert!(!EncryptionType::Wpa.is_secure());
        assert!(EncryptionType::Wpa2.is_secure());
        assert!(EncryptionType::Wpa3.is_secure());
    }

    #[test]
    fn test_wifi_security_assessment() {
        let mut sec = WifiSecurity::new(EncryptionType::Wep, AuthenticationMode::PSK);
        sec.assess();
        assert!(!sec.vulnerabilities.is_empty());
        assert!(!sec.is_secure());
    }

    #[test]
    fn test_wifi_security_wpa3() {
        let mut sec = WifiSecurity::new(EncryptionType::Wpa3, AuthenticationMode::SAE);
        sec.assess();
        assert!(sec.vulnerabilities.is_empty());
        assert!(sec.is_secure());
    }

    #[test]
    fn test_access_point_signal_quality() {
        let ap = create_test_ap("TestNet", EncryptionType::Wpa2, 1);
        assert_eq!(ap.signal_quality(), 80);
    }

    #[test]
    fn test_access_point_rogue_detection() {
        let mut ap = create_test_ap("FreeWiFi", EncryptionType::Open, 6);
        assert!(ap.is_rogue());

        ap.hidden = true;
        assert!(!ap.is_rogue());
    }

    #[test]
    fn test_channel_analysis() {
        let aps = vec![
            create_test_ap("Net1", EncryptionType::Wpa2, 1),
            create_test_ap("Net2", EncryptionType::Wpa2, 1),
            create_test_ap("Net3", EncryptionType::Wpa2, 6),
        ];

        let channels = WifiScanner::channel_analysis(&aps);
        assert_eq!(channels.len(), 2);

        let ch1 = channels.iter().find(|c| c.channel == 1).unwrap();
        assert_eq!(ch1.ap_count, 2);
    }

    #[test]
    fn test_security_assessment() {
        let aps = vec![
            create_test_ap("OpenNet", EncryptionType::Open, 1),
            create_test_ap("WepNet", EncryptionType::Wep, 6),
            create_test_ap("SecureNet", EncryptionType::Wpa3, 11),
        ];

        let findings = WifiScanner::security_assessment(&aps);
        assert!(!findings.is_empty());

        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Critical)
            .collect();
        assert!(critical.len() >= 1);
    }

    #[test]
    fn test_security_summary() {
        let aps = vec![
            create_test_ap("Open", EncryptionType::Open, 1),
            create_test_ap("Wep", EncryptionType::Wep, 1),
            create_test_ap("Wpa2", EncryptionType::Wpa2, 6),
            create_test_ap("Wpa3", EncryptionType::Wpa3, 11),
        ];

        let scan_result = WifiScanResult {
            access_points: aps,
            clients: Vec::new(),
            channels: Vec::new(),
            scan_duration_secs: 10,
            total_networks: 4,
            open_networks: 1,
            encrypted_networks: 3,
            wps_enabled_count: 0,
            rogue_suspects: 1,
        };

        let summary = scan_result.security_summary();
        assert_eq!(summary.total_aps, 4);
        assert_eq!(summary.open, 1);
        assert_eq!(summary.wep, 1);
        assert_eq!(summary.wpa2, 1);
        assert_eq!(summary.wpa3, 1);
    }

    #[test]
    fn test_channel_to_frequency() {
        assert_eq!(
            WifiScanner::channel_to_frequency(1, &WifiBand::Band2GHz),
            2412
        );
        assert_eq!(
            WifiScanner::channel_to_frequency(6, &WifiBand::Band2GHz),
            2437
        );
        assert_eq!(
            WifiScanner::channel_to_frequency(36, &WifiBand::Band5GHz),
            5180
        );
    }

    #[test]
    fn test_default_scan_config() {
        let config = WifiScanConfig::default();
        assert_eq!(config.interface, "wlan0");
        assert_eq!(config.scan_duration_secs, 10);
        assert!(config.include_hidden);
    }

    #[test]
    fn test_interference_level() {
        assert_eq!(InterferenceLevel::from_ap_count(0), InterferenceLevel::None);
        assert_eq!(InterferenceLevel::from_ap_count(2), InterferenceLevel::Low);
        assert_eq!(
            InterferenceLevel::from_ap_count(5),
            InterferenceLevel::Medium
        );
        assert_eq!(InterferenceLevel::from_ap_count(8), InterferenceLevel::High);
        assert_eq!(
            InterferenceLevel::from_ap_count(15),
            InterferenceLevel::Critical
        );
    }

    #[test]
    fn test_wps_security_finding() {
        let mut ap = create_test_ap("WpsNet", EncryptionType::Wpa2, 1);
        ap.wps_enabled = true;

        let findings = WifiScanner::security_assessment(&[ap]);
        let wps_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.finding_type == SecurityFindingType::WpsEnabled)
            .collect();
        assert_eq!(wps_findings.len(), 1);
    }
}
