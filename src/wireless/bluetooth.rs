use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceClass {
    Computer,
    Phone,
    AudioVideo,
    Peripheral,
    Imaging,
    Wearable,
    Health,
    Network,
    Uncategorized,
}

impl DeviceClass {
    pub fn from_class_code(code: u32) -> Self {
        let major = (code >> 8) & 0x1F;
        match major {
            0x01 => DeviceClass::Computer,
            0x02 => DeviceClass::Phone,
            0x04 => DeviceClass::AudioVideo,
            0x05 => DeviceClass::Peripheral,
            0x06 => DeviceClass::Imaging,
            0x07 => DeviceClass::Wearable,
            0x09 => DeviceClass::Health,
            _ => DeviceClass::Uncategorized,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            DeviceClass::Computer => "Computer",
            DeviceClass::Phone => "Phone",
            DeviceClass::AudioVideo => "Audio/Video",
            DeviceClass::Peripheral => "Peripheral",
            DeviceClass::Imaging => "Imaging",
            DeviceClass::Wearable => "Wearable",
            DeviceClass::Health => "Health",
            DeviceClass::Network => "Network",
            DeviceClass::Uncategorized => "Uncategorized",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ServiceUuid {
    Spp,
    A2dp,
    Avrcp,
    Hfp,
    Hid,
    HOGP,
    FileTransfer,
    ObjectPush,
    HealthDevice,
    GenericAccess,
    GenericAttribute,
    BatteryService,
    DeviceInformation,
    Custom(String),
}

impl ServiceUuid {
    pub fn as_str(&self) -> &str {
        match self {
            ServiceUuid::Spp => "SPP (Serial Port Profile)",
            ServiceUuid::A2dp => "A2DP (Advanced Audio)",
            ServiceUuid::Avrcp => "AVRCP (Remote Control)",
            ServiceUuid::Hfp => "HFP (Hands-Free)",
            ServiceUuid::Hid => "HID (Human Interface Device)",
            ServiceUuid::HOGP => "HOGP (HID over GATT)",
            ServiceUuid::FileTransfer => "FTP (File Transfer)",
            ServiceUuid::ObjectPush => "OPP (Object Push)",
            ServiceUuid::HealthDevice => "HDP (Health Device)",
            ServiceUuid::GenericAccess => "GAP (Generic Access)",
            ServiceUuid::GenericAttribute => "GATT (Generic Attribute)",
            ServiceUuid::BatteryService => "Battery Service",
            ServiceUuid::DeviceInformation => "Device Information",
            ServiceUuid::Custom(name) => name,
        }
    }

    pub fn from_uuid(uuid: &str) -> Self {
        match uuid.to_lowercase().as_str() {
            "00001101-0000-1000-8000-00805f9b34fb" => ServiceUuid::Spp,
            "0000110d-0000-1000-8000-00805f9b34fb" => ServiceUuid::A2dp,
            "0000110e-0000-1000-8000-00805f9b34fb" => ServiceUuid::Avrcp,
            "0000111e-0000-1000-8000-00805f9b34fb" => ServiceUuid::Hfp,
            "00001124-0000-1000-8000-00805f9b34fb" => ServiceUuid::Hid,
            "00001812-0000-1000-8000-00805f9b34fb" => ServiceUuid::HOGP,
            "00001106-0000-1000-8000-00805f9b34fb" => ServiceUuid::FileTransfer,
            "00001105-0000-1000-8000-00805f9b34fb" => ServiceUuid::ObjectPush,
            "00001400-0000-1000-8000-00805f9b34fb" => ServiceUuid::HealthDevice,
            "00001800-0000-1000-8000-00805f9b34fb" => ServiceUuid::GenericAccess,
            "00001801-0000-1000-8000-00805f9b34fb" => ServiceUuid::GenericAttribute,
            "0000180f-0000-1000-8000-00805f9b34fb" => ServiceUuid::BatteryService,
            "0000180a-0000-1000-8000-00805f9b34fb" => ServiceUuid::DeviceInformation,
            _ => ServiceUuid::Custom(uuid.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BluetoothSecurityLevel {
    None,
    SecureConnections,
    LegacyPairing,
    SecureSimplePairing,
    OutOfBand,
}

impl BluetoothSecurityLevel {
    pub fn is_secure(&self) -> bool {
        matches!(
            self,
            BluetoothSecurityLevel::SecureConnections | BluetoothSecurityLevel::OutOfBand
        )
    }

    pub fn as_str(&self) -> &str {
        match self {
            BluetoothSecurityLevel::None => "None",
            BluetoothSecurityLevel::SecureConnections => "Secure Connections",
            BluetoothSecurityLevel::LegacyPairing => "Legacy Pairing",
            BluetoothSecurityLevel::SecureSimplePairing => "Secure Simple Pairing",
            BluetoothSecurityLevel::OutOfBand => "Out of Band",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothService {
    pub uuid: ServiceUuid,
    pub name: String,
    pub channel: Option<u16>,
    pub is_running: bool,
    pub security_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothDevice {
    pub address: String,
    pub name: Option<String>,
    pub device_class: DeviceClass,
    pub class_code: u32,
    pub rssi: Option<i32>,
    pub tx_power: Option<i32>,
    pub manufacturer: Option<String>,
    pub is_paired: bool,
    pub is_connectable: bool,
    pub is_bonded: bool,
    pub security_level: BluetoothSecurityLevel,
    pub services: Vec<BluetoothService>,
    pub vulnerabilities: Vec<String>,
    pub is_ble: bool,
    pub firmware_version: Option<String>,
}

impl BluetoothDevice {
    pub fn assess_security(&mut self) {
        self.vulnerabilities.clear();

        if !self.security_level.is_secure() && self.security_level != BluetoothSecurityLevel::None {
            self.vulnerabilities
                .push("Uses legacy pairing which is vulnerable to eavesdropping".to_string());
        }

        if self.is_paired && !self.is_bonded {
            self.vulnerabilities
                .push("Device is paired but not bonded (no key storage)".to_string());
        }

        let has_file_transfer = self
            .services
            .iter()
            .any(|s| matches!(s.uuid, ServiceUuid::FileTransfer | ServiceUuid::ObjectPush));
        if has_file_transfer {
            self.vulnerabilities.push(
                "File transfer service exposed - potential data exfiltration risk".to_string(),
            );
        }

        let has_insecure_services = self.services.iter().any(|s| !s.security_required);
        if has_insecure_services && self.is_connectable {
            self.vulnerabilities
                .push("Device exposes services that do not require authentication".to_string());
        }

        if self.is_ble && self.security_level == BluetoothSecurityLevel::None {
            self.vulnerabilities
                .push("BLE device has no security - susceptible to sniffing".to_string());
        }
    }

    pub fn is_vulnerable(&self) -> bool {
        !self.vulnerabilities.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleDevice {
    pub address: String,
    pub name: Option<String>,
    pub rssi: Option<i32>,
    pub tx_power: Option<i32>,
    pub is_connectable: bool,
    pub is_scannable: bool,
    pub advertised_services: Vec<ServiceUuid>,
    pub manufacturer_data: HashMap<u16, Vec<u8>>,
    pub service_data: HashMap<String, Vec<u8>>,
    pub appearance: Option<u16>,
    pub interval_ms: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothScanConfig {
    pub interface: String,
    pub scan_duration_secs: u64,
    pub scan_ble: bool,
    pub scan_classic: bool,
    pub discover_services: bool,
    pub max_devices: usize,
    pub rssi_threshold: Option<i32>,
}

impl Default for BluetoothScanConfig {
    fn default() -> Self {
        Self {
            interface: "hci0".to_string(),
            scan_duration_secs: 15,
            scan_ble: true,
            scan_classic: true,
            discover_services: true,
            max_devices: 100,
            rssi_threshold: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothScanResult {
    pub devices: Vec<BluetoothDevice>,
    pub ble_devices: Vec<BleDevice>,
    pub scan_duration_secs: u64,
    pub total_devices: usize,
    pub vulnerable_devices: usize,
    pub connectable_devices: usize,
    pub ble_only_devices: usize,
}

impl BluetoothScanResult {
    pub fn security_summary(&self) -> BluetoothSecuritySummary {
        let mut summary = BluetoothSecuritySummary::default();
        summary.total_devices = self.devices.len();

        for device in &self.devices {
            match device.security_level {
                BluetoothSecurityLevel::None => summary.no_security += 1,
                BluetoothSecurityLevel::LegacyPairing => summary.legacy_pairing += 1,
                BluetoothSecurityLevel::SecureSimplePairing => summary.ssp += 1,
                BluetoothSecurityLevel::SecureConnections => summary.secure_connections += 1,
                BluetoothSecurityLevel::OutOfBand => summary.oob += 1,
            }

            if device.is_vulnerable() {
                summary.vulnerable += 1;
            }

            match device.device_class {
                DeviceClass::Phone => summary.phones += 1,
                DeviceClass::Computer => summary.computers += 1,
                DeviceClass::AudioVideo => summary.audio_devices += 1,
                DeviceClass::Peripheral => summary.peripherals += 1,
                _ => {}
            }
        }

        summary.ble_devices = self.ble_devices.len();
        summary
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BluetoothSecuritySummary {
    pub total_devices: usize,
    pub no_security: usize,
    pub legacy_pairing: usize,
    pub ssp: usize,
    pub secure_connections: usize,
    pub oob: usize,
    pub vulnerable: usize,
    pub ble_devices: usize,
    pub phones: usize,
    pub computers: usize,
    pub audio_devices: usize,
    pub peripherals: usize,
}

pub struct BluetoothScanner {
    config: BluetoothScanConfig,
}

impl BluetoothScanner {
    pub fn new(config: BluetoothScanConfig) -> Self {
        Self { config }
    }

    pub fn with_default_config(interface: &str) -> Self {
        Self {
            config: BluetoothScanConfig {
                interface: interface.to_string(),
                ..Default::default()
            },
        }
    }

    pub fn config(&self) -> &BluetoothScanConfig {
        &self.config
    }

    pub fn discover_services(device: &mut BluetoothDevice) {
        let services = Self::get_services_for_device(device);
        device.services = services;
    }

    pub fn assess_security(devices: &mut [BluetoothDevice]) {
        for device in devices.iter_mut() {
            device.assess_security();
        }
    }

    pub fn filter_vulnerable(devices: &[BluetoothDevice]) -> Vec<&BluetoothDevice> {
        devices.iter().filter(|d| d.is_vulnerable()).collect()
    }

    fn get_services_for_device(device: &BluetoothDevice) -> Vec<BluetoothService> {
        let mut services = Vec::new();

        match device.device_class {
            DeviceClass::Phone => {
                services.push(BluetoothService {
                    uuid: ServiceUuid::Hfp,
                    name: "Hands-Free".to_string(),
                    channel: Some(1),
                    is_running: true,
                    security_required: true,
                });
                services.push(BluetoothService {
                    uuid: ServiceUuid::A2dp,
                    name: "Advanced Audio".to_string(),
                    channel: Some(25),
                    is_running: true,
                    security_required: true,
                });
                services.push(BluetoothService {
                    uuid: ServiceUuid::Spp,
                    name: "Serial Port".to_string(),
                    channel: Some(3),
                    is_running: false,
                    security_required: false,
                });
            }
            DeviceClass::AudioVideo => {
                services.push(BluetoothService {
                    uuid: ServiceUuid::A2dp,
                    name: "Advanced Audio".to_string(),
                    channel: Some(25),
                    is_running: true,
                    security_required: true,
                });
                services.push(BluetoothService {
                    uuid: ServiceUuid::Avrcp,
                    name: "Remote Control".to_string(),
                    channel: Some(23),
                    is_running: true,
                    security_required: false,
                });
            }
            DeviceClass::Peripheral => {
                services.push(BluetoothService {
                    uuid: ServiceUuid::Hid,
                    name: "Human Interface".to_string(),
                    channel: Some(17),
                    is_running: true,
                    security_required: true,
                });
            }
            _ => {}
        }

        services
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_device(name: &str, security: BluetoothSecurityLevel) -> BluetoothDevice {
        BluetoothDevice {
            address: "AA:BB:CC:DD:EE:FF".to_string(),
            name: Some(name.to_string()),
            device_class: DeviceClass::Phone,
            class_code: 0x020104,
            rssi: Some(-60),
            tx_power: Some(4),
            manufacturer: Some("TestCorp".to_string()),
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

    #[test]
    fn test_device_class_from_code() {
        assert_eq!(
            DeviceClass::from_class_code(0x020104),
            DeviceClass::Computer
        );
        assert_eq!(DeviceClass::from_class_code(0x020204), DeviceClass::Phone);
        assert_eq!(
            DeviceClass::from_class_code(0x040404),
            DeviceClass::AudioVideo
        );
        assert_eq!(
            DeviceClass::from_class_code(0x000000),
            DeviceClass::Uncategorized
        );
    }

    #[test]
    fn test_service_uuid_from_string() {
        assert_eq!(
            ServiceUuid::from_uuid("00001101-0000-1000-8000-00805f9b34fb"),
            ServiceUuid::Spp
        );
        assert_eq!(
            ServiceUuid::from_uuid("00001812-0000-1000-8000-00805f9b34fb"),
            ServiceUuid::HOGP
        );
        match ServiceUuid::from_uuid("custom-uuid") {
            ServiceUuid::Custom(s) => assert_eq!(s, "custom-uuid"),
            _ => panic!("Expected Custom variant"),
        }
    }

    #[test]
    fn test_bluetooth_security_level() {
        assert!(BluetoothSecurityLevel::SecureConnections.is_secure());
        assert!(BluetoothSecurityLevel::OutOfBand.is_secure());
        assert!(!BluetoothSecurityLevel::LegacyPairing.is_secure());
        assert!(!BluetoothSecurityLevel::None.is_secure());
    }

    #[test]
    fn test_device_security_assessment() {
        let mut device = create_test_device("TestPhone", BluetoothSecurityLevel::LegacyPairing);
        device.is_paired = true;
        device.is_bonded = false;

        device.assess_security();
        assert!(!device.vulnerabilities.is_empty());
        assert!(device.is_vulnerable());
    }

    #[test]
    fn test_secure_device_assessment() {
        let mut device =
            create_test_device("SecurePhone", BluetoothSecurityLevel::SecureConnections);
        device.assess_security();
        assert!(device.vulnerabilities.is_empty());
    }

    #[test]
    fn test_ble_no_security() {
        let mut device = create_test_device("BleSensor", BluetoothSecurityLevel::None);
        device.is_ble = true;
        device.assess_security();
        assert!(device.vulnerabilities.iter().any(|v| v.contains("BLE")));
    }

    #[test]
    fn test_filter_vulnerable() {
        let mut devices = vec![
            create_test_device("Secure", BluetoothSecurityLevel::SecureConnections),
            create_test_device("Insecure", BluetoothSecurityLevel::LegacyPairing),
        ];
        BluetoothScanner::assess_security(&mut devices);

        let vulnerable = BluetoothScanner::filter_vulnerable(&devices);
        assert_eq!(vulnerable.len(), 1);
        assert_eq!(vulnerable[0].name.as_ref().unwrap(), "Insecure");
    }

    #[test]
    fn test_security_summary() {
        let devices = vec![
            create_test_device("Dev1", BluetoothSecurityLevel::SecureConnections),
            create_test_device("Dev2", BluetoothSecurityLevel::LegacyPairing),
            create_test_device("Dev3", BluetoothSecurityLevel::None),
        ];

        let result = BluetoothScanResult {
            devices,
            ble_devices: Vec::new(),
            scan_duration_secs: 15,
            total_devices: 3,
            vulnerable_devices: 0,
            connectable_devices: 3,
            ble_only_devices: 0,
        };

        let summary = result.security_summary();
        assert_eq!(summary.total_devices, 3);
        assert_eq!(summary.secure_connections, 1);
        assert_eq!(summary.legacy_pairing, 1);
        assert_eq!(summary.no_security, 1);
    }

    #[test]
    fn test_service_discovery() {
        let mut device = create_test_device("Phone", BluetoothSecurityLevel::SecureConnections);
        BluetoothScanner::discover_services(&mut device);
        assert!(!device.services.is_empty());
    }

    #[test]
    fn test_default_scan_config() {
        let config = BluetoothScanConfig::default();
        assert_eq!(config.interface, "hci0");
        assert!(config.scan_ble);
        assert!(config.scan_classic);
    }
}
