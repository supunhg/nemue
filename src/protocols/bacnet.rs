use anyhow::{anyhow, Result};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

/// BACnet service types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BacnetService {
    WhoIs = 0x00,
    IAm = 0x01,
    ReadProperty = 0x0C,
    ReadPropertyMultiple = 0x0E,
    WriteProperty = 0x0F,
    WritePropertyMultiple = 0x10,
    WhoHas = 0x07,
    IHave = 0x08,
    DeviceCommunicationControl = 0x11,
    ReinitializeDevice = 0x14,
}

/// BACnet object types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum BacnetObjectType {
    AnalogInput = 0,
    AnalogOutput = 1,
    AnalogValue = 2,
    BinaryInput = 3,
    BinaryOutput = 4,
    BinaryValue = 5,
    Calendar = 6,
    Command = 7,
    Device = 8,
    EventEnrollment = 9,
    File = 10,
    Group = 11,
    Loop = 12,
    MultiStateInput = 13,
    MultiStateOutput = 14,
    NotificationClass = 15,
    Program = 16,
    Schedule = 17,
    Averaging = 18,
    MultiStateValue = 19,
    TrendLog = 20,
    LifeSafetyPoint = 21,
    LifeSafetyZone = 22,
    Accumulator = 23,
    PulseConverter = 24,
    EventLog = 25,
    GlobalGroup = 26,
    TrendLogMultiple = 27,
    LoadControl = 28,
    StructuredView = 29,
    AccessPoint = 30,
    AccessZone = 31,
    AccessUser = 32,
    AccessRights = 33,
    AccessCredential = 34,
    CredentialDataInput = 35,
    NetworkSecurity = 36,
    BitstringValue = 37,
    CharacterstringValue = 38,
    DatePatternValue = 39,
    DateValue = 40,
    DatetimePatternValue = 41,
    DatetimeValue = 42,
    IntegerValue = 43,
    LargeAnalogValue = 44,
    PositiveIntegerValue = 45,
    TimePatternValue = 46,
    TimeValue = 47,
}

impl BacnetObjectType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0 => BacnetObjectType::AnalogInput,
            1 => BacnetObjectType::AnalogOutput,
            2 => BacnetObjectType::AnalogValue,
            3 => BacnetObjectType::BinaryInput,
            4 => BacnetObjectType::BinaryOutput,
            5 => BacnetObjectType::BinaryValue,
            8 => BacnetObjectType::Device,
            10 => BacnetObjectType::File,
            13 => BacnetObjectType::MultiStateInput,
            14 => BacnetObjectType::MultiStateOutput,
            20 => BacnetObjectType::TrendLog,
            _ => BacnetObjectType::Device,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            BacnetObjectType::AnalogInput => "Analog Input",
            BacnetObjectType::AnalogOutput => "Analog Output",
            BacnetObjectType::AnalogValue => "Analog Value",
            BacnetObjectType::BinaryInput => "Binary Input",
            BacnetObjectType::BinaryOutput => "Binary Output",
            BacnetObjectType::BinaryValue => "Binary Value",
            BacnetObjectType::Calendar => "Calendar",
            BacnetObjectType::Command => "Command",
            BacnetObjectType::Device => "Device",
            BacnetObjectType::EventEnrollment => "Event Enrollment",
            BacnetObjectType::File => "File",
            BacnetObjectType::Group => "Group",
            BacnetObjectType::Loop => "Loop",
            BacnetObjectType::MultiStateInput => "Multi-State Input",
            BacnetObjectType::MultiStateOutput => "Multi-State Output",
            BacnetObjectType::NotificationClass => "Notification Class",
            BacnetObjectType::Program => "Program",
            BacnetObjectType::Schedule => "Schedule",
            BacnetObjectType::Averaging => "Averaging",
            BacnetObjectType::MultiStateValue => "Multi-State Value",
            BacnetObjectType::TrendLog => "Trend Log",
            _ => "Unknown",
        }
    }
}

/// BACnet device discovery result
#[derive(Debug, Clone)]
pub struct BacnetDeviceInfo {
    pub device_instance: u32,
    pub max_apdu_length: u32,
    pub segmentation_support: u8,
    pub vendor_id: u16,
    pub vendor_name: Option<String>,
    pub firmware_revision: Option<String>,
    pub application_software_version: Option<String>,
    pub model_name: Option<String>,
    pub location: Option<String>,
    pub description: Option<String>,
    pub object_list: Vec<BacnetObjectEntry>,
}

/// A BACnet object entry discovered via enumeration
#[derive(Debug, Clone)]
pub struct BacnetObjectEntry {
    pub object_type: BacnetObjectType,
    pub instance_number: u32,
    pub name: Option<String>,
}

/// Security finding for a BACnet device
#[derive(Debug, Clone)]
pub enum BacnetSecurityFinding {
    NoAuthentication,
    UnencryptedProtocol,
    WhoIsBroadcast,
    ObjectEnumerationPossible,
    DeviceIdentExposed,
    WriteAccessAvailable,
    ReinitializeDeviceSupported,
    DeviceCommunicationControlSupported,
    DefaultPortUsed,
}

impl BacnetSecurityFinding {
    pub fn severity(&self) -> &str {
        match self {
            BacnetSecurityFinding::NoAuthentication => "HIGH",
            BacnetSecurityFinding::UnencryptedProtocol => "MEDIUM",
            BacnetSecurityFinding::WhoIsBroadcast => "LOW",
            BacnetSecurityFinding::ObjectEnumerationPossible => "MEDIUM",
            BacnetSecurityFinding::DeviceIdentExposed => "LOW",
            BacnetSecurityFinding::WriteAccessAvailable => "HIGH",
            BacnetSecurityFinding::ReinitializeDeviceSupported => "CRITICAL",
            BacnetSecurityFinding::DeviceCommunicationControlSupported => "CRITICAL",
            BacnetSecurityFinding::DefaultPortUsed => "LOW",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            BacnetSecurityFinding::NoAuthentication => "BACnet has no authentication enabled",
            BacnetSecurityFinding::UnencryptedProtocol => "BACnet/IP traffic is unencrypted",
            BacnetSecurityFinding::WhoIsBroadcast => "Device responds to Who-Is broadcasts",
            BacnetSecurityFinding::ObjectEnumerationPossible => "Device objects can be enumerated",
            BacnetSecurityFinding::DeviceIdentExposed => {
                "Device identification information is exposed"
            }
            BacnetSecurityFinding::WriteAccessAvailable => "Write property operations are accepted",
            BacnetSecurityFinding::ReinitializeDeviceSupported => {
                "Device supports Reinitialize-Device service"
            }
            BacnetSecurityFinding::DeviceCommunicationControlSupported => {
                "Device supports Device-Communication-Control"
            }
            BacnetSecurityFinding::DefaultPortUsed => "Device listens on default BACnet port 47808",
        }
    }
}

/// BACnet scan result
#[derive(Debug, Clone)]
pub struct BacnetScanResult {
    pub target: IpAddr,
    pub port: u16,
    pub is_bacnet: bool,
    pub device_info: Option<BacnetDeviceInfo>,
    pub security_findings: Vec<BacnetSecurityFinding>,
}

/// BACnet/IP scanner
#[derive(Clone)]
pub struct BacnetScanner {
    timeout_duration: Duration,
}

impl BacnetScanner {
    pub const DEFAULT_PORT: u16 = 47808; // 0xBAC0
    pub const BVLC_TYPE: u8 = 0x81;

    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
        }
    }

    /// Perform a full BACnet scan
    pub async fn scan(&self, target: IpAddr, port: u16) -> Result<BacnetScanResult> {
        let is_bacnet = self.detect_bacnet(target, port)?;

        if !is_bacnet {
            return Ok(BacnetScanResult {
                target,
                port,
                is_bacnet: false,
                device_info: None,
                security_findings: Vec::new(),
            });
        }

        let device_info = self.discover_device(target, port).ok();
        let security_findings = self.assess_security(device_info.as_ref());

        Ok(BacnetScanResult {
            target,
            port,
            is_bacnet: true,
            device_info,
            security_findings,
        })
    }

    /// Detect if a device speaks BACnet/IP
    pub fn detect_bacnet(&self, target: IpAddr, port: u16) -> Result<bool> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(self.timeout_duration))?;

        let who_is = self.build_who_is_request();
        let addr = SocketAddr::new(target, port);

        socket.send_to(&who_is, addr)?;

        let mut response = [0u8; 1024];
        match socket.recv_from(&mut response) {
            Ok((n, _)) if n >= 4 => {
                // Check BVLC type
                Ok(response[0] == Self::BVLC_TYPE)
            }
            _ => Ok(false),
        }
    }

    /// Discover BACnet device information
    pub fn discover_device(&self, target: IpAddr, port: u16) -> Result<BacnetDeviceInfo> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(self.timeout_duration))?;
        let addr = SocketAddr::new(target, port);

        // Send Who-Is to discover devices
        let who_is = self.build_who_is_request();
        socket.send_to(&who_is, addr)?;

        let mut response = [0u8; 2048];
        let n = socket.recv_from(&mut response).map(|(n, _)| n)?;

        if n < 4 || response[0] != Self::BVLC_TYPE {
            return Err(anyhow!("Invalid BACnet response"));
        }

        let mut info = BacnetDeviceInfo {
            device_instance: 0,
            max_apdu_length: 1476,
            segmentation_support: 0,
            vendor_id: 0,
            vendor_name: None,
            firmware_revision: None,
            application_software_version: None,
            model_name: None,
            location: None,
            description: None,
            object_list: Vec::new(),
        };

        // Parse I-Am response
        self.parse_i_am_response(&response[..n], &mut info);

        // Try to read device properties
        self.read_device_properties(target, port, &mut info);

        Ok(info)
    }

    /// Parse an I-Am response to extract device information
    fn parse_i_am_response(&self, data: &[u8], info: &mut BacnetDeviceInfo) {
        // BACnet I-Am parsing:
        // Byte 0: BVLC type (0x81)
        // Byte 1: BVLC function
        // Bytes 2-3: BVLC length
        // Byte 4+: NPDU
        // After NPDU: APDU with I-Am service

        if data.len() < 12 {
            return;
        }

        // Look for the I-Am service data in the APDU
        // NPDU typically starts at byte 4
        let npdu_start = 4;

        // Skip NPDU (variable length, typically 2-4 bytes)
        let apdu_start = npdu_start + 2;
        if data.len() < apdu_start + 6 {
            return;
        }

        // APDU: unconfirmed service request, service choice = I-Am (0)
        if data[apdu_start] == 0x10 && data[apdu_start + 1] == 0x00 {
            let data_start = apdu_start + 2;

            // Object identifier (4 bytes, BACnet object ID)
            if data.len() >= data_start + 4 {
                let object_id = u32::from_be_bytes([
                    data[data_start],
                    data[data_start + 1],
                    data[data_start + 2],
                    data[data_start + 3],
                ]);
                // Extract instance number (lower 22 bits)
                info.device_instance = object_id & 0x003FFFFF;
            }

            // Parse remaining fields
            if data.len() >= data_start + 12 {
                info.max_apdu_length = u32::from_be_bytes([
                    data[data_start + 4],
                    data[data_start + 5],
                    data[data_start + 6],
                    data[data_start + 7],
                ]);
            }
            if data.len() >= data_start + 13 {
                info.segmentation_support = data[data_start + 12];
            }
            if data.len() >= data_start + 15 {
                info.vendor_id = u16::from_be_bytes([data[data_start + 13], data[data_start + 14]]);
                info.vendor_name = Some(self.vendor_name_from_id(info.vendor_id));
            }
        }
    }

    /// Read device properties using ReadProperty requests
    fn read_device_properties(&self, target: IpAddr, port: u16, info: &mut BacnetDeviceInfo) {
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => {
                s.set_read_timeout(Some(self.timeout_duration)).ok();
                s
            }
            Err(_) => return,
        };
        let addr = SocketAddr::new(target, port);

        // Try to read object list
        let read_request = self.build_read_property(
            BacnetObjectType::Device as u16,
            info.device_instance,
            76, // propertyIdentifier for object-list
        );

        if socket.send_to(&read_request, addr).is_ok() {
            let mut response = [0u8; 4096];
            if let Ok(n) = socket.recv(&mut response) {
                self.parse_object_list(&response[..n], info);
            }
        }
    }

    /// Parse object list from ReadProperty response
    fn parse_object_list(&self, data: &[u8], info: &mut BacnetDeviceInfo) {
        // Look for BACnet object identifiers in the response
        // Each is a 4-byte value with object type in upper bits
        for window in data.windows(4) {
            let val = u32::from_be_bytes([window[0], window[1], window[2], window[3]]);
            let obj_type = ((val >> 22) & 0x3FF) as u16;
            let instance = val & 0x003FFFFF;

            // Filter for valid object types
            if obj_type <= 47 && instance < 4194303 {
                let object_type = BacnetObjectType::from_u16(obj_type);
                info.object_list.push(BacnetObjectEntry {
                    object_type,
                    instance_number: instance,
                    name: None,
                });
            }
        }
    }

    /// Assess security posture of the BACnet device
    pub fn assess_security(
        &self,
        device_info: Option<&BacnetDeviceInfo>,
    ) -> Vec<BacnetSecurityFinding> {
        let mut findings = Vec::new();

        findings.push(BacnetSecurityFinding::NoAuthentication);
        findings.push(BacnetSecurityFinding::UnencryptedProtocol);
        findings.push(BacnetSecurityFinding::WhoIsBroadcast);
        findings.push(BacnetSecurityFinding::DefaultPortUsed);

        if let Some(info) = device_info {
            if info.vendor_name.is_some()
                || info.model_name.is_some()
                || info.firmware_revision.is_some()
            {
                findings.push(BacnetSecurityFinding::DeviceIdentExposed);
            }

            if !info.object_list.is_empty() {
                findings.push(BacnetSecurityFinding::ObjectEnumerationPossible);
            }

            // Check for dangerous objects/services
            for obj in &info.object_list {
                if obj.object_type == BacnetObjectType::Command {
                    findings.push(BacnetSecurityFinding::WriteAccessAvailable);
                }
            }
        }

        findings
    }

    /// Build a BACnet Who-Is request
    fn build_who_is_request(&self) -> Vec<u8> {
        // BVLC: Type=0x81, Function=0x0B (Original-Broadcast-NPDU), Length=0x000E
        // NPDU: Version=0x01, Control=0x00
        // APDU: Unconfirmed-REQ, Service=Who-Is (0)
        let mut packet = Vec::with_capacity(18);

        // BVLC header
        packet.push(Self::BVLC_TYPE); // Type
        packet.push(0x0B); // Function: Original-Broadcast-NPDU
        packet.extend_from_slice(&0x0012u16.to_be_bytes()); // Length (18 bytes)

        // NPDU
        packet.push(0x01); // Version
        packet.push(0x00); // Control: no more data, no priority

        // APDU: Unconfirmed-REQ
        packet.push(0x10); // PDU type: unconfirmed request
        packet.push(0x00); // Service choice: Who-Is

        // Optional: device instance range low limit
        packet.push(0x29); // context tag 0, length/value = 1
        packet.push(0x00);
        // Optional: device instance range high limit
        packet.push(0x29); // context tag 1, length/value = 1
        packet.push(0xFF);

        // Update length
        let len = packet.len() as u16;
        packet[2] = (len >> 8) as u8;
        packet[3] = (len & 0xFF) as u8;

        packet
    }

    /// Build a BACnet ReadProperty request
    fn build_read_property(&self, object_type: u16, instance: u32, property_id: u32) -> Vec<u8> {
        let mut packet = Vec::with_capacity(32);

        // BVLC header
        packet.push(Self::BVLC_TYPE);
        packet.push(0x0B); // Original-Broadcast-NPDU
        packet.extend_from_slice(&0x0000u16.to_be_bytes()); // Length placeholder

        // NPDU
        packet.push(0x01); // Version
        packet.push(0x00); // Control

        // APDU: Confirmed-REQ, invoke ID=1, service=ReadProperty
        packet.push(0x00); // PDU type: confirmed request, segmented
        packet.push(0x01); // Max response segments
        packet.push(0x01); // Invoke ID
        packet.push(0x0C); // Service choice: ReadProperty

        // Object ID (context tag 0)
        let object_id = ((object_type as u32) << 22) | (instance & 0x003FFFFF);
        packet.push(0x0C); // Context tag 0, length 4
        packet.extend_from_slice(&object_id.to_be_bytes());

        // Property ID (context tag 1)
        packet.push(0x19); // Context tag 1, length 1
        packet.push(property_id as u8);

        // Update length
        let len = packet.len() as u16;
        packet[2] = (len >> 8) as u8;
        packet[3] = (len & 0xFF) as u8;

        packet
    }

    /// Map BACnet vendor ID to name
    fn vendor_name_from_id(&self, vendor_id: u16) -> String {
        match vendor_id {
            0 => "ASHRAE".to_string(),
            1 => "NIST".to_string(),
            2 => "The Trane Company".to_string(),
            5 => "McQuay International".to_string(),
            10 => "Siemens Building Technologies".to_string(),
            15 => "Carrier Corporation".to_string(),
            17 => "Honeywell".to_string(),
            25 => "Johnson Controls".to_string(),
            37 => "Automated Logic Corporation".to_string(),
            42 => "Delta Controls".to_string(),
            79 => "KMC Controls".to_string(),
            131 => "Cimetrics Technology".to_string(),
            165 => "Robert Bosch GmbH".to_string(),
            178 => "Schneider Electric".to_string(),
            _ => format!("Unknown ({})", vendor_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bacnet_object_type_from_u16() {
        assert_eq!(BacnetObjectType::from_u16(0), BacnetObjectType::AnalogInput);
        assert_eq!(BacnetObjectType::from_u16(8), BacnetObjectType::Device);
        assert_eq!(BacnetObjectType::from_u16(20), BacnetObjectType::TrendLog);
    }

    #[test]
    fn test_bacnet_object_type_description() {
        assert_eq!(BacnetObjectType::AnalogInput.description(), "Analog Input");
        assert_eq!(BacnetObjectType::Device.description(), "Device");
        assert_eq!(
            BacnetObjectType::BinaryOutput.description(),
            "Binary Output"
        );
    }

    #[test]
    fn test_bacnet_security_finding_severity() {
        assert_eq!(
            BacnetSecurityFinding::ReinitializeDeviceSupported.severity(),
            "CRITICAL"
        );
        assert_eq!(
            BacnetSecurityFinding::DeviceCommunicationControlSupported.severity(),
            "CRITICAL"
        );
        assert_eq!(BacnetSecurityFinding::NoAuthentication.severity(), "HIGH");
        assert_eq!(
            BacnetSecurityFinding::WriteAccessAvailable.severity(),
            "HIGH"
        );
        assert_eq!(
            BacnetSecurityFinding::UnencryptedProtocol.severity(),
            "MEDIUM"
        );
        assert_eq!(BacnetSecurityFinding::WhoIsBroadcast.severity(), "LOW");
    }

    #[test]
    fn test_bacnet_security_finding_description() {
        assert!(!BacnetSecurityFinding::NoAuthentication
            .description()
            .is_empty());
        assert!(!BacnetSecurityFinding::ReinitializeDeviceSupported
            .description()
            .is_empty());
    }

    #[test]
    fn test_bacnet_scanner_creation() {
        let scanner = BacnetScanner::new(2000);
        assert_eq!(scanner.timeout_duration, Duration::from_millis(2000));
    }

    #[test]
    fn test_bacnet_constants() {
        assert_eq!(BacnetScanner::DEFAULT_PORT, 47808);
        assert_eq!(BacnetScanner::BVLC_TYPE, 0x81);
    }

    #[test]
    fn test_who_is_request_structure() {
        let scanner = BacnetScanner::new(1000);
        let request = scanner.build_who_is_request();
        assert!(request.len() >= 10);
        // BVLC type
        assert_eq!(request[0], 0x81);
        // BVLC function
        assert_eq!(request[1], 0x0B);
    }

    #[test]
    fn test_read_property_request_structure() {
        let scanner = BacnetScanner::new(1000);
        let request = scanner.build_read_property(8, 0, 76);
        assert!(request.len() >= 16);
        // BVLC type
        assert_eq!(request[0], 0x81);
        // APDU service choice: ReadProperty (at index 9)
        assert_eq!(request[9], 0x0C);
    }

    #[test]
    fn test_vendor_name_lookup() {
        let scanner = BacnetScanner::new(1000);
        assert_eq!(scanner.vendor_name_from_id(17), "Honeywell");
        assert_eq!(scanner.vendor_name_from_id(25), "Johnson Controls");
        assert_eq!(scanner.vendor_name_from_id(178), "Schneider Electric");
        assert!(scanner.vendor_name_from_id(9999).contains("Unknown"));
    }

    #[test]
    fn test_assess_security_no_device_info() {
        let scanner = BacnetScanner::new(1000);
        let findings = scanner.assess_security(None);
        assert!(findings.len() >= 3);
    }

    #[test]
    fn test_assess_security_with_device_info() {
        let scanner = BacnetScanner::new(1000);
        let info = BacnetDeviceInfo {
            device_instance: 100,
            max_apdu_length: 1476,
            segmentation_support: 0,
            vendor_id: 17,
            vendor_name: Some("Honeywell".to_string()),
            firmware_revision: Some("1.0".to_string()),
            application_software_version: None,
            model_name: None,
            location: None,
            description: None,
            object_list: vec![BacnetObjectEntry {
                object_type: BacnetObjectType::AnalogInput,
                instance_number: 0,
                name: None,
            }],
        };
        let findings = scanner.assess_security(Some(&info));
        assert!(findings
            .iter()
            .any(|f| matches!(f, BacnetSecurityFinding::DeviceIdentExposed)));
        assert!(findings
            .iter()
            .any(|f| matches!(f, BacnetSecurityFinding::ObjectEnumerationPossible)));
    }
}
