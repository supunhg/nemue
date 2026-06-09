use anyhow::{anyhow, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// DNP3 function codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dnp3Function {
    Read = 0x01,
    Write = 0x02,
    Select = 0x03,
    Operate = 0x04,
    DirectOperate = 0x05,
    DirectOperateNoAck = 0x06,
    Freeze = 0x07,
    FreezeNoAck = 0x08,
    FreezeClear = 0x09,
    FreezeClearNoAck = 0x0A,
    ColdRestart = 0x0D,
    WarmRestart = 0x0E,
    InitializeData = 0x0F,
    InitializeApplication = 0x10,
    StartApplication = 0x11,
    StopApplication = 0x12,
    SaveConfiguration = 0x13,
    EnableUnsolicited = 0x14,
    DisableUnsolicited = 0x15,
    AssignClass = 0x16,
    DelayMeasure = 0x17,
    RecordCurrentTime = 0x18,
    OpenFile = 0x19,
    CloseFile = 0x1A,
    DeleteFile = 0x1B,
    GetFileInformation = 0x1C,
    AuthenticateFile = 0x1D,
    AbortFile = 0x1E,
    Response = 0x81,
    UnsolicitedResponse = 0x82,
}

impl Dnp3Function {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Dnp3Function::Read),
            0x02 => Some(Dnp3Function::Write),
            0x03 => Some(Dnp3Function::Select),
            0x04 => Some(Dnp3Function::Operate),
            0x05 => Some(Dnp3Function::DirectOperate),
            0x06 => Some(Dnp3Function::DirectOperateNoAck),
            0x0D => Some(Dnp3Function::ColdRestart),
            0x0E => Some(Dnp3Function::WarmRestart),
            0x17 => Some(Dnp3Function::DelayMeasure),
            0x81 => Some(Dnp3Function::Response),
            0x82 => Some(Dnp3Function::UnsolicitedResponse),
            _ => None,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            Dnp3Function::Read => "Read",
            Dnp3Function::Write => "Write",
            Dnp3Function::Select => "Select",
            Dnp3Function::Operate => "Operate",
            Dnp3Function::DirectOperate => "Direct Operate",
            Dnp3Function::DirectOperateNoAck => "Direct Operate (No ACK)",
            Dnp3Function::ColdRestart => "Cold Restart",
            Dnp3Function::WarmRestart => "Warm Restart",
            Dnp3Function::DelayMeasure => "Delay Measure",
            Dnp3Function::Response => "Response",
            Dnp3Function::UnsolicitedResponse => "Unsolicited Response",
            _ => "Unknown",
        }
    }
}

/// DNP3 object group identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dnp3ObjectGroup {
    BinaryInput = 1,
    BinaryOutput = 10,
    Counter = 20,
    AnalogInput = 30,
    AnalogOutput = 40,
    FileControl = 70,
    DeviceAttributes = 80,
    InternalIndications = 81,
}

impl Dnp3ObjectGroup {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Dnp3ObjectGroup::BinaryInput,
            10 => Dnp3ObjectGroup::BinaryOutput,
            20 => Dnp3ObjectGroup::Counter,
            30 => Dnp3ObjectGroup::AnalogInput,
            40 => Dnp3ObjectGroup::AnalogOutput,
            70 => Dnp3ObjectGroup::FileControl,
            80 => Dnp3ObjectGroup::InternalIndications,
            _ => Dnp3ObjectGroup::DeviceAttributes,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            Dnp3ObjectGroup::BinaryInput => "Binary Input",
            Dnp3ObjectGroup::BinaryOutput => "Binary Output",
            Dnp3ObjectGroup::Counter => "Counter",
            Dnp3ObjectGroup::AnalogInput => "Analog Input",
            Dnp3ObjectGroup::AnalogOutput => "Analog Output",
            Dnp3ObjectGroup::FileControl => "File Control",
            Dnp3ObjectGroup::DeviceAttributes => "Device Attributes",
            Dnp3ObjectGroup::InternalIndications => "Internal Indications",
        }
    }
}

/// DNP3 link layer control byte interpretation
#[derive(Debug, Clone)]
pub struct Dnp3LinkControl {
    pub direction: bool,
    pub primary: bool,
    pub fcv: bool,
    pub fcb: bool,
    pub function_code: u8,
}

/// DNP3 device information
#[derive(Debug, Clone)]
pub struct Dnp3DeviceInfo {
    pub source_address: u16,
    pub destination_address: u16,
    pub device_name: Option<String>,
    pub vendor_name: Option<String>,
    pub serial_number: Option<String>,
    pub software_version: Option<String>,
    pub hardware_version: Option<String>,
    pub supported_functions: Vec<Dnp3Function>,
}

/// Security finding for a DNP3 device
#[derive(Debug, Clone)]
pub enum Dnp3SecurityFinding {
    NoAuthentication,
    UnencryptedProtocol,
    ColdRestartSupported,
    WriteAccessAvailable,
    DirectOperateSupported,
    ConfigurationChangeAllowed,
    DeviceIdentExposed,
    DefaultAddresses,
}

impl Dnp3SecurityFinding {
    pub fn severity(&self) -> &str {
        match self {
            Dnp3SecurityFinding::NoAuthentication => "HIGH",
            Dnp3SecurityFinding::UnencryptedProtocol => "MEDIUM",
            Dnp3SecurityFinding::ColdRestartSupported => "CRITICAL",
            Dnp3SecurityFinding::WriteAccessAvailable => "HIGH",
            Dnp3SecurityFinding::DirectOperateSupported => "HIGH",
            Dnp3SecurityFinding::ConfigurationChangeAllowed => "CRITICAL",
            Dnp3SecurityFinding::DeviceIdentExposed => "LOW",
            Dnp3SecurityFinding::DefaultAddresses => "MEDIUM",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            Dnp3SecurityFinding::NoAuthentication => "DNP3 has no authentication enabled",
            Dnp3SecurityFinding::UnencryptedProtocol => "DNP3 traffic is unencrypted",
            Dnp3SecurityFinding::ColdRestartSupported => "Device supports cold restart command",
            Dnp3SecurityFinding::WriteAccessAvailable => "Write operations are available",
            Dnp3SecurityFinding::DirectOperateSupported => "Direct operate commands are accepted",
            Dnp3SecurityFinding::ConfigurationChangeAllowed => "Configuration can be modified remotely",
            Dnp3SecurityFinding::DeviceIdentExposed => "Device identification information is exposed",
            Dnp3SecurityFinding::DefaultAddresses => "Device uses default source/destination addresses",
        }
    }
}

/// DNP3 scan result
#[derive(Debug, Clone)]
pub struct Dnp3ScanResult {
    pub target: IpAddr,
    pub port: u16,
    pub is_dnp3: bool,
    pub device_info: Option<Dnp3DeviceInfo>,
    pub security_findings: Vec<Dnp3SecurityFinding>,
}

/// DNP3 protocol scanner
#[derive(Clone)]
pub struct Dnp3Scanner {
    timeout_duration: Duration,
    source_address: u16,
    destination_address: u16,
}

impl Dnp3Scanner {
    pub const DEFAULT_PORT: u16 = 20000;

    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
            source_address: 1,
            destination_address: 0,
        }
    }

    pub fn with_addresses(timeout_ms: u64, source: u16, destination: u16) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
            source_address: source,
            destination_address: destination,
        }
    }

    /// Perform a full DNP3 scan
    pub async fn scan(&self, target: IpAddr, port: u16) -> Result<Dnp3ScanResult> {
        let is_dnp3 = self.detect_dnp3(target, port).await?;

        if !is_dnp3 {
            return Ok(Dnp3ScanResult {
                target,
                port,
                is_dnp3: false,
                device_info: None,
                security_findings: Vec::new(),
            });
        }

        let device_info = self.identify_device(target, port).await.ok();
        let security_findings = self.assess_security(device_info.as_ref());

        Ok(Dnp3ScanResult {
            target,
            port,
            is_dnp3: true,
            device_info,
            security_findings,
        })
    }

    /// Detect if a device speaks DNP3
    pub async fn detect_dnp3(&self, target: IpAddr, port: u16) -> Result<bool> {
        let addr = SocketAddr::new(target, port);
        let stream = match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        let (mut reader, mut writer) = stream.into_split();

        // Send DNP3 request: Read function code with class 0 data
        let request = self.build_dnp3_request(Dnp3Function::Read as u8, &[0x3C, 0x02, 0x06]);

        if writer.write_all(&request).await.is_err() {
            return Ok(false);
        }

        let mut response = [0u8; 512];
        match timeout(self.timeout_duration, reader.read(&mut response)).await {
            Ok(Ok(n)) if n >= 10 => {
                // Check DNP3 start bytes (0x05 0x64)
                Ok(response[0] == 0x05 && response[1] == 0x64)
            }
            _ => Ok(false),
        }
    }

    /// Identify the DNP3 device
    pub async fn identify_device(&self, target: IpAddr, port: u16) -> Result<Dnp3DeviceInfo> {
        let addr = SocketAddr::new(target, port);
        let stream = timeout(self.timeout_duration, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("Connection timeout"))?
            .map_err(|e| anyhow!("Connection failed: {}", e))?;

        let (mut reader, mut writer) = stream.into_split();

        let mut info = Dnp3DeviceInfo {
            source_address: self.source_address,
            destination_address: self.destination_address,
            device_name: None,
            vendor_name: None,
            serial_number: None,
            software_version: None,
            hardware_version: None,
            supported_functions: Vec::new(),
        };

        // Request device attributes (Object Group 80)
        let request = self.build_dnp3_request(Dnp3Function::Read as u8, &[0x50, 0x00, 0x06]);

        if writer.write_all(&request).await.is_ok() {
            let mut response = [0u8; 1024];
            if let Ok(Ok(n)) = timeout(self.timeout_duration, reader.read(&mut response)).await {
                if n >= 10 && response[0] == 0x05 && response[1] == 0x64 {
                    self.parse_device_attributes(&response[..n], &mut info);
                }
            }
        }

        // Probe for supported functions
        info.supported_functions = self.probe_functions(target, port).await;

        Ok(info)
    }

    /// Parse device attributes from DNP3 response
    fn parse_device_attributes(&self, data: &[u8], info: &mut Dnp3DeviceInfo) {
        // Skip link layer (10 bytes) + transport header (1 byte)
        if data.len() < 14 {
            return;
        }

        let app_start = 11;
        if data.len() > app_start + 2 {
            // Try to extract strings from response data
            let payload = &data[app_start..];
            let text = String::from_utf8_lossy(payload);

            if text.contains("Device") || text.contains("device") {
                info.device_name = Some(text.chars().take(32).collect());
            }
        }
    }

    /// Probe which DNP3 functions the device supports
    async fn probe_functions(&self, target: IpAddr, port: u16) -> Vec<Dnp3Function> {
        let functions_to_probe = [
            Dnp3Function::Read,
            Dnp3Function::Write,
            Dnp3Function::Select,
            Dnp3Function::Operate,
            Dnp3Function::DirectOperate,
            Dnp3Function::ColdRestart,
            Dnp3Function::WarmRestart,
            Dnp3Function::DelayMeasure,
        ];

        let mut supported = Vec::new();

        for func in &functions_to_probe {
            if self.test_function(target, port, *func).await {
                supported.push(*func);
            }
        }

        supported
    }

    /// Test if a specific DNP3 function is supported
    async fn test_function(&self, target: IpAddr, port: u16, function: Dnp3Function) -> bool {
        let addr = SocketAddr::new(target, port);
        let stream = match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return false,
        };

        let (mut reader, mut writer) = stream.into_split();

        let data = match function {
            Dnp3Function::Read => vec![0x3C, 0x02, 0x06], // Class 0 data
            Dnp3Function::DelayMeasure => vec![],
            Dnp3Function::ColdRestart => vec![],
            Dnp3Function::WarmRestart => vec![],
            _ => vec![0x01, 0x00, 0x06], // Default: write to object group 1
        };

        let request = self.build_dnp3_request(function as u8, &data);

        if writer.write_all(&request).await.is_err() {
            return false;
        }

        let mut response = [0u8; 512];
        match timeout(self.timeout_duration, reader.read(&mut response)).await {
            Ok(Ok(n)) if n >= 10 => {
                if response[0] == 0x05 && response[1] == 0x64 {
                    // Valid DNP3 response - check for function code in application layer
                    // The response function code should be 0x81 (response) or 0x82 (unsolicited)
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Assess security posture of the DNP3 device
    pub fn assess_security(&self, device_info: Option<&Dnp3DeviceInfo>) -> Vec<Dnp3SecurityFinding> {
        let mut findings = Vec::new();

        // DNP3 over TCP is typically unencrypted unless TLS is used
        findings.push(Dnp3SecurityFinding::UnencryptedProtocol);
        findings.push(Dnp3SecurityFinding::NoAuthentication);

        // Check default addresses
        if self.source_address == 1 && self.destination_address == 0 {
            findings.push(Dnp3SecurityFinding::DefaultAddresses);
        }

        if let Some(info) = device_info {
            // Check if device identification is exposed
            if info.device_name.is_some()
                || info.vendor_name.is_some()
                || info.serial_number.is_some()
            {
                findings.push(Dnp3SecurityFinding::DeviceIdentExposed);
            }

            // Check dangerous functions
            if info.supported_functions.contains(&Dnp3Function::ColdRestart) {
                findings.push(Dnp3SecurityFinding::ColdRestartSupported);
            }

            if info.supported_functions.contains(&Dnp3Function::WarmRestart) {
                findings.push(Dnp3SecurityFinding::ColdRestartSupported);
            }

            let write_functions = [Dnp3Function::Write, Dnp3Function::Select, Dnp3Function::Operate];
            for func in &write_functions {
                if info.supported_functions.contains(func) {
                    findings.push(Dnp3SecurityFinding::WriteAccessAvailable);
                    break;
                }
            }

            if info.supported_functions.contains(&Dnp3Function::DirectOperate) {
                findings.push(Dnp3SecurityFinding::DirectOperateSupported);
            }

            let config_functions = [
                Dnp3Function::InitializeData,
                Dnp3Function::InitializeApplication,
                Dnp3Function::SaveConfiguration,
            ];
            for func in &config_functions {
                if info.supported_functions.contains(func) {
                    findings.push(Dnp3SecurityFinding::ConfigurationChangeAllowed);
                    break;
                }
            }
        }

        findings
    }

    /// Build a DNP3 request frame
    fn build_dnp3_request(&self, function_code: u8, data: &[u8]) -> Vec<u8> {
        let app_control: u8 = 0xC0; // FIR, FIN flags
        let application_seq: u8 = 0x00;

        // Application layer
        let mut app_layer = Vec::with_capacity(3 + data.len());
        app_layer.push(app_control);
        app_layer.push(application_seq);
        app_layer.push(function_code);
        app_layer.extend_from_slice(data);

        // Transport header
        let transport_header: u8 = 0xC0; // FIR, FIN flags

        // Build full payload: transport + app
        let mut payload = Vec::with_capacity(1 + app_layer.len());
        payload.push(transport_header);
        payload.extend_from_slice(&app_layer);

        // Link layer
        let user_data_len = payload.len() as u8;
        let link_length = 5 + user_data_len; // 5 = dest(2) + src(2) + control(1)

        let link_control: u8 = 0xC0 | 0x03; // DIR=1, PRM=1, FUNC=3 (User Data)

        let mut frame = Vec::with_capacity(10 + payload.len() + 2);
        frame.push(0x05); // Start byte 1
        frame.push(0x64); // Start byte 2
        frame.push(link_length);
        frame.push(0x00); // Control (placeholder)
        frame.push(link_control);
        // Destination address (little-endian)
        frame.extend_from_slice(&self.destination_address.to_le_bytes());
        // Source address (little-endian)
        frame.extend_from_slice(&self.source_address.to_le_bytes());

        // CRC placeholder (DNP3 CRC is CRC-16/DNP)
        let crc = self.calculate_dnp3_crc(&frame[2..]);
        frame.extend_from_slice(&crc.to_le_bytes());

        // Application data
        frame.extend_from_slice(&payload);

        frame
    }

    /// Calculate DNP3 CRC-16 (CRC-16/DNP polynomial)
    fn calculate_dnp3_crc(&self, data: &[u8]) -> u16 {
        let mut crc: u16 = 0x0000;
        for &byte in data {
            crc ^= byte as u16;
            for _ in 0..8 {
                if crc & 0x0001 != 0 {
                    crc = (crc >> 1) ^ 0xA6BC;
                } else {
                    crc >>= 1;
                }
            }
        }
        crc ^ 0xFFFF
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dnp3_function_from_u8() {
        assert_eq!(Dnp3Function::from_u8(0x01), Some(Dnp3Function::Read));
        assert_eq!(Dnp3Function::from_u8(0x02), Some(Dnp3Function::Write));
        assert_eq!(Dnp3Function::from_u8(0x0D), Some(Dnp3Function::ColdRestart));
        assert_eq!(Dnp3Function::from_u8(0x81), Some(Dnp3Function::Response));
        assert_eq!(Dnp3Function::from_u8(0xFF), None);
    }

    #[test]
    fn test_dnp3_function_description() {
        assert_eq!(Dnp3Function::Read.description(), "Read");
        assert_eq!(Dnp3Function::ColdRestart.description(), "Cold Restart");
        assert_eq!(Dnp3Function::DelayMeasure.description(), "Delay Measure");
    }

    #[test]
    fn test_dnp3_object_group() {
        assert_eq!(Dnp3ObjectGroup::from_u8(1), Dnp3ObjectGroup::BinaryInput);
        assert_eq!(Dnp3ObjectGroup::from_u8(30), Dnp3ObjectGroup::AnalogInput);
        assert_eq!(Dnp3ObjectGroup::from_u8(99), Dnp3ObjectGroup::DeviceAttributes);
    }

    #[test]
    fn test_dnp3_object_group_description() {
        assert_eq!(Dnp3ObjectGroup::BinaryInput.description(), "Binary Input");
        assert_eq!(Dnp3ObjectGroup::AnalogOutput.description(), "Analog Output");
    }

    #[test]
    fn test_dnp3_security_finding_severity() {
        assert_eq!(Dnp3SecurityFinding::ColdRestartSupported.severity(), "CRITICAL");
        assert_eq!(Dnp3SecurityFinding::NoAuthentication.severity(), "HIGH");
        assert_eq!(Dnp3SecurityFinding::UnencryptedProtocol.severity(), "MEDIUM");
        assert_eq!(Dnp3SecurityFinding::DeviceIdentExposed.severity(), "LOW");
    }

    #[test]
    fn test_dnp3_security_finding_description() {
        assert!(!Dnp3SecurityFinding::NoAuthentication.description().is_empty());
        assert!(!Dnp3SecurityFinding::ColdRestartSupported.description().is_empty());
    }

    #[test]
    fn test_dnp3_scanner_creation() {
        let scanner = Dnp3Scanner::new(2000);
        assert_eq!(scanner.timeout_duration, Duration::from_millis(2000));
        assert_eq!(scanner.source_address, 1);
        assert_eq!(scanner.destination_address, 0);
    }

    #[test]
    fn test_dnp3_scanner_with_addresses() {
        let scanner = Dnp3Scanner::with_addresses(3000, 10, 5);
        assert_eq!(scanner.source_address, 10);
        assert_eq!(scanner.destination_address, 5);
    }

    #[test]
    fn test_dnp3_default_port() {
        assert_eq!(Dnp3Scanner::DEFAULT_PORT, 20000);
    }

    #[test]
    fn test_dnp3_crc_calculation() {
        let scanner = Dnp3Scanner::new(1000);
        // CRC of empty data should be deterministic
        let crc = scanner.calculate_dnp3_crc(&[]);
        assert_eq!(crc, 0xFFFF);
    }

    #[test]
    fn test_dnp3_request_building() {
        let scanner = Dnp3Scanner::new(1000);
        let request = scanner.build_dnp3_request(0x01, &[0x3C, 0x02, 0x06]);
        assert!(request.len() >= 10);
        // Check start bytes
        assert_eq!(request[0], 0x05);
        assert_eq!(request[1], 0x64);
    }

    #[tokio::test]
    async fn test_detect_dnp3_on_closed_port() {
        let scanner = Dnp3Scanner::new(200);
        let result = scanner.detect_dnp3(IpAddr::V4([127, 0, 0, 1].into()), 1).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_assess_security_no_device_info() {
        let scanner = Dnp3Scanner::new(1000);
        let findings = scanner.assess_security(None);
        assert!(findings.len() >= 2); // At least NoAuthentication + UnencryptedProtocol
    }

    #[test]
    fn test_assess_security_with_default_addresses() {
        let scanner = Dnp3Scanner::new(1000);
        let info = Dnp3DeviceInfo {
            source_address: 1,
            destination_address: 0,
            device_name: None,
            vendor_name: None,
            serial_number: None,
            software_version: None,
            hardware_version: None,
            supported_functions: Vec::new(),
        };
        let findings = scanner.assess_security(Some(&info));
        assert!(findings.iter().any(|f| matches!(f, Dnp3SecurityFinding::DefaultAddresses)));
    }
}
