use anyhow::{anyhow, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// EtherNet/IP command codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EnipCommand {
    NOP = 0x0000,
    ListServices = 0x0004,
    ListIdentity = 0x0063,
    ListInterfaces = 0x0064,
    RegisterSession = 0x0065,
    UnregisterSession = 0x0066,
    SendRRData = 0x006F,
    SendUnitData = 0x0070,
}

impl EnipCommand {
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x0000 => Some(EnipCommand::NOP),
            0x0004 => Some(EnipCommand::ListServices),
            0x0063 => Some(EnipCommand::ListIdentity),
            0x0064 => Some(EnipCommand::ListInterfaces),
            0x0065 => Some(EnipCommand::RegisterSession),
            0x0066 => Some(EnipCommand::UnregisterSession),
            0x006F => Some(EnipCommand::SendRRData),
            0x0070 => Some(EnipCommand::SendUnitData),
            _ => None,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            EnipCommand::NOP => "NOP",
            EnipCommand::ListServices => "List Services",
            EnipCommand::ListIdentity => "List Identity",
            EnipCommand::ListInterfaces => "List Interfaces",
            EnipCommand::RegisterSession => "Register Session",
            EnipCommand::UnregisterSession => "Unregister Session",
            EnipCommand::SendRRData => "Send RR Data",
            EnipCommand::SendUnitData => "Send Unit Data",
        }
    }
}

/// CIP service codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipService {
    GetAttributeAll = 0x01,
    SetAttributeAll = 0x02,
    GetAttributeList = 0x03,
    SetAttributeList = 0x04,
    Reset = 0x05,
    Start = 0x06,
    Stop = 0x07,
    Create = 0x08,
    Delete = 0x09,
    MultipleServicePacket = 0x0A,
    ApplyAttributes = 0x0D,
    GetAttributeSingle = 0x0E,
    SetAttributeSingle = 0x10,
    FindNextObjectInstance = 0x11,
    ReadTag = 0x4C,
    WriteTag = 0x4D,
    ReadModifyWriteTag = 0x4E,
    ReadFragmentedTag = 0x52,
    WriteFragmentedTag = 0x53,
}

impl CipService {
    pub fn description(&self) -> &str {
        match self {
            CipService::GetAttributeAll => "Get Attribute All",
            CipService::SetAttributeAll => "Set Attribute All",
            CipService::GetAttributeList => "Get Attribute List",
            CipService::Reset => "Reset",
            CipService::Start => "Start",
            CipService::Stop => "Stop",
            CipService::MultipleServicePacket => "Multiple Service Packet",
            CipService::GetAttributeSingle => "Get Attribute Single",
            CipService::SetAttributeSingle => "Set Attribute Single",
            CipService::ReadTag => "Read Tag",
            CipService::WriteTag => "Write Tag",
            CipService::ReadModifyWriteTag => "Read-Modify-Write Tag",
            _ => "Unknown",
        }
    }
}

/// Device type classification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceType {
    ProgrammableLogicController,
    HumanMachineInterface,
    IoModule,
    Drive,
    SafetyController,
    Gateway,
    Unknown,
}

impl DeviceType {
    pub fn from_type_code(code: u16) -> Self {
        match code {
            0x0C => DeviceType::ProgrammableLogicController,
            0x17 => DeviceType::HumanMachineInterface,
            0x19 => DeviceType::IoModule,
            0x2A => DeviceType::Drive,
            0x30 => DeviceType::SafetyController,
            0x2C => DeviceType::Gateway,
            _ => DeviceType::Unknown,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            DeviceType::ProgrammableLogicController => "Programmable Logic Controller (PLC)",
            DeviceType::HumanMachineInterface => "Human Machine Interface (HMI)",
            DeviceType::IoModule => "I/O Module",
            DeviceType::Drive => "Drive",
            DeviceType::SafetyController => "Safety Controller",
            DeviceType::Gateway => "Gateway",
            DeviceType::Unknown => "Unknown",
        }
    }
}

/// EtherNet/IP device information
#[derive(Debug, Clone)]
pub struct EnipDeviceInfo {
    pub item_count: u16,
    pub device_type: DeviceType,
    pub vendor_id: u16,
    pub serial_number: u32,
    pub product_name: Option<String>,
    pub device_ip: Option<IpAddr>,
    pub state: u8,
    pub supported_commands: Vec<EnipCommand>,
}

/// Security finding for an EtherNet/IP device
#[derive(Debug, Clone)]
pub enum EnipSecurityFinding {
    NoAuthentication,
    UnencryptedProtocol,
    SessionRegistration,
    IdentityExposed,
    ListServicesExposed,
    SendRRDataAccepted,
    DeviceResetSupported,
    DefaultPortUsed,
}

impl EnipSecurityFinding {
    pub fn severity(&self) -> &str {
        match self {
            EnipSecurityFinding::NoAuthentication => "HIGH",
            EnipSecurityFinding::UnencryptedProtocol => "MEDIUM",
            EnipSecurityFinding::SessionRegistration => "MEDIUM",
            EnipSecurityFinding::IdentityExposed => "LOW",
            EnipSecurityFinding::ListServicesExposed => "LOW",
            EnipSecurityFinding::SendRRDataAccepted => "HIGH",
            EnipSecurityFinding::DeviceResetSupported => "CRITICAL",
            EnipSecurityFinding::DefaultPortUsed => "LOW",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            EnipSecurityFinding::NoAuthentication => "EtherNet/IP has no authentication enabled",
            EnipSecurityFinding::UnencryptedProtocol => "EtherNet/IP traffic is unencrypted",
            EnipSecurityFinding::SessionRegistration => {
                "Sessions can be registered without authentication"
            }
            EnipSecurityFinding::IdentityExposed => "Device identity information is exposed",
            EnipSecurityFinding::ListServicesExposed => "Device services can be enumerated",
            EnipSecurityFinding::SendRRDataAccepted => "SendRRData commands are accepted",
            EnipSecurityFinding::DeviceResetSupported => "Device supports remote reset commands",
            EnipSecurityFinding::DefaultPortUsed => {
                "Device listens on default EtherNet/IP port 44818"
            }
        }
    }
}

/// EtherNet/IP scan result
#[derive(Debug, Clone)]
pub struct EnipScanResult {
    pub target: IpAddr,
    pub port: u16,
    pub is_enip: bool,
    pub device_info: Option<EnipDeviceInfo>,
    pub security_findings: Vec<EnipSecurityFinding>,
}

/// EtherNet/IP scanner
#[derive(Clone)]
pub struct EnipScanner {
    timeout_duration: Duration,
}

impl EnipScanner {
    pub const DEFAULT_PORT: u16 = 44818;

    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
        }
    }

    /// Perform a full EtherNet/IP scan
    pub async fn scan(&self, target: IpAddr, port: u16) -> Result<EnipScanResult> {
        let is_enip = self.detect_enip(target, port).await?;

        if !is_enip {
            return Ok(EnipScanResult {
                target,
                port,
                is_enip: false,
                device_info: None,
                security_findings: Vec::new(),
            });
        }

        let device_info = self.identify_device(target, port).await.ok();
        let security_findings = self.assess_security(device_info.as_ref());

        Ok(EnipScanResult {
            target,
            port,
            is_enip: true,
            device_info,
            security_findings,
        })
    }

    /// Detect if a device speaks EtherNet/IP
    pub async fn detect_enip(&self, target: IpAddr, port: u16) -> Result<bool> {
        let addr = SocketAddr::new(target, port);
        let stream = match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        let (mut reader, mut writer) = stream.into_split();

        // Send ListIdentity command
        let request = self.build_enip_header(EnipCommand::ListIdentity, &[]);

        if writer.write_all(&request).await.is_err() {
            return Ok(false);
        }

        let mut response = [0u8; 512];
        match timeout(self.timeout_duration, reader.read(&mut response)).await {
            Ok(Ok(n)) if n >= 24 => {
                // Check command in response
                let cmd = u16::from_be_bytes([response[0], response[1]]);
                Ok(cmd == EnipCommand::ListIdentity as u16)
            }
            _ => Ok(false),
        }
    }

    /// Identify the EtherNet/IP device
    pub async fn identify_device(&self, target: IpAddr, port: u16) -> Result<EnipDeviceInfo> {
        let addr = SocketAddr::new(target, port);
        let stream = timeout(self.timeout_duration, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("Connection timeout"))?
            .map_err(|e| anyhow!("Connection failed: {}", e))?;

        let (mut reader, mut writer) = stream.into_split();

        let mut info = EnipDeviceInfo {
            item_count: 0,
            device_type: DeviceType::Unknown,
            vendor_id: 0,
            serial_number: 0,
            product_name: None,
            device_ip: None,
            state: 0,
            supported_commands: Vec::new(),
        };

        // ListIdentity
        let request = self.build_enip_header(EnipCommand::ListIdentity, &[]);
        if writer.write_all(&request).await.is_ok() {
            let mut response = [0u8; 1024];
            if let Ok(Ok(n)) = timeout(self.timeout_duration, reader.read(&mut response)).await {
                self.parse_list_identity(&response[..n], &mut info);
            }
        }

        // ListServices
        let request = self.build_enip_header(EnipCommand::ListServices, &[]);
        if writer.write_all(&request).await.is_ok() {
            let mut response = [0u8; 1024];
            if let Ok(Ok(n)) = timeout(self.timeout_duration, reader.read(&mut response)).await {
                self.parse_list_services(&response[..n], &mut info);
            }
        }

        // Probe supported commands
        info.supported_commands = self.probe_commands(target, port).await;

        Ok(info)
    }

    /// Parse ListIdentity response
    fn parse_list_identity(&self, data: &[u8], info: &mut EnipDeviceInfo) {
        // ENIP header is 24 bytes
        // Command (2) + Length (2) + Session Handle (4) + Status (4) + Sender Context (8) + Options (4)
        if data.len() < 28 {
            return;
        }

        let item_count_offset = 24;
        if data.len() > item_count_offset + 2 {
            info.item_count =
                u16::from_be_bytes([data[item_count_offset], data[item_count_offset + 1]]);
        }

        // Parse CIP Identity item (type code 0x000C)
        if data.len() > item_count_offset + 30 {
            let item_type =
                u16::from_be_bytes([data[item_count_offset + 2], data[item_count_offset + 3]]);
            if item_type == 0x000C {
                let _item_length =
                    u16::from_be_bytes([data[item_count_offset + 4], data[item_count_offset + 5]]);

                let ident_offset = item_count_offset + 6;
                if data.len() > ident_offset + 20 {
                    info.vendor_id =
                        u16::from_be_bytes([data[ident_offset], data[ident_offset + 1]]);
                    let device_type_code =
                        u16::from_be_bytes([data[ident_offset + 2], data[ident_offset + 3]]);
                    info.device_type = DeviceType::from_type_code(device_type_code);
                    info.serial_number = u32::from_be_bytes([
                        data[ident_offset + 12],
                        data[ident_offset + 13],
                        data[ident_offset + 14],
                        data[ident_offset + 15],
                    ]);
                    info.state = data.get(ident_offset + 19).copied().unwrap_or(0);

                    // Product name (byte 20+ of identity item, length-prefixed)
                    let name_len_offset = ident_offset + 20;
                    if data.len() > name_len_offset + 1 {
                        let name_len = data[name_len_offset] as usize;
                        let name_start = name_len_offset + 1;
                        if data.len() >= name_start + name_len {
                            info.product_name = Some(
                                String::from_utf8_lossy(&data[name_start..name_start + name_len])
                                    .to_string(),
                            );
                        }
                    }
                }
            }
        }
    }

    /// Parse ListServices response
    fn parse_list_services(&self, data: &[u8], info: &mut EnipDeviceInfo) {
        if data.len() < 28 {
            return;
        }

        let item_count_offset = 24;
        if data.len() > item_count_offset + 2 {
            let count = u16::from_be_bytes([data[item_count_offset], data[item_count_offset + 1]]);
            info.item_count = info.item_count.max(count);
        }
    }

    /// Probe which ENIP commands the device supports
    async fn probe_commands(&self, target: IpAddr, port: u16) -> Vec<EnipCommand> {
        let commands_to_probe = [
            EnipCommand::ListServices,
            EnipCommand::ListIdentity,
            EnipCommand::ListInterfaces,
            EnipCommand::RegisterSession,
        ];

        let mut supported = Vec::new();

        for cmd in &commands_to_probe {
            if self.test_command(target, port, *cmd).await {
                supported.push(*cmd);
            }
        }

        supported
    }

    /// Test if a specific ENIP command is supported
    async fn test_command(&self, target: IpAddr, port: u16, command: EnipCommand) -> bool {
        let addr = SocketAddr::new(target, port);
        let stream = match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return false,
        };

        let (mut reader, mut writer) = stream.into_split();

        let request = match command {
            EnipCommand::RegisterSession => {
                self.build_enip_header(command, &[0x01, 0x00, 0x00, 0x00])
            }
            _ => self.build_enip_header(command, &[]),
        };

        if writer.write_all(&request).await.is_err() {
            return false;
        }

        let mut response = [0u8; 512];
        match timeout(self.timeout_duration, reader.read(&mut response)).await {
            Ok(Ok(n)) if n >= 24 => {
                let cmd = u16::from_be_bytes([response[0], response[1]]);
                cmd == command as u16
            }
            _ => false,
        }
    }

    /// Assess security posture of the EtherNet/IP device
    pub fn assess_security(
        &self,
        device_info: Option<&EnipDeviceInfo>,
    ) -> Vec<EnipSecurityFinding> {
        let mut findings = Vec::new();

        findings.push(EnipSecurityFinding::NoAuthentication);
        findings.push(EnipSecurityFinding::UnencryptedProtocol);
        findings.push(EnipSecurityFinding::DefaultPortUsed);

        if let Some(info) = device_info {
            if info.product_name.is_some() {
                findings.push(EnipSecurityFinding::IdentityExposed);
            }

            if info.item_count > 0 {
                findings.push(EnipSecurityFinding::ListServicesExposed);
            }

            if info
                .supported_commands
                .contains(&EnipCommand::RegisterSession)
            {
                findings.push(EnipSecurityFinding::SessionRegistration);
            }

            if info.supported_commands.contains(&EnipCommand::SendRRData) {
                findings.push(EnipSecurityFinding::SendRRDataAccepted);
            }

            if info.supported_commands.contains(&EnipCommand::SendUnitData) {
                findings.push(EnipSecurityFinding::SendRRDataAccepted);
            }
        }

        findings
    }

    /// Build an EtherNet/IP encapsulation header
    fn build_enip_header(&self, command: EnipCommand, data: &[u8]) -> Vec<u8> {
        let length = data.len() as u16;
        let mut packet = Vec::with_capacity(24 + data.len());

        // Command
        packet.extend_from_slice(&(command as u16).to_be_bytes());
        // Length
        packet.extend_from_slice(&length.to_be_bytes());
        // Session Handle (0 for pre-session)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Status (0 = success)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Sender Context (8 bytes)
        packet.extend_from_slice(&[0x00; 8]);
        // Options (0)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Command-specific data
        packet.extend_from_slice(data);

        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enip_command_from_u16() {
        assert_eq!(
            EnipCommand::from_u16(0x0004),
            Some(EnipCommand::ListServices)
        );
        assert_eq!(
            EnipCommand::from_u16(0x0063),
            Some(EnipCommand::ListIdentity)
        );
        assert_eq!(
            EnipCommand::from_u16(0x0065),
            Some(EnipCommand::RegisterSession)
        );
        assert_eq!(EnipCommand::from_u16(0x006F), Some(EnipCommand::SendRRData));
        assert_eq!(EnipCommand::from_u16(0xFFFF), None);
    }

    #[test]
    fn test_enip_command_description() {
        assert_eq!(EnipCommand::ListIdentity.description(), "List Identity");
        assert_eq!(
            EnipCommand::RegisterSession.description(),
            "Register Session"
        );
        assert_eq!(EnipCommand::SendRRData.description(), "Send RR Data");
    }

    #[test]
    fn test_device_type_from_code() {
        assert_eq!(
            DeviceType::from_type_code(0x0C),
            DeviceType::ProgrammableLogicController
        );
        assert_eq!(
            DeviceType::from_type_code(0x17),
            DeviceType::HumanMachineInterface
        );
        assert_eq!(DeviceType::from_type_code(0x19), DeviceType::IoModule);
        assert_eq!(DeviceType::from_type_code(0xFF), DeviceType::Unknown);
    }

    #[test]
    fn test_device_type_description() {
        assert_eq!(
            DeviceType::ProgrammableLogicController.description(),
            "Programmable Logic Controller (PLC)"
        );
        assert_eq!(
            DeviceType::HumanMachineInterface.description(),
            "Human Machine Interface (HMI)"
        );
    }

    #[test]
    fn test_enip_security_finding_severity() {
        assert_eq!(
            EnipSecurityFinding::DeviceResetSupported.severity(),
            "CRITICAL"
        );
        assert_eq!(EnipSecurityFinding::NoAuthentication.severity(), "HIGH");
        assert_eq!(EnipSecurityFinding::SendRRDataAccepted.severity(), "HIGH");
        assert_eq!(
            EnipSecurityFinding::UnencryptedProtocol.severity(),
            "MEDIUM"
        );
        assert_eq!(EnipSecurityFinding::IdentityExposed.severity(), "LOW");
    }

    #[test]
    fn test_enip_security_finding_description() {
        assert!(!EnipSecurityFinding::NoAuthentication
            .description()
            .is_empty());
        assert!(!EnipSecurityFinding::SessionRegistration
            .description()
            .is_empty());
    }

    #[test]
    fn test_enip_scanner_creation() {
        let scanner = EnipScanner::new(2000);
        assert_eq!(scanner.timeout_duration, Duration::from_millis(2000));
    }

    #[test]
    fn test_enip_default_port() {
        assert_eq!(EnipScanner::DEFAULT_PORT, 44818);
    }

    #[test]
    fn test_enip_header_building() {
        let scanner = EnipScanner::new(1000);
        let header = scanner.build_enip_header(EnipCommand::ListIdentity, &[]);
        assert_eq!(header.len(), 24);
        // Command
        assert_eq!(header[0], 0x00);
        assert_eq!(header[1], 0x63);
        // Length = 0
        assert_eq!(header[2], 0x00);
        assert_eq!(header[3], 0x00);
    }

    #[test]
    fn test_enip_header_with_data() {
        let scanner = EnipScanner::new(1000);
        let header =
            scanner.build_enip_header(EnipCommand::RegisterSession, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(header.len(), 28);
        // Length = 4
        assert_eq!(header[2], 0x00);
        assert_eq!(header[3], 0x04);
    }

    #[tokio::test]
    async fn test_detect_enip_on_closed_port() {
        let scanner = EnipScanner::new(200);
        let result = scanner
            .detect_enip(IpAddr::V4([127, 0, 0, 1].into()), 1)
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_assess_security_no_device_info() {
        let scanner = EnipScanner::new(1000);
        let findings = scanner.assess_security(None);
        assert!(findings.len() >= 3);
    }

    #[test]
    fn test_assess_security_with_device_info() {
        let scanner = EnipScanner::new(1000);
        let info = EnipDeviceInfo {
            item_count: 5,
            device_type: DeviceType::ProgrammableLogicController,
            vendor_id: 1,
            serial_number: 12345,
            product_name: Some("CompactLogix".to_string()),
            device_ip: None,
            state: 0,
            supported_commands: vec![EnipCommand::ListIdentity, EnipCommand::RegisterSession],
        };
        let findings = scanner.assess_security(Some(&info));
        assert!(findings
            .iter()
            .any(|f| matches!(f, EnipSecurityFinding::IdentityExposed)));
        assert!(findings
            .iter()
            .any(|f| matches!(f, EnipSecurityFinding::SessionRegistration)));
        assert!(findings
            .iter()
            .any(|f| matches!(f, EnipSecurityFinding::ListServicesExposed)));
    }
}
