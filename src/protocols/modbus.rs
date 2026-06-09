use anyhow::{anyhow, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Modbus function codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ModbusFunction {
    ReadCoils = 0x01,
    ReadDiscreteInputs = 0x02,
    ReadHoldingRegisters = 0x03,
    ReadInputRegisters = 0x04,
    WriteSingleCoil = 0x05,
    WriteSingleRegister = 0x06,
    WriteMultipleCoils = 0x0F,
    WriteMultipleRegisters = 0x10,
    ReportServerId = 0x11,
    ReadExceptionStatus = 0x07,
}

impl ModbusFunction {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(ModbusFunction::ReadCoils),
            0x02 => Some(ModbusFunction::ReadDiscreteInputs),
            0x03 => Some(ModbusFunction::ReadHoldingRegisters),
            0x04 => Some(ModbusFunction::ReadInputRegisters),
            0x05 => Some(ModbusFunction::WriteSingleCoil),
            0x06 => Some(ModbusFunction::WriteSingleRegister),
            0x0F => Some(ModbusFunction::WriteMultipleCoils),
            0x10 => Some(ModbusFunction::WriteMultipleRegisters),
            0x11 => Some(ModbusFunction::ReportServerId),
            0x07 => Some(ModbusFunction::ReadExceptionStatus),
            _ => None,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            ModbusFunction::ReadCoils => "Read Coils",
            ModbusFunction::ReadDiscreteInputs => "Read Discrete Inputs",
            ModbusFunction::ReadHoldingRegisters => "Read Holding Registers",
            ModbusFunction::ReadInputRegisters => "Read Input Registers",
            ModbusFunction::WriteSingleCoil => "Write Single Coil",
            ModbusFunction::WriteSingleRegister => "Write Single Register",
            ModbusFunction::WriteMultipleCoils => "Write Multiple Coils",
            ModbusFunction::WriteMultipleRegisters => "Write Multiple Registers",
            ModbusFunction::ReportServerId => "Report Server ID",
            ModbusFunction::ReadExceptionStatus => "Read Exception Status",
        }
    }
}

/// Modbus exception codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ModbusException {
    IllegalFunction = 0x01,
    IllegalDataAddress = 0x02,
    IllegalDataValue = 0x03,
    SlaveDeviceFailure = 0x04,
    Acknowledge = 0x05,
    SlaveDeviceBusy = 0x06,
    MemoryParityError = 0x08,
    GatewayPathUnavailable = 0x0A,
    GatewayTargetFailed = 0x0B,
}

impl ModbusException {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(ModbusException::IllegalFunction),
            0x02 => Some(ModbusException::IllegalDataAddress),
            0x03 => Some(ModbusException::IllegalDataValue),
            0x04 => Some(ModbusException::SlaveDeviceFailure),
            0x05 => Some(ModbusException::Acknowledge),
            0x06 => Some(ModbusException::SlaveDeviceBusy),
            0x08 => Some(ModbusException::MemoryParityError),
            0x0A => Some(ModbusException::GatewayPathUnavailable),
            0x0B => Some(ModbusException::GatewayTargetFailed),
            _ => None,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            ModbusException::IllegalFunction => "Illegal Function",
            ModbusException::IllegalDataAddress => "Illegal Data Address",
            ModbusException::IllegalDataValue => "Illegal Data Value",
            ModbusException::SlaveDeviceFailure => "Slave Device Failure",
            ModbusException::Acknowledge => "Acknowledge",
            ModbusException::SlaveDeviceBusy => "Slave Device Busy",
            ModbusException::MemoryParityError => "Memory Parity Error",
            ModbusException::GatewayPathUnavailable => "Gateway Path Unavailable",
            ModbusException::GatewayTargetFailed => "Gateway Target Failed",
        }
    }
}

/// Modbus device identification
#[derive(Debug, Clone)]
pub struct ModbusDeviceInfo {
    pub unit_id: u8,
    pub vendor_name: Option<String>,
    pub product_code: Option<String>,
    pub major_minor_revision: Option<String>,
    pub supported_functions: Vec<ModbusFunction>,
}

/// Modbus register data
#[derive(Debug, Clone)]
pub struct RegisterData {
    pub start_address: u16,
    pub values: Vec<u16>,
}

/// Security finding for a Modbus device
#[derive(Debug, Clone)]
pub enum ModbusSecurityFinding {
    NoAuthentication,
    WriteAccessAvailable,
    DefaultCredentials,
    UnencryptedProtocol,
    ExcessiveAccess,
    DeviceIdentExposed,
}

impl ModbusSecurityFinding {
    pub fn severity(&self) -> &str {
        match self {
            ModbusSecurityFinding::NoAuthentication => "HIGH",
            ModbusSecurityFinding::WriteAccessAvailable => "CRITICAL",
            ModbusSecurityFinding::DefaultCredentials => "HIGH",
            ModbusSecurityFinding::UnencryptedProtocol => "MEDIUM",
            ModbusSecurityFinding::ExcessiveAccess => "MEDIUM",
            ModbusSecurityFinding::DeviceIdentExposed => "LOW",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            ModbusSecurityFinding::NoAuthentication => "Modbus protocol has no authentication mechanism",
            ModbusSecurityFinding::WriteAccessAvailable => "Write operations are available without authentication",
            ModbusSecurityFinding::DefaultCredentials => "Device uses default unit ID (0 or 1)",
            ModbusSecurityFinding::UnencryptedProtocol => "Modbus TCP traffic is unencrypted",
            ModbusSecurityFinding::ExcessiveAccess => "Device responds to arbitrary function codes",
            ModbusSecurityFinding::DeviceIdentExposed => "Device identification information is exposed",
        }
    }
}

/// Modbus scan result
#[derive(Debug, Clone)]
pub struct ModbusScanResult {
    pub target: IpAddr,
    pub port: u16,
    pub is_modbus: bool,
    pub device_info: Option<ModbusDeviceInfo>,
    pub register_data: Option<RegisterData>,
    pub security_findings: Vec<ModbusSecurityFinding>,
}

/// Modbus TCP scanner
#[derive(Clone)]
pub struct ModbusScanner {
    timeout_duration: Duration,
    unit_id: u8,
}

impl ModbusScanner {
    pub const DEFAULT_PORT: u16 = 502;

    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
            unit_id: 1,
        }
    }

    pub fn with_unit_id(timeout_ms: u64, unit_id: u8) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
            unit_id,
        }
    }

    /// Perform a full Modbus scan: detection, identification, register reading, security assessment
    pub async fn scan(&self, target: IpAddr, port: u16) -> Result<ModbusScanResult> {
        let is_modbus = self.detect_modbus(target, port).await?;

        if !is_modbus {
            return Ok(ModbusScanResult {
                target,
                port,
                is_modbus: false,
                device_info: None,
                register_data: None,
                security_findings: Vec::new(),
            });
        }

        let device_info = self.identify_device(target, port).await.ok();
        let register_data = self.read_holding_registers(target, port, 0, 10).await.ok();
        let security_findings = self.assess_security(target, port, device_info.as_ref()).await;

        Ok(ModbusScanResult {
            target,
            port,
            is_modbus: true,
            device_info,
            register_data,
            security_findings,
        })
    }

    /// Detect if a device speaks Modbus TCP
    pub async fn detect_modbus(&self, target: IpAddr, port: u16) -> Result<bool> {
        let addr = SocketAddr::new(target, port);
        let stream = match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(_)) => return Ok(false),
            Err(_) => return Ok(false),
        };

        let (mut reader, mut writer) = stream.into_split();

        // Send Modbus TCP probe: MBAP header + Unit ID + Function 0x01 (Read Coils)
        let transaction_id: u16 = 0x0001;
        let protocol_id: u16 = 0x0000; // Modbus protocol
        let length: u16 = 0x0006; // Unit ID (1) + Function (1) + Start Addr (2) + Quantity (2)
        let unit_id = self.unit_id;
        let function_code: u8 = ModbusFunction::ReadCoils as u8;
        let start_address: u16 = 0x0000;
        let quantity: u16 = 0x0001;

        let mut request = Vec::with_capacity(12);
        request.extend_from_slice(&transaction_id.to_be_bytes());
        request.extend_from_slice(&protocol_id.to_be_bytes());
        request.extend_from_slice(&length.to_be_bytes());
        request.push(unit_id);
        request.push(function_code);
        request.extend_from_slice(&start_address.to_be_bytes());
        request.extend_from_slice(&quantity.to_be_bytes());

        if writer.write_all(&request).await.is_err() {
            return Ok(false);
        }

        let mut response = [0u8; 256];
        match timeout(self.timeout_duration, reader.read(&mut response)).await {
            Ok(Ok(n)) if n >= 8 => {
                // Check MBAP header: protocol ID should be 0x0000 for Modbus
                let proto = u16::from_be_bytes([response[2], response[3]]);
                Ok(proto == 0x0000)
            }
            _ => Ok(false),
        }
    }

    /// Identify the Modbus device using MEI (function 0x2B / 0x0E)
    pub async fn identify_device(&self, target: IpAddr, port: u16) -> Result<ModbusDeviceInfo> {
        let addr = SocketAddr::new(target, port);
        let stream = timeout(self.timeout_duration, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("Connection timeout"))?
            .map_err(|e| anyhow!("Connection failed: {}", e))?;

        let (mut reader, mut writer) = stream.into_split();

        // MEI Transport: Function 0x2B, MEI Type 0x0E (Device Identification)
        let request = self.build_mbp_request(
            self.unit_id,
            0x2B,
            &[0x0E, 0x01, 0x00], // MEI type 0x0E, Read Device ID code 0x01 (basic)
        );

        let _ = writer.write_all(&request).await;

        let mut response = [0u8; 512];
        let n = match timeout(self.timeout_duration, reader.read(&mut response)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => {
                return Ok(ModbusDeviceInfo {
                    unit_id: self.unit_id,
                    vendor_name: None,
                    product_code: None,
                    major_minor_revision: None,
                    supported_functions: Vec::new(),
                });
            }
        };

        let mut info = ModbusDeviceInfo {
            unit_id: self.unit_id,
            vendor_name: None,
            product_code: None,
            major_minor_revision: None,
            supported_functions: Vec::new(),
        };

        // Try to parse MEI response
        if n > 12 && response[7] == 0x2B && response[8] == 0x0E {
            let objects_start = 12;
            let num_objects = response[11] as usize;
            let mut offset = objects_start;

            for i in 0..num_objects {
                if offset + 2 >= n {
                    break;
                }
                let object_id = response[offset];
                let object_len = response[offset + 1] as usize;
                offset += 2;

                if offset + object_len > n {
                    break;
                }

                let value = String::from_utf8_lossy(&response[offset..offset + object_len]).to_string();
                match object_id {
                    0x00 => info.vendor_name = Some(value),
                    0x01 => info.product_code = Some(value),
                    0x02 => info.major_minor_revision = Some(value),
                    _ => {}
                }
                offset += object_len;
            }
        }

        // Probe supported functions
        info.supported_functions = self.probe_functions(target, port).await;

        Ok(info)
    }

    /// Probe which Modbus function codes the device supports
    async fn probe_functions(&self, target: IpAddr, port: u16) -> Vec<ModbusFunction> {
        let functions_to_probe = [
            ModbusFunction::ReadCoils,
            ModbusFunction::ReadDiscreteInputs,
            ModbusFunction::ReadHoldingRegisters,
            ModbusFunction::ReadInputRegisters,
            ModbusFunction::ReadExceptionStatus,
            ModbusFunction::ReportServerId,
        ];

        let mut supported = Vec::new();

        for func in &functions_to_probe {
            if self.test_function(target, port, *func).await {
                supported.push(*func);
            }
        }

        supported
    }

    /// Test if a specific function code is supported
    async fn test_function(&self, target: IpAddr, port: u16, function: ModbusFunction) -> bool {
        let addr = SocketAddr::new(target, port);
        let stream = match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return false,
        };

        let (mut reader, mut writer) = stream.into_split();

        let request = match function {
            ModbusFunction::ReportServerId => {
                self.build_mbp_request(self.unit_id, function as u8, &[])
            }
            ModbusFunction::ReadExceptionStatus => {
                self.build_mbp_request(self.unit_id, function as u8, &[])
            }
            _ => {
                self.build_mbp_request(self.unit_id, function as u8, &[0x00, 0x00, 0x00, 0x01])
            }
        };

        if writer.write_all(&request).await.is_err() {
            return false;
        }

        let mut response = [0u8; 256];
        match timeout(self.timeout_duration, reader.read(&mut response)).await {
            Ok(Ok(n)) if n >= 8 => {
                let func_code = response[7];
                // If the function code has the high bit set, it's an exception response
                // which still means the function is recognized (just errored)
                (func_code & 0x7F) == (function as u8)
            }
            _ => false,
        }
    }

    /// Read holding registers from the device
    pub async fn read_holding_registers(
        &self,
        target: IpAddr,
        port: u16,
        start_address: u16,
        quantity: u16,
    ) -> Result<RegisterData> {
        let addr = SocketAddr::new(target, port);
        let stream = timeout(self.timeout_duration, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("Connection timeout"))?
            .map_err(|e| anyhow!("Connection failed: {}", e))?;

        let (mut reader, mut writer) = stream.into_split();

        let mut data = Vec::with_capacity(4);
        data.extend_from_slice(&start_address.to_be_bytes());
        data.extend_from_slice(&quantity.to_be_bytes());

        let request = self.build_mbp_request(self.unit_id, ModbusFunction::ReadHoldingRegisters as u8, &data);

        writer.write_all(&request).await.map_err(|e| anyhow!("Write failed: {}", e))?;

        let mut response = [0u8; 512];
        let n = timeout(self.timeout_duration, reader.read(&mut response))
            .await
            .map_err(|_| anyhow!("Read timeout"))?
            .map_err(|e| anyhow!("Read failed: {}", e))?;

        if n < 9 {
            return Err(anyhow!("Response too short"));
        }

        // Check for exception response
        let func_code = response[7];
        if func_code & 0x80 != 0 {
            let exception_code = response[8];
            return Err(anyhow!(
                "Modbus exception: {}",
                ModbusException::from_u8(exception_code)
                    .map(|e| e.description().to_string())
                    .unwrap_or_else(|| format!("Unknown ({})", exception_code))
            ));
        }

        let byte_count = response[8] as usize;
        let num_registers = byte_count / 2;
        let mut values = Vec::with_capacity(num_registers);

        for i in 0..num_registers {
            let offset = 9 + i * 2;
            if offset + 2 <= n {
                values.push(u16::from_be_bytes([response[offset], response[offset + 1]]));
            }
        }

        Ok(RegisterData {
            start_address,
            values,
        })
    }

    /// Assess security posture of the Modbus device
    pub async fn assess_security(
        &self,
        _target: IpAddr,
        _port: u16,
        device_info: Option<&ModbusDeviceInfo>,
    ) -> Vec<ModbusSecurityFinding> {
        let mut findings = Vec::new();

        // Modbus TCP has no authentication by design
        findings.push(ModbusSecurityFinding::NoAuthentication);
        findings.push(ModbusSecurityFinding::UnencryptedProtocol);

        // Check for default unit ID
        if self.unit_id == 0 || self.unit_id == 1 {
            findings.push(ModbusSecurityFinding::DefaultCredentials);
        }

        // Check if device identification is exposed
        if let Some(info) = device_info {
            if info.vendor_name.is_some()
                || info.product_code.is_some()
                || info.major_minor_revision.is_some()
            {
                findings.push(ModbusSecurityFinding::DeviceIdentExposed);
            }

            // Check if write functions are available
            let write_functions = [
                ModbusFunction::WriteSingleCoil,
                ModbusFunction::WriteSingleRegister,
                ModbusFunction::WriteMultipleCoils,
                ModbusFunction::WriteMultipleRegisters,
            ];
            for write_func in &write_functions {
                if info.supported_functions.contains(write_func) {
                    findings.push(ModbusSecurityFinding::WriteAccessAvailable);
                    break;
                }
            }
        }

        findings
    }

    /// Build a Modbus TCP (MBAP) request packet
    fn build_mbp_request(&self, unit_id: u8, function_code: u8, data: &[u8]) -> Vec<u8> {
        let transaction_id: u16 = 0x0001;
        let protocol_id: u16 = 0x0000;
        let length = (data.len() + 2) as u16; // Unit ID + Function Code + data

        let mut packet = Vec::with_capacity(7 + 1 + 1 + data.len());
        packet.extend_from_slice(&transaction_id.to_be_bytes());
        packet.extend_from_slice(&protocol_id.to_be_bytes());
        packet.extend_from_slice(&length.to_be_bytes());
        packet.push(unit_id);
        packet.push(function_code);
        packet.extend_from_slice(data);
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modbus_function_from_u8() {
        assert_eq!(ModbusFunction::from_u8(0x01), Some(ModbusFunction::ReadCoils));
        assert_eq!(ModbusFunction::from_u8(0x03), Some(ModbusFunction::ReadHoldingRegisters));
        assert_eq!(ModbusFunction::from_u8(0x11), Some(ModbusFunction::ReportServerId));
        assert_eq!(ModbusFunction::from_u8(0xFF), None);
    }

    #[test]
    fn test_modbus_function_description() {
        assert_eq!(ModbusFunction::ReadCoils.description(), "Read Coils");
        assert_eq!(
            ModbusFunction::ReadHoldingRegisters.description(),
            "Read Holding Registers"
        );
    }

    #[test]
    fn test_modbus_exception_from_u8() {
        assert_eq!(
            ModbusException::from_u8(0x01),
            Some(ModbusException::IllegalFunction)
        );
        assert_eq!(
            ModbusException::from_u8(0x02),
            Some(ModbusException::IllegalDataAddress)
        );
        assert_eq!(ModbusException::from_u8(0xFF), None);
    }

    #[test]
    fn test_modbus_exception_severity() {
        assert_eq!(ModbusSecurityFinding::NoAuthentication.severity(), "HIGH");
        assert_eq!(ModbusSecurityFinding::WriteAccessAvailable.severity(), "CRITICAL");
    }

    #[test]
    fn test_modbus_scanner_creation() {
        let scanner = ModbusScanner::new(2000);
        assert_eq!(scanner.timeout_duration, Duration::from_millis(2000));
        assert_eq!(scanner.unit_id, 1);
    }

    #[test]
    fn test_modbus_scanner_with_unit_id() {
        let scanner = ModbusScanner::with_unit_id(3000, 5);
        assert_eq!(scanner.unit_id, 5);
    }

    #[test]
    fn test_mbp_request_building() {
        let scanner = ModbusScanner::new(1000);
        let request = scanner.build_mbp_request(1, 0x03, &[0x00, 0x00, 0x00, 0x0A]);
        assert_eq!(request.len(), 12);
        // Transaction ID
        assert_eq!(request[0], 0x00);
        assert_eq!(request[1], 0x01);
        // Protocol ID
        assert_eq!(request[2], 0x00);
        assert_eq!(request[3], 0x00);
        // Length
        assert_eq!(request[4], 0x00);
        assert_eq!(request[5], 0x06);
        // Unit ID
        assert_eq!(request[6], 0x01);
        // Function code
        assert_eq!(request[7], 0x03);
    }

    #[test]
    fn test_modbus_default_port() {
        assert_eq!(ModbusScanner::DEFAULT_PORT, 502);
    }

    #[tokio::test]
    async fn test_detect_modbus_on_closed_port() {
        let scanner = ModbusScanner::new(200);
        let result = scanner.detect_modbus(IpAddr::V4([127, 0, 0, 1].into()), 1).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
