use anyhow::{anyhow, Result};

/// Custom payload configuration for packet manipulation
#[derive(Debug, Clone, Default)]
pub struct PayloadConfig {
    /// Hex data to append (--data)
    pub hex_data: Option<Vec<u8>>,
    /// ASCII string to append (--data-string)
    pub string_data: Option<String>,
    /// Random data length (--data-length)
    pub random_length: Option<usize>,
    /// IP options (--ip-options)
    pub ip_options: Option<Vec<u8>>,
    /// TTL value (--ttl)
    pub ttl: Option<u8>,
    /// Send with incorrect checksum (--badsum)
    pub bad_checksum: bool,
}

impl PayloadConfig {
    /// Create new payload config
    pub fn new() -> Self {
        Self::default()
    }

    /// Add hex data (--data)
    pub fn with_hex_data(mut self, hex: &str) -> Result<Self> {
        self.hex_data = Some(Self::parse_hex(hex)?);
        Ok(self)
    }

    /// Add ASCII string data (--data-string)
    pub fn with_string_data(mut self, data: String) -> Self {
        self.string_data = Some(data);
        self
    }

    /// Add random data of specified length (--data-length)
    pub fn with_random_data(mut self, length: usize) -> Self {
        self.random_length = Some(length);
        self
    }

    /// Set IP options (--ip-options)
    pub fn with_ip_options(mut self, options: Vec<u8>) -> Self {
        self.ip_options = Some(options);
        self
    }

    /// Set TTL (--ttl)
    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Enable bad checksum (--badsum)
    pub fn with_bad_checksum(mut self) -> Self {
        self.bad_checksum = true;
        self
    }

    /// Parse hex string to bytes
    fn parse_hex(hex: &str) -> Result<Vec<u8>> {
        let clean = hex.replace(['0', 'x', 'X', ' ', '\t', '\n'], "");

        if !clean.len().is_multiple_of(2) {
            return Err(anyhow!("Hex string must have even number of characters"));
        }

        let mut bytes = Vec::new();
        for chunk in clean.as_bytes().chunks(2) {
            let hex_str = std::str::from_utf8(chunk).map_err(|_| anyhow!("Invalid hex format"))?;
            let byte = u8::from_str_radix(hex_str, 16)
                .map_err(|_| anyhow!("Invalid hex digit: {}", hex_str))?;
            bytes.push(byte);
        }

        Ok(bytes)
    }

    /// Get combined payload data
    pub fn get_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        // Add hex data
        if let Some(ref hex) = self.hex_data {
            payload.extend_from_slice(hex);
        }

        // Add string data
        if let Some(ref string) = self.string_data {
            payload.extend_from_slice(string.as_bytes());
        }

        // Add random data
        if let Some(length) = self.random_length {
            let random: Vec<u8> = (0..length).map(|_| rand::random()).collect();
            payload.extend(random);
        }

        payload
    }

    /// Check if any payload data is set
    pub fn has_payload(&self) -> bool {
        self.hex_data.is_some() || self.string_data.is_some() || self.random_length.is_some()
    }
}

/// IP options for packet manipulation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpOption {
    /// End of Options List
    EndOfList,
    /// No Operation (padding)
    NoOp,
    /// Record Route
    RecordRoute,
    /// Timestamp
    Timestamp,
    /// Loose Source Routing
    LooseSourceRoute,
    /// Strict Source Routing
    StrictSourceRoute,
}

impl IpOption {
    /// Get option type code
    pub fn code(&self) -> u8 {
        match self {
            IpOption::EndOfList => 0,
            IpOption::NoOp => 1,
            IpOption::RecordRoute => 7,
            IpOption::Timestamp => 68,
            IpOption::LooseSourceRoute => 131,
            IpOption::StrictSourceRoute => 137,
        }
    }

    /// Parse option from code
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(IpOption::EndOfList),
            1 => Some(IpOption::NoOp),
            7 => Some(IpOption::RecordRoute),
            68 => Some(IpOption::Timestamp),
            131 => Some(IpOption::LooseSourceRoute),
            137 => Some(IpOption::StrictSourceRoute),
            _ => None,
        }
    }

    /// Build IP options header
    pub fn build(options: &[IpOption]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for opt in options {
            bytes.push(opt.code());
        }
        // Pad to multiple of 4 bytes
        while bytes.len() % 4 != 0 {
            bytes.push(IpOption::NoOp.code());
        }
        bytes
    }
}

/// Custom packet builder with payload manipulation
pub struct CustomPacketBuilder {
    config: PayloadConfig,
}

impl CustomPacketBuilder {
    /// Create new packet builder
    pub fn new(config: PayloadConfig) -> Self {
        Self { config }
    }

    /// Create with default config
    pub fn default() -> Self {
        Self::new(PayloadConfig::default())
    }

    /// Build packet with custom payload
    pub fn build_packet(&self, base_packet: &[u8]) -> Vec<u8> {
        let mut packet = base_packet.to_vec();

        // Append custom payload
        let payload = self.config.get_payload();
        packet.extend(payload);

        packet
    }

    /// Apply TTL to IP header (assumes IP header starts at offset 0)
    pub fn apply_ttl(&self, packet: &mut [u8]) -> Result<()> {
        if packet.len() < 20 {
            return Err(anyhow!("Packet too small for IP header"));
        }

        if let Some(ttl) = self.config.ttl {
            packet[8] = ttl; // TTL is at byte 8 in IP header
        }

        Ok(())
    }

    /// Apply IP options to header
    pub fn apply_ip_options(&self, packet: &mut Vec<u8>) -> Result<()> {
        if let Some(ref options) = self.config.ip_options {
            if packet.len() < 20 {
                return Err(anyhow!("Packet too small for IP header"));
            }

            // Insert options after base IP header (20 bytes)
            let mut new_packet = packet[..20].to_vec();
            new_packet.extend(options);
            new_packet.extend(&packet[20..]);

            // Update IP header length
            let ihl = 5 + (options.len() / 4) as u8; // IHL in 32-bit words
            new_packet[0] = (new_packet[0] & 0x0F) | (ihl << 4);

            *packet = new_packet;
        }

        Ok(())
    }

    /// Corrupt checksum (--badsum)
    pub fn corrupt_checksum(&self, packet: &mut [u8]) -> Result<()> {
        if !self.config.bad_checksum {
            return Ok(());
        }

        if packet.len() < 20 {
            return Err(anyhow!("Packet too small for IP header"));
        }

        // Corrupt IP checksum (bytes 10-11)
        packet[10] = 0xFF;
        packet[11] = 0xFF;

        // Corrupt TCP/UDP checksum if present (bytes 36-37 for TCP, 26-27 for UDP)
        if packet.len() >= 38 {
            packet[36] = 0xFF;
            packet[37] = 0xFF;
        }

        Ok(())
    }

    /// Get configuration
    pub fn config(&self) -> &PayloadConfig {
        &self.config
    }
}

/// TTL preset values
pub struct TtlPresets;

impl TtlPresets {
    /// Default TTL (64 - Linux/macOS)
    pub const DEFAULT: u8 = 64;

    /// Windows default
    pub const WINDOWS: u8 = 128;

    /// Very low TTL for local network
    pub const LOCAL: u8 = 1;

    /// Maximum TTL
    pub const MAX: u8 = 255;

    /// Common router hop count
    pub const ROUTER: u8 = 32;

    /// Get OS-specific TTL
    pub fn for_os(os: &str) -> u8 {
        match os.to_lowercase().as_str() {
            "linux" | "macos" | "unix" => 64,
            "windows" => 128,
            "router" | "cisco" => 255,
            _ => Self::DEFAULT,
        }
    }
}

/// Payload data builder for fluent API
pub struct PayloadBuilder {
    config: PayloadConfig,
}

impl PayloadBuilder {
    /// Create new builder
    pub fn new() -> Self {
        Self {
            config: PayloadConfig::new(),
        }
    }

    /// Add hex data
    pub fn hex(mut self, hex: &str) -> Result<Self> {
        self.config.hex_data = Some(PayloadConfig::parse_hex(hex)?);
        Ok(self)
    }

    /// Add ASCII string
    pub fn string(mut self, data: &str) -> Self {
        self.config.string_data = Some(data.to_string());
        self
    }

    /// Add random bytes
    pub fn random(mut self, length: usize) -> Self {
        self.config.random_length = Some(length);
        self
    }

    /// Set TTL
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.config.ttl = Some(ttl);
        self
    }

    /// Add IP options
    pub fn ip_options(mut self, options: Vec<u8>) -> Self {
        self.config.ip_options = Some(options);
        self
    }

    /// Enable bad checksum
    pub fn bad_checksum(mut self) -> Self {
        self.config.bad_checksum = true;
        self
    }

    /// Build configuration
    pub fn build(self) -> PayloadConfig {
        self.config
    }
}

impl Default for PayloadBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_config_default() {
        let config = PayloadConfig::default();
        assert!(config.hex_data.is_none());
        assert!(config.string_data.is_none());
        assert!(config.random_length.is_none());
        assert!(!config.bad_checksum);
    }

    #[test]
    fn test_parse_hex() {
        let hex = PayloadConfig::parse_hex("48656c6c6f").unwrap();
        assert_eq!(hex, b"Hello");

        let hex2 = PayloadConfig::parse_hex("0x48 0x65 0x6c").unwrap();
        assert_eq!(hex2, b"Hel");
    }

    #[test]
    fn test_parse_hex_invalid() {
        assert!(PayloadConfig::parse_hex("ZZZ").is_err());
        assert!(PayloadConfig::parse_hex("123").is_err()); // Odd length
    }

    #[test]
    fn test_payload_config_hex_data() {
        let config = PayloadConfig::new().with_hex_data("48656c6c6f").unwrap();

        assert!(config.hex_data.is_some());
        assert_eq!(config.hex_data.unwrap(), b"Hello");
    }

    #[test]
    fn test_payload_config_string_data() {
        let config = PayloadConfig::new().with_string_data("Test".to_string());

        assert!(config.string_data.is_some());
        assert_eq!(config.string_data.unwrap(), "Test");
    }

    #[test]
    fn test_payload_config_random_data() {
        let config = PayloadConfig::new().with_random_data(10);

        assert_eq!(config.random_length, Some(10));
    }

    #[test]
    fn test_payload_config_ttl() {
        let config = PayloadConfig::new().with_ttl(64);

        assert_eq!(config.ttl, Some(64));
    }

    #[test]
    fn test_payload_config_bad_checksum() {
        let config = PayloadConfig::new().with_bad_checksum();

        assert!(config.bad_checksum);
    }

    #[test]
    fn test_get_payload_combined() {
        let config = PayloadConfig::new()
            .with_hex_data("4142")
            .unwrap() // "AB"
            .with_string_data("CD".to_string());

        let payload = config.get_payload();
        assert_eq!(payload, b"ABCD");
    }

    #[test]
    fn test_get_payload_random() {
        let config = PayloadConfig::new().with_random_data(10);

        let payload = config.get_payload();
        assert_eq!(payload.len(), 10);
    }

    #[test]
    fn test_has_payload() {
        let config1 = PayloadConfig::new();
        assert!(!config1.has_payload());

        let config2 = PayloadConfig::new().with_hex_data("4142").unwrap();
        assert!(config2.has_payload());
    }

    #[test]
    fn test_ip_option_codes() {
        assert_eq!(IpOption::EndOfList.code(), 0);
        assert_eq!(IpOption::NoOp.code(), 1);
        assert_eq!(IpOption::RecordRoute.code(), 7);
        assert_eq!(IpOption::Timestamp.code(), 68);
    }

    #[test]
    fn test_ip_option_from_code() {
        assert_eq!(IpOption::from_code(0), Some(IpOption::EndOfList));
        assert_eq!(IpOption::from_code(1), Some(IpOption::NoOp));
        assert_eq!(IpOption::from_code(99), None);
    }

    #[test]
    fn test_ip_option_build() {
        let options = vec![IpOption::RecordRoute, IpOption::Timestamp];
        let bytes = IpOption::build(&options);

        assert_eq!(bytes.len() % 4, 0); // Should be padded
        assert_eq!(bytes[0], 7); // RecordRoute
        assert_eq!(bytes[1], 68); // Timestamp
    }

    #[test]
    fn test_custom_packet_builder() {
        let config = PayloadConfig::new().with_hex_data("ABCD").unwrap();

        let builder = CustomPacketBuilder::new(config);
        let base = vec![0u8; 20]; // Base packet
        let packet = builder.build_packet(&base);

        assert_eq!(packet.len(), 22); // 20 + 2 bytes payload
    }

    #[test]
    fn test_ttl_presets() {
        assert_eq!(TtlPresets::DEFAULT, 64);
        assert_eq!(TtlPresets::WINDOWS, 128);
        assert_eq!(TtlPresets::MAX, 255);

        assert_eq!(TtlPresets::for_os("linux"), 64);
        assert_eq!(TtlPresets::for_os("windows"), 128);
    }

    #[test]
    fn test_payload_builder() {
        let config = PayloadBuilder::new()
            .hex("4142")
            .unwrap()
            .string("CD")
            .ttl(64)
            .bad_checksum()
            .build();

        assert!(config.hex_data.is_some());
        assert!(config.string_data.is_some());
        assert_eq!(config.ttl, Some(64));
        assert!(config.bad_checksum);
    }

    #[test]
    fn test_apply_ttl() {
        let config = PayloadConfig::new().with_ttl(128);
        let builder = CustomPacketBuilder::new(config);

        let mut packet = vec![0u8; 20];
        builder.apply_ttl(&mut packet).unwrap();

        assert_eq!(packet[8], 128); // TTL at byte 8
    }

    #[test]
    fn test_corrupt_checksum() {
        let config = PayloadConfig::new().with_bad_checksum();
        let builder = CustomPacketBuilder::new(config);

        let mut packet = vec![0u8; 40];
        builder.corrupt_checksum(&mut packet).unwrap();

        assert_eq!(packet[10], 0xFF); // IP checksum corrupted
        assert_eq!(packet[11], 0xFF);
    }
}
