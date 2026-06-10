use anyhow::{anyhow, Result};
use std::net::IpAddr;

/// MAC address representation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// Create MAC address from bytes
    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Parse MAC address from string
    /// Formats: "00:11:22:33:44:55", "00-11-22-33-44-55", "001122334455"
    pub fn parse(s: &str) -> Result<Self> {
        let clean = s.replace([':', '-'], "");

        if clean.len() != 12 {
            return Err(anyhow!("MAC address must be 12 hex characters"));
        }

        let mut bytes = [0u8; 6];
        for (i, chunk) in clean.as_bytes().chunks(2).enumerate() {
            let hex_str =
                std::str::from_utf8(chunk).map_err(|_| anyhow!("Invalid MAC address format"))?;
            bytes[i] = u8::from_str_radix(hex_str, 16)
                .map_err(|_| anyhow!("Invalid hex in MAC address: {}", hex_str))?;
        }

        Ok(Self(bytes))
    }

    /// Generate random MAC address
    pub fn random() -> Self {
        let mut bytes = [0u8; 6];
        for byte in &mut bytes {
            *byte = rand::random();
        }
        // Set locally administered bit and clear multicast bit
        bytes[0] = (bytes[0] & 0xFE) | 0x02;
        Self(bytes)
    }

    /// Get vendor-specific MAC (Apple, Cisco, etc.)
    pub fn vendor(vendor: &str) -> Result<Self> {
        let prefix = match vendor.to_lowercase().as_str() {
            "apple" => [0x00, 0x1B, 0x63],
            "cisco" => [0x00, 0x1E, 0x14],
            "dell" => [0x00, 0x14, 0x22],
            "hp" => [0x00, 0x1E, 0x0B],
            "intel" => [0x00, 0x1B, 0x21],
            "vmware" => [0x00, 0x50, 0x56],
            _ => return Err(anyhow!("Unknown vendor: {}", vendor)),
        };

        let mut bytes = [0u8; 6];
        bytes[0..3].copy_from_slice(&prefix);
        bytes[3] = rand::random();
        bytes[4] = rand::random();
        bytes[5] = rand::random();

        Ok(Self(bytes))
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Convert to string (colon-separated)
    pub fn to_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Source manipulation configuration
#[derive(Debug, Clone, Default)]
pub struct SourceConfig {
    /// Spoofed source IP address (-S)
    pub source_ip: Option<IpAddr>,
    /// Specific source port (-g/--source-port)
    pub source_port: Option<u16>,
    /// Network interface to use (-e)
    pub interface: Option<String>,
    /// Spoofed MAC address (--spoof-mac)
    pub spoof_mac: Option<MacAddress>,
}

impl SourceConfig {
    /// Create new source config
    pub fn new() -> Self {
        Self::default()
    }

    /// Set spoofed source IP
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Set specific source port
    pub fn with_source_port(mut self, port: u16) -> Self {
        self.source_port = Some(port);
        self
    }

    /// Set network interface
    pub fn with_interface(mut self, interface: String) -> Self {
        self.interface = Some(interface);
        self
    }

    /// Set spoofed MAC address
    pub fn with_spoof_mac(mut self, mac: MacAddress) -> Self {
        self.spoof_mac = Some(mac);
        self
    }

    /// Parse MAC address specification
    /// Formats: "0" (random), "Apple", "Cisco", or explicit MAC
    pub fn parse_mac_spec(spec: &str) -> Result<MacAddress> {
        match spec {
            "0" => Ok(MacAddress::random()),
            vendor if !vendor.contains(':') && !vendor.contains('-') => MacAddress::vendor(vendor),
            mac => MacAddress::parse(mac),
        }
    }
}

/// Source port strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcePortStrategy {
    /// Use random port (default)
    Random,
    /// Use specific port
    Fixed(u16),
    /// Use privileged port (< 1024)
    Privileged,
    /// Use common source port (53, 88, 123, etc.)
    Common,
}

impl SourcePortStrategy {
    /// Get a port based on strategy
    pub fn get_port(&self) -> u16 {
        match self {
            SourcePortStrategy::Random => rand::random::<u16>() | 0x8000, // Ensure high port
            SourcePortStrategy::Fixed(port) => *port,
            SourcePortStrategy::Privileged => {
                // Random port < 1024
                (rand::random::<u16>() % 1023) + 1
            }
            SourcePortStrategy::Common => {
                // Common source ports that firewalls often allow
                let common_ports = [53, 88, 123, 161, 500, 4500];
                common_ports[rand::random::<usize>() % common_ports.len()]
            }
        }
    }
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_addr: Option<IpAddr>,
    pub mac_addr: Option<MacAddress>,
    pub is_up: bool,
}

impl NetworkInterface {
    /// Create new interface
    pub fn new(name: String) -> Self {
        Self {
            name,
            ip_addr: None,
            mac_addr: None,
            is_up: false,
        }
    }

    /// List available network interfaces
    pub fn list() -> Result<Vec<Self>> {
        // In a real implementation, this would use platform-specific APIs
        // For now, return common interface names
        Ok(vec![
            Self {
                name: "eth0".to_string(),
                ip_addr: None,
                mac_addr: None,
                is_up: true,
            },
            Self {
                name: "wlan0".to_string(),
                ip_addr: None,
                mac_addr: None,
                is_up: true,
            },
        ])
    }

    /// Find interface by name
    pub fn find(name: &str) -> Result<Self> {
        let interfaces = Self::list()?;
        interfaces
            .into_iter()
            .find(|i| i.name == name)
            .ok_or_else(|| anyhow!("Interface not found: {}", name))
    }

    /// Validate interface exists and is usable
    pub fn validate(name: &str) -> Result<()> {
        let interface = Self::find(name)?;
        if !interface.is_up {
            return Err(anyhow!("Interface {} is down", name));
        }
        Ok(())
    }
}

/// Source IP spoofing manager
pub struct SourceSpoofer {
    config: SourceConfig,
    port_strategy: SourcePortStrategy,
}

impl SourceSpoofer {
    /// Create new spoofer with configuration
    pub fn new(config: SourceConfig) -> Self {
        let port_strategy = match config.source_port {
            Some(port) => SourcePortStrategy::Fixed(port),
            None => SourcePortStrategy::Random,
        };

        Self {
            config,
            port_strategy,
        }
    }

    /// Create spoofer with IP spoofing
    pub fn with_ip_spoofing(source_ip: IpAddr) -> Self {
        Self::new(SourceConfig::new().with_source_ip(source_ip))
    }

    /// Create spoofer with MAC spoofing
    pub fn with_mac_spoofing(mac: MacAddress) -> Self {
        Self::new(SourceConfig::new().with_spoof_mac(mac))
    }

    /// Get source IP for packet (spoofed or real)
    pub fn get_source_ip(&self, real_ip: IpAddr) -> IpAddr {
        self.config.source_ip.unwrap_or(real_ip)
    }

    /// Get source port for packet
    pub fn get_source_port(&self) -> u16 {
        self.port_strategy.get_port()
    }

    /// Get MAC address for packet (spoofed or real)
    pub fn get_mac_address(&self, real_mac: MacAddress) -> MacAddress {
        self.config.spoof_mac.unwrap_or(real_mac)
    }

    /// Get network interface to use
    pub fn get_interface(&self) -> Option<&str> {
        self.config.interface.as_deref()
    }

    /// Check if IP spoofing is enabled
    pub fn is_ip_spoofed(&self) -> bool {
        self.config.source_ip.is_some()
    }

    /// Check if MAC spoofing is enabled
    pub fn is_mac_spoofed(&self) -> bool {
        self.config.spoof_mac.is_some()
    }

    /// Check if source port is fixed
    pub fn is_port_fixed(&self) -> bool {
        matches!(self.port_strategy, SourcePortStrategy::Fixed(_))
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate interface if specified
        if let Some(ref iface) = self.config.interface {
            NetworkInterface::validate(iface)?;
        }

        // Validate source IP if spoofed
        if let Some(ip) = self.config.source_ip {
            if ip.is_loopback() {
                return Err(anyhow!("Cannot spoof loopback address"));
            }
        }

        Ok(())
    }

    /// Get configuration
    pub fn config(&self) -> &SourceConfig {
        &self.config
    }
}

/// Builder for source spoofing configuration
pub struct SourceSpooferBuilder {
    config: SourceConfig,
    port_strategy: SourcePortStrategy,
}

impl SourceSpooferBuilder {
    /// Create new builder
    pub fn new() -> Self {
        Self {
            config: SourceConfig::new(),
            port_strategy: SourcePortStrategy::Random,
        }
    }

    /// Spoof source IP (-S)
    pub fn spoof_ip(mut self, ip: IpAddr) -> Self {
        self.config.source_ip = Some(ip);
        self
    }

    /// Parse and spoof source IP
    pub fn spoof_ip_str(mut self, ip: &str) -> Result<Self> {
        let addr = ip
            .parse()
            .map_err(|_| anyhow!("Invalid IP address: {}", ip))?;
        self.config.source_ip = Some(addr);
        Ok(self)
    }

    /// Use specific source port (-g)
    pub fn source_port(mut self, port: u16) -> Self {
        self.config.source_port = Some(port);
        self.port_strategy = SourcePortStrategy::Fixed(port);
        self
    }

    /// Use common source port
    pub fn common_port(mut self) -> Self {
        self.port_strategy = SourcePortStrategy::Common;
        self
    }

    /// Use privileged source port
    pub fn privileged_port(mut self) -> Self {
        self.port_strategy = SourcePortStrategy::Privileged;
        self
    }

    /// Specify network interface (-e)
    pub fn interface(mut self, name: String) -> Self {
        self.config.interface = Some(name);
        self
    }

    /// Spoof MAC address (--spoof-mac)
    pub fn spoof_mac(mut self, mac: MacAddress) -> Self {
        self.config.spoof_mac = Some(mac);
        self
    }

    /// Spoof MAC with random address
    pub fn spoof_mac_random(mut self) -> Self {
        self.config.spoof_mac = Some(MacAddress::random());
        self
    }

    /// Spoof MAC with vendor-specific address
    pub fn spoof_mac_vendor(mut self, vendor: &str) -> Result<Self> {
        self.config.spoof_mac = Some(MacAddress::vendor(vendor)?);
        Ok(self)
    }

    /// Build the spoofer
    pub fn build(self) -> SourceSpoofer {
        SourceSpoofer {
            config: self.config,
            port_strategy: self.port_strategy,
        }
    }
}

impl Default for SourceSpooferBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_address_parse() {
        let mac1 = MacAddress::parse("00:11:22:33:44:55").unwrap();
        assert_eq!(mac1.as_bytes(), &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let mac2 = MacAddress::parse("00-11-22-33-44-55").unwrap();
        assert_eq!(mac2.as_bytes(), &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let mac3 = MacAddress::parse("001122334455").unwrap();
        assert_eq!(mac3.as_bytes(), &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_mac_address_parse_invalid() {
        assert!(MacAddress::parse("invalid").is_err());
        assert!(MacAddress::parse("00:11:22:33:44").is_err()); // Too short
        assert!(MacAddress::parse("00:11:22:33:44:55:66").is_err()); // Too long
    }

    #[test]
    fn test_mac_address_random() {
        let mac1 = MacAddress::random();
        let mac2 = MacAddress::random();

        // Should be different (very high probability)
        assert_ne!(mac1, mac2);

        // Should have locally administered bit set
        assert_eq!(mac1.as_bytes()[0] & 0x02, 0x02);

        // Should not have multicast bit set
        assert_eq!(mac1.as_bytes()[0] & 0x01, 0x00);
    }

    #[test]
    fn test_mac_address_vendor() {
        let apple = MacAddress::vendor("apple").unwrap();
        assert_eq!(&apple.as_bytes()[0..3], &[0x00, 0x1B, 0x63]);

        let cisco = MacAddress::vendor("cisco").unwrap();
        assert_eq!(&cisco.as_bytes()[0..3], &[0x00, 0x1E, 0x14]);
    }

    #[test]
    fn test_mac_address_vendor_invalid() {
        assert!(MacAddress::vendor("unknown").is_err());
    }

    #[test]
    fn test_mac_address_display() {
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(mac.to_string(), "00:11:22:33:44:55");
    }

    #[test]
    fn test_source_config_default() {
        let config = SourceConfig::default();
        assert!(config.source_ip.is_none());
        assert!(config.source_port.is_none());
        assert!(config.interface.is_none());
        assert!(config.spoof_mac.is_none());
    }

    #[test]
    fn test_source_config_builder() {
        let config = SourceConfig::new()
            .with_source_ip("192.168.1.1".parse().unwrap())
            .with_source_port(53)
            .with_interface("eth0".to_string());

        assert!(config.source_ip.is_some());
        assert_eq!(config.source_port, Some(53));
        assert_eq!(config.interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn test_source_port_strategy_random() {
        let port = SourcePortStrategy::Random.get_port();
        assert!(port >= 32768); // Should be high port
    }

    #[test]
    fn test_source_port_strategy_fixed() {
        let port = SourcePortStrategy::Fixed(53).get_port();
        assert_eq!(port, 53);
    }

    #[test]
    fn test_source_port_strategy_privileged() {
        let port = SourcePortStrategy::Privileged.get_port();
        assert!(port > 0 && port < 1024);
    }

    #[test]
    fn test_source_port_strategy_common() {
        let port = SourcePortStrategy::Common.get_port();
        let common = [53, 88, 123, 161, 500, 4500];
        assert!(common.contains(&port));
    }

    #[test]
    fn test_source_spoofer_ip() {
        let real_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let spoof_ip: IpAddr = "192.168.1.1".parse().unwrap();

        let spoofer = SourceSpoofer::with_ip_spoofing(spoof_ip);
        assert_eq!(spoofer.get_source_ip(real_ip), spoof_ip);
        assert!(spoofer.is_ip_spoofed());
    }

    #[test]
    fn test_source_spoofer_no_spoof() {
        let real_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let spoofer = SourceSpoofer::new(SourceConfig::new());

        assert_eq!(spoofer.get_source_ip(real_ip), real_ip);
        assert!(!spoofer.is_ip_spoofed());
    }

    #[test]
    fn test_source_spoofer_mac() {
        let mac = MacAddress::random();
        let real_mac = MacAddress::random();

        let spoofer = SourceSpoofer::with_mac_spoofing(mac);
        assert_eq!(spoofer.get_mac_address(real_mac), mac);
        assert!(spoofer.is_mac_spoofed());
    }

    #[test]
    fn test_source_spoofer_port() {
        let config = SourceConfig::new().with_source_port(53);
        let spoofer = SourceSpoofer::new(config);

        assert_eq!(spoofer.get_source_port(), 53);
        assert!(spoofer.is_port_fixed());
    }

    #[test]
    fn test_source_spoofer_builder() {
        let spoofer = SourceSpooferBuilder::new()
            .spoof_ip("192.168.1.1".parse().unwrap())
            .source_port(53)
            .interface("eth0".to_string())
            .spoof_mac_random()
            .build();

        assert!(spoofer.is_ip_spoofed());
        assert!(spoofer.is_mac_spoofed());
        assert!(spoofer.is_port_fixed());
        assert_eq!(spoofer.get_interface(), Some("eth0"));
    }

    #[test]
    fn test_network_interface_list() {
        let interfaces = NetworkInterface::list().unwrap();
        assert!(!interfaces.is_empty());
    }

    #[test]
    fn test_parse_mac_spec_random() {
        let mac = SourceConfig::parse_mac_spec("0").unwrap();
        // Just ensure it's valid, randomness tested elsewhere
        assert_eq!(mac.as_bytes().len(), 6);
    }

    #[test]
    fn test_parse_mac_spec_vendor() {
        let mac = SourceConfig::parse_mac_spec("apple").unwrap();
        assert_eq!(&mac.as_bytes()[0..3], &[0x00, 0x1B, 0x63]);
    }

    #[test]
    fn test_parse_mac_spec_explicit() {
        let mac = SourceConfig::parse_mac_spec("00:11:22:33:44:55").unwrap();
        assert_eq!(mac.as_bytes(), &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }
}
