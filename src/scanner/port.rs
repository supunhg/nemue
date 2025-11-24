use anyhow::{anyhow, Result};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Port(u16);

impl Port {
    pub fn new(port: u16) -> Result<Self> {
        if port == 0 {
            return Err(anyhow!("Port 0 is invalid"));
        }
        Ok(Port(port))
    }

    pub fn value(&self) -> u16 {
        self.0
    }
}

/// Protocol type for port specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortProtocol {
    Tcp,
    Udp,
    Sctp,
}

impl PortProtocol {
    /// Parse from short notation (T, U, S)
    pub fn from_char(c: char) -> Option<Self> {
        match c.to_ascii_uppercase() {
            'T' => Some(PortProtocol::Tcp),
            'U' => Some(PortProtocol::Udp),
            'S' => Some(PortProtocol::Sctp),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            PortProtocol::Tcp => "tcp",
            PortProtocol::Udp => "udp",
            PortProtocol::Sctp => "sctp",
        }
    }
}

/// Port with protocol specification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolPort {
    pub port: Port,
    pub protocol: PortProtocol,
}

impl ProtocolPort {
    pub fn new(port: u16, protocol: PortProtocol) -> Result<Self> {
        Ok(ProtocolPort {
            port: Port::new(port)?,
            protocol,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Result<Self> {
        if start == 0 || end == 0 {
            return Err(anyhow!("Port 0 is invalid"));
        }
        if start > end {
            return Err(anyhow!("Start port must be less than or equal to end port"));
        }
        Ok(PortRange { start, end })
    }

    pub fn to_vec(&self) -> Vec<Port> {
        (self.start..=self.end)
            .map(|p| Port(p))
            .collect()
    }
}

/// Port selection mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSelectionMode {
    /// Default mode - scan specified ports
    Normal,
    /// Fast scan - top 100 ports only (-F)
    Fast,
    /// Sequential - don't randomize order (-r)
    Sequential,
}

/// Port specification configuration
#[derive(Debug, Clone)]
pub struct PortSpec {
    pub ports: Vec<Port>,
    pub protocol_ports: HashMap<PortProtocol, Vec<Port>>,
    pub mode: PortSelectionMode,
    pub randomize: bool,
}

impl Default for PortSpec {
    fn default() -> Self {
        Self {
            ports: Vec::new(),
            protocol_ports: HashMap::new(),
            mode: PortSelectionMode::Normal,
            randomize: true,
        }
    }
}

impl PortSpec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create fast scan spec (-F flag)
    pub fn fast() -> Self {
        Self {
            ports: PortParser::top_100_ports(),
            protocol_ports: HashMap::new(),
            mode: PortSelectionMode::Fast,
            randomize: true,
        }
    }

    /// Create sequential scan spec (-r flag)
    pub fn sequential(ports: Vec<Port>) -> Self {
        Self {
            ports,
            protocol_ports: HashMap::new(),
            mode: PortSelectionMode::Sequential,
            randomize: false,
        }
    }

    /// Get all ports (combining protocol-specific and general)
    pub fn all_ports(&self) -> Vec<Port> {
        let mut all = self.ports.clone();
        
        for ports in self.protocol_ports.values() {
            all.extend(ports.clone());
        }
        
        all.sort_by_key(|p| p.value());
        all.dedup();
        all
    }

    /// Get ports for specific protocol
    pub fn ports_for_protocol(&self, protocol: PortProtocol) -> Vec<Port> {
        self.protocol_ports
            .get(&protocol)
            .cloned()
            .unwrap_or_default()
    }
}

pub struct PortParser;

impl PortParser {
    /// Parse port specification into a list of ports
    /// Supports: 
    /// - Single ports: 80
    /// - Ranges: 1-1000
    /// - Comma-separated: 80,443,8080
    /// - Presets: common, top100, top1000
    /// - Protocol-specific: T:80,443 U:53,161 S:22
    pub fn parse(ports: &str) -> Result<Vec<Port>> {
        // Check for preset port lists
        if ports.eq_ignore_ascii_case("common") {
            return Ok(Self::common_ports());
        } else if ports.eq_ignore_ascii_case("top100") {
            return Ok(Self::top_100_ports());
        } else if ports.eq_ignore_ascii_case("top1000") {
            return Ok(Self::top_1000_ports());
        }

        let mut result = Vec::new();

        for part in ports.split(',') {
            let part = part.trim();
            
            if part.contains('-') {
                // Range
                let range = Self::parse_range(part)?;
                result.extend(range.to_vec());
            } else {
                // Single port
                let port: u16 = part
                    .parse()
                    .map_err(|_| anyhow!("Invalid port number: {}", part))?;
                result.push(Port::new(port)?);
            }
        }

        // Remove duplicates and sort
        result.sort_by_key(|p| p.value());
        result.dedup();

        if result.is_empty() {
            return Err(anyhow!("No valid ports specified"));
        }

        Ok(result)
    }

    /// Parse protocol-specific port specification (e.g., "T:80,443 U:53,161")
    pub fn parse_protocol_spec(spec: &str) -> Result<PortSpec> {
        let mut port_spec = PortSpec::new();
        
        // Split by whitespace to get protocol groups
        for group in spec.split_whitespace() {
            if let Some(colon_pos) = group.find(':') {
                // Protocol-specific format: "T:80,443"
                let protocol_char = group.chars().next().unwrap();
                let protocol = PortProtocol::from_char(protocol_char)
                    .ok_or_else(|| anyhow!("Invalid protocol: {}", protocol_char))?;
                
                let ports_str = &group[colon_pos + 1..];
                let ports = Self::parse(ports_str)?;
                
                port_spec.protocol_ports.insert(protocol, ports);
            } else {
                // No protocol specified, add to general ports
                let ports = Self::parse(group)?;
                port_spec.ports.extend(ports);
            }
        }

        if port_spec.ports.is_empty() && port_spec.protocol_ports.is_empty() {
            return Err(anyhow!("No valid ports specified"));
        }

        Ok(port_spec)
    }

    /// Filter ports by popularity ratio (--port-ratio)
    /// ratio: 0.0 to 1.0, where 1.0 = only most popular, 0.0 = all
    pub fn filter_by_ratio(ratio: f32) -> Result<Vec<Port>> {
        if ratio < 0.0 || ratio > 1.0 {
            return Err(anyhow!("Port ratio must be between 0.0 and 1.0"));
        }

        // Use popularity-based filtering
        // Higher ratio = fewer ports (more selective)
        let port_count = if ratio >= 0.9 {
            10  // Top 10 most popular
        } else if ratio >= 0.8 {
            50  // Top 50
        } else if ratio >= 0.7 {
            100 // Top 100
        } else if ratio >= 0.5 {
            500 // Top 500
        } else {
            1000 // Top 1000 (default)
        };

        let all_ports = Self::top_1000_ports();
        Ok(all_ports.into_iter().take(port_count).collect())
    }

    fn parse_range(range: &str) -> Result<PortRange> {
        let parts: Vec<&str> = range.split('-').collect();
        
        if parts.len() != 2 {
            return Err(anyhow!("Invalid port range: {}", range));
        }

        let start: u16 = parts[0]
            .trim()
            .parse()
            .map_err(|_| anyhow!("Invalid start port: {}", parts[0]))?;
        
        let end: u16 = parts[1]
            .trim()
            .parse()
            .map_err(|_| anyhow!("Invalid end port: {}", parts[1]))?;

        PortRange::new(start, end)
    }

    /// Common ports (most frequently used services)
    pub fn common_ports() -> Vec<Port> {
        vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
            1723, 3306, 3389, 5900, 8080, 8443
        ]
        .into_iter()
        .map(|p| Port(p))
        .collect()
    }

    /// Top 100 most common ports (-F flag)
    pub fn top_100_ports() -> Vec<Port> {
        vec![
            7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 
            113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 
            513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 
            1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 
            2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 
            5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 
            6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 
            32768, 49152, 49153, 49154, 49155, 49156, 49157
        ]
        .into_iter()
        .map(|p| Port(p))
        .collect()
    }

    /// Top 1000 most common ports (Nmap default)
    pub fn top_1000_ports() -> Vec<Port> {
        // For brevity, using ranges that cover most common ports
        let mut ports = Vec::new();
        
        // Well-known ports (1-1023)
        for p in 1..=1023 {
            ports.push(Port(p));
        }
        
        // Common high ports
        for p in &[1433, 1521, 1723, 3306, 3389, 5432, 5900, 5901, 5902, 6379, 
                   8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 10000,
                   27017, 27018, 27019, 50000] {
            ports.push(Port(*p));
        }
        
        ports.sort_by_key(|p| p.value());
        ports.dedup();
        ports
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_port() {
        let result = PortParser::parse("80").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value(), 80);
    }

    #[test]
    fn test_parse_range() {
        let result = PortParser::parse("1-5").unwrap();
        assert_eq!(result.len(), 5);
        assert_eq!(result[0].value(), 1);
        assert_eq!(result[4].value(), 5);
    }

    #[test]
    fn test_parse_mixed() {
        let result = PortParser::parse("80,443,8000-8002").unwrap();
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_parse_duplicates() {
        let result = PortParser::parse("80,80,443").unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_protocol_from_char() {
        assert_eq!(PortProtocol::from_char('T'), Some(PortProtocol::Tcp));
        assert_eq!(PortProtocol::from_char('t'), Some(PortProtocol::Tcp));
        assert_eq!(PortProtocol::from_char('U'), Some(PortProtocol::Udp));
        assert_eq!(PortProtocol::from_char('S'), Some(PortProtocol::Sctp));
        assert_eq!(PortProtocol::from_char('X'), None);
    }

    #[test]
    fn test_parse_protocol_spec() {
        let spec = PortParser::parse_protocol_spec("T:80,443 U:53").unwrap();
        
        let tcp_ports = spec.ports_for_protocol(PortProtocol::Tcp);
        assert_eq!(tcp_ports.len(), 2);
        assert_eq!(tcp_ports[0].value(), 80);
        assert_eq!(tcp_ports[1].value(), 443);
        
        let udp_ports = spec.ports_for_protocol(PortProtocol::Udp);
        assert_eq!(udp_ports.len(), 1);
        assert_eq!(udp_ports[0].value(), 53);
    }

    #[test]
    fn test_parse_protocol_spec_mixed() {
        let spec = PortParser::parse_protocol_spec("T:80 22,23 U:53,161").unwrap();
        
        // Should have general ports (22, 23)
        assert!(spec.ports.len() >= 2);
        
        // And protocol-specific ports
        assert!(!spec.ports_for_protocol(PortProtocol::Tcp).is_empty());
        assert!(!spec.ports_for_protocol(PortProtocol::Udp).is_empty());
    }

    #[test]
    fn test_port_spec_fast() {
        let spec = PortSpec::fast();
        assert_eq!(spec.mode, PortSelectionMode::Fast);
        assert_eq!(spec.ports.len(), 100);
        assert!(spec.randomize);
    }

    #[test]
    fn test_port_spec_sequential() {
        let ports = vec![Port(80), Port(443)];
        let spec = PortSpec::sequential(ports);
        assert_eq!(spec.mode, PortSelectionMode::Sequential);
        assert!(!spec.randomize);
    }

    #[test]
    fn test_filter_by_ratio() {
        let high = PortParser::filter_by_ratio(0.9).unwrap();
        let low = PortParser::filter_by_ratio(0.5).unwrap();
        
        assert!(high.len() < low.len());
        assert!(high.len() > 0);
    }

    #[test]
    fn test_filter_by_ratio_invalid() {
        assert!(PortParser::filter_by_ratio(1.5).is_err());
        assert!(PortParser::filter_by_ratio(-0.1).is_err());
    }

    #[test]
    fn test_port_spec_all_ports() {
        let mut spec = PortSpec::new();
        spec.ports = vec![Port(80), Port(443)];
        spec.protocol_ports.insert(
            PortProtocol::Udp,
            vec![Port(53), Port(80)], // 80 duplicated
        );
        
        let all = spec.all_ports();
        assert_eq!(all.len(), 3); // 80, 443, 53 (deduplicated)
    }

    #[test]
    fn test_protocol_port_creation() {
        let pp = ProtocolPort::new(80, PortProtocol::Tcp).unwrap();
        assert_eq!(pp.port.value(), 80);
        assert_eq!(pp.protocol, PortProtocol::Tcp);
    }
}

