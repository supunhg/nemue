use anyhow::{anyhow, Result};

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

pub struct PortParser;

impl PortParser {
    /// Parse port specification into a list of ports
    /// Supports: single ports (80), ranges (1-1000), and comma-separated (80,443,8080)
    pub fn parse(ports: &str) -> Result<Vec<Port>> {
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
}
