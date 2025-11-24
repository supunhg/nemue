use anyhow::{anyhow, Result};
use ipnetwork::IpNetwork;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Target {
    pub addr: IpAddr,
}

pub struct TargetParser;

impl TargetParser {
    /// Parse a target string into a list of IP addresses
    /// Supports single IPs (192.168.1.1) and CIDR notation (192.168.1.0/24)
    pub fn parse(target: &str) -> Result<Vec<IpAddr>> {
        if target.contains('/') {
            // CIDR notation
            Self::parse_cidr(target)
        } else {
            // Single IP
            let ip: IpAddr = target
                .parse()
                .map_err(|_| anyhow!("Invalid IP address: {}", target))?;
            Ok(vec![ip])
        }
    }

    fn parse_cidr(cidr: &str) -> Result<Vec<IpAddr>> {
        let network: IpNetwork = cidr
            .parse()
            .map_err(|_| anyhow!("Invalid CIDR notation: {}", cidr))?;

        let ips: Vec<IpAddr> = network.iter().collect();

        if ips.len() > 65536 {
            return Err(anyhow!(
                "CIDR range too large: {} addresses. Maximum is 65536",
                ips.len()
            ));
        }

        Ok(ips)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_ip() {
        let result = TargetParser::parse("192.168.1.1").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "192.168.1.1");
    }

    #[test]
    fn test_parse_cidr() {
        let result = TargetParser::parse("192.168.1.0/30").unwrap();
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_invalid_ip() {
        let result = TargetParser::parse("invalid");
        assert!(result.is_err());
    }
}
