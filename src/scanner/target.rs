use anyhow::{anyhow, Result};
use ipnetwork::IpNetwork;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use rand::Rng;

#[derive(Debug, Clone)]
pub struct Target {
    pub addr: IpAddr,
}

/// Configuration for target input parsing
#[derive(Debug, Clone)]
pub struct TargetConfig {
    /// Resolve all IP addresses from hostnames
    pub resolve_all: bool,
    /// Scan each IP only once (deduplicate)
    pub unique: bool,
    /// Excluded IPs or networks
    pub exclusions: HashSet<IpAddr>,
    /// Excluded networks (CIDR)
    pub excluded_networks: Vec<IpNetwork>,
}

impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            resolve_all: false,
            unique: true,
            exclusions: HashSet::new(),
            excluded_networks: Vec::new(),
        }
    }
}

impl TargetConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load exclusions from a file (nmap --excludefile)
    pub fn load_exclusions_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            
            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Parse as CIDR or single IP
            if trimmed.contains('/') {
                let network: IpNetwork = trimmed.parse()
                    .map_err(|_| anyhow!("Invalid CIDR in exclusion file: {}", trimmed))?;
                self.excluded_networks.push(network);
            } else {
                let ip: IpAddr = trimmed.parse()
                    .map_err(|_| anyhow!("Invalid IP in exclusion file: {}", trimmed))?;
                self.exclusions.insert(ip);
            }
        }

        Ok(())
    }

    /// Check if an IP is excluded
    pub fn is_excluded(&self, ip: &IpAddr) -> bool {
        // Check direct exclusions
        if self.exclusions.contains(ip) {
            return true;
        }

        // Check network exclusions
        for network in &self.excluded_networks {
            if network.contains(*ip) {
                return true;
            }
        }

        false
    }

    /// Add a single IP to exclusion list
    pub fn exclude_ip(&mut self, ip: IpAddr) {
        self.exclusions.insert(ip);
    }

    /// Add a network to exclusion list
    pub fn exclude_network(&mut self, network: IpNetwork) {
        self.excluded_networks.push(network);
    }
}

pub struct TargetParser;

impl TargetParser {
    /// Parse a target string into a list of IP addresses
    /// Supports:
    /// - Single IPs: 192.168.1.1
    /// - Hostnames/domains: example.com, scanme.nmap.org
    /// - CIDR notation: 192.168.1.0/24
    /// - Octet ranges: 192.168.0-255.1-254
    pub fn parse(target: &str) -> Result<Vec<IpAddr>> {
        if target.contains('/') {
            // CIDR notation
            Self::parse_cidr(target)
        } else if target.contains('-') && !target.contains("::") {
            // Octet ranges (not IPv6)
            Self::parse_octet_range(target)
        } else {
            // Try to parse as IP first
            if let Ok(ip) = target.parse::<IpAddr>() {
                return Ok(vec![ip]);
            }
            
            // If not an IP, try DNS resolution
            Self::resolve_hostname(target)
        }
    }

    /// Parse targets with config (applies filters)
    pub fn parse_with_config(target: &str, config: &TargetConfig) -> Result<Vec<IpAddr>> {
        let mut ips = Self::parse(target)?;

        // Apply exclusions
        ips.retain(|ip| !config.is_excluded(ip));

        // Apply uniqueness
        if config.unique {
            let unique: HashSet<_> = ips.into_iter().collect();
            ips = unique.into_iter().collect();
        }

        Ok(ips)
    }

    /// Load targets from file (nmap -iL)
    /// Supports multiple formats:
    /// - IP addresses (one per line)
    /// - CIDR notation
    /// - Octet ranges
    /// - Hostnames (if resolve_all enabled)
    /// - Comments (#) and blank lines
    /// - Space, tab, and newline delimited
    pub fn parse_from_file<P: AsRef<Path>>(path: P, config: &TargetConfig) -> Result<Vec<IpAddr>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut all_ips = Vec::new();

        for line in reader.lines() {
            let line = line?;
            
            // Split by whitespace (space, tab)
            for target in line.split_whitespace() {
                let trimmed = target.trim();
                
                // Skip comments and empty
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

                // Parse the target
                match Self::parse_with_config(trimmed, config) {
                    Ok(mut ips) => all_ips.append(&mut ips),
                    Err(e) => eprintln!("Warning: Failed to parse '{}': {}", trimmed, e),
                }
            }
        }

        // Apply uniqueness to entire result set if needed
        if config.unique {
            let unique: HashSet<_> = all_ips.into_iter().collect();
            all_ips = unique.into_iter().collect();
        }

        Ok(all_ips)
    }

    /// Generate random targets (nmap -iR)
    /// Skips private/reserved ranges by default
    pub fn generate_random(count: usize, skip_private: bool) -> Result<Vec<IpAddr>> {
        if count == 0 {
            return Ok(Vec::new());
        }

        if count > 1_000_000 {
            return Err(anyhow!("Random target count too large: {}. Maximum is 1,000,000", count));
        }

        let mut rng = rand::thread_rng();
        let mut ips = Vec::with_capacity(count);

        // Private/reserved ranges to skip
        let private_ranges = if skip_private {
            vec![
                "0.0.0.0/8",        // Current network
                "10.0.0.0/8",       // Private
                "127.0.0.0/8",      // Loopback
                "169.254.0.0/16",   // Link-local
                "172.16.0.0/12",    // Private
                "192.0.0.0/24",     // IETF Protocol Assignments
                "192.0.2.0/24",     // TEST-NET-1
                "192.168.0.0/16",   // Private
                "198.18.0.0/15",    // Benchmarking
                "198.51.100.0/24",  // TEST-NET-2
                "203.0.113.0/24",   // TEST-NET-3
                "224.0.0.0/4",      // Multicast
                "240.0.0.0/4",      // Reserved
                "255.255.255.255/32", // Broadcast
            ].iter()
            .map(|s| s.parse::<IpNetwork>().unwrap())
            .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        let mut attempts = 0;
        let max_attempts = count * 10; // Prevent infinite loops

        while ips.len() < count && attempts < max_attempts {
            attempts += 1;

            // Generate random IPv4 (more common than IPv6 for random scanning)
            let octets: [u8; 4] = [
                rng.gen(),
                rng.gen(),
                rng.gen(),
                rng.gen(),
            ];
            let ip = IpAddr::from(octets);

            // Skip if in private range
            if skip_private {
                let mut skip = false;
                for network in &private_ranges {
                    if network.contains(ip) {
                        skip = true;
                        break;
                    }
                }
                if skip {
                    continue;
                }
            }

            ips.push(ip);
        }

        if ips.len() < count {
            return Err(anyhow!(
                "Could not generate {} unique public IPs after {} attempts",
                count,
                max_attempts
            ));
        }

        Ok(ips)
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

    /// Parse octet range notation (e.g., 192.168.0-255.1-254)
    /// Resolve a hostname to IP address(es)
    fn resolve_hostname(hostname: &str) -> Result<Vec<IpAddr>> {
        // Add default port for resolution (doesn't matter which)
        let addr_str = format!("{}:0", hostname);
        
        let addrs: Vec<_> = addr_str
            .to_socket_addrs()
            .map_err(|e| anyhow!("Failed to resolve hostname '{}': {}", hostname, e))?
            .map(|socket_addr| socket_addr.ip())
            .collect();

        if addrs.is_empty() {
            return Err(anyhow!("No IP addresses found for hostname: {}", hostname));
        }

        Ok(addrs)
    }

    /// Parse octet range notation (e.g., 192.168.0-255.1-254)
    fn parse_octet_range(range: &str) -> Result<Vec<IpAddr>> {
        let parts: Vec<&str> = range.split('.').collect();
        if parts.len() != 4 {
            return Err(anyhow!("Invalid octet range format: {}", range));
        }

        // Parse each octet or range
        let mut octet_ranges: Vec<Vec<u8>> = Vec::new();
        for part in parts {
            if part.contains('-') {
                // Range: "0-255"
                let range_parts: Vec<&str> = part.split('-').collect();
                if range_parts.len() != 2 {
                    return Err(anyhow!("Invalid octet range: {}", part));
                }

                let start: u8 = range_parts[0].parse()
                    .map_err(|_| anyhow!("Invalid octet start: {}", range_parts[0]))?;
                let end: u8 = range_parts[1].parse()
                    .map_err(|_| anyhow!("Invalid octet end: {}", range_parts[1]))?;

                if start > end {
                    return Err(anyhow!("Invalid range: {} > {}", start, end));
                }

                octet_ranges.push((start..=end).collect());
            } else {
                // Single value
                let val: u8 = part.parse()
                    .map_err(|_| anyhow!("Invalid octet: {}", part))?;
                octet_ranges.push(vec![val]);
            }
        }

        // Calculate total combinations
        let total: usize = octet_ranges.iter()
            .map(|r| r.len())
            .product();

        if total > 65536 {
            return Err(anyhow!(
                "Octet range too large: {} addresses. Maximum is 65536",
                total
            ));
        }

        // Generate all combinations
        let mut ips = Vec::with_capacity(total);
        for o1 in &octet_ranges[0] {
            for o2 in &octet_ranges[1] {
                for o3 in &octet_ranges[2] {
                    for o4 in &octet_ranges[3] {
                        ips.push(IpAddr::from([*o1, *o2, *o3, *o4]));
                    }
                }
            }
        }

        Ok(ips)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_single_ip() {
        let result = TargetParser::parse("192.168.1.1").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "192.168.1.1");
    }

    #[test]
    fn test_parse_hostname() {
        // This test requires network access
        let result = TargetParser::parse("localhost");
        assert!(result.is_ok());
        let ips = result.unwrap();
        assert!(!ips.is_empty());
        // localhost should resolve to 127.0.0.1 or ::1
        assert!(ips.iter().any(|ip| ip.is_loopback()));
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

    #[test]
    fn test_parse_octet_range_single() {
        let result = TargetParser::parse("192.168.1.1-3").unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].to_string(), "192.168.1.1");
        assert_eq!(result[1].to_string(), "192.168.1.2");
        assert_eq!(result[2].to_string(), "192.168.1.3");
    }

    #[test]
    fn test_parse_octet_range_multiple() {
        let result = TargetParser::parse("192.168.1-2.1-2").unwrap();
        assert_eq!(result.len(), 4); // 2 * 2 = 4
        assert!(result.contains(&"192.168.1.1".parse().unwrap()));
        assert!(result.contains(&"192.168.1.2".parse().unwrap()));
        assert!(result.contains(&"192.168.2.1".parse().unwrap()));
        assert!(result.contains(&"192.168.2.2".parse().unwrap()));
    }

    #[test]
    fn test_octet_range_too_large() {
        let result = TargetParser::parse("0-255.0-255.0-255.0-255");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_target_config_default() {
        let config = TargetConfig::default();
        assert!(!config.resolve_all);
        assert!(config.unique);
        assert!(config.exclusions.is_empty());
    }

    #[test]
    fn test_exclusion_single_ip() {
        let mut config = TargetConfig::new();
        config.exclude_ip("192.168.1.1".parse().unwrap());
        
        assert!(config.is_excluded(&"192.168.1.1".parse().unwrap()));
        assert!(!config.is_excluded(&"192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_exclusion_network() {
        let mut config = TargetConfig::new();
        config.exclude_network("192.168.1.0/24".parse().unwrap());
        
        assert!(config.is_excluded(&"192.168.1.1".parse().unwrap()));
        assert!(config.is_excluded(&"192.168.1.255".parse().unwrap()));
        assert!(!config.is_excluded(&"192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn test_parse_with_config_exclusions() {
        let mut config = TargetConfig::new();
        config.exclude_ip("192.168.1.2".parse().unwrap());
        
        let result = TargetParser::parse_with_config("192.168.1.1-3", &config).unwrap();
        assert_eq!(result.len(), 2);
        assert!(!result.contains(&"192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_parse_from_file() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        writeln!(file, "192.168.1.1")?;
        writeln!(file, "# Comment line")?;
        writeln!(file, "")?;
        writeln!(file, "192.168.1.2 192.168.1.3")?;
        writeln!(file, "192.168.1.4-5")?;
        
        let config = TargetConfig::default();
        let result = TargetParser::parse_from_file(file.path(), &config)?;
        
        assert_eq!(result.len(), 5);
        assert!(result.contains(&"192.168.1.1".parse().unwrap()));
        assert!(result.contains(&"192.168.1.5".parse().unwrap()));
        
        Ok(())
    }

    #[test]
    fn test_exclusion_file() -> Result<()> {
        let mut file = NamedTempFile::new()?;
        writeln!(file, "192.168.1.1")?;
        writeln!(file, "# Exclude this network")?;
        writeln!(file, "10.0.0.0/8")?;
        
        let mut config = TargetConfig::new();
        config.load_exclusions_from_file(file.path())?;
        
        assert!(config.is_excluded(&"192.168.1.1".parse().unwrap()));
        assert!(config.is_excluded(&"10.0.0.1".parse().unwrap()));
        assert!(config.is_excluded(&"10.255.255.255".parse().unwrap()));
        
        Ok(())
    }

    #[test]
    fn test_generate_random() {
        let result = TargetParser::generate_random(10, false).unwrap();
        assert_eq!(result.len(), 10);
        
        // Should all be valid IPs
        for ip in result {
            assert!(ip.is_ipv4());
        }
    }

    #[test]
    fn test_generate_random_skip_private() {
        let result = TargetParser::generate_random(100, true).unwrap();
        assert_eq!(result.len(), 100);
        
        // None should be in private ranges
        for ip in result {
            let ip_str = ip.to_string();
            assert!(!ip_str.starts_with("192.168."));
            assert!(!ip_str.starts_with("10."));
            assert!(!ip_str.starts_with("127."));
        }
    }

    #[test]
    fn test_random_count_too_large() {
        let result = TargetParser::generate_random(2_000_000, false);
        assert!(result.is_err());
    }
}
