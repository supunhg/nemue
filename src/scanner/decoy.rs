use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr};

/// Position of real source in decoy list
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealSourcePosition {
    /// Place at specific index
    Index(usize),
    /// Place randomly (ME in random position)
    Random,
    /// Place at beginning
    First,
    /// Place at end
    Last,
}

impl RealSourcePosition {
    /// Calculate actual index for given decoy count
    pub fn calculate_index(&self, decoy_count: usize, real_index: usize) -> usize {
        match self {
            RealSourcePosition::Index(idx) => *idx,
            RealSourcePosition::Random => real_index,
            RealSourcePosition::First => 0,
            RealSourcePosition::Last => decoy_count,
        }
    }
}

/// Decoy scanning configuration
#[derive(Debug, Clone)]
pub struct DecoyConfig {
    /// List of decoy IP addresses
    pub decoys: Vec<IpAddr>,
    /// Position of real source in the list
    pub real_position: RealSourcePosition,
    /// Whether to randomize decoy order
    pub randomize: bool,
}

impl DecoyConfig {
    /// Create new decoy config with specified decoys
    pub fn new(decoys: Vec<IpAddr>) -> Self {
        Self {
            decoys,
            real_position: RealSourcePosition::Random,
            randomize: true,
        }
    }

    /// Create with random decoys
    pub fn with_random_decoys(count: usize) -> Self {
        let decoys = Self::generate_random_decoys(count);
        Self::new(decoys)
    }

    /// Parse nmap-style decoy specification
    /// Format: "decoy1,decoy2,ME,decoy3" or "RND:10" for 10 random decoys
    pub fn parse(spec: &str) -> Result<Self> {
        if spec.is_empty() {
            return Err(anyhow!("Empty decoy specification"));
        }

        // Check for RND:n format (random decoys)
        if spec.starts_with("RND:") || spec.starts_with("rnd:") {
            let count_str = &spec[4..];
            let count: usize = count_str
                .parse()
                .map_err(|_| anyhow!("Invalid random decoy count: {}", count_str))?;
            
            if count == 0 || count > 1000 {
                return Err(anyhow!("Random decoy count must be 1-1000"));
            }
            
            return Ok(Self::with_random_decoys(count));
        }

        // Parse comma-separated list
        let parts: Vec<&str> = spec.split(',').map(|s| s.trim()).collect();
        let mut decoys = Vec::new();
        let mut real_position = RealSourcePosition::Random;
        let mut me_index = None;

        for (i, part) in parts.iter().enumerate() {
            if part.eq_ignore_ascii_case("ME") {
                // Mark position of real source
                me_index = Some(i);
            } else {
                // Parse IP address
                let ip: IpAddr = part
                    .parse()
                    .map_err(|_| anyhow!("Invalid decoy IP address: {}", part))?;
                decoys.push(ip);
            }
        }

        // Set real source position
        if let Some(idx) = me_index {
            real_position = RealSourcePosition::Index(idx);
        }

        if decoys.is_empty() {
            return Err(anyhow!("No valid decoy addresses specified"));
        }

        Ok(Self {
            decoys,
            real_position,
            randomize: false, // Don't randomize if explicit order given
        })
    }

    /// Generate random decoy IP addresses
    fn generate_random_decoys(count: usize) -> Vec<IpAddr> {
        let mut decoys = Vec::with_capacity(count);
        
        for _ in 0..count {
            // Generate random private IP to avoid issues
            // Using 192.168.x.x range
            let octets = [
                192,
                168,
                rand::random::<u8>(),
                rand::random::<u8>(),
            ];
            decoys.push(IpAddr::V4(Ipv4Addr::from(octets)));
        }
        
        decoys
    }

    /// Set real source position
    pub fn with_real_position(mut self, position: RealSourcePosition) -> Self {
        self.real_position = position;
        self
    }

    /// Enable/disable randomization
    pub fn with_randomize(mut self, randomize: bool) -> Self {
        self.randomize = randomize;
        self
    }

    /// Get total sources count (decoys + real)
    pub fn total_sources(&self) -> usize {
        self.decoys.len() + 1 // +1 for real source
    }
}

/// Decoy scanner for performing scans with IP spoofing/decoys
pub struct DecoyScanner {
    config: DecoyConfig,
    real_source: IpAddr,
}

impl DecoyScanner {
    /// Create new decoy scanner
    pub fn new(config: DecoyConfig, real_source: IpAddr) -> Self {
        Self {
            config,
            real_source,
        }
    }

    /// Create scanner with parsed decoy specification
    pub fn from_spec(spec: &str, real_source: IpAddr) -> Result<Self> {
        let config = DecoyConfig::parse(spec)?;
        Ok(Self::new(config, real_source))
    }

    /// Get ordered list of source IPs for scanning (including real source)
    pub fn get_scan_sources(&self) -> Vec<IpAddr> {
        let mut sources = self.config.decoys.clone();
        
        // Determine where to insert real source
        let real_index = if self.config.randomize {
            rand::random::<usize>() % (sources.len() + 1)
        } else {
            match self.config.real_position {
                RealSourcePosition::Random => rand::random::<usize>() % (sources.len() + 1),
                RealSourcePosition::Index(idx) => idx.min(sources.len()),
                RealSourcePosition::First => 0,
                RealSourcePosition::Last => sources.len(),
            }
        };

        // Insert real source at calculated position
        sources.insert(real_index, self.real_source);

        // Randomize other positions if requested
        if self.config.randomize {
            // Keep real source in place, shuffle others
            let real = sources.remove(real_index);
            self.shuffle_ips(&mut sources);
            sources.insert(real_index, real);
        }

        sources
    }

    /// Get only decoy addresses (excluding real source)
    pub fn get_decoys(&self) -> &[IpAddr] {
        &self.config.decoys
    }

    /// Get real source IP
    pub fn real_source(&self) -> IpAddr {
        self.real_source
    }

    /// Perform scan with decoys (returns which sources to use for each probe)
    pub fn plan_probe_sources(&self, probe_count: usize) -> Vec<IpAddr> {
        let sources = self.get_scan_sources();
        let mut probe_sources = Vec::with_capacity(probe_count);

        // Round-robin through sources
        for i in 0..probe_count {
            let source_idx = i % sources.len();
            probe_sources.push(sources[source_idx]);
        }

        probe_sources
    }

    /// Shuffle IP addresses (Fisher-Yates)
    fn shuffle_ips(&self, ips: &mut [IpAddr]) {
        for i in (1..ips.len()).rev() {
            let j = rand::random::<usize>() % (i + 1);
            ips.swap(i, j);
        }
    }

    /// Get configuration
    pub fn config(&self) -> &DecoyConfig {
        &self.config
    }

    /// Get number of decoys
    pub fn decoy_count(&self) -> usize {
        self.config.decoys.len()
    }

    /// Get total number of sources (decoys + real)
    pub fn total_sources(&self) -> usize {
        self.config.total_sources()
    }
}

/// Decoy list builder for fluent API
pub struct DecoyListBuilder {
    decoys: Vec<IpAddr>,
    real_position: RealSourcePosition,
    randomize: bool,
}

impl DecoyListBuilder {
    /// Create new builder
    pub fn new() -> Self {
        Self {
            decoys: Vec::new(),
            real_position: RealSourcePosition::Random,
            randomize: true,
        }
    }

    /// Add a decoy IP
    pub fn add_decoy(mut self, ip: IpAddr) -> Self {
        self.decoys.push(ip);
        self
    }

    /// Add multiple decoys
    pub fn add_decoys(mut self, ips: Vec<IpAddr>) -> Self {
        self.decoys.extend(ips);
        self
    }

    /// Add random decoys
    pub fn add_random(mut self, count: usize) -> Self {
        let random = DecoyConfig::generate_random_decoys(count);
        self.decoys.extend(random);
        self
    }

    /// Set real source position
    pub fn real_at(mut self, position: RealSourcePosition) -> Self {
        self.real_position = position;
        self
    }

    /// Enable randomization
    pub fn randomized(mut self) -> Self {
        self.randomize = true;
        self
    }

    /// Disable randomization
    pub fn ordered(mut self) -> Self {
        self.randomize = false;
        self
    }

    /// Build decoy configuration
    pub fn build(self) -> DecoyConfig {
        DecoyConfig {
            decoys: self.decoys,
            real_position: self.real_position,
            randomize: self.randomize,
        }
    }
}

impl Default for DecoyListBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn test_decoy_config_new() {
        let decoys = vec![test_ip(1, 2, 3, 4), test_ip(5, 6, 7, 8)];
        let config = DecoyConfig::new(decoys.clone());
        
        assert_eq!(config.decoys.len(), 2);
        assert_eq!(config.real_position, RealSourcePosition::Random);
        assert!(config.randomize);
    }

    #[test]
    fn test_decoy_config_with_random() {
        let config = DecoyConfig::with_random_decoys(5);
        assert_eq!(config.decoys.len(), 5);
    }

    #[test]
    fn test_decoy_config_parse_list() {
        let config = DecoyConfig::parse("192.168.1.1,192.168.1.2,ME,192.168.1.3").unwrap();
        
        assert_eq!(config.decoys.len(), 3);
        assert_eq!(config.real_position, RealSourcePosition::Index(2));
        assert!(!config.randomize); // Explicit order
    }

    #[test]
    fn test_decoy_config_parse_random() {
        let config = DecoyConfig::parse("RND:10").unwrap();
        assert_eq!(config.decoys.len(), 10);
    }

    #[test]
    fn test_decoy_config_parse_invalid_random() {
        assert!(DecoyConfig::parse("RND:0").is_err());
        assert!(DecoyConfig::parse("RND:2000").is_err());
        assert!(DecoyConfig::parse("RND:abc").is_err());
    }

    #[test]
    fn test_decoy_config_parse_invalid_ip() {
        assert!(DecoyConfig::parse("192.168.1.1,not.an.ip,192.168.1.2").is_err());
    }

    #[test]
    fn test_decoy_config_parse_empty() {
        assert!(DecoyConfig::parse("").is_err());
    }

    #[test]
    fn test_decoy_scanner_new() {
        let decoys = vec![test_ip(1, 2, 3, 4)];
        let config = DecoyConfig::new(decoys);
        let scanner = DecoyScanner::new(config, test_ip(10, 0, 0, 1));
        
        assert_eq!(scanner.real_source(), test_ip(10, 0, 0, 1));
        assert_eq!(scanner.decoy_count(), 1);
        assert_eq!(scanner.total_sources(), 2);
    }

    #[test]
    fn test_decoy_scanner_from_spec() {
        let scanner = DecoyScanner::from_spec(
            "192.168.1.1,ME,192.168.1.2",
            test_ip(10, 0, 0, 1),
        ).unwrap();
        
        assert_eq!(scanner.decoy_count(), 2);
        assert_eq!(scanner.total_sources(), 3);
    }

    #[test]
    fn test_decoy_scanner_get_sources() {
        let decoys = vec![test_ip(1, 1, 1, 1), test_ip(2, 2, 2, 2)];
        let config = DecoyConfig::new(decoys).with_randomize(false);
        let scanner = DecoyScanner::new(config, test_ip(10, 0, 0, 1));
        
        let sources = scanner.get_scan_sources();
        assert_eq!(sources.len(), 3);
        
        // Should contain all IPs
        assert!(sources.contains(&test_ip(1, 1, 1, 1)));
        assert!(sources.contains(&test_ip(2, 2, 2, 2)));
        assert!(sources.contains(&test_ip(10, 0, 0, 1)));
    }

    #[test]
    fn test_decoy_scanner_plan_probes() {
        let decoys = vec![test_ip(1, 1, 1, 1), test_ip(2, 2, 2, 2)];
        let config = DecoyConfig::new(decoys);
        let scanner = DecoyScanner::new(config, test_ip(10, 0, 0, 1));
        
        let probe_sources = scanner.plan_probe_sources(6);
        assert_eq!(probe_sources.len(), 6);
        
        // Should round-robin through 3 sources
        assert_eq!(probe_sources[0], probe_sources[3]);
    }

    #[test]
    fn test_real_source_position_first() {
        let decoys = vec![test_ip(1, 1, 1, 1), test_ip(2, 2, 2, 2)];
        let config = DecoyConfig::new(decoys)
            .with_real_position(RealSourcePosition::First)
            .with_randomize(false);
        let scanner = DecoyScanner::new(config, test_ip(10, 0, 0, 1));
        
        let sources = scanner.get_scan_sources();
        assert_eq!(sources[0], test_ip(10, 0, 0, 1));
    }

    #[test]
    fn test_real_source_position_last() {
        let decoys = vec![test_ip(1, 1, 1, 1), test_ip(2, 2, 2, 2)];
        let config = DecoyConfig::new(decoys)
            .with_real_position(RealSourcePosition::Last)
            .with_randomize(false);
        let scanner = DecoyScanner::new(config, test_ip(10, 0, 0, 1));
        
        let sources = scanner.get_scan_sources();
        assert_eq!(sources[2], test_ip(10, 0, 0, 1)); // Last position
    }

    #[test]
    fn test_real_source_position_index() {
        let decoys = vec![test_ip(1, 1, 1, 1), test_ip(2, 2, 2, 2)];
        let config = DecoyConfig::new(decoys)
            .with_real_position(RealSourcePosition::Index(1))
            .with_randomize(false);
        let scanner = DecoyScanner::new(config, test_ip(10, 0, 0, 1));
        
        let sources = scanner.get_scan_sources();
        assert_eq!(sources[1], test_ip(10, 0, 0, 1)); // Middle position
    }

    #[test]
    fn test_decoy_list_builder() {
        let config = DecoyListBuilder::new()
            .add_decoy(test_ip(1, 1, 1, 1))
            .add_decoy(test_ip(2, 2, 2, 2))
            .real_at(RealSourcePosition::First)
            .ordered()
            .build();
        
        assert_eq!(config.decoys.len(), 2);
        assert_eq!(config.real_position, RealSourcePosition::First);
        assert!(!config.randomize);
    }

    #[test]
    fn test_decoy_list_builder_with_random() {
        let config = DecoyListBuilder::new()
            .add_random(5)
            .randomized()
            .build();
        
        assert_eq!(config.decoys.len(), 5);
        assert!(config.randomize);
    }

    #[test]
    fn test_decoy_total_sources() {
        let config = DecoyConfig::with_random_decoys(10);
        assert_eq!(config.total_sources(), 11); // 10 decoys + 1 real
    }
}
