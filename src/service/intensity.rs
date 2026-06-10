use anyhow::{anyhow, Result};
use regex::bytes::Regex;
use std::fmt;

/// Service detection intensity levels (0-9) matching nmap --version-intensity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IntensityLevel(u8);

impl IntensityLevel {
    /// Create new intensity level (0-9)
    pub fn new(level: u8) -> Result<Self> {
        if level > 9 {
            return Err(anyhow!("Intensity level must be 0-9, got {}", level));
        }
        Ok(Self(level))
    }

    /// Light probing (nmap --version-light = intensity 2)
    pub fn light() -> Self {
        Self(2)
    }

    /// Default intensity (nmap default = intensity 7)
    pub fn default() -> Self {
        Self(7)
    }

    /// All probes (nmap --version-all = intensity 9)
    pub fn all() -> Self {
        Self(9)
    }

    /// Get numeric value
    pub fn value(&self) -> u8 {
        self.0
    }

    /// Check if probe should be used at this intensity
    pub fn should_use_probe(&self, probe_intensity: u8) -> bool {
        probe_intensity <= self.0
    }

    /// Get description of intensity level
    pub fn description(&self) -> &str {
        match self.0 {
            0 => "No version detection",
            1 => "Very light (fastest)",
            2 => "Light (--version-light)",
            3 => "Light-medium",
            4 => "Medium-low",
            5 => "Medium",
            6 => "Medium-high",
            7 => "Default intensity",
            8 => "High",
            9 => "All probes (--version-all)",
            _ => "Unknown",
        }
    }

    /// Estimated number of probes at this level
    pub fn estimated_probes(&self) -> usize {
        match self.0 {
            0 => 0,
            1 => 1,
            2 => 3, // --version-light
            3 => 5,
            4 => 8,
            5 => 12,
            6 => 18,
            7 => 25, // default
            8 => 40,
            9 => 100, // --version-all
            _ => 0,
        }
    }

    /// Estimated time impact (relative to default)
    pub fn time_multiplier(&self) -> f32 {
        match self.0 {
            0 => 0.0,
            1 => 0.1,
            2 => 0.3, // light
            3 => 0.5,
            4 => 0.7,
            5 => 0.85,
            6 => 0.95,
            7 => 1.0, // default baseline
            8 => 1.5,
            9 => 4.0, // all probes - significantly slower
            _ => 1.0,
        }
    }
}

impl Default for IntensityLevel {
    fn default() -> Self {
        Self::default()
    }
}

impl fmt::Display for IntensityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.0, self.description())
    }
}

impl From<u8> for IntensityLevel {
    fn from(level: u8) -> Self {
        Self::new(level).unwrap_or_else(|_| Self::default())
    }
}

/// Service probe with intensity rating
#[derive(Debug, Clone)]
pub struct ServiceProbe {
    pub name: String,
    pub protocol: ProbeProtocol,
    pub probe_data: Vec<u8>,
    pub intensity: u8,
    pub rarity: ProbeRarity,
    pub fallback: bool,
    pub matches: Vec<MatchPattern>,
    pub softmatches: Vec<MatchPattern>,
    pub fallback_name: Option<String>,
}

/// A match pattern for service/version detection
#[derive(Debug, Clone)]
pub struct MatchPattern {
    pub service: String,
    pub pattern_str: String,
    pub version_info: VersionInfo,
    pub is_softmatch: bool,
    pub case_insensitive: bool,
}

/// Version information extracted from a match
#[derive(Debug, Clone, Default)]
pub struct VersionInfo {
    pub product: Option<String>,
    pub version_template: Option<String>,
    pub info: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub cpe: Option<String>,
    pub device_type: Option<String>,
}

impl MatchPattern {
    /// Try to match against response data, return captures if matched
    pub fn try_match(&self, data: &[u8]) -> Option<Vec<String>> {
        let pattern = if self.case_insensitive {
            format!("(?i){}", self.pattern_str)
        } else {
            self.pattern_str.clone()
        };

        let re = match Regex::new(&pattern) {
            Ok(r) => r,
            Err(_) => return None,
        };

        let caps = re.captures(data)?;
        let mut groups = Vec::new();
        for i in 0..caps.len() {
            groups.push(
                caps.get(i)
                    .map(|m| String::from_utf8_lossy(m.as_bytes()).to_string())
                    .unwrap_or_default(),
            );
        }
        Some(groups)
    }

    /// Substitute version template with captured groups
    pub fn substitute_template(template: &str, captures: &[String]) -> String {
        let mut result = template.to_string();
        for (i, cap) in captures.iter().enumerate() {
            result = result.replace(&format!("${}", i), cap);
        }
        result
    }
}

/// Probe protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeProtocol {
    Tcp,
    Udp,
}

/// How common/rare the service is
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeRarity {
    /// Very common services (HTTP, SSH, FTP) - intensity 1-2
    VeryCommon,
    /// Common services (SMTP, DNS, MySQL) - intensity 3-4
    Common,
    /// Moderately common (PostgreSQL, Redis) - intensity 5-6
    Moderate,
    /// Uncommon services - intensity 7-8
    Uncommon,
    /// Rare/specialized services - intensity 9
    Rare,
}

impl ProbeRarity {
    /// Get minimum intensity level for this rarity
    pub fn min_intensity(&self) -> u8 {
        match self {
            ProbeRarity::VeryCommon => 1,
            ProbeRarity::Common => 3,
            ProbeRarity::Moderate => 5,
            ProbeRarity::Uncommon => 7,
            ProbeRarity::Rare => 9,
        }
    }
}

impl ServiceProbe {
    pub fn new(name: String, protocol: ProbeProtocol) -> Self {
        Self {
            name,
            protocol,
            probe_data: Vec::new(),
            intensity: 7, // default
            rarity: ProbeRarity::Moderate,
            fallback: false,
            matches: Vec::new(),
            softmatches: Vec::new(),
            fallback_name: None,
        }
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.probe_data = data;
        self
    }

    pub fn with_intensity(mut self, intensity: u8) -> Self {
        self.intensity = intensity.min(9);
        self
    }

    pub fn with_rarity(mut self, rarity: ProbeRarity) -> Self {
        self.rarity = rarity;
        // Auto-adjust intensity based on rarity
        self.intensity = rarity.min_intensity();
        self
    }

    pub fn as_fallback(mut self) -> Self {
        self.fallback = true;
        self
    }

    pub fn with_fallback_name(mut self, name: &str) -> Self {
        self.fallback_name = Some(name.to_string());
        self
    }

    pub fn with_match(mut self, m: MatchPattern) -> Self {
        self.matches.push(m);
        self
    }

    pub fn with_softmatch(mut self, m: MatchPattern) -> Self {
        self.softmatches.push(m);
        self
    }

    /// Check if this probe should be used at given intensity level
    pub fn should_use(&self, level: &IntensityLevel) -> bool {
        self.intensity <= level.value()
    }
}

/// Service detection configuration
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    pub intensity: IntensityLevel,
    pub all_ports: bool,
    pub trace: bool,
    pub probe_timeout_ms: u64,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            intensity: IntensityLevel::default(),
            all_ports: false,
            trace: false,
            probe_timeout_ms: 5000,
        }
    }
}

impl DetectionConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set to light mode (--version-light)
    pub fn light() -> Self {
        Self {
            intensity: IntensityLevel::light(),
            ..Default::default()
        }
    }

    /// Set to all probes (--version-all)
    pub fn all() -> Self {
        Self {
            intensity: IntensityLevel::all(),
            all_ports: true,
            ..Default::default()
        }
    }

    pub fn with_intensity(mut self, level: u8) -> Result<Self> {
        self.intensity = IntensityLevel::new(level)?;
        Ok(self)
    }

    pub fn with_all_ports(mut self) -> Self {
        self.all_ports = true;
        self
    }

    pub fn with_trace(mut self) -> Self {
        self.trace = true;
        self
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.probe_timeout_ms = timeout_ms;
        self
    }
}

/// Probe database with intensity-based filtering
pub struct ProbeDatabase {
    probes: Vec<ServiceProbe>,
}

impl ProbeDatabase {
    pub fn new() -> Self {
        let mut db = Self { probes: Vec::new() };
        db.load_default_probes();
        db
    }

    /// Load default probe set
    fn load_default_probes(&mut self) {
        // Very common services (intensity 1-2)
        self.add_probe(
            ServiceProbe::new("HTTP".to_string(), ProbeProtocol::Tcp)
                .with_data(b"GET / HTTP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::VeryCommon),
        );

        self.add_probe(
            ServiceProbe::new("SSH".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new()) // Banner grab only
                .with_rarity(ProbeRarity::VeryCommon),
        );

        self.add_probe(
            ServiceProbe::new("FTP".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::VeryCommon),
        );

        // Common services (intensity 3-4)
        self.add_probe(
            ServiceProbe::new("SMTP".to_string(), ProbeProtocol::Tcp)
                .with_data(b"EHLO test\r\n".to_vec())
                .with_rarity(ProbeRarity::Common),
        );

        self.add_probe(
            ServiceProbe::new("DNS".to_string(), ProbeProtocol::Udp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::Common),
        );

        self.add_probe(
            ServiceProbe::new("MySQL".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::Common),
        );

        // Moderate services (intensity 5-6)
        self.add_probe(
            ServiceProbe::new("PostgreSQL".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::Moderate),
        );

        self.add_probe(
            ServiceProbe::new("Redis".to_string(), ProbeProtocol::Tcp)
                .with_data(b"PING\r\n".to_vec())
                .with_rarity(ProbeRarity::Moderate),
        );

        self.add_probe(
            ServiceProbe::new("MongoDB".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::Moderate),
        );

        // Uncommon services (intensity 7-8)
        self.add_probe(
            ServiceProbe::new("Memcached".to_string(), ProbeProtocol::Tcp)
                .with_data(b"stats\r\n".to_vec())
                .with_rarity(ProbeRarity::Uncommon),
        );

        self.add_probe(
            ServiceProbe::new("Elasticsearch".to_string(), ProbeProtocol::Tcp)
                .with_data(b"GET / HTTP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::Uncommon),
        );

        // Rare/specialized (intensity 9)
        self.add_probe(
            ServiceProbe::new("Cassandra".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::Rare),
        );

        self.add_probe(
            ServiceProbe::new("CouchDB".to_string(), ProbeProtocol::Tcp)
                .with_data(b"GET / HTTP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::Rare),
        );
    }

    fn add_probe(&mut self, probe: ServiceProbe) {
        self.probes.push(probe);
    }

    /// Get probes filtered by intensity level
    pub fn get_probes(&self, config: &DetectionConfig) -> Vec<&ServiceProbe> {
        self.probes
            .iter()
            .filter(|p| p.should_use(&config.intensity))
            .collect()
    }

    /// Get probe count at intensity level
    pub fn probe_count(&self, level: &IntensityLevel) -> usize {
        self.probes
            .iter()
            .filter(|p| p.intensity <= level.value())
            .count()
    }

    /// Get all probes (for intensity 9)
    pub fn get_all_probes(&self) -> &[ServiceProbe] {
        &self.probes
    }
}

impl Default for ProbeDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intensity_level_valid() {
        assert!(IntensityLevel::new(0).is_ok());
        assert!(IntensityLevel::new(5).is_ok());
        assert!(IntensityLevel::new(9).is_ok());
        assert!(IntensityLevel::new(10).is_err());
    }

    #[test]
    fn test_intensity_presets() {
        assert_eq!(IntensityLevel::light().value(), 2);
        assert_eq!(IntensityLevel::default().value(), 7);
        assert_eq!(IntensityLevel::all().value(), 9);
    }

    #[test]
    fn test_intensity_should_use_probe() {
        let level = IntensityLevel::new(5).unwrap();
        assert!(level.should_use_probe(3));
        assert!(level.should_use_probe(5));
        assert!(!level.should_use_probe(7));
    }

    #[test]
    fn test_intensity_description() {
        let light = IntensityLevel::light();
        assert_eq!(light.description(), "Light (--version-light)");

        let all = IntensityLevel::all();
        assert_eq!(all.description(), "All probes (--version-all)");
    }

    #[test]
    fn test_intensity_estimated_probes() {
        assert_eq!(IntensityLevel::light().estimated_probes(), 3);
        assert_eq!(IntensityLevel::default().estimated_probes(), 25);
        assert_eq!(IntensityLevel::all().estimated_probes(), 100);
    }

    #[test]
    fn test_intensity_time_multiplier() {
        assert_eq!(IntensityLevel::light().time_multiplier(), 0.3);
        assert_eq!(IntensityLevel::default().time_multiplier(), 1.0);
        assert_eq!(IntensityLevel::all().time_multiplier(), 4.0);
    }

    #[test]
    fn test_probe_rarity_min_intensity() {
        assert_eq!(ProbeRarity::VeryCommon.min_intensity(), 1);
        assert_eq!(ProbeRarity::Common.min_intensity(), 3);
        assert_eq!(ProbeRarity::Moderate.min_intensity(), 5);
        assert_eq!(ProbeRarity::Uncommon.min_intensity(), 7);
        assert_eq!(ProbeRarity::Rare.min_intensity(), 9);
    }

    #[test]
    fn test_service_probe_creation() {
        let probe = ServiceProbe::new("HTTP".to_string(), ProbeProtocol::Tcp)
            .with_data(b"GET /".to_vec())
            .with_intensity(5)
            .as_fallback();

        assert_eq!(probe.name, "HTTP");
        assert_eq!(probe.intensity, 5);
        assert!(probe.fallback);
    }

    #[test]
    fn test_service_probe_should_use() {
        let probe = ServiceProbe::new("Test".to_string(), ProbeProtocol::Tcp).with_intensity(5);

        let level_low = IntensityLevel::new(3).unwrap();
        let level_high = IntensityLevel::new(7).unwrap();

        assert!(!probe.should_use(&level_low));
        assert!(probe.should_use(&level_high));
    }

    #[test]
    fn test_detection_config_presets() {
        let light = DetectionConfig::light();
        assert_eq!(light.intensity.value(), 2);

        let all = DetectionConfig::all();
        assert_eq!(all.intensity.value(), 9);
        assert!(all.all_ports);
    }

    #[test]
    fn test_detection_config_builder() {
        let config = DetectionConfig::new()
            .with_intensity(5)
            .unwrap()
            .with_all_ports()
            .with_trace()
            .with_timeout(3000);

        assert_eq!(config.intensity.value(), 5);
        assert!(config.all_ports);
        assert!(config.trace);
        assert_eq!(config.probe_timeout_ms, 3000);
    }

    #[test]
    fn test_probe_database() {
        let db = ProbeDatabase::new();

        // Should have default probes loaded
        assert!(!db.probes.is_empty());

        // Light mode should have fewer probes
        let light_config = DetectionConfig::light();
        let light_probes = db.get_probes(&light_config);

        // All mode should have all probes
        let all_config = DetectionConfig::all();
        let all_probes = db.get_probes(&all_config);

        assert!(light_probes.len() < all_probes.len());
    }

    #[test]
    fn test_probe_database_probe_count() {
        let db = ProbeDatabase::new();

        let count_light = db.probe_count(&IntensityLevel::light());
        let count_all = db.probe_count(&IntensityLevel::all());

        assert!(count_light < count_all);
        assert_eq!(count_all, db.probes.len());
    }

    #[test]
    fn test_intensity_display() {
        let level = IntensityLevel::new(7).unwrap();
        let display = format!("{}", level);
        assert!(display.contains("7"));
        assert!(display.contains("Default"));
    }
}
