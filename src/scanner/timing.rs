use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Timing templates (T0-T5) similar to nmap
/// These control scan speed, aggressiveness, and stealth
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TimingTemplate {
    /// T0: Paranoid - IDS evasion mode (5 minutes between probes)
    Paranoid,
    /// T1: Sneaky - Slow and stealthy (15 seconds between probes)
    Sneaky,
    /// T2: Polite - Slower to reduce bandwidth usage (0.4 seconds between probes)
    Polite,
    /// T3: Normal - Default nmap timing (balanced speed and accuracy)
    #[default]
    Normal,
    /// T4: Aggressive - Fast scan for modern reliable networks
    Aggressive,
    /// T5: Insane - Maximum speed, may sacrifice accuracy
    Insane,
}

impl TimingTemplate {
    /// Parse timing template from command line argument (0-5)
    pub fn from_number(n: u8) -> Option<Self> {
        match n {
            0 => Some(Self::Paranoid),
            1 => Some(Self::Sneaky),
            2 => Some(Self::Polite),
            3 => Some(Self::Normal),
            4 => Some(Self::Aggressive),
            5 => Some(Self::Insane),
            _ => None,
        }
    }

    /// Convert to numeric value (0-5)
    pub fn to_number(&self) -> u8 {
        match self {
            Self::Paranoid => 0,
            Self::Sneaky => 1,
            Self::Polite => 2,
            Self::Normal => 3,
            Self::Aggressive => 4,
            Self::Insane => 5,
        }
    }

    /// Convert timing template to configuration
    pub fn to_config(&self) -> TimingConfig {
        match self {
            Self::Paranoid => TimingConfig {
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(300),
                initial_rtt_timeout: Duration::from_secs(300),
                max_retries: 10,
                host_timeout: Duration::from_secs(0), // No timeout
                scan_delay: Duration::from_secs(300), // 5 minutes
                max_scan_delay: Duration::from_secs(300),
                min_parallelism: 1,
                max_parallelism: 1,
                min_hostgroup: 1,
                max_hostgroup: 1,
                min_rate: 0,
                max_rate: 1,
            },
            Self::Sneaky => TimingConfig {
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                initial_rtt_timeout: Duration::from_secs(1),
                max_retries: 5,
                host_timeout: Duration::from_secs(0), // No timeout
                scan_delay: Duration::from_secs(15),
                max_scan_delay: Duration::from_secs(15),
                min_parallelism: 1,
                max_parallelism: 1,
                min_hostgroup: 1,
                max_hostgroup: 1,
                min_rate: 0,
                max_rate: 10,
            },
            Self::Polite => TimingConfig {
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                initial_rtt_timeout: Duration::from_secs(1),
                max_retries: 4,
                host_timeout: Duration::from_secs(0), // No timeout
                scan_delay: Duration::from_millis(400),
                max_scan_delay: Duration::from_secs(1),
                min_parallelism: 1,
                max_parallelism: 10,
                min_hostgroup: 1,
                max_hostgroup: 10,
                min_rate: 0,
                max_rate: 100,
            },
            Self::Normal => TimingConfig {
                min_rtt_timeout: Duration::from_millis(100),
                max_rtt_timeout: Duration::from_secs(10),
                initial_rtt_timeout: Duration::from_secs(1),
                max_retries: 3,
                host_timeout: Duration::from_secs(0), // No timeout
                scan_delay: Duration::from_millis(0),
                max_scan_delay: Duration::from_millis(10),
                min_parallelism: 1,
                max_parallelism: 100,
                min_hostgroup: 1,
                max_hostgroup: 100,
                min_rate: 0,
                max_rate: 1000,
            },
            Self::Aggressive => TimingConfig {
                min_rtt_timeout: Duration::from_millis(50),
                max_rtt_timeout: Duration::from_millis(1250),
                initial_rtt_timeout: Duration::from_millis(500),
                max_retries: 2,
                host_timeout: Duration::from_secs(900), // 15 minutes
                scan_delay: Duration::from_millis(0),
                max_scan_delay: Duration::from_millis(10),
                min_parallelism: 1,
                max_parallelism: 1000,
                min_hostgroup: 1,
                max_hostgroup: 256,
                min_rate: 0,
                max_rate: 5000,
            },
            Self::Insane => TimingConfig {
                min_rtt_timeout: Duration::from_millis(50),
                max_rtt_timeout: Duration::from_millis(300),
                initial_rtt_timeout: Duration::from_millis(250),
                max_retries: 1,
                host_timeout: Duration::from_secs(300), // 5 minutes
                scan_delay: Duration::from_millis(0),
                max_scan_delay: Duration::from_millis(5),
                min_parallelism: 1,
                max_parallelism: 5000,
                min_hostgroup: 1,
                max_hostgroup: 1024,
                min_rate: 0,
                max_rate: 10000,
            },
        }
    }
}

impl std::fmt::Display for TimingTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paranoid => write!(f, "Paranoid (T0)"),
            Self::Sneaky => write!(f, "Sneaky (T1)"),
            Self::Polite => write!(f, "Polite (T2)"),
            Self::Normal => write!(f, "Normal (T3)"),
            Self::Aggressive => write!(f, "Aggressive (T4)"),
            Self::Insane => write!(f, "Insane (T5)"),
        }
    }
}

/// Detailed timing configuration with all nmap timing parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimingConfig {
    /// Minimum RTT timeout for probes
    pub min_rtt_timeout: Duration,
    /// Maximum RTT timeout for probes
    pub max_rtt_timeout: Duration,
    /// Initial RTT timeout for first probe
    pub initial_rtt_timeout: Duration,
    /// Maximum number of probe retransmissions
    pub max_retries: u32,
    /// Maximum time to wait for a single host (0 = no timeout)
    pub host_timeout: Duration,
    /// Minimum delay between probes to same host
    pub scan_delay: Duration,
    /// Maximum delay between probes to same host
    pub max_scan_delay: Duration,
    /// Minimum number of parallel probes
    pub min_parallelism: usize,
    /// Maximum number of parallel probes
    pub max_parallelism: usize,
    /// Minimum number of hosts to scan in parallel
    pub min_hostgroup: usize,
    /// Maximum number of hosts to scan in parallel
    pub max_hostgroup: usize,
    /// Minimum packet rate (packets per second, 0 = no minimum)
    pub min_rate: u32,
    /// Maximum packet rate (packets per second)
    pub max_rate: u32,
}

impl TimingConfig {
    /// Create a new timing config from a template
    pub fn from_template(template: TimingTemplate) -> Self {
        template.to_config()
    }

    /// Create a custom timing config with builder pattern
    pub fn custom() -> TimingConfigBuilder {
        TimingConfigBuilder::new()
    }

    /// Get the effective timeout for the initial probe attempt
    pub fn get_initial_timeout(&self) -> Duration {
        self.initial_rtt_timeout
    }

    /// Get the effective timeout for a retry (may adjust based on network conditions)
    pub fn get_retry_timeout(&self, _attempt: u32) -> Duration {
        // Could implement adaptive timeout based on attempt number
        // For now, use max_rtt_timeout for retries
        self.max_rtt_timeout
    }

    /// Check if host timeout has been exceeded
    pub fn is_host_timeout_exceeded(&self, elapsed: Duration) -> bool {
        if self.host_timeout.is_zero() {
            false
        } else {
            elapsed >= self.host_timeout
        }
    }

    /// Get delay to apply before next probe
    pub fn get_scan_delay(&self) -> Duration {
        self.scan_delay
    }

    /// Get maximum parallelism for the scan
    pub fn get_max_parallelism(&self) -> usize {
        self.max_parallelism
    }

    /// Get maximum packet rate
    pub fn get_max_rate(&self) -> u32 {
        self.max_rate
    }

    /// Validate timing configuration and fix invalid values
    pub fn validate(&mut self) {
        // Ensure min RTT timeout is at least 1ms
        if self.min_rtt_timeout.as_millis() == 0 {
            self.min_rtt_timeout = Duration::from_millis(1);
        }

        // Ensure min <= max for RTT timeouts
        if self.min_rtt_timeout > self.max_rtt_timeout {
            std::mem::swap(&mut self.min_rtt_timeout, &mut self.max_rtt_timeout);
        }

        // Ensure initial RTT is within min/max bounds
        if self.initial_rtt_timeout < self.min_rtt_timeout {
            self.initial_rtt_timeout = self.min_rtt_timeout;
        }
        if self.initial_rtt_timeout > self.max_rtt_timeout {
            self.initial_rtt_timeout = self.max_rtt_timeout;
        }

        // Ensure scan delays are valid
        if self.scan_delay > self.max_scan_delay {
            std::mem::swap(&mut self.scan_delay, &mut self.max_scan_delay);
        }

        // Ensure parallelism values are valid
        if self.min_parallelism > self.max_parallelism {
            std::mem::swap(&mut self.min_parallelism, &mut self.max_parallelism);
        }
        if self.min_parallelism == 0 {
            self.min_parallelism = 1;
        }

        // Ensure hostgroup values are valid
        if self.min_hostgroup > self.max_hostgroup {
            std::mem::swap(&mut self.min_hostgroup, &mut self.max_hostgroup);
        }
        if self.min_hostgroup == 0 {
            self.min_hostgroup = 1;
        }

        // Ensure rate values are valid
        if self.min_rate > self.max_rate && self.max_rate > 0 {
            std::mem::swap(&mut self.min_rate, &mut self.max_rate);
        }
    }
}

impl Default for TimingConfig {
    fn default() -> Self {
        TimingTemplate::Normal.to_config()
    }
}

/// Builder for creating custom timing configurations
pub struct TimingConfigBuilder {
    config: TimingConfig,
}

impl TimingConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: TimingConfig::default(),
        }
    }

    pub fn min_rtt_timeout(mut self, timeout: Duration) -> Self {
        self.config.min_rtt_timeout = timeout;
        self
    }

    pub fn max_rtt_timeout(mut self, timeout: Duration) -> Self {
        self.config.max_rtt_timeout = timeout;
        self
    }

    pub fn initial_rtt_timeout(mut self, timeout: Duration) -> Self {
        self.config.initial_rtt_timeout = timeout;
        self
    }

    pub fn max_retries(mut self, retries: u32) -> Self {
        self.config.max_retries = retries;
        self
    }

    pub fn host_timeout(mut self, timeout: Duration) -> Self {
        self.config.host_timeout = timeout;
        self
    }

    pub fn scan_delay(mut self, delay: Duration) -> Self {
        self.config.scan_delay = delay;
        self
    }

    pub fn max_scan_delay(mut self, delay: Duration) -> Self {
        self.config.max_scan_delay = delay;
        self
    }

    pub fn min_parallelism(mut self, parallelism: usize) -> Self {
        self.config.min_parallelism = parallelism;
        self
    }

    pub fn max_parallelism(mut self, parallelism: usize) -> Self {
        self.config.max_parallelism = parallelism;
        self
    }

    pub fn min_hostgroup(mut self, size: usize) -> Self {
        self.config.min_hostgroup = size;
        self
    }

    pub fn max_hostgroup(mut self, size: usize) -> Self {
        self.config.max_hostgroup = size;
        self
    }

    pub fn min_rate(mut self, rate: u32) -> Self {
        self.config.min_rate = rate;
        self
    }

    pub fn max_rate(mut self, rate: u32) -> Self {
        self.config.max_rate = rate;
        self
    }

    pub fn build(self) -> TimingConfig {
        self.config
    }
}

impl Default for TimingConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse duration from human-readable string (e.g., "1.5s", "500ms", "2m")
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim().to_lowercase();

    // Check for milliseconds
    if let Some(num_str) = s.strip_suffix("ms") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("Invalid milliseconds value: {}", num_str))?;
        return Ok(Duration::from_millis(num));
    }

    // Check for seconds
    if let Some(num_str) = s.strip_suffix('s') {
        let num: f64 = num_str
            .parse()
            .map_err(|_| format!("Invalid seconds value: {}", num_str))?;
        return Ok(Duration::from_secs_f64(num));
    }

    // Check for minutes
    if let Some(num_str) = s.strip_suffix('m') {
        let num: f64 = num_str
            .parse()
            .map_err(|_| format!("Invalid minutes value: {}", num_str))?;
        return Ok(Duration::from_secs_f64(num * 60.0));
    }

    // Check for hours
    if let Some(num_str) = s.strip_suffix('h') {
        let num: f64 = num_str
            .parse()
            .map_err(|_| format!("Invalid hours value: {}", num_str))?;
        return Ok(Duration::from_secs_f64(num * 3600.0));
    }

    // Default to milliseconds if no suffix
    let num: u64 = s
        .parse()
        .map_err(|_| format!("Invalid duration value: {}", s))?;
    Ok(Duration::from_millis(num))
}

/// Parse parallelism value (number of simultaneous operations)
pub fn parse_parallelism(s: &str) -> Result<usize, String> {
    let num: usize = s
        .parse()
        .map_err(|_| format!("Invalid parallelism value: {}", s))?;

    if num == 0 {
        return Err("Parallelism must be greater than 0".to_string());
    }

    if num > 10000 {
        return Err("Parallelism too high (max 10000)".to_string());
    }

    Ok(num)
}

/// Parse rate value (packets per second)
pub fn parse_rate(s: &str) -> Result<u32, String> {
    let num: u32 = s
        .parse()
        .map_err(|_| format!("Invalid rate value: {}", s))?;

    if num > 100000 {
        return Err("Rate too high (max 100000 pps)".to_string());
    }

    Ok(num)
}

/// Parse retries value
pub fn parse_retries(s: &str) -> Result<u32, String> {
    let num: u32 = s
        .parse()
        .map_err(|_| format!("Invalid retries value: {}", s))?;

    if num > 20 {
        return Err("Max retries too high (max 20)".to_string());
    }

    Ok(num)
}

/// Parse hostgroup size
pub fn parse_hostgroup(s: &str) -> Result<usize, String> {
    let num: usize = s
        .parse()
        .map_err(|_| format!("Invalid hostgroup value: {}", s))?;

    if num == 0 {
        return Err("Hostgroup size must be greater than 0".to_string());
    }

    if num > 65536 {
        return Err("Hostgroup size too large (max 65536)".to_string());
    }

    Ok(num)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_template_from_number() {
        assert_eq!(
            TimingTemplate::from_number(0),
            Some(TimingTemplate::Paranoid)
        );
        assert_eq!(TimingTemplate::from_number(1), Some(TimingTemplate::Sneaky));
        assert_eq!(TimingTemplate::from_number(2), Some(TimingTemplate::Polite));
        assert_eq!(TimingTemplate::from_number(3), Some(TimingTemplate::Normal));
        assert_eq!(
            TimingTemplate::from_number(4),
            Some(TimingTemplate::Aggressive)
        );
        assert_eq!(TimingTemplate::from_number(5), Some(TimingTemplate::Insane));
        assert_eq!(TimingTemplate::from_number(6), None);
    }

    #[test]
    fn test_timing_template_to_number() {
        assert_eq!(TimingTemplate::Paranoid.to_number(), 0);
        assert_eq!(TimingTemplate::Sneaky.to_number(), 1);
        assert_eq!(TimingTemplate::Polite.to_number(), 2);
        assert_eq!(TimingTemplate::Normal.to_number(), 3);
        assert_eq!(TimingTemplate::Aggressive.to_number(), 4);
        assert_eq!(TimingTemplate::Insane.to_number(), 5);
    }

    #[test]
    fn test_paranoid_timing() {
        let config = TimingTemplate::Paranoid.to_config();
        assert_eq!(config.scan_delay, Duration::from_secs(300)); // 5 minutes
        assert_eq!(config.max_parallelism, 1);
        assert_eq!(config.max_rate, 1);
        assert_eq!(config.max_retries, 10);
    }

    #[test]
    fn test_sneaky_timing() {
        let config = TimingTemplate::Sneaky.to_config();
        assert_eq!(config.scan_delay, Duration::from_secs(15));
        assert_eq!(config.max_parallelism, 1);
        assert_eq!(config.max_rate, 10);
    }

    #[test]
    fn test_polite_timing() {
        let config = TimingTemplate::Polite.to_config();
        assert_eq!(config.scan_delay, Duration::from_millis(400));
        assert_eq!(config.max_parallelism, 10);
        assert_eq!(config.max_rate, 100);
    }

    #[test]
    fn test_normal_timing() {
        let config = TimingTemplate::Normal.to_config();
        assert_eq!(config.max_parallelism, 100);
        assert_eq!(config.max_rate, 1000);
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_aggressive_timing() {
        let config = TimingTemplate::Aggressive.to_config();
        assert_eq!(config.max_parallelism, 1000);
        assert_eq!(config.max_rate, 5000);
        assert_eq!(config.max_retries, 2);
        assert_eq!(config.host_timeout, Duration::from_secs(900)); // 15 min
    }

    #[test]
    fn test_insane_timing() {
        let config = TimingTemplate::Insane.to_config();
        assert_eq!(config.max_parallelism, 5000);
        assert_eq!(config.max_rate, 10000);
        assert_eq!(config.max_retries, 1);
        assert_eq!(config.host_timeout, Duration::from_secs(300)); // 5 min
    }

    #[test]
    fn test_default_timing_template() {
        assert_eq!(TimingTemplate::default(), TimingTemplate::Normal);
    }

    #[test]
    fn test_timing_config_builder() {
        let config = TimingConfig::custom()
            .max_rate(2000)
            .max_parallelism(500)
            .max_retries(5)
            .scan_delay(Duration::from_millis(100))
            .build();

        assert_eq!(config.max_rate, 2000);
        assert_eq!(config.max_parallelism, 500);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.scan_delay, Duration::from_millis(100));
    }

    #[test]
    fn test_host_timeout_check() {
        let config = TimingTemplate::Aggressive.to_config();
        assert!(!config.is_host_timeout_exceeded(Duration::from_secs(60)));
        assert!(config.is_host_timeout_exceeded(Duration::from_secs(1000)));

        // Paranoid has no timeout
        let paranoid = TimingTemplate::Paranoid.to_config();
        assert!(!paranoid.is_host_timeout_exceeded(Duration::from_secs(100000)));
    }

    #[test]
    fn test_timing_template_display() {
        assert_eq!(TimingTemplate::Paranoid.to_string(), "Paranoid (T0)");
        assert_eq!(TimingTemplate::Sneaky.to_string(), "Sneaky (T1)");
        assert_eq!(TimingTemplate::Normal.to_string(), "Normal (T3)");
        assert_eq!(TimingTemplate::Insane.to_string(), "Insane (T5)");
    }

    #[test]
    fn test_parse_duration_milliseconds() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(
            parse_duration("1000MS").unwrap(),
            Duration::from_millis(1000)
        );
        assert_eq!(parse_duration("100ms").unwrap(), Duration::from_millis(100));
    }

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(parse_duration("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(
            parse_duration("1.5s").unwrap(),
            Duration::from_secs_f64(1.5)
        );
        assert_eq!(parse_duration("10S").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration("0.5s").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
        assert_eq!(
            parse_duration("2.5m").unwrap(),
            Duration::from_secs_f64(150.0)
        );
        assert_eq!(parse_duration("5M").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("0.5h").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("2H").unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn test_parse_duration_no_suffix() {
        // Should default to milliseconds
        assert_eq!(parse_duration("500").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("1000").unwrap(), Duration::from_millis(1000));
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("invalid").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("s").is_err());
    }

    #[test]
    fn test_parse_parallelism() {
        assert_eq!(parse_parallelism("1").unwrap(), 1);
        assert_eq!(parse_parallelism("100").unwrap(), 100);
        assert_eq!(parse_parallelism("1000").unwrap(), 1000);
    }

    #[test]
    fn test_parse_parallelism_invalid() {
        assert!(parse_parallelism("0").is_err()); // Must be > 0
        assert!(parse_parallelism("20000").is_err()); // Too high
        assert!(parse_parallelism("invalid").is_err());
    }

    #[test]
    fn test_parse_rate() {
        assert_eq!(parse_rate("100").unwrap(), 100);
        assert_eq!(parse_rate("1000").unwrap(), 1000);
        assert_eq!(parse_rate("10000").unwrap(), 10000);
    }

    #[test]
    fn test_parse_rate_invalid() {
        assert!(parse_rate("200000").is_err()); // Too high
        assert!(parse_rate("invalid").is_err());
    }

    #[test]
    fn test_parse_retries() {
        assert_eq!(parse_retries("3").unwrap(), 3);
        assert_eq!(parse_retries("10").unwrap(), 10);
    }

    #[test]
    fn test_parse_retries_invalid() {
        assert!(parse_retries("50").is_err()); // Too high
        assert!(parse_retries("invalid").is_err());
    }

    #[test]
    fn test_parse_hostgroup() {
        assert_eq!(parse_hostgroup("1").unwrap(), 1);
        assert_eq!(parse_hostgroup("256").unwrap(), 256);
        assert_eq!(parse_hostgroup("1024").unwrap(), 1024);
    }

    #[test]
    fn test_parse_hostgroup_invalid() {
        assert!(parse_hostgroup("0").is_err()); // Must be > 0
        assert!(parse_hostgroup("100000").is_err()); // Too large
        assert!(parse_hostgroup("invalid").is_err());
    }
}
