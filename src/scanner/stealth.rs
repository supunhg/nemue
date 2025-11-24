use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthOptions {
    pub timing_template: TimingTemplate,
    pub fragment_packets: bool,
    pub decoy_addresses: Vec<String>,
    pub source_port: Option<u16>,
    pub randomize_hosts: bool,
    pub ttl: Option<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum TimingTemplate {
    Paranoid,  // T0: Wait 5 minutes between packets
    Sneaky,    // T1: Wait 15 seconds between packets  
    Polite,    // T2: Wait 0.4 seconds between packets
    Normal,    // T3: Default timing
    Aggressive, // T4: Fast scan
    Insane,    // T5: Very fast, may miss ports
}

impl TimingTemplate {
    pub fn delay_ms(&self) -> u64 {
        match self {
            TimingTemplate::Paranoid => 300_000,  // 5 minutes
            TimingTemplate::Sneaky => 15_000,     // 15 seconds
            TimingTemplate::Polite => 400,        // 0.4 seconds
            TimingTemplate::Normal => 0,          // No delay
            TimingTemplate::Aggressive => 0,      // No delay
            TimingTemplate::Insane => 0,          // No delay
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "0" | "paranoid" => Some(TimingTemplate::Paranoid),
            "1" | "sneaky" => Some(TimingTemplate::Sneaky),
            "2" | "polite" => Some(TimingTemplate::Polite),
            "3" | "normal" => Some(TimingTemplate::Normal),
            "4" | "aggressive" => Some(TimingTemplate::Aggressive),
            "5" | "insane" => Some(TimingTemplate::Insane),
            _ => None,
        }
    }
}

impl Default for StealthOptions {
    fn default() -> Self {
        Self {
            timing_template: TimingTemplate::Normal,
            fragment_packets: false,
            decoy_addresses: vec![],
            source_port: None,
            randomize_hosts: false,
            ttl: None,
        }
    }
}

impl StealthOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_timing(mut self, timing: TimingTemplate) -> Self {
        self.timing_template = timing;
        self
    }

    pub fn with_decoys(mut self, decoys: Vec<String>) -> Self {
        self.decoy_addresses = decoys;
        self
    }

    pub fn with_source_port(mut self, port: u16) -> Self {
        self.source_port = Some(port);
        self
    }

    pub fn with_fragmentation(mut self, fragment: bool) -> Self {
        self.fragment_packets = fragment;
        self
    }

    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    pub fn randomize(mut self) -> Self {
        self.randomize_hosts = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_delays() {
        assert_eq!(TimingTemplate::Paranoid.delay_ms(), 300_000);
        assert_eq!(TimingTemplate::Sneaky.delay_ms(), 15_000);
        assert_eq!(TimingTemplate::Normal.delay_ms(), 0);
    }

    #[test]
    fn test_timing_from_str() {
        assert_eq!(TimingTemplate::from_str("0"), Some(TimingTemplate::Paranoid));
        assert_eq!(TimingTemplate::from_str("paranoid"), Some(TimingTemplate::Paranoid));
        assert_eq!(TimingTemplate::from_str("3"), Some(TimingTemplate::Normal));
        assert_eq!(TimingTemplate::from_str("invalid"), None);
    }

    #[test]
    fn test_stealth_options_builder() {
        let opts = StealthOptions::new()
            .with_timing(TimingTemplate::Sneaky)
            .with_decoys(vec!["192.168.1.100".to_string()])
            .with_source_port(53)
            .randomize();
        
        assert_eq!(opts.timing_template, TimingTemplate::Sneaky);
        assert_eq!(opts.decoy_addresses.len(), 1);
        assert_eq!(opts.source_port, Some(53));
        assert!(opts.randomize_hosts);
    }
}
