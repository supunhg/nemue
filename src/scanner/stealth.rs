use serde::{Deserialize, Serialize};
use super::timing::TimingTemplate;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthOptions {
    pub timing_template: TimingTemplate,
    pub fragment_packets: bool,
    pub decoy_addresses: Vec<String>,
    pub source_port: Option<u16>,
    pub randomize_hosts: bool,
    pub ttl: Option<u8>,
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
