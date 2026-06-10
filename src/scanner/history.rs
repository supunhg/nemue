use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

use crate::scanner::{PortState, ScanResults};

const DEFAULT_MAX_ENTRIES: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistory {
    pub scans: Vec<HistoryEntry>,
    pub max_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub scan_id: String,
    pub timestamp: DateTime<Utc>,
    pub target: String,
    pub results: ScanResults,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_ports: usize,
    pub open_ports: usize,
    pub closed_ports: usize,
    pub filtered_ports: usize,
    pub services: HashMap<u16, String>,
}

impl ScanHistory {
    pub fn new() -> Self {
        Self {
            scans: Vec::new(),
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }

    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            scans: Vec::new(),
            max_entries,
        }
    }

    pub fn add_entry(&mut self, target: String, results: ScanResults) -> String {
        let scan_id = Uuid::new_v4().to_string();
        let summary = ScanSummary::from_results(&results);

        let entry = HistoryEntry {
            scan_id: scan_id.clone(),
            timestamp: Utc::now(),
            target,
            results,
            summary,
        };

        self.scans.push(entry);

        while self.scans.len() > self.max_entries {
            self.scans.remove(0);
        }

        scan_id
    }

    pub fn get_entry(&self, scan_id: &str) -> Option<&HistoryEntry> {
        self.scans.iter().find(|e| e.scan_id == scan_id)
    }

    pub fn get_latest(&self) -> Option<&HistoryEntry> {
        self.scans.last()
    }

    pub fn get_previous(&self) -> Option<&HistoryEntry> {
        if self.scans.len() >= 2 {
            self.scans.get(self.scans.len() - 2)
        } else {
            None
        }
    }

    pub fn entries_for_target(&self, target: &str) -> Vec<&HistoryEntry> {
        self.scans
            .iter()
            .filter(|e| e.target == target)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.scans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scans.is_empty()
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let history: ScanHistory = serde_json::from_str(&contents)?;
        Ok(history)
    }

    pub fn save_to_default_path(&self) -> Result<()> {
        let path = default_history_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        self.save_to_file(path)
    }

    pub fn load_from_default_path() -> Result<Self> {
        let path = default_history_path()?;
        if path.exists() {
            Self::load_from_file(path)
        } else {
            Ok(Self::new())
        }
    }
}

impl Default for ScanHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanSummary {
    pub fn from_results(results: &ScanResults) -> Self {
        let mut services = HashMap::new();
        let mut open_ports = 0;
        let mut closed_ports = 0;
        let mut filtered_ports = 0;

        for result in &results.results {
            match result.state {
                PortState::Open => {
                    open_ports += 1;
                    if let Some(ref service) = result.service {
                        services.insert(result.port, service.clone());
                    }
                }
                PortState::Closed => closed_ports += 1,
                PortState::Filtered | PortState::OpenFiltered => filtered_ports += 1,
                _ => {}
            }
        }

        Self {
            total_ports: results.results.len(),
            open_ports,
            closed_ports,
            filtered_ports,
            services,
        }
    }
}

fn default_history_path() -> Result<std::path::PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home.join(".nemue").join("history.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Protocol, ScanResult, ScanResults};
    use std::net::IpAddr;

    fn create_test_results(port: u16, state: PortState) -> ScanResults {
        ScanResults {
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 1,
            port_count: 1,
            results: vec![ScanResult {
                target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                port,
                state,
                protocol: Protocol::TCP,
                service: Some("http".to_string()),
                service_info: None,
                hostname: None,
                reason: None,
                timestamp: Utc::now(),
            }],
            os_fingerprints: Vec::new(),
            script_results: Vec::new(),
        }
    }

    #[test]
    fn test_new_history() {
        let history = ScanHistory::new();
        assert!(history.is_empty());
        assert_eq!(history.max_entries, DEFAULT_MAX_ENTRIES);
    }

    #[test]
    fn test_add_entry() {
        let mut history = ScanHistory::new();
        let results = create_test_results(80, PortState::Open);
        let scan_id = history.add_entry("192.168.1.1".to_string(), results);

        assert_eq!(history.len(), 1);
        assert!(!scan_id.is_empty());
        assert!(history.get_entry(&scan_id).is_some());
    }

    #[test]
    fn test_get_latest() {
        let mut history = ScanHistory::new();
        history.add_entry("target1".to_string(), create_test_results(80, PortState::Open));
        history.add_entry("target2".to_string(), create_test_results(443, PortState::Open));

        let latest = history.get_latest().unwrap();
        assert_eq!(latest.target, "target2");
    }

    #[test]
    fn test_get_previous() {
        let mut history = ScanHistory::new();
        assert!(history.get_previous().is_none());

        history.add_entry("target1".to_string(), create_test_results(80, PortState::Open));
        assert!(history.get_previous().is_none());

        history.add_entry("target2".to_string(), create_test_results(443, PortState::Open));
        let prev = history.get_previous().unwrap();
        assert_eq!(prev.target, "target1");
    }

    #[test]
    fn test_max_entries() {
        let mut history = ScanHistory::with_max_entries(3);
        for i in 0..5 {
            history.add_entry(format!("target{}", i), create_test_results(80, PortState::Open));
        }
        assert_eq!(history.len(), 3);
        assert_eq!(history.scans[0].target, "target2");
    }

    #[test]
    fn test_entries_for_target() {
        let mut history = ScanHistory::new();
        history.add_entry("192.168.1.1".to_string(), create_test_results(80, PortState::Open));
        history.add_entry("192.168.1.2".to_string(), create_test_results(443, PortState::Open));
        history.add_entry("192.168.1.1".to_string(), create_test_results(22, PortState::Open));

        let entries = history.entries_for_target("192.168.1.1");
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_scan_summary() {
        let results = ScanResults {
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 1,
            port_count: 3,
            results: vec![
                ScanResult {
                    target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                    port: 22,
                    state: PortState::Open,
                    protocol: Protocol::TCP,
                    service: Some("ssh".to_string()),
                    service_info: None,
                    hostname: None,
                    reason: None,
                    timestamp: Utc::now(),
                },
                ScanResult {
                    target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                    port: 80,
                    state: PortState::Open,
                    protocol: Protocol::TCP,
                    service: Some("http".to_string()),
                    service_info: None,
                    hostname: None,
                    reason: None,
                    timestamp: Utc::now(),
                },
                ScanResult {
                    target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                    port: 443,
                    state: PortState::Closed,
                    protocol: Protocol::TCP,
                    service: None,
                    service_info: None,
                    hostname: None,
                    reason: None,
                    timestamp: Utc::now(),
                },
            ],
            os_fingerprints: Vec::new(),
            script_results: Vec::new(),
        };

        let summary = ScanSummary::from_results(&results);
        assert_eq!(summary.total_ports, 3);
        assert_eq!(summary.open_ports, 2);
        assert_eq!(summary.closed_ports, 1);
        assert_eq!(summary.filtered_ports, 0);
        assert_eq!(summary.services.len(), 2);
        assert_eq!(summary.services.get(&22).unwrap(), "ssh");
        assert_eq!(summary.services.get(&80).unwrap(), "http");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut history = ScanHistory::new();
        history.add_entry("192.168.1.1".to_string(), create_test_results(80, PortState::Open));
        history.add_entry("192.168.1.1".to_string(), create_test_results(443, PortState::Closed));

        let json = serde_json::to_string(&history).unwrap();
        let loaded: ScanHistory = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.scans[0].target, "192.168.1.1");
        assert_eq!(loaded.scans[1].summary.closed_ports, 1);
    }

    #[test]
    fn test_save_load_file() {
        let mut history = ScanHistory::new();
        history.add_entry("192.168.1.1".to_string(), create_test_results(80, PortState::Open));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_history.json");

        history.save_to_file(&path).unwrap();
        let loaded = ScanHistory::load_from_file(&path).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.scans[0].target, "192.168.1.1");
    }
}
