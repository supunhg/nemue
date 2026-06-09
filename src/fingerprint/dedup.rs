use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResultKey {
    pub target: IpAddr,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicatedResult<T: Clone> {
    pub key: ResultKey,
    pub data: T,
    pub occurrences: u32,
    pub first_seen: u64,
    pub last_seen: u64,
}

pub struct ResultDeduplicator<T: Clone + Send + Sync> {
    seen: HashMap<ResultKey, DeduplicatedResult<T>>,
    duplicates_removed: u64,
    total_processed: u64,
}

impl<T: Clone + Send + Sync> ResultDeduplicator<T> {
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
            duplicates_removed: 0,
            total_processed: 0,
        }
    }

    pub fn add(&mut self, key: ResultKey, data: T) -> bool {
        self.total_processed += 1;
        
        if self.seen.contains_key(&key) {
            self.duplicates_removed += 1;
            if let Some(entry) = self.seen.get_mut(&key) {
                entry.occurrences += 1;
                entry.last_seen = 0;
            }
            return false;
        }
        
        let entry = DeduplicatedResult {
            key: key.clone(),
            data,
            occurrences: 1,
            first_seen: 0,
            last_seen: 0,
        };
        
        self.seen.insert(key, entry);
        true
    }

    pub fn contains(&self, key: &ResultKey) -> bool {
        self.seen.contains_key(key)
    }

    pub fn get(&self, key: &ResultKey) -> Option<&DeduplicatedResult<T>> {
        self.seen.get(key)
    }

    pub fn results(&self) -> Vec<&DeduplicatedResult<T>> {
        self.seen.values().collect()
    }

    pub fn into_results(self) -> Vec<DeduplicatedResult<T>> {
        self.seen.into_values().collect()
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn duplicates_removed(&self) -> u64 {
        self.duplicates_removed
    }

    pub fn total_processed(&self) -> u64 {
        self.total_processed
    }

    pub fn dedup_ratio(&self) -> f64 {
        if self.total_processed == 0 {
            return 0.0;
        }
        self.duplicates_removed as f64 / self.total_processed as f64
    }

    pub fn clear(&mut self) {
        self.seen.clear();
        self.duplicates_removed = 0;
        self.total_processed = 0;
    }
}

impl<T: Clone + Send + Sync> Default for ResultDeduplicator<T> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ScanDeduplicator {
    open_ports: HashMap<IpAddr, HashSet<u16>>,
    closed_ports: HashMap<IpAddr, HashSet<u16>>,
    filtered_ports: HashMap<IpAddr, HashSet<u16>>,
    stats: DedupStats,
}

#[derive(Debug, Clone, Default)]
pub struct DedupStats {
    pub total_scans: u64,
    pub duplicate_open: u64,
    pub duplicate_closed: u64,
    pub duplicate_filtered: u64,
    pub unique_results: u64,
}

impl ScanDeduplicator {
    pub fn new() -> Self {
        Self {
            open_ports: HashMap::new(),
            closed_ports: HashMap::new(),
            filtered_ports: HashMap::new(),
            stats: DedupStats::default(),
        }
    }

    pub fn record_open(&mut self, target: IpAddr, port: u16) -> bool {
        self.stats.total_scans += 1;
        let ports = self.open_ports.entry(target).or_insert_with(|| HashSet::new());
        if ports.insert(port) {
            self.stats.unique_results += 1;
            true
        } else {
            self.stats.duplicate_open += 1;
            false
        }
    }

    pub fn record_closed(&mut self, target: IpAddr, port: u16) -> bool {
        self.stats.total_scans += 1;
        let ports = self.closed_ports.entry(target).or_insert_with(|| HashSet::new());
        if ports.insert(port) {
            self.stats.unique_results += 1;
            true
        } else {
            self.stats.duplicate_closed += 1;
            false
        }
    }

    pub fn record_filtered(&mut self, target: IpAddr, port: u16) -> bool {
        self.stats.total_scans += 1;
        let ports = self.filtered_ports.entry(target).or_insert_with(|| HashSet::new());
        if ports.insert(port) {
            self.stats.unique_results += 1;
            true
        } else {
            self.stats.duplicate_filtered += 1;
            false
        }
    }

    pub fn is_open(&self, target: &IpAddr, port: &u16) -> bool {
        self.open_ports.get(target).map_or(false, |ports| ports.contains(port))
    }

    pub fn is_closed(&self, target: &IpAddr, port: &u16) -> bool {
        self.closed_ports.get(target).map_or(false, |ports| ports.contains(port))
    }

    pub fn is_filtered(&self, target: &IpAddr, port: &u16) -> bool {
        self.filtered_ports.get(target).map_or(false, |ports| ports.contains(port))
    }

    pub fn open_ports(&self, target: &IpAddr) -> Vec<u16> {
        self.open_ports.get(target).map_or_else(Vec::new, |ports| {
            let mut sorted: Vec<u16> = ports.iter().cloned().collect();
            sorted.sort();
            sorted
        })
    }

    pub fn all_targets(&self) -> Vec<IpAddr> {
        let mut targets: HashSet<IpAddr> = HashSet::new();
        targets.extend(self.open_ports.keys());
        targets.extend(self.closed_ports.keys());
        targets.extend(self.filtered_ports.keys());
        targets.into_iter().collect()
    }

    pub fn stats(&self) -> &DedupStats {
        &self.stats
    }

    pub fn clear(&mut self) {
        self.open_ports.clear();
        self.closed_ports.clear();
        self.filtered_ports.clear();
        self.stats = DedupStats::default();
    }
}

impl Default for ScanDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedup_basic() {
        let mut dedup = ResultDeduplicator::new();
        let key = ResultKey {
            target: "127.0.0.1".parse().unwrap(),
            port: 80,
            protocol: "tcp".to_string(),
        };
        
        assert!(dedup.add(key.clone(), "open".to_string()));
        assert!(!dedup.add(key.clone(), "open".to_string()));
        assert_eq!(dedup.len(), 1);
        assert_eq!(dedup.duplicates_removed(), 1);
    }

    #[test]
    fn test_dedup_ratio() {
        let mut dedup = ResultDeduplicator::new();
        let key1 = ResultKey {
            target: "127.0.0.1".parse().unwrap(),
            port: 80,
            protocol: "tcp".to_string(),
        };
        let key2 = ResultKey {
            target: "127.0.0.1".parse().unwrap(),
            port: 443,
            protocol: "tcp".to_string(),
        };
        
        dedup.add(key1.clone(), "open".to_string());
        dedup.add(key1.clone(), "open".to_string());
        dedup.add(key2.clone(), "open".to_string());
        
        assert_eq!(dedup.len(), 2);
        assert_eq!(dedup.total_processed(), 3);
        assert_eq!(dedup.duplicates_removed(), 1);
    }

    #[test]
    fn test_scan_dedup() {
        let mut dedup = ScanDeduplicator::new();
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        
        assert!(dedup.record_open(target, 80));
        assert!(!dedup.record_open(target, 80));
        assert!(dedup.record_open(target, 443));
        
        assert!(dedup.is_open(&target, &80));
        assert!(dedup.is_open(&target, &443));
        assert!(!dedup.is_open(&target, &8080));
        
        let ports = dedup.open_ports(&target);
        assert_eq!(ports, vec![80, 443]);
    }

    #[test]
    fn test_scan_dedup_stats() {
        let mut dedup = ScanDeduplicator::new();
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        
        dedup.record_open(target, 80);
        dedup.record_open(target, 80);
        dedup.record_closed(target, 443);
        dedup.record_filtered(target, 8080);
        
        let stats = dedup.stats();
        assert_eq!(stats.total_scans, 4);
        assert_eq!(stats.unique_results, 3);
        assert_eq!(stats.duplicate_open, 1);
    }

    #[test]
    fn test_scan_dedup_all_targets() {
        let mut dedup = ScanDeduplicator::new();
        let target1: IpAddr = "127.0.0.1".parse().unwrap();
        let target2: IpAddr = "192.168.1.1".parse().unwrap();
        
        dedup.record_open(target1, 80);
        dedup.record_open(target2, 443);
        
        let targets = dedup.all_targets();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn test_result_dedup_clear() {
        let mut dedup = ResultDeduplicator::new();
        let key = ResultKey {
            target: "127.0.0.1".parse().unwrap(),
            port: 80,
            protocol: "tcp".to_string(),
        };
        
        dedup.add(key, "open".to_string());
        assert_eq!(dedup.len(), 1);
        
        dedup.clear();
        assert_eq!(dedup.len(), 0);
        assert_eq!(dedup.total_processed(), 0);
    }
}
