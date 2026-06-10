use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

use crate::scanner::{PortState, ScanResult, ScanResults};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupStats {
    pub total_input: usize,
    pub duplicates_found: usize,
    pub unique_results: usize,
    pub merged_findings: usize,
    pub dedup_ratio: f64,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct FindingKey {
    target: IpAddr,
    port: u16,
    protocol: String,
}

impl FindingKey {
    fn from_result(result: &ScanResult) -> Self {
        Self {
            target: result.target,
            port: result.port,
            protocol: format!("{:?}", result.protocol),
        }
    }
}

#[derive(Debug, Clone)]
struct MergedFinding {
    result: ScanResult,
    occurrences: usize,
    first_seen: chrono::DateTime<chrono::Utc>,
    last_seen: chrono::DateTime<chrono::Utc>,
    services_seen: Vec<String>,
}

pub struct ScanDeduplicator {
    merge_services: bool,
    track_frequency: bool,
}

impl ScanDeduplicator {
    pub fn new() -> Self {
        Self {
            merge_services: true,
            track_frequency: true,
        }
    }

    pub fn with_options(merge_services: bool, track_frequency: bool) -> Self {
        Self {
            merge_services,
            track_frequency,
        }
    }

    pub fn deduplicate(&self, results: &ScanResults) -> (ScanResults, DedupStats) {
        self.deduplicate_multiple(&[results.clone()])
    }

    pub fn deduplicate_multiple(&self, scans: &[ScanResults]) -> (ScanResults, DedupStats) {
        let mut merged: HashMap<FindingKey, MergedFinding> = HashMap::new();
        let mut total_input = 0;

        let earliest_start = scans
            .iter()
            .map(|s| s.scan_start)
            .min()
            .unwrap_or_else(chrono::Utc::now);
        let latest_end = scans
            .iter()
            .map(|s| s.scan_end)
            .max()
            .unwrap_or_else(chrono::Utc::now);
        let total_targets: usize = scans.iter().map(|s| s.target_count).sum();
        let total_ports: usize = scans.iter().map(|s| s.port_count).sum();

        for scan in scans {
            for result in &scan.results {
                total_input += 1;
                let key = FindingKey::from_result(result);

                if let Some(existing) = merged.get_mut(&key) {
                    existing.occurrences += 1;
                    existing.last_seen = result.timestamp;
                    if self.merge_services {
                        if let Some(ref service) = result.service {
                            if !existing.services_seen.contains(service) {
                                existing.services_seen.push(service.clone());
                            }
                        }
                    }
                    if result.state == PortState::Open && existing.result.state != PortState::Open {
                        existing.result = result.clone();
                    }
                } else {
                    merged.insert(
                        key,
                        MergedFinding {
                            result: result.clone(),
                            occurrences: 1,
                            first_seen: result.timestamp,
                            last_seen: result.timestamp,
                            services_seen: result
                                .service
                                .as_ref()
                                .map(|s| vec![s.clone()])
                                .unwrap_or_default(),
                        },
                    );
                }
            }
        }

        let duplicates_found = total_input - merged.len();
        let unique_results = merged.len();

        let mut deduped_results: Vec<ScanResult> = merged
            .into_values()
            .map(|f| {
                let mut result = f.result;
                if self.track_frequency && f.occurrences > 1 {
                    result.reason = Some(format!("seen {} times", f.occurrences));
                }
                result
            })
            .collect();

        deduped_results.sort_by(|a, b| {
            a.target
                .cmp(&b.target)
                .then(a.port.cmp(&b.port))
        });

        let dedup_ratio = if total_input > 0 {
            duplicates_found as f64 / total_input as f64
        } else {
            0.0
        };

        (
            ScanResults {
                scan_start: earliest_start,
                scan_end: latest_end,
                target_count: total_targets,
                port_count: total_ports,
                results: deduped_results,
                os_fingerprints: scans
                    .iter()
                    .flat_map(|s| s.os_fingerprints.clone())
                    .collect(),
                script_results: scans
                    .iter()
                    .flat_map(|s| s.script_results.clone())
                    .collect(),
            },
            DedupStats {
                total_input,
                duplicates_found,
                unique_results,
                merged_findings: if self.merge_services { total_input } else { 0 },
                dedup_ratio,
            },
        )
    }

    pub fn find_duplicates(&self, results: &ScanResults) -> Vec<DuplicateGroup> {
        let mut groups: HashMap<FindingKey, Vec<&ScanResult>> = HashMap::new();

        for result in &results.results {
            let key = FindingKey::from_result(result);
            groups.entry(key).or_default().push(result);
        }

        groups
            .into_iter()
            .filter(|(_, entries)| entries.len() > 1)
            .map(|(key, entries)| DuplicateGroup {
                target: key.target,
                port: key.port,
                protocol: key.protocol,
                count: entries.len(),
                states: entries.iter().map(|e| format!("{:?}", e.state)).collect(),
                services: entries
                    .iter()
                    .filter_map(|e| e.service.clone())
                    .collect(),
            })
            .collect()
    }
}

impl Default for ScanDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub target: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub count: usize,
    pub states: Vec<String>,
    pub services: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Protocol, ScanResults};
    use chrono::Utc;
    use std::net::IpAddr;

    fn create_test_result(port: u16, state: PortState) -> ScanResult {
        ScanResult {
            target: "192.168.1.1".parse::<IpAddr>().unwrap(),
            port,
            state,
            protocol: Protocol::TCP,
            service: Some("http".to_string()),
            service_info: None,
            hostname: None,
            reason: None,
            timestamp: Utc::now(),
        }
    }

    fn create_scan(results: Vec<ScanResult>) -> ScanResults {
        ScanResults {
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 1,
            port_count: results.len(),
            results,
            os_fingerprints: Vec::new(),
            script_results: Vec::new(),
        }
    }

    #[test]
    fn test_no_duplicates() {
        let dedup = ScanDeduplicator::new();
        let results = create_scan(vec![
            create_test_result(80, PortState::Open),
            create_test_result(443, PortState::Open),
        ]);

        let (deduped, stats) = dedup.deduplicate(&results);
        assert_eq!(stats.total_input, 2);
        assert_eq!(stats.duplicates_found, 0);
        assert_eq!(stats.unique_results, 2);
        assert_eq!(deduped.results.len(), 2);
    }

    #[test]
    fn test_with_duplicates() {
        let dedup = ScanDeduplicator::new();
        let results = create_scan(vec![
            create_test_result(80, PortState::Open),
            create_test_result(80, PortState::Open),
            create_test_result(80, PortState::Closed),
            create_test_result(443, PortState::Open),
        ]);

        let (deduped, stats) = dedup.deduplicate(&results);
        assert_eq!(stats.total_input, 4);
        assert_eq!(stats.duplicates_found, 2);
        assert_eq!(stats.unique_results, 2);
        assert_eq!(deduped.results.len(), 2);
    }

    #[test]
    fn test_deduplicate_multiple_scans() {
        let dedup = ScanDeduplicator::new();
        let scan1 = create_scan(vec![
            create_test_result(80, PortState::Open),
            create_test_result(443, PortState::Closed),
        ]);
        let scan2 = create_scan(vec![
            create_test_result(80, PortState::Open),
            create_test_result(22, PortState::Open),
        ]);

        let (_, stats) = dedup.deduplicate_multiple(&[scan1, scan2]);
        assert_eq!(stats.total_input, 4);
        assert_eq!(stats.duplicates_found, 1);
        assert_eq!(stats.unique_results, 3);
    }

    #[test]
    fn test_open_state_priority() {
        let dedup = ScanDeduplicator::new();
        let results = create_scan(vec![
            create_test_result(80, PortState::Closed),
            create_test_result(80, PortState::Open),
        ]);

        let (deduped, _) = dedup.deduplicate(&results);
        assert_eq!(deduped.results.len(), 1);
        assert_eq!(deduped.results[0].state, PortState::Open);
    }

    #[test]
    fn test_find_duplicates() {
        let dedup = ScanDeduplicator::new();
        let results = create_scan(vec![
            create_test_result(80, PortState::Open),
            create_test_result(80, PortState::Open),
            create_test_result(443, PortState::Open),
        ]);

        let groups = dedup.find_duplicates(&results);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].port, 80);
        assert_eq!(groups[0].count, 2);
    }

    #[test]
    fn test_no_duplicate_groups() {
        let dedup = ScanDeduplicator::new();
        let results = create_scan(vec![
            create_test_result(80, PortState::Open),
            create_test_result(443, PortState::Open),
        ]);

        let groups = dedup.find_duplicates(&results);
        assert!(groups.is_empty());
    }

    #[test]
    fn test_dedup_ratio() {
        let dedup = ScanDeduplicator::new();
        let results = create_scan(vec![
            create_test_result(80, PortState::Open),
            create_test_result(80, PortState::Open),
            create_test_result(80, PortState::Open),
            create_test_result(443, PortState::Open),
        ]);

        let (_, stats) = dedup.deduplicate(&results);
        assert!((stats.dedup_ratio - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_sorted_output() {
        let dedup = ScanDeduplicator::new();
        let results = create_scan(vec![
            create_test_result(443, PortState::Open),
            create_test_result(22, PortState::Open),
            create_test_result(80, PortState::Open),
        ]);

        let (deduped, _) = dedup.deduplicate(&results);
        assert_eq!(deduped.results[0].port, 22);
        assert_eq!(deduped.results[1].port, 80);
        assert_eq!(deduped.results[2].port, 443);
    }
}
