use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::scanner::{PortState, ScanResults};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanGroup {
    pub id: String,
    pub name: String,
    pub description: String,
    pub targets: Vec<GroupTarget>,
    pub tags: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupTarget {
    pub address: String,
    pub label: Option<String>,
    pub ports: Option<String>,
}

impl ScanGroup {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: description.to_string(),
            targets: Vec::new(),
            tags: Vec::new(),
            created_at: chrono::Utc::now(),
        }
    }

    pub fn add_target(&mut self, address: &str) {
        self.targets.push(GroupTarget {
            address: address.to_string(),
            label: None,
            ports: None,
        });
    }

    pub fn add_target_with_label(&mut self, address: &str, label: &str) {
        self.targets.push(GroupTarget {
            address: address.to_string(),
            label: Some(label.to_string()),
            ports: None,
        });
    }

    pub fn add_target_with_ports(&mut self, address: &str, ports: &str) {
        self.targets.push(GroupTarget {
            address: address.to_string(),
            label: None,
            ports: Some(ports.to_string()),
        });
    }

    pub fn add_full_target(&mut self, address: &str, label: &str, ports: &str) {
        self.targets.push(GroupTarget {
            address: address.to_string(),
            label: Some(label.to_string()),
            ports: Some(ports.to_string()),
        });
    }

    pub fn add_tag(&mut self, tag: &str) {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
        }
    }

    pub fn remove_target(&mut self, address: &str) -> bool {
        let len_before = self.targets.len();
        self.targets.retain(|t| t.address != address);
        self.targets.len() < len_before
    }

    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    pub fn has_target(&self, address: &str) -> bool {
        self.targets.iter().any(|t| t.address == address)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupResult {
    pub group_id: String,
    pub group_name: String,
    pub scan_results: HashMap<String, ScanResults>,
    pub group_stats: GroupStats,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupStats {
    pub total_targets: usize,
    pub scanned_targets: usize,
    pub total_ports_scanned: usize,
    pub total_open: usize,
    pub total_closed: usize,
    pub total_filtered: usize,
    pub unique_services: Vec<String>,
    pub per_target_stats: HashMap<String, TargetStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetStats {
    pub address: String,
    pub ports_scanned: usize,
    pub open_ports: usize,
    pub closed_ports: usize,
    pub filtered_ports: usize,
    pub services: HashMap<u16, String>,
}

impl GroupResult {
    pub fn from_scan_results(
        group: &ScanGroup,
        results: HashMap<String, ScanResults>,
    ) -> Self {
        let stats = GroupStats::compute(group, &results);
        Self {
            group_id: group.id.clone(),
            group_name: group.name.clone(),
            scan_results: results,
            group_stats: stats,
            completed_at: chrono::Utc::now(),
        }
    }

    pub fn all_open_ports(&self) -> Vec<(String, u16)> {
        let mut ports = Vec::new();
        for (target, results) in &self.scan_results {
            for r in &results.results {
                if r.state == PortState::Open {
                    ports.push((target.clone(), r.port));
                }
            }
        }
        ports
    }

    pub fn all_services(&self) -> HashMap<String, Vec<(u16, String)>> {
        let mut services: HashMap<String, Vec<(u16, String)>> = HashMap::new();
        for (target, results) in &self.scan_results {
            for r in &results.results {
                if r.state == PortState::Open {
                    if let Some(ref svc) = r.service {
                        services
                            .entry(target.clone())
                            .or_default()
                            .push((r.port, svc.clone()));
                    }
                }
            }
        }
        services
    }
}

impl GroupStats {
    pub fn compute(
        group: &ScanGroup,
        results: &HashMap<String, ScanResults>,
    ) -> Self {
        let mut total_open = 0;
        let mut total_closed = 0;
        let mut total_filtered = 0;
        let mut total_ports_scanned = 0;
        let mut all_services: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut per_target_stats = HashMap::new();

        for target in &group.targets {
            if let Some(scan_results) = results.get(&target.address) {
                let mut t_open = 0;
                let mut t_closed = 0;
                let mut t_filtered = 0;
                let mut t_services = HashMap::new();

                for r in &scan_results.results {
                    match r.state {
                        PortState::Open => {
                            t_open += 1;
                            if let Some(ref svc) = r.service {
                                t_services.insert(r.port, svc.clone());
                                all_services.insert(svc.clone());
                            }
                        }
                        PortState::Closed => t_closed += 1,
                        PortState::Filtered | PortState::OpenFiltered => {
                            t_filtered += 1;
                        }
                        _ => {}
                    }
                }

                total_open += t_open;
                total_closed += t_closed;
                total_filtered += t_filtered;
                total_ports_scanned += scan_results.results.len();

                per_target_stats.insert(
                    target.address.clone(),
                    TargetStats {
                        address: target.address.clone(),
                        ports_scanned: scan_results.results.len(),
                        open_ports: t_open,
                        closed_ports: t_closed,
                        filtered_ports: t_filtered,
                        services: t_services,
                    },
                );
            }
        }

        let mut unique_services: Vec<String> = all_services.into_iter().collect();
        unique_services.sort();

        Self {
            total_targets: group.targets.len(),
            scanned_targets: results.len(),
            total_ports_scanned,
            total_open,
            total_closed,
            total_filtered,
            unique_services,
            per_target_stats,
        }
    }

    pub fn open_port_ratio(&self) -> f64 {
        if self.total_ports_scanned == 0 {
            return 0.0;
        }
        self.total_open as f64 / self.total_ports_scanned as f64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupManager {
    groups: HashMap<String, ScanGroup>,
}

impl GroupManager {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    pub fn create_group(&mut self, name: &str, description: &str) -> String {
        let group = ScanGroup::new(name, description);
        let id = group.id.clone();
        self.groups.insert(id.clone(), group);
        id
    }

    pub fn get(&self, id: &str) -> Option<&ScanGroup> {
        self.groups.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut ScanGroup> {
        self.groups.get_mut(id)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&ScanGroup> {
        self.groups.values().find(|g| g.name == name)
    }

    pub fn list(&self) -> Vec<&ScanGroup> {
        self.groups.values().collect()
    }

    pub fn remove(&mut self, id: &str) -> Option<ScanGroup> {
        self.groups.remove(id)
    }

    pub fn len(&self) -> usize {
        self.groups.len()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    pub fn find_by_tag(&self, tag: &str) -> Vec<&ScanGroup> {
        self.groups
            .values()
            .filter(|g| g.tags.contains(&tag.to_string()))
            .collect()
    }

    pub fn all_targets(&self) -> Vec<String> {
        let mut targets: Vec<String> = self
            .groups
            .values()
            .flat_map(|g| g.targets.iter().map(|t| t.address.clone()))
            .collect();
        targets.sort();
        targets.dedup();
        targets
    }
}

impl Default for GroupManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{IpAddr, PortState, Protocol, ScanResult, ScanResults};

    fn create_test_scan_results(port: u16, state: PortState) -> ScanResults {
        ScanResults {
            scan_start: chrono::Utc::now(),
            scan_end: chrono::Utc::now(),
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
                timestamp: chrono::Utc::now(),
            }],
            os_fingerprints: Vec::new(),
            script_results: Vec::new(),
        }
    }

    #[test]
    fn test_group_creation() {
        let group = ScanGroup::new("web-servers", "Production web servers");
        assert_eq!(group.name, "web-servers");
        assert_eq!(group.description, "Production web servers");
        assert!(group.targets.is_empty());
        assert!(group.tags.is_empty());
        assert!(!group.id.is_empty());
    }

    #[test]
    fn test_group_add_targets() {
        let mut group = ScanGroup::new("test", "desc");
        group.add_target("192.168.1.1");
        group.add_target_with_label("192.168.1.2", "web-server");
        group.add_target_with_ports("192.168.1.3", "80,443");
        group.add_full_target("192.168.1.4", "db-server", "3306,5432");

        assert_eq!(group.target_count(), 4);
        assert!(group.has_target("192.168.1.1"));
        assert!(group.has_target("192.168.1.2"));
        assert!(!group.has_target("192.168.1.5"));

        let labeled = group.targets.iter().find(|t| t.address == "192.168.1.2").unwrap();
        assert_eq!(labeled.label.as_deref(), Some("web-server"));

        let with_ports = group.targets.iter().find(|t| t.address == "192.168.1.3").unwrap();
        assert_eq!(with_ports.ports.as_deref(), Some("80,443"));

        let full = group.targets.iter().find(|t| t.address == "192.168.1.4").unwrap();
        assert_eq!(full.label.as_deref(), Some("db-server"));
        assert_eq!(full.ports.as_deref(), Some("3306,5432"));
    }

    #[test]
    fn test_group_remove_target() {
        let mut group = ScanGroup::new("test", "desc");
        group.add_target("192.168.1.1");
        group.add_target("192.168.1.2");

        assert!(group.remove_target("192.168.1.1"));
        assert_eq!(group.target_count(), 1);
        assert!(!group.has_target("192.168.1.1"));
        assert!(!group.remove_target("192.168.1.5"));
    }

    #[test]
    fn test_group_tags() {
        let mut group = ScanGroup::new("test", "desc");
        group.add_tag("production");
        group.add_tag("web");
        group.add_tag("production");

        assert_eq!(group.tags.len(), 2);
        assert!(group.tags.contains(&"production".to_string()));
        assert!(group.tags.contains(&"web".to_string()));
    }

    #[test]
    fn test_group_manager() {
        let mut mgr = GroupManager::new();
        assert!(mgr.is_empty());

        let id = mgr.create_group("web", "Web servers");
        assert_eq!(mgr.len(), 1);
        assert!(mgr.get(&id).is_some());
        assert_eq!(mgr.get(&id).unwrap().name, "web");

        let by_name = mgr.get_by_name("web");
        assert!(by_name.is_some());
        assert_eq!(by_name.unwrap().id, id);

        assert!(mgr.get_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_group_manager_remove() {
        let mut mgr = GroupManager::new();
        let id = mgr.create_group("test", "desc");

        let removed = mgr.remove(&id);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "test");
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_group_manager_find_by_tag() {
        let mut mgr = GroupManager::new();

        let id1 = mgr.create_group("web", "Web servers");
        mgr.get_mut(&id1).unwrap().add_tag("production");

        let id2 = mgr.create_group("db", "DB servers");
        mgr.get_mut(&id2).unwrap().add_tag("production");
        mgr.get_mut(&id2).unwrap().add_tag("database");

        let id3 = mgr.create_group("dev", "Dev servers");
        mgr.get_mut(&id3).unwrap().add_tag("development");

        let prod = mgr.find_by_tag("production");
        assert_eq!(prod.len(), 2);

        let db = mgr.find_by_tag("database");
        assert_eq!(db.len(), 1);
        assert_eq!(db[0].name, "db");
    }

    #[test]
    fn test_group_manager_all_targets() {
        let mut mgr = GroupManager::new();

        let id1 = mgr.create_group("g1", "desc");
        mgr.get_mut(&id1).unwrap().add_target("192.168.1.1");
        mgr.get_mut(&id1).unwrap().add_target("192.168.1.2");

        let id2 = mgr.create_group("g2", "desc");
        mgr.get_mut(&id2).unwrap().add_target("192.168.1.2");
        mgr.get_mut(&id2).unwrap().add_target("192.168.1.3");

        let all = mgr.all_targets();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&"192.168.1.1".to_string()));
        assert!(all.contains(&"192.168.1.2".to_string()));
        assert!(all.contains(&"192.168.1.3".to_string()));
    }

    #[test]
    fn test_group_result_from_scan_results() {
        let mut group = ScanGroup::new("test", "desc");
        group.add_target("192.168.1.1");
        group.add_target("192.168.1.2");

        let mut results = HashMap::new();
        results.insert(
            "192.168.1.1".to_string(),
            create_test_scan_results(80, PortState::Open),
        );
        results.insert(
            "192.168.1.2".to_string(),
            create_test_scan_results(443, PortState::Closed),
        );

        let group_result = GroupResult::from_scan_results(&group, results);

        assert_eq!(group_result.group_name, "test");
        assert_eq!(group_result.group_stats.total_targets, 2);
        assert_eq!(group_result.group_stats.scanned_targets, 2);
        assert_eq!(group_result.group_stats.total_open, 1);
        assert_eq!(group_result.group_stats.total_closed, 1);
    }

    #[test]
    fn test_group_result_all_open_ports() {
        let mut group = ScanGroup::new("test", "desc");
        group.add_target("192.168.1.1");

        let mut results = HashMap::new();
        results.insert(
            "192.168.1.1".to_string(),
            ScanResults {
                scan_start: chrono::Utc::now(),
                scan_end: chrono::Utc::now(),
                target_count: 1,
                port_count: 2,
                results: vec![
                    ScanResult {
                        target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                        port: 80,
                        state: PortState::Open,
                        protocol: Protocol::TCP,
                        service: Some("http".to_string()),
                        service_info: None,
                        hostname: None,
                        reason: None,
                        timestamp: chrono::Utc::now(),
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
                        timestamp: chrono::Utc::now(),
                    },
                ],
                os_fingerprints: Vec::new(),
                script_results: Vec::new(),
            },
        );

        let group_result = GroupResult::from_scan_results(&group, results);
        let open = group_result.all_open_ports();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].0, "192.168.1.1");
        assert_eq!(open[0].1, 80);
    }

    #[test]
    fn test_group_stats_open_port_ratio() {
        let mut stats = GroupStats {
            total_targets: 1,
            scanned_targets: 1,
            total_ports_scanned: 10,
            total_open: 3,
            total_closed: 5,
            total_filtered: 2,
            unique_services: Vec::new(),
            per_target_stats: HashMap::new(),
        };

        let ratio = stats.open_port_ratio();
        assert!((ratio - 0.3).abs() < 0.001);

        stats.total_ports_scanned = 0;
        assert_eq!(stats.open_port_ratio(), 0.0);
    }

    #[test]
    fn test_group_result_all_services() {
        let mut group = ScanGroup::new("test", "desc");
        group.add_target("192.168.1.1");

        let mut results = HashMap::new();
        results.insert(
            "192.168.1.1".to_string(),
            ScanResults {
                scan_start: chrono::Utc::now(),
                scan_end: chrono::Utc::now(),
                target_count: 1,
                port_count: 2,
                results: vec![
                    ScanResult {
                        target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                        port: 80,
                        state: PortState::Open,
                        protocol: Protocol::TCP,
                        service: Some("http".to_string()),
                        service_info: None,
                        hostname: None,
                        reason: None,
                        timestamp: chrono::Utc::now(),
                    },
                    ScanResult {
                        target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                        port: 22,
                        state: PortState::Open,
                        protocol: Protocol::TCP,
                        service: Some("ssh".to_string()),
                        service_info: None,
                        hostname: None,
                        reason: None,
                        timestamp: chrono::Utc::now(),
                    },
                ],
                os_fingerprints: Vec::new(),
                script_results: Vec::new(),
            },
        );

        let group_result = GroupResult::from_scan_results(&group, results);
        let services = group_result.all_services();
        let target_svcs = services.get("192.168.1.1").unwrap();
        assert_eq!(target_svcs.len(), 2);
    }

    #[test]
    fn test_group_serialization() {
        let mut group = ScanGroup::new("test", "desc");
        group.add_target("192.168.1.1");
        group.add_tag("production");

        let json = serde_json::to_string(&group).unwrap();
        let loaded: ScanGroup = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.name, "test");
        assert_eq!(loaded.target_count(), 1);
        assert_eq!(loaded.tags, vec!["production"]);
    }

    #[test]
    fn test_group_manager_serialization() {
        let mut mgr = GroupManager::new();
        mgr.create_group("g1", "desc1");
        mgr.create_group("g2", "desc2");

        let json = serde_json::to_string(&mgr).unwrap();
        let loaded: GroupManager = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.len(), 2);
        assert!(loaded.get_by_name("g1").is_some());
        assert!(loaded.get_by_name("g2").is_some());
    }

    #[test]
    fn test_group_stats_unique_services() {
        let mut group = ScanGroup::new("test", "desc");
        group.add_target("192.168.1.1");
        group.add_target("192.168.1.2");

        let svc_result = ScanResults {
            scan_start: chrono::Utc::now(),
            scan_end: chrono::Utc::now(),
            target_count: 1,
            port_count: 1,
            results: vec![ScanResult {
                target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                port: 80,
                state: PortState::Open,
                protocol: Protocol::TCP,
                service: Some("http".to_string()),
                service_info: None,
                hostname: None,
                reason: None,
                timestamp: chrono::Utc::now(),
            }],
            os_fingerprints: Vec::new(),
            script_results: Vec::new(),
        };

        let mut results = HashMap::new();
        results.insert("192.168.1.1".to_string(), svc_result.clone());
        results.insert("192.168.1.2".to_string(), svc_result);

        let stats = GroupStats::compute(&group, &results);
        assert_eq!(stats.unique_services.len(), 1);
        assert!(stats.unique_services.contains(&"http".to_string()));
    }
}
