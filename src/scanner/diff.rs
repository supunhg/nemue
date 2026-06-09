// Scan comparison/diff module
// Compares two scan results and reports changes

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use crate::scanner::{ScanResult, ScanResults, PortState};

/// Changes between two scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiff {
    pub summary: DiffSummary,
    pub new_ports: Vec<PortChange>,
    pub closed_ports: Vec<PortChange>,
    pub changed_services: Vec<ServiceChange>,
    pub new_hosts: Vec<IpAddr>,
    pub removed_hosts: Vec<IpAddr>,
}

/// Summary of changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub scan_a_time: String,
    pub scan_b_time: String,
    pub total_changes: usize,
    pub new_ports: usize,
    pub closed_ports: usize,
    pub service_changes: usize,
    pub new_hosts: usize,
    pub removed_hosts: usize,
}

/// A port state change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortChange {
    pub host: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub old_state: String,
    pub new_state: String,
    pub service: Option<String>,
}

/// A service version change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceChange {
    pub host: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub old_service: Option<String>,
    pub new_service: Option<String>,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
}

/// Load scan results from a JSON file
pub fn load_scan<P: AsRef<Path>>(path: P) -> Result<ScanResults> {
    let contents = std::fs::read_to_string(path)?;
    let results: ScanResults = serde_json::from_str(&contents)?;
    Ok(results)
}

/// Compare two scan results and produce a diff
pub fn compare_scans(scan_a: &ScanResults, scan_b: &ScanResults) -> ScanDiff {
    // Index results by (host, port, protocol)
    let index_a = index_results(&scan_a.results);
    let index_b = index_results(&scan_b.results);

    // Find hosts
    let hosts_a: HashSet<IpAddr> = scan_a.results.iter().map(|r| r.target).collect();
    let hosts_b: HashSet<IpAddr> = scan_b.results.iter().map(|r| r.target).collect();

    let new_hosts: Vec<IpAddr> = hosts_b.difference(&hosts_a).cloned().collect();
    let removed_hosts: Vec<IpAddr> = hosts_a.difference(&hosts_b).cloned().collect();

    // Find port changes
    let mut new_ports = Vec::new();
    let mut closed_ports = Vec::new();
    let mut changed_services = Vec::new();

    // Check all ports in scan B
    for (key, result_b) in &index_b {
        if let Some(result_a) = index_a.get(key) {
            // Port exists in both scans - check for state change
            if result_a.state != result_b.state {
                if result_b.state == PortState::Open && result_a.state != PortState::Open {
                    new_ports.push(PortChange {
                        host: result_b.target,
                        port: result_b.port,
                        protocol: format!("{:?}", result_b.protocol),
                        old_state: format!("{:?}", result_a.state),
                        new_state: format!("{:?}", result_b.state),
                        service: result_b.service.clone(),
                    });
                } else if result_b.state != PortState::Open && result_a.state == PortState::Open {
                    closed_ports.push(PortChange {
                        host: result_b.target,
                        port: result_b.port,
                        protocol: format!("{:?}", result_b.protocol),
                        old_state: format!("{:?}", result_a.state),
                        new_state: format!("{:?}", result_b.state),
                        service: result_a.service.clone(),
                    });
                }
            }

            // Check for service change
            if result_a.service != result_b.service
                || get_version(result_a) != get_version(result_b)
            {
                changed_services.push(ServiceChange {
                    host: result_b.target,
                    port: result_b.port,
                    protocol: format!("{:?}", result_b.protocol),
                    old_service: result_a.service.clone(),
                    new_service: result_b.service.clone(),
                    old_version: get_version(result_a),
                    new_version: get_version(result_b),
                });
            }
        } else {
            // Port only in scan B - new port
            if result_b.state == PortState::Open {
                new_ports.push(PortChange {
                    host: result_b.target,
                    port: result_b.port,
                    protocol: format!("{:?}", result_b.protocol),
                    old_state: "unknown".to_string(),
                    new_state: "open".to_string(),
                    service: result_b.service.clone(),
                });
            }
        }
    }

    // Check for ports that disappeared from scan B
    for (key, result_a) in &index_a {
        if !index_b.contains_key(key) && result_a.state == PortState::Open {
            closed_ports.push(PortChange {
                host: result_a.target,
                port: result_a.port,
                protocol: format!("{:?}", result_a.protocol),
                old_state: "open".to_string(),
                new_state: "gone".to_string(),
                service: result_a.service.clone(),
            });
        }
    }

    // Sort results
    new_ports.sort_by(|a, b| a.host.cmp(&b.host).then(a.port.cmp(&b.port)));
    closed_ports.sort_by(|a, b| a.host.cmp(&b.host).then(a.port.cmp(&b.port)));
    changed_services.sort_by(|a, b| a.host.cmp(&b.host).then(a.port.cmp(&b.port)));

    let total_changes = new_ports.len() + closed_ports.len() + changed_services.len()
        + new_hosts.len() + removed_hosts.len();

    ScanDiff {
        summary: DiffSummary {
            scan_a_time: scan_a.scan_start.to_rfc3339(),
            scan_b_time: scan_b.scan_start.to_rfc3339(),
            total_changes,
            new_ports: new_ports.len(),
            closed_ports: closed_ports.len(),
            service_changes: changed_services.len(),
            new_hosts: new_hosts.len(),
            removed_hosts: removed_hosts.len(),
        },
        new_ports,
        closed_ports,
        changed_services,
        new_hosts,
        removed_hosts,
    }
}

/// Format a diff as human-readable text
pub fn format_diff_text(diff: &ScanDiff) -> String {
    let mut output = String::new();

    output.push_str("=== Scan Comparison Results ===\n\n");
    output.push_str(&format!("Scan A: {}\n", diff.summary.scan_a_time));
    output.push_str(&format!("Scan B: {}\n", diff.summary.scan_b_time));
    output.push_str(&format!("Total changes: {}\n\n", diff.summary.total_changes));

    // Summary
    output.push_str("--- Summary ---\n");
    output.push_str(&format!("  New open ports:    {}\n", diff.summary.new_ports));
    output.push_str(&format!("  Closed ports:      {}\n", diff.summary.closed_ports));
    output.push_str(&format!("  Service changes:   {}\n", diff.summary.service_changes));
    output.push_str(&format!("  New hosts:         {}\n", diff.summary.new_hosts));
    output.push_str(&format!("  Removed hosts:     {}\n", diff.summary.removed_hosts));

    // New ports
    if !diff.new_ports.is_empty() {
        output.push_str("\n--- New Open Ports ---\n");
        output.push_str("HOST                PORT     PROTO    SERVICE\n");
        for change in &diff.new_ports {
            output.push_str(&format!(
                "{:<18}  {:<7}  {:<7}  {}\n",
                change.host,
                change.port,
                change.protocol,
                change.service.as_deref().unwrap_or("unknown"),
            ));
        }
    }

    // Closed ports
    if !diff.closed_ports.is_empty() {
        output.push_str("\n--- Closed Ports ---\n");
        output.push_str("HOST                PORT     PROTO    SERVICE\n");
        for change in &diff.closed_ports {
            output.push_str(&format!(
                "{:<18}  {:<7}  {:<7}  {}\n",
                change.host,
                change.port,
                change.protocol,
                change.service.as_deref().unwrap_or("unknown"),
            ));
        }
    }

    // Service changes
    if !diff.changed_services.is_empty() {
        output.push_str("\n--- Service Changes ---\n");
        output.push_str("HOST                PORT     PROTO    OLD                      NEW\n");
        for change in &diff.changed_services {
            let old = format_service(&change.old_service, &change.old_version);
            let new = format_service(&change.new_service, &change.new_version);
            output.push_str(&format!(
                "{:<18}  {:<7}  {:<7}  {:<23}  {}\n",
                change.host, change.port, change.protocol, old, new,
            ));
        }
    }

    // New hosts
    if !diff.new_hosts.is_empty() {
        output.push_str("\n--- New Hosts ---\n");
        for host in &diff.new_hosts {
            output.push_str(&format!("  {}\n", host));
        }
    }

    // Removed hosts
    if !diff.removed_hosts.is_empty() {
        output.push_str("\n--- Removed Hosts ---\n");
        for host in &diff.removed_hosts {
            output.push_str(&format!("  {}\n", host));
        }
    }

    if diff.summary.total_changes == 0 {
        output.push_str("\nNo changes detected between scans.\n");
    }

    output
}

fn index_results(results: &[ScanResult]) -> HashMap<(IpAddr, u16, String), &ScanResult> {
    let mut index = HashMap::new();
    for result in results {
        let key = (result.target, result.port, format!("{:?}", result.protocol));
        index.insert(key, result);
    }
    index
}

fn get_version(result: &ScanResult) -> Option<String> {
    result.service_info.as_ref().and_then(|si| si.version.clone())
}

fn format_service(service: &Option<String>, version: &Option<String>) -> String {
    match (service, version) {
        (Some(s), Some(v)) => format!("{}/{}", s, v),
        (Some(s), None) => s.clone(),
        (None, _) => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Protocol, ScanResults};
    use chrono::Utc;
    use std::net::IpAddr;

    fn create_scan_a() -> ScanResults {
        ScanResults {
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
        }
    }

    fn create_scan_b() -> ScanResults {
        ScanResults {
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 1,
            port_count: 4,
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
                    state: PortState::Open,
                    protocol: Protocol::TCP,
                    service: Some("https".to_string()),
                    service_info: None,
                    hostname: None,
                    reason: None,
                    timestamp: Utc::now(),
                },
                ScanResult {
                    target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                    port: 8080,
                    state: PortState::Open,
                    protocol: Protocol::TCP,
                    service: Some("http-proxy".to_string()),
                    service_info: None,
                    hostname: None,
                    reason: None,
                    timestamp: Utc::now(),
                },
            ],
            os_fingerprints: Vec::new(),
            script_results: Vec::new(),
        }
    }

    #[test]
    fn test_compare_scans_new_ports() {
        let scan_a = create_scan_a();
        let scan_b = create_scan_b();
        let diff = compare_scans(&scan_a, &scan_b);

        // 443 changed from closed to open, 8080 is new
        assert_eq!(diff.new_ports.len(), 2);
        assert!(diff.new_ports.iter().any(|p| p.port == 443));
        assert!(diff.new_ports.iter().any(|p| p.port == 8080));
    }

    #[test]
    fn test_compare_scans_no_changes() {
        let scan_a = create_scan_a();
        let diff = compare_scans(&scan_a, &scan_a);
        assert_eq!(diff.summary.total_changes, 0);
    }

    #[test]
    fn test_format_diff_text() {
        let scan_a = create_scan_a();
        let scan_b = create_scan_b();
        let diff = compare_scans(&scan_a, &scan_b);
        let text = format_diff_text(&diff);

        assert!(text.contains("New Open Ports"));
        assert!(text.contains("443"));
        assert!(text.contains("8080"));
    }

    #[test]
    fn test_compare_scans_service_change() {
        let mut scan_a = create_scan_a();
        let mut scan_b = create_scan_a();

        // Change service on port 80
        scan_b.results[1].service = Some("nginx".to_string());

        let diff = compare_scans(&scan_a, &scan_b);
        assert_eq!(diff.changed_services.len(), 1);
        assert_eq!(diff.changed_services[0].port, 80);
    }
}
