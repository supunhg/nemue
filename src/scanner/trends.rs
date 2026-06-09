use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::scanner::diff::compare_scans;
use crate::scanner::history::{HistoryEntry, ScanHistory};
use crate::scanner::PortState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendReport {
    pub period: String,
    pub generated_at: DateTime<Utc>,
    pub scan_count: usize,
    pub new_ports: Vec<PortTrend>,
    pub closed_ports: Vec<PortTrend>,
    pub service_changes: Vec<ServiceTrend>,
    pub summary: TrendSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortTrend {
    pub host: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub change_time: DateTime<Utc>,
    pub old_state: String,
    pub new_state: String,
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceTrend {
    pub host: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub change_time: DateTime<Utc>,
    pub old_service: Option<String>,
    pub new_service: Option<String>,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendSummary {
    pub total_scans_analyzed: usize,
    pub total_new_ports: usize,
    pub total_closed_ports: usize,
    pub total_service_changes: usize,
    pub period_start: Option<DateTime<Utc>>,
    pub period_end: Option<DateTime<Utc>>,
    pub stability_score: f64,
}

pub struct TrendAnalyzer;

impl TrendAnalyzer {
    pub fn analyze(history: &ScanHistory, target: &str) -> TrendReport {
        let entries: Vec<&HistoryEntry> = history
            .scans
            .iter()
            .filter(|e| e.target == target)
            .collect();

        if entries.len() < 2 {
            return TrendReport {
                period: "N/A".to_string(),
                generated_at: Utc::now(),
                scan_count: entries.len(),
                new_ports: Vec::new(),
                closed_ports: Vec::new(),
                service_changes: Vec::new(),
                summary: TrendSummary {
                    total_scans_analyzed: entries.len(),
                    total_new_ports: 0,
                    total_closed_ports: 0,
                    total_service_changes: 0,
                    period_start: entries.first().map(|e| e.timestamp),
                    period_end: entries.last().map(|e| e.timestamp),
                    stability_score: 100.0,
                },
            };
        }

        let period_start = entries.first().unwrap().timestamp;
        let period_end = entries.last().unwrap().timestamp;
        let period = format_duration(period_start, period_end);

        let mut all_new_ports = Vec::new();
        let mut all_closed_ports = Vec::new();
        let mut all_service_changes = Vec::new();

        for window in entries.windows(2) {
            let prev = &window[0];
            let curr = &window[1];
            let diff = compare_scans(&prev.results, &curr.results);

            for np in &diff.new_ports {
                all_new_ports.push(PortTrend {
                    host: np.host,
                    port: np.port,
                    protocol: np.protocol.clone(),
                    change_time: curr.timestamp,
                    old_state: np.old_state.clone(),
                    new_state: np.new_state.clone(),
                    service: np.service.clone(),
                });
            }

            for cp in &diff.closed_ports {
                all_closed_ports.push(PortTrend {
                    host: cp.host,
                    port: cp.port,
                    protocol: cp.protocol.clone(),
                    change_time: curr.timestamp,
                    old_state: cp.old_state.clone(),
                    new_state: cp.new_state.clone(),
                    service: cp.service.clone(),
                });
            }

            for sc in &diff.changed_services {
                all_service_changes.push(ServiceTrend {
                    host: sc.host,
                    port: sc.port,
                    protocol: sc.protocol.clone(),
                    change_time: curr.timestamp,
                    old_service: sc.old_service.clone(),
                    new_service: sc.new_service.clone(),
                    old_version: sc.old_version.clone(),
                    new_version: sc.new_version.clone(),
                });
            }
        }

        let total_new = all_new_ports.len();
        let total_closed = all_closed_ports.len();
        let total_service = all_service_changes.len();
        let total_changes = total_new + total_closed + total_service;
        let scan_pairs = entries.len() - 1;
        let stability_score = if scan_pairs > 0 {
            let max_possible_changes = scan_pairs * 100;
            let score = 100.0 - ((total_changes as f64 / max_possible_changes as f64) * 100.0);
            score.max(0.0).min(100.0)
        } else {
            100.0
        };

        TrendReport {
            period,
            generated_at: Utc::now(),
            scan_count: entries.len(),
            new_ports: all_new_ports,
            closed_ports: all_closed_ports,
            service_changes: all_service_changes,
            summary: TrendSummary {
                total_scans_analyzed: entries.len(),
                total_new_ports: total_new,
                total_closed_ports: total_closed,
                total_service_changes: total_service,
                period_start: Some(period_start),
                period_end: Some(period_end),
                stability_score,
            },
        }
    }

    pub fn analyze_range(
        history: &ScanHistory,
        target: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> TrendReport {
        let entries: Vec<&HistoryEntry> = history
            .scans
            .iter()
            .filter(|e| e.target == target && e.timestamp >= start && e.timestamp <= end)
            .collect();

        if entries.len() < 2 {
            return TrendReport {
                period: format_duration(start, end),
                generated_at: Utc::now(),
                scan_count: entries.len(),
                new_ports: Vec::new(),
                closed_ports: Vec::new(),
                service_changes: Vec::new(),
                summary: TrendSummary {
                    total_scans_analyzed: entries.len(),
                    total_new_ports: 0,
                    total_closed_ports: 0,
                    total_service_changes: 0,
                    period_start: Some(start),
                    period_end: Some(end),
                    stability_score: 100.0,
                },
            };
        }

        let mut all_new_ports = Vec::new();
        let mut all_closed_ports = Vec::new();
        let mut all_service_changes = Vec::new();

        for window in entries.windows(2) {
            let prev = &window[0];
            let curr = &window[1];
            let diff = compare_scans(&prev.results, &curr.results);

            for np in &diff.new_ports {
                all_new_ports.push(PortTrend {
                    host: np.host,
                    port: np.port,
                    protocol: np.protocol.clone(),
                    change_time: curr.timestamp,
                    old_state: np.old_state.clone(),
                    new_state: np.new_state.clone(),
                    service: np.service.clone(),
                });
            }

            for cp in &diff.closed_ports {
                all_closed_ports.push(PortTrend {
                    host: cp.host,
                    port: cp.port,
                    protocol: cp.protocol.clone(),
                    change_time: curr.timestamp,
                    old_state: cp.old_state.clone(),
                    new_state: cp.new_state.clone(),
                    service: cp.service.clone(),
                });
            }

            for sc in &diff.changed_services {
                all_service_changes.push(ServiceTrend {
                    host: sc.host,
                    port: sc.port,
                    protocol: sc.protocol.clone(),
                    change_time: curr.timestamp,
                    old_service: sc.old_service.clone(),
                    new_service: sc.new_service.clone(),
                    old_version: sc.old_version.clone(),
                    new_version: sc.new_version.clone(),
                });
            }
        }

        let total_new = all_new_ports.len();
        let total_closed = all_closed_ports.len();
        let total_service = all_service_changes.len();
        let total_changes = total_new + total_closed + total_service;
        let scan_pairs = entries.len() - 1;
        let stability_score = if scan_pairs > 0 {
            let max_possible_changes = scan_pairs * 100;
            let score = 100.0 - ((total_changes as f64 / max_possible_changes as f64) * 100.0);
            score.max(0.0).min(100.0)
        } else {
            100.0
        };

        TrendReport {
            period: format_duration(start, end),
            generated_at: Utc::now(),
            scan_count: entries.len(),
            new_ports: all_new_ports,
            closed_ports: all_closed_ports,
            service_changes: all_service_changes,
            summary: TrendSummary {
                total_scans_analyzed: entries.len(),
                total_new_ports: total_new,
                total_closed_ports: total_closed,
                total_service_changes: total_service,
                period_start: Some(start),
                period_end: Some(end),
                stability_score,
            },
        }
    }

    pub fn format_report(report: &TrendReport) -> String {
        let mut output = String::new();

        output.push_str("=== Trend Analysis Report ===\n\n");
        output.push_str(&format!("Period: {}\n", report.period));
        output.push_str(&format!("Generated: {}\n", report.generated_at.format("%Y-%m-%d %H:%M:%S UTC")));
        output.push_str(&format!("Scans analyzed: {}\n", report.scan_count));
        output.push_str(&format!("Stability score: {:.1}%\n\n", report.summary.stability_score));

        output.push_str("--- Summary ---\n");
        output.push_str(&format!("  New ports appeared:    {}\n", report.summary.total_new_ports));
        output.push_str(&format!("  Ports closed:         {}\n", report.summary.total_closed_ports));
        output.push_str(&format!("  Service changes:      {}\n", report.summary.total_service_changes));

        if !report.new_ports.is_empty() {
            output.push_str("\n--- New Ports (over time) ---\n");
            output.push_str("TIME                     HOST                PORT     SERVICE\n");
            for trend in &report.new_ports {
                output.push_str(&format!(
                    "{:<24} {:<18} {:<7} {}\n",
                    trend.change_time.format("%Y-%m-%d %H:%M"),
                    trend.host,
                    trend.port,
                    trend.service.as_deref().unwrap_or("unknown"),
                ));
            }
        }

        if !report.closed_ports.is_empty() {
            output.push_str("\n--- Closed Ports (over time) ---\n");
            output.push_str("TIME                     HOST                PORT     SERVICE\n");
            for trend in &report.closed_ports {
                output.push_str(&format!(
                    "{:<24} {:<18} {:<7} {}\n",
                    trend.change_time.format("%Y-%m-%d %H:%M"),
                    trend.host,
                    trend.port,
                    trend.service.as_deref().unwrap_or("unknown"),
                ));
            }
        }

        if !report.service_changes.is_empty() {
            output.push_str("\n--- Service Changes ---\n");
            output.push_str("TIME                     HOST                PORT     OLD                      NEW\n");
            for trend in &report.service_changes {
                let old = format_service_opt(&trend.old_service, &trend.old_version);
                let new = format_service_opt(&trend.new_service, &trend.new_version);
                output.push_str(&format!(
                    "{:<24} {:<18} {:<7} {:<23} {}\n",
                    trend.change_time.format("%Y-%m-%d %H:%M"),
                    trend.host,
                    trend.port,
                    old,
                    new,
                ));
            }
        }

        if report.summary.total_new_ports == 0
            && report.summary.total_closed_ports == 0
            && report.summary.total_service_changes == 0
        {
            output.push_str("\nNo changes detected across scans.\n");
        }

        output
    }
}

fn format_duration(start: DateTime<Utc>, end: DateTime<Utc>) -> String {
    let duration = end - start;
    if duration.num_days() > 0 {
        format!("{} day(s)", duration.num_days())
    } else if duration.num_hours() > 0 {
        format!("{} hour(s)", duration.num_hours())
    } else if duration.num_minutes() > 0 {
        format!("{} minute(s)", duration.num_minutes())
    } else {
        format!("{} second(s)", duration.num_seconds())
    }
}

fn format_service_opt(service: &Option<String>, version: &Option<String>) -> String {
    match (service, version) {
        (Some(s), Some(v)) => format!("{}/{}", s, v),
        (Some(s), None) => s.clone(),
        (None, _) => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::history::ScanHistory;
    use crate::scanner::{Protocol, ScanResult, ScanResults};

    fn create_results(port: u16, state: PortState, service: Option<&str>) -> ScanResults {
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
                service: service.map(|s| s.to_string()),
                service_info: None,
                hostname: None,
                reason: None,
                timestamp: Utc::now(),
            }],
            os_fingerprints: Vec::new(),
            script_results: Vec::new(),
        }
    }

    fn create_multi_results(ports: &[(u16, PortState, Option<&str>)]) -> ScanResults {
        ScanResults {
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 1,
            port_count: ports.len(),
            results: ports
                .iter()
                .map(|(port, state, service)| ScanResult {
                    target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                    port: *port,
                    state: state.clone(),
                    protocol: Protocol::TCP,
                    service: service.map(|s| s.to_string()),
                    service_info: None,
                    hostname: None,
                    reason: None,
                    timestamp: Utc::now(),
                })
                .collect(),
            os_fingerprints: Vec::new(),
            script_results: Vec::new(),
        }
    }

    #[test]
    fn test_analyze_insufficient_data() {
        let mut history = ScanHistory::new();
        history.add_entry("192.168.1.1".to_string(), create_results(80, PortState::Open, Some("http")));

        let report = TrendAnalyzer::analyze(&history, "192.168.1.1");
        assert_eq!(report.scan_count, 1);
        assert_eq!(report.summary.total_new_ports, 0);
        assert_eq!(report.summary.stability_score, 100.0);
    }

    #[test]
    fn test_analyze_new_port_detected() {
        let mut history = ScanHistory::new();
        history.add_entry(
            "192.168.1.1".to_string(),
            create_multi_results(&[(22, PortState::Open, Some("ssh"))]),
        );
        history.add_entry(
            "192.168.1.1".to_string(),
            create_multi_results(&[
                (22, PortState::Open, Some("ssh")),
                (80, PortState::Open, Some("http")),
            ]),
        );

        let report = TrendAnalyzer::analyze(&history, "192.168.1.1");
        assert_eq!(report.scan_count, 2);
        assert_eq!(report.summary.total_new_ports, 1);
        assert_eq!(report.new_ports[0].port, 80);
    }

    #[test]
    fn test_analyze_port_closed() {
        let mut history = ScanHistory::new();
        history.add_entry(
            "192.168.1.1".to_string(),
            create_multi_results(&[
                (22, PortState::Open, Some("ssh")),
                (80, PortState::Open, Some("http")),
            ]),
        );
        history.add_entry(
            "192.168.1.1".to_string(),
            create_multi_results(&[(22, PortState::Open, Some("ssh"))]),
        );

        let report = TrendAnalyzer::analyze(&history, "192.168.1.1");
        assert_eq!(report.summary.total_closed_ports, 1);
        assert_eq!(report.closed_ports[0].port, 80);
    }

    #[test]
    fn test_analyze_service_change() {
        let mut history = ScanHistory::new();
        history.add_entry(
            "192.168.1.1".to_string(),
            create_results(80, PortState::Open, Some("apache")),
        );
        history.add_entry(
            "192.168.1.1".to_string(),
            create_results(80, PortState::Open, Some("nginx")),
        );

        let report = TrendAnalyzer::analyze(&history, "192.168.1.1");
        assert_eq!(report.summary.total_service_changes, 1);
        assert_eq!(report.service_changes[0].old_service, Some("apache".to_string()));
        assert_eq!(report.service_changes[0].new_service, Some("nginx".to_string()));
    }

    #[test]
    fn test_analyze_no_changes() {
        let mut history = ScanHistory::new();
        history.add_entry(
            "192.168.1.1".to_string(),
            create_results(80, PortState::Open, Some("http")),
        );
        history.add_entry(
            "192.168.1.1".to_string(),
            create_results(80, PortState::Open, Some("http")),
        );

        let report = TrendAnalyzer::analyze(&history, "192.168.1.1");
        assert_eq!(report.summary.total_new_ports, 0);
        assert_eq!(report.summary.total_closed_ports, 0);
        assert_eq!(report.summary.total_service_changes, 0);
    }

    #[test]
    fn test_analyze_multiple_scans() {
        let mut history = ScanHistory::new();
        history.add_entry(
            "192.168.1.1".to_string(),
            create_multi_results(&[(22, PortState::Open, Some("ssh"))]),
        );
        history.add_entry(
            "192.168.1.1".to_string(),
            create_multi_results(&[
                (22, PortState::Open, Some("ssh")),
                (80, PortState::Open, Some("http")),
            ]),
        );
        history.add_entry(
            "192.168.1.1".to_string(),
            create_multi_results(&[
                (22, PortState::Open, Some("ssh")),
                (80, PortState::Open, Some("http")),
                (443, PortState::Open, Some("https")),
            ]),
        );

        let report = TrendAnalyzer::analyze(&history, "192.168.1.1");
        assert_eq!(report.scan_count, 3);
        assert_eq!(report.summary.total_new_ports, 2);
        assert!(report.new_ports.iter().any(|p| p.port == 80));
        assert!(report.new_ports.iter().any(|p| p.port == 443));
    }

    #[test]
    fn test_format_report() {
        let mut history = ScanHistory::new();
        history.add_entry(
            "192.168.1.1".to_string(),
            create_results(80, PortState::Open, Some("http")),
        );
        history.add_entry(
            "192.168.1.1".to_string(),
            create_multi_results(&[
                (80, PortState::Open, Some("http")),
                (443, PortState::Open, Some("https")),
            ]),
        );

        let report = TrendAnalyzer::analyze(&history, "192.168.1.1");
        let text = TrendAnalyzer::format_report(&report);

        assert!(text.contains("Trend Analysis Report"));
        assert!(text.contains("New Ports"));
        assert!(text.contains("443"));
        assert!(text.contains("Stability score"));
    }

    #[test]
    fn test_trend_serialization() {
        let mut history = ScanHistory::new();
        history.add_entry(
            "192.168.1.1".to_string(),
            create_results(80, PortState::Open, Some("http")),
        );
        history.add_entry(
            "192.168.1.1".to_string(),
            create_results(443, PortState::Open, Some("https")),
        );

        let report = TrendAnalyzer::analyze(&history, "192.168.1.1");
        let json = serde_json::to_string(&report).unwrap();
        let loaded: TrendReport = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.scan_count, 2);
        assert_eq!(loaded.summary.total_new_ports, 1);
    }

    #[test]
    fn test_analyze_different_target_ignored() {
        let mut history = ScanHistory::new();
        history.add_entry(
            "192.168.1.1".to_string(),
            create_results(80, PortState::Open, Some("http")),
        );
        history.add_entry(
            "10.0.0.1".to_string(),
            create_results(443, PortState::Open, Some("https")),
        );

        let report = TrendAnalyzer::analyze(&history, "192.168.1.1");
        assert_eq!(report.scan_count, 1);
    }
}
