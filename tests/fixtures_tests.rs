use nemue::scanner::{ScanResults, ScanResult, PortState, Protocol};
use nemue::reporting::{
    ReportBuilder, ReportMetadata, ExecutiveSummary, VulnerabilitySummary,
    ComplianceStatus, ComplianceFramework, Finding, Severity, Recommendation,
    Priority, ScanReport,
};
use nemue::scanner::config::NemueConfig;
use chrono::Utc;
use std::net::IpAddr;

// =============================================================================
// Sample Configurations
// =============================================================================

pub fn minimal_config_toml() -> &'static str {
    r#"
[scan]
timing = "T3"
scan_type = "connect"
rate = 1000
timeout_ms = 1000
"#
}

pub fn full_config_toml() -> &'static str {
    r#"
[scan]
timing = "T4"
scan_type = "syn"
rate = 5000
timeout_ms = 2000
version_detect = true
os_detect = true

[output]
format = "json"
color = true
progress = true

[performance]
adaptive_rate = true
buffer_pool_size = 2000
max_concurrent_targets = 8
"#
}

pub fn aggressive_config_toml() -> &'static str {
    r#"
[scan]
timing = "T5"
scan_type = "syn"
rate = 10000
timeout_ms = 500
version_detect = true
os_detect = true

[output]
format = "json"
color = false
progress = false

[performance]
adaptive_rate = false
buffer_pool_size = 4000
max_concurrent_targets = 16
"#
}

// =============================================================================
// Sample Scan Results
// =============================================================================

pub fn open_port_results() -> ScanResults {
    ScanResults {
        scan_start: Utc::now(),
        scan_end: Utc::now(),
        target_count: 1,
        port_count: 3,
        results: vec![
            ScanResult {
                target: "192.168.1.1".parse().unwrap(),
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
                target: "192.168.1.1".parse().unwrap(),
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
                target: "192.168.1.1".parse().unwrap(),
                port: 443,
                state: PortState::Open,
                protocol: Protocol::TCP,
                service: Some("https".to_string()),
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

pub fn mixed_state_results() -> ScanResults {
    ScanResults {
        scan_start: Utc::now(),
        scan_end: Utc::now(),
        target_count: 2,
        port_count: 6,
        results: vec![
            ScanResult {
                target: "10.0.0.1".parse().unwrap(),
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
                target: "10.0.0.1".parse().unwrap(),
                port: 80,
                state: PortState::Closed,
                protocol: Protocol::TCP,
                service: None,
                service_info: None,
                hostname: None,
                reason: None,
                timestamp: Utc::now(),
            },
            ScanResult {
                target: "10.0.0.1".parse().unwrap(),
                port: 443,
                state: PortState::Filtered,
                protocol: Protocol::TCP,
                service: None,
                service_info: None,
                hostname: None,
                reason: None,
                timestamp: Utc::now(),
            },
            ScanResult {
                target: "10.0.0.2".parse().unwrap(),
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
                target: "10.0.0.2".parse().unwrap(),
                port: 3306,
                state: PortState::Open,
                protocol: Protocol::TCP,
                service: Some("mysql".to_string()),
                service_info: None,
                hostname: None,
                reason: None,
                timestamp: Utc::now(),
            },
            ScanResult {
                target: "10.0.0.2".parse().unwrap(),
                port: 8080,
                state: PortState::OpenFiltered,
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

pub fn udp_results() -> ScanResults {
    ScanResults {
        scan_start: Utc::now(),
        scan_end: Utc::now(),
        target_count: 1,
        port_count: 3,
        results: vec![
            ScanResult {
                target: "192.168.1.1".parse().unwrap(),
                port: 53,
                state: PortState::Open,
                protocol: Protocol::UDP,
                service: Some("dns".to_string()),
                service_info: None,
                hostname: None,
                reason: None,
                timestamp: Utc::now(),
            },
            ScanResult {
                target: "192.168.1.1".parse().unwrap(),
                port: 161,
                state: PortState::OpenFiltered,
                protocol: Protocol::UDP,
                service: Some("snmp".to_string()),
                service_info: None,
                hostname: None,
                reason: None,
                timestamp: Utc::now(),
            },
            ScanResult {
                target: "192.168.1.1".parse().unwrap(),
                port: 123,
                state: PortState::Open,
                protocol: Protocol::UDP,
                service: Some("ntp".to_string()),
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

pub fn large_results(count: usize) -> ScanResults {
    let results: Vec<ScanResult> = (0..count)
        .map(|i| ScanResult {
            target: format!("192.168.{}.{}", (i / 256) % 256, i % 256).parse().unwrap(),
            port: (1024 + (i as u16 % 64511)),
            state: if i % 3 == 0 { PortState::Open } else if i % 3 == 1 { PortState::Closed } else { PortState::Filtered },
            protocol: Protocol::TCP,
            service: if i % 3 == 0 { Some("http".to_string()) } else { None },
            service_info: None,
            hostname: None,
            reason: None,
            timestamp: Utc::now(),
        })
        .collect();

    ScanResults {
        scan_start: Utc::now(),
        scan_end: Utc::now(),
        target_count: count,
        port_count: 1,
        results,
        os_fingerprints: Vec::new(),
        script_results: Vec::new(),
    }
}

// =============================================================================
// Sample Reports
// =============================================================================

pub fn minimal_report() -> ScanReport {
    ReportBuilder::new()
        .metadata(ReportMetadata {
            scan_id: "min-scan".to_string(),
            report_id: "min-report".to_string(),
            generated_at: Utc::now(),
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 1,
            version: "0.1.0".to_string(),
        })
        .summary(ExecutiveSummary {
            total_hosts: 1,
            hosts_up: 1,
            total_ports: 100,
            open_ports: 5,
            vulnerabilities: VulnerabilitySummary {
                critical: 0,
                high: 0,
                medium: 1,
                low: 2,
                info: 2,
            },
            risk_score: 3.0,
            compliance_score: 90.0,
        })
        .compliance(ComplianceStatus {
            frameworks: vec![],
            overall_score: 90.0,
        })
        .build()
        .unwrap()
}

pub fn comprehensive_report() -> ScanReport {
    ReportBuilder::new()
        .metadata(ReportMetadata {
            scan_id: "comp-scan-001".to_string(),
            report_id: "comp-report-001".to_string(),
            generated_at: Utc::now(),
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 50,
            version: "0.1.0".to_string(),
        })
        .summary(ExecutiveSummary {
            total_hosts: 50,
            hosts_up: 42,
            total_ports: 5000,
            open_ports: 210,
            vulnerabilities: VulnerabilitySummary {
                critical: 3,
                high: 8,
                medium: 15,
                low: 20,
                info: 50,
            },
            risk_score: 8.2,
            compliance_score: 65.0,
        })
        .compliance(ComplianceStatus {
            frameworks: vec![
                ComplianceFramework {
                    name: "PCI-DSS".to_string(),
                    version: "4.0".to_string(),
                    controls_total: 100,
                    controls_passing: 65,
                    controls_failing: 35,
                    score: 65.0,
                    findings: vec!["Weak encryption".to_string()],
                },
                ComplianceFramework {
                    name: "HIPAA".to_string(),
                    version: "2023".to_string(),
                    controls_total: 50,
                    controls_passing: 40,
                    controls_failing: 10,
                    score: 80.0,
                    findings: vec![],
                },
            ],
            overall_score: 72.5,
        })
        .add_finding(Finding {
            id: "F001".to_string(),
            severity: Severity::Critical,
            title: "Remote Code Execution via Deserialization".to_string(),
            description: "Untrusted data deserialization allows remote code execution".to_string(),
            affected_hosts: vec!["10.0.0.5".to_string(), "10.0.0.6".to_string()],
            cvss_score: Some(9.8),
            cve_ids: vec!["CVE-2024-1234".to_string()],
            remediation: "Upgrade library to patched version".to_string(),
        })
        .add_finding(Finding {
            id: "F002".to_string(),
            severity: Severity::High,
            title: "SQL Injection in Authentication".to_string(),
            description: "User input not properly sanitized in login form".to_string(),
            affected_hosts: vec!["10.0.0.10".to_string()],
            cvss_score: Some(8.1),
            cve_ids: vec!["CVE-2024-5678".to_string()],
            remediation: "Use parameterized queries".to_string(),
        })
        .add_finding(Finding {
            id: "F003".to_string(),
            severity: Severity::Medium,
            title: "Missing Security Headers".to_string(),
            description: "HTTP responses missing X-Frame-Options and CSP headers".to_string(),
            affected_hosts: vec!["10.0.0.10".to_string(), "10.0.0.20".to_string()],
            cvss_score: Some(5.3),
            cve_ids: vec![],
            remediation: "Add security headers to web server configuration".to_string(),
        })
        .add_recommendation(Recommendation {
            priority: Priority::Critical,
            category: "Patch Management".to_string(),
            title: "Apply critical security patches".to_string(),
            description: "Install vendor patches for critical vulnerabilities".to_string(),
            impact: "High".to_string(),
            effort: "Medium".to_string(),
        })
        .add_recommendation(Recommendation {
            priority: Priority::High,
            category: "Configuration".to_string(),
            title: "Harden web server configuration".to_string(),
            description: "Add security headers and disable unnecessary features".to_string(),
            impact: "Medium".to_string(),
            effort: "Low".to_string(),
        })
        .build()
        .unwrap()
}

// =============================================================================
// Test Data Generators
// =============================================================================

pub fn generate_scan_results(target_count: usize, ports_per_target: usize) -> ScanResults {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut results = Vec::with_capacity(target_count * ports_per_target);

    for t in 0..target_count {
        let ip = format!("192.168.{}.{}", (t / 256) % 256, t % 256);
        for p in 0..ports_per_target {
            let port = (1024 + p) as u16;
            let state = match rng.gen_range(0..4) {
                0 => PortState::Open,
                1 => PortState::Closed,
                2 => PortState::Filtered,
                _ => PortState::OpenFiltered,
            };
            results.push(ScanResult {
                target: ip.parse().unwrap(),
                port,
                state,
                protocol: Protocol::TCP,
                service: if rng.gen_bool(0.3) { Some("http".to_string()) } else { None },
                service_info: None,
                hostname: None,
                reason: None,
                timestamp: Utc::now(),
            });
        }
    }

    ScanResults {
        scan_start: Utc::now(),
        scan_end: Utc::now(),
        target_count,
        port_count: ports_per_target,
        results,
        os_fingerprints: Vec::new(),
        script_results: Vec::new(),
    }
}

pub fn generate_report(finding_count: usize) -> ScanReport {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut builder = ReportBuilder::new()
        .metadata(ReportMetadata {
            scan_id: "gen-scan".to_string(),
            report_id: "gen-report".to_string(),
            generated_at: Utc::now(),
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 100,
            version: "0.1.0".to_string(),
        })
        .summary(ExecutiveSummary {
            total_hosts: 100,
            hosts_up: 85,
            total_ports: 10000,
            open_ports: 4500,
            vulnerabilities: VulnerabilitySummary {
                critical: rng.gen_range(0..5),
                high: rng.gen_range(5..15),
                medium: rng.gen_range(10..30),
                low: rng.gen_range(20..50),
                info: rng.gen_range(50..100),
            },
            risk_score: rng.gen_range(3.0..9.0),
            compliance_score: rng.gen_range(60.0..95.0),
        })
        .compliance(ComplianceStatus {
            frameworks: vec![],
            overall_score: 75.0,
        });

    for i in 0..finding_count {
        let severity = match rng.gen_range(0..5) {
            0 => Severity::Critical,
            1 => Severity::High,
            2 => Severity::Medium,
            3 => Severity::Low,
            _ => Severity::Info,
        };
        builder = builder.add_finding(Finding {
            id: format!("GEN-{:04}", i),
            severity,
            title: format!("Generated Finding {}", i),
            description: format!("Auto-generated finding description {}", i),
            affected_hosts: vec![format!("192.168.1.{}", rng.gen_range(1..255))],
            cvss_score: Some(rng.gen_range(0.0..10.0)),
            cve_ids: vec![format!("CVE-2024-{:04}", rng.gen_range(0..9999))],
            remediation: "Apply recommended patches".to_string(),
        });
    }

    builder.build().unwrap()
}

pub fn generate_ip_list(count: usize) -> Vec<IpAddr> {
    (0..count)
        .map(|i| format!("10.0.{}.{}", (i / 256) % 256, i % 256).parse().unwrap())
        .collect()
}

// =============================================================================
// Fixture Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_config_fixture() {
        let config: NemueConfig = toml::from_str(minimal_config_toml()).unwrap();
        assert_eq!(config.scan.timing, "T3");
        assert_eq!(config.scan.rate, 1000);
    }

    #[test]
    fn test_full_config_fixture() {
        let config: NemueConfig = toml::from_str(full_config_toml()).unwrap();
        assert_eq!(config.scan.timing, "T4");
        assert!(config.scan.version_detect);
    }

    #[test]
    fn test_aggressive_config_fixture() {
        let config: NemueConfig = toml::from_str(aggressive_config_toml()).unwrap();
        assert_eq!(config.scan.timing, "T5");
        assert!(!config.output.color);
    }

    #[test]
    fn test_open_port_results_fixture() {
        let results = open_port_results();
        assert_eq!(results.results.len(), 3);
        assert!(results.results.iter().all(|r| r.state == PortState::Open));
    }

    #[test]
    fn test_mixed_state_results_fixture() {
        let results = mixed_state_results();
        assert_eq!(results.results.len(), 6);
        assert!(results.results.iter().any(|r| r.state == PortState::Open));
        assert!(results.results.iter().any(|r| r.state == PortState::Closed));
    }

    #[test]
    fn test_udp_results_fixture() {
        let results = udp_results();
        assert!(results.results.iter().all(|r| r.protocol == Protocol::UDP));
    }

    #[test]
    fn test_large_results_fixture() {
        let results = large_results(100);
        assert_eq!(results.results.len(), 100);
    }

    #[test]
    fn test_minimal_report_fixture() {
        let report = minimal_report();
        assert_eq!(report.metadata.target_count, 1);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_comprehensive_report_fixture() {
        let report = comprehensive_report();
        assert_eq!(report.findings.len(), 3);
        assert_eq!(report.recommendations.len(), 2);
        assert_eq!(report.compliance.frameworks.len(), 2);
    }

    #[test]
    fn test_generate_scan_results() {
        let results = generate_scan_results(5, 10);
        assert_eq!(results.results.len(), 50);
        assert_eq!(results.target_count, 5);
    }

    #[test]
    fn test_generate_report() {
        let report = generate_report(10);
        assert_eq!(report.findings.len(), 10);
    }

    #[test]
    fn test_generate_ip_list() {
        let ips = generate_ip_list(256);
        assert_eq!(ips.len(), 256);
    }
}
