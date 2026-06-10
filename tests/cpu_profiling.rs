use std::time::{Duration, Instant};
use nemue::scanner::{PortParser, TargetParser};
use nemue::performance::Profiler;

#[test]
fn test_port_parser_cpu_efficiency() {
    let start = Instant::now();
    let iterations = 50000;

    for _ in 0..iterations {
        let _ = PortParser::parse("22,80,443,8080,3306,5432,6379");
    }

    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() as f64 / iterations as f64;

    assert!(avg_micros < 100.0, "Average port parse time: {:.2}µs", avg_micros);
}

#[test]
fn test_target_parser_cpu_efficiency() {
    let start = Instant::now();
    let iterations = 50000;

    for _ in 0..iterations {
        let _ = TargetParser::parse("192.168.1.1");
    }

    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() as f64 / iterations as f64;

    assert!(avg_micros < 100.0, "Average target parse time: {:.2}µs", avg_micros);
}

#[test]
fn test_timing_template_cpu_efficiency() {
    use nemue::scanner::TimingTemplate;

    let start = Instant::now();
    let iterations = 100000;

    for _ in 0..iterations {
        for i in 0..=5u8 {
            if let Some(t) = TimingTemplate::from_number(i) {
                let _ = t.to_config();
            }
        }
    }

    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() as f64 / iterations as f64;

    assert!(avg_micros < 50.0, "Average timing template time: {:.2}µs", avg_micros);
}

#[tokio::test]
async fn test_profiler_overhead() {
    let profiler = Profiler::new();

    let start = Instant::now();

    for _ in 0..1000 {
        profiler.profile("test_op", async {
            let _ = 1 + 1;
        }).await;
    }

    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() as f64 / 1000.0;

    assert!(avg_micros < 100.0, "Average profiler overhead: {:.2}µs", avg_micros);

    let snapshot = profiler.snapshot().await;
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].call_count, 1000);
}

#[test]
fn test_serialization_cpu_efficiency() {
    use nemue::reporting::{
        ReportBuilder, ReportMetadata, ExecutiveSummary, VulnerabilitySummary,
        ComplianceStatus, Finding, Severity,
    };
    use chrono::Utc;

    let report = ReportBuilder::new()
        .metadata(ReportMetadata {
            scan_id: "cpu-test".to_string(),
            report_id: "cpu-test".to_string(),
            generated_at: Utc::now(),
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 10,
            version: "0.1.0".to_string(),
        })
        .summary(ExecutiveSummary {
            total_hosts: 10,
            hosts_up: 8,
            total_ports: 1000,
            open_ports: 45,
            vulnerabilities: VulnerabilitySummary {
                critical: 2, high: 5, medium: 10, low: 8, info: 3,
            },
            risk_score: 7.5,
            compliance_score: 75.0,
        })
        .compliance(ComplianceStatus {
            frameworks: vec![],
            overall_score: 75.0,
        })
        .add_finding(Finding {
            id: "F001".to_string(),
            severity: Severity::Critical,
            title: "Test".to_string(),
            description: "Test".to_string(),
            affected_hosts: vec!["192.168.1.1".to_string()],
            cvss_score: Some(9.8),
            cve_ids: vec!["CVE-2024-0001".to_string()],
            remediation: "Fix".to_string(),
        })
        .build()
        .unwrap();

    let start = Instant::now();
    let iterations = 10000;

    for _ in 0..iterations {
        let _ = report.to_json();
    }

    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() as f64 / iterations as f64;

    assert!(avg_micros < 500.0, "Average JSON serialization time: {:.2}µs", avg_micros);
}

#[test]
fn test_text_generation_cpu_efficiency() {
    use nemue::reporting::{
        ReportBuilder, ReportMetadata, ExecutiveSummary, VulnerabilitySummary,
        ComplianceStatus,
    };
    use chrono::Utc;

    let report = ReportBuilder::new()
        .metadata(ReportMetadata {
            scan_id: "cpu-test".to_string(),
            report_id: "cpu-test".to_string(),
            generated_at: Utc::now(),
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 10,
            version: "0.1.0".to_string(),
        })
        .summary(ExecutiveSummary {
            total_hosts: 10,
            hosts_up: 8,
            total_ports: 1000,
            open_ports: 45,
            vulnerabilities: VulnerabilitySummary {
                critical: 2, high: 5, medium: 10, low: 8, info: 3,
            },
            risk_score: 7.5,
            compliance_score: 75.0,
        })
        .compliance(ComplianceStatus {
            frameworks: vec![],
            overall_score: 75.0,
        })
        .build()
        .unwrap();

    let start = Instant::now();
    let iterations = 10000;

    for _ in 0..iterations {
        let _ = report.to_text();
    }

    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() as f64 / iterations as f64;

    assert!(avg_micros < 500.0, "Average text generation time: {:.2}µs", avg_micros);
}
