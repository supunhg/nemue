use chrono::Utc;
use nemue::reporting::{
    ComplianceFramework, ComplianceStatus, ExecutiveSummary, Finding, Priority, Recommendation,
    ReportBuilder, ReportMetadata, ScanReport, Severity, VulnerabilitySummary,
};
use nemue::scanner::{
    cache::{CacheConfig, CacheKey, ScanCache},
    compression::ScanCompressor,
    config::NemueConfig,
    dedup::ScanDeduplicator,
    validation::InputValidator,
    PortParser, PortState, Protocol, ScanResult, ScanResults, TargetParser, TimingTemplate,
};
use std::net::IpAddr;
use std::time::Duration;

// =============================================================================
// Test Helpers
// =============================================================================

fn create_scan_result(port: u16, state: PortState, service: Option<&str>) -> ScanResult {
    ScanResult {
        target: "192.168.1.1".parse::<IpAddr>().unwrap(),
        port,
        state,
        protocol: Protocol::TCP,
        service: service.map(|s| s.to_string()),
        service_info: None,
        hostname: None,
        reason: None,
        timestamp: Utc::now(),
    }
}

fn create_scan_results(ports: &[(u16, PortState, Option<&str>)]) -> ScanResults {
    ScanResults {
        scan_start: Utc::now(),
        scan_end: Utc::now(),
        target_count: 1,
        port_count: ports.len(),
        results: ports
            .iter()
            .map(|(port, state, service)| create_scan_result(*port, state.clone(), *service))
            .collect(),
        os_fingerprints: Vec::new(),
        script_results: Vec::new(),
    }
}

fn sample_report_metadata() -> ReportMetadata {
    ReportMetadata {
        scan_id: "test-scan-001".to_string(),
        report_id: "test-report-001".to_string(),
        generated_at: Utc::now(),
        scan_start: Utc::now(),
        scan_end: Utc::now(),
        target_count: 10,
        version: "0.1.0".to_string(),
    }
}

fn sample_executive_summary() -> ExecutiveSummary {
    ExecutiveSummary {
        total_hosts: 10,
        hosts_up: 8,
        total_ports: 1000,
        open_ports: 45,
        vulnerabilities: VulnerabilitySummary {
            critical: 2,
            high: 5,
            medium: 10,
            low: 8,
            info: 3,
        },
        risk_score: 7.5,
        compliance_score: 75.0,
    }
}

fn sample_compliance_status() -> ComplianceStatus {
    ComplianceStatus {
        frameworks: vec![ComplianceFramework {
            name: "PCI-DSS".to_string(),
            version: "4.0".to_string(),
            controls_total: 100,
            controls_passing: 80,
            controls_failing: 20,
            score: 80.0,
            findings: vec![],
        }],
        overall_score: 80.0,
    }
}

fn sample_report() -> ScanReport {
    ReportBuilder::new()
        .metadata(sample_report_metadata())
        .summary(sample_executive_summary())
        .compliance(sample_compliance_status())
        .add_finding(Finding {
            id: "F001".to_string(),
            severity: Severity::Critical,
            title: "Test Finding".to_string(),
            description: "Test description".to_string(),
            affected_hosts: vec!["192.168.1.1".to_string()],
            cvss_score: Some(7.5),
            cve_ids: vec!["CVE-2024-0001".to_string()],
            remediation: "Apply security patch".to_string(),
        })
        .add_finding(Finding {
            id: "F002".to_string(),
            severity: Severity::High,
            title: "Test Finding 2".to_string(),
            description: "Test description 2".to_string(),
            affected_hosts: vec!["192.168.1.2".to_string()],
            cvss_score: Some(8.0),
            cve_ids: vec!["CVE-2024-0002".to_string()],
            remediation: "Apply security patch".to_string(),
        })
        .add_recommendation(Recommendation {
            priority: Priority::Critical,
            category: "Patch".to_string(),
            title: "Apply critical patches".to_string(),
            description: "Install latest security patches".to_string(),
            impact: "High".to_string(),
            effort: "Low".to_string(),
        })
        .build()
        .unwrap()
}

fn large_report(finding_count: usize) -> ScanReport {
    let mut builder = ReportBuilder::new()
        .metadata(ReportMetadata {
            scan_id: "large-scan".to_string(),
            report_id: "large-report".to_string(),
            generated_at: Utc::now(),
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 1000,
            version: "0.1.0".to_string(),
        })
        .summary(ExecutiveSummary {
            total_hosts: 1000,
            hosts_up: 850,
            total_ports: 10000,
            open_ports: 4500,
            vulnerabilities: VulnerabilitySummary {
                critical: 30,
                high: 80,
                medium: 150,
                low: 200,
                info: 500,
            },
            risk_score: 7.2,
            compliance_score: 78.5,
        })
        .compliance(sample_compliance_status());

    for i in 0..finding_count {
        builder = builder.add_finding(Finding {
            id: format!("F{:04}", i),
            severity: match i % 5 {
                0 => Severity::Critical,
                1 => Severity::High,
                2 => Severity::Medium,
                3 => Severity::Low,
                _ => Severity::Info,
            },
            title: format!("Finding {}", i),
            description: format!("Description for finding {}", i),
            affected_hosts: vec![format!("192.168.1.{}", i % 255 + 1)],
            cvss_score: Some(5.0 + (i as f64 * 0.1) % 5.0),
            cve_ids: vec![format!("CVE-2024-{:04}", i)],
            remediation: "Apply patch".to_string(),
        });
    }

    builder.build().unwrap()
}

// =============================================================================
// Port and Target Parsing Integration Tests
// =============================================================================

#[test]
fn test_port_parser_common_presets() {
    let common = PortParser::parse("common").unwrap();
    assert!(!common.is_empty());

    let top100 = PortParser::parse("top100").unwrap();
    assert!(!top100.is_empty());
}

#[test]
fn test_port_parser_protocol_spec() {
    let result = PortParser::parse_protocol_spec("T:80,443 U:53,161");
    assert!(result.is_ok());
}

#[test]
fn test_target_parser_various_formats() {
    assert!(TargetParser::parse("192.168.1.1").is_ok());
    assert!(TargetParser::parse("192.168.1.0/24").is_ok());
    assert!(TargetParser::parse("::1").is_ok());
    assert!(TargetParser::parse("example.com").is_ok());
}

// =============================================================================
// Timing Template Integration Tests
// =============================================================================

#[test]
fn test_timing_template_all_levels() {
    for i in 0..=5u8 {
        let template = TimingTemplate::from_number(i);
        assert!(template.is_some(), "Template {} should exist", i);

        let config = template.unwrap().to_config();
        assert!(config.min_rtt_timeout.as_millis() > 0);
        assert!(config.max_retries > 0);
    }
}

#[test]
fn test_timing_config_validation() {
    let config = TimingTemplate::Normal.to_config();
    assert!(config.min_rtt_timeout <= config.max_rtt_timeout);
    assert!(config.max_retries > 0);
}

// =============================================================================
// Configuration Integration Tests
// =============================================================================

#[test]
fn test_config_serialization_roundtrip() {
    let config = NemueConfig::default();
    let toml_str = toml::to_string(&config).unwrap();
    let parsed: NemueConfig = toml::from_str(&toml_str).unwrap();

    assert_eq!(config.scan.timing, parsed.scan.timing);
    assert_eq!(config.scan.rate, parsed.scan.rate);
    assert_eq!(config.output.format, parsed.output.format);
}

// =============================================================================
// Input Validation Integration Tests
// =============================================================================

#[test]
fn test_input_validator_security() {
    let validator = InputValidator::new();

    assert!(validator.validate_target("192.168.1.1; rm -rf /").is_err());
    assert!(validator
        .validate_target("192.168.1.1 UNION SELECT")
        .is_err());
    assert!(validator
        .validate_target("<script>alert(1)</script>")
        .is_err());
}

#[test]
fn test_input_validator_strict_mode() {
    let validator = InputValidator::strict();
    assert!(validator.validate_target("192.168.1.1").is_err());
    assert!(validator.validate_target("10.0.0.1").is_err());
    assert!(validator.validate_target("8.8.8.8").is_ok());
}

#[test]
fn test_input_validator_port_validation() {
    let validator = InputValidator::new();
    assert!(validator.validate_ports(&[80, 443, 8080]).is_ok());
    assert!(validator.validate_ports(&[0]).is_err());
    assert!(validator.validate_ports(&[]).is_err());
}

#[test]
fn test_input_validator_port_range() {
    let validator = InputValidator::new();
    assert!(validator.validate_port_range(80, 443).is_ok());
    assert!(validator.validate_port_range(443, 80).is_err());
    assert!(validator.validate_port_range(1, 2000).is_err());
}

// =============================================================================
// Cache Integration Tests
// =============================================================================

#[tokio::test]
async fn test_cache_basic_operations() {
    let cache = ScanCache::with_defaults();
    let key = CacheKey::new("192.168.1.1", "80", "syn");

    assert!(cache.get(&key).await.is_none());
    assert_eq!(cache.stats().await.misses, 1);
}

#[tokio::test]
async fn test_cache_invalidation() {
    let cache = ScanCache::with_defaults();
    let key = CacheKey::new("192.168.1.1", "80", "syn");

    assert!(!cache.invalidate(&key).await);
    assert_eq!(cache.stats().await.invalidations, 0);
}

#[tokio::test]
async fn test_cache_cleanup() {
    let cache = ScanCache::new(CacheConfig {
        max_entries: 100,
        default_ttl: Duration::from_millis(1),
        enable_stats: true,
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    let removed = cache.cleanup().await;
    assert_eq!(removed, 0);
}

// =============================================================================
// Deduplication Integration Tests
// =============================================================================

#[test]
fn test_deduplicator_creation() {
    let _dedup = ScanDeduplicator::new();
}

// =============================================================================
// Compression Integration Tests
// =============================================================================

#[test]
fn test_compressor_gzip() {
    let _compressor = ScanCompressor::with_gzip(6);
}

#[test]
fn test_compressor_zstd() {
    let _compressor = ScanCompressor::with_zstd(3);
}

// =============================================================================
// Scan Results Fixtures Integration Tests
// =============================================================================

#[test]
fn test_scan_results_fixture() {
    let results = create_scan_results(&[
        (22, PortState::Open, Some("ssh")),
        (80, PortState::Open, Some("http")),
        (443, PortState::Closed, None),
    ]);

    assert_eq!(results.results.len(), 3);
    assert_eq!(results.results[0].port, 22);
    assert_eq!(results.results[0].state, PortState::Open);
    assert_eq!(results.results[2].state, PortState::Closed);
}

// =============================================================================
// Report Fixtures Integration Tests
// =============================================================================

#[test]
fn test_sample_report_fixture() {
    let report = sample_report();
    assert_eq!(report.metadata.scan_id, "test-scan-001");
    assert_eq!(report.findings.len(), 2);
    assert_eq!(report.recommendations.len(), 1);
}

#[test]
fn test_large_report_fixture() {
    let report = large_report(50);
    assert_eq!(report.findings.len(), 50);
    assert_eq!(report.metadata.target_count, 1000);
}

#[test]
fn test_report_json_serialization() {
    let report = sample_report();
    let json = report.to_json().unwrap();

    assert!(json.contains("test-scan-001"));
    assert!(json.contains("Critical"));

    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed.get("metadata").is_some());
    assert!(parsed.get("findings").is_some());
}

#[test]
fn test_report_text_output() {
    let report = sample_report();
    let text = report.to_text();

    assert!(text.contains("SECURITY SCAN REPORT"));
    assert!(text.contains("EXECUTIVE SUMMARY"));
    assert!(text.contains("VULNERABILITIES"));
}

#[test]
fn test_report_csv_output() {
    let report = sample_report();
    let csv = report.to_csv();

    assert!(csv.contains("Report Metadata"));
    assert!(csv.contains("ID,Severity,Title"));
}

#[test]
fn test_report_xml_output() {
    let report = sample_report();
    let xml = report.to_xml();

    assert!(xml.contains("<?xml version=\"1.0\""));
    assert!(xml.contains("<security_report>"));
    assert!(xml.contains("</security_report>"));
}

#[test]
fn test_report_xml_escape() {
    let report = ReportBuilder::new()
        .metadata(sample_report_metadata())
        .summary(sample_executive_summary())
        .compliance(sample_compliance_status())
        .add_finding(Finding {
            id: "XSS".to_string(),
            severity: Severity::High,
            title: "Test <script>alert(1)</script>".to_string(),
            description: "Description with & ampersand".to_string(),
            affected_hosts: vec![],
            cvss_score: None,
            cve_ids: vec![],
            remediation: "Fix \"quotes\" in config".to_string(),
        })
        .build()
        .unwrap();

    let xml = report.to_xml();
    assert!(xml.contains("&lt;script&gt;"));
    assert!(xml.contains("&amp;"));
    assert!(xml.contains("&quot;"));
}

#[test]
fn test_report_builder_validation() {
    let result = ReportBuilder::new().build();
    assert!(result.is_err());

    let result = ReportBuilder::new()
        .metadata(sample_report_metadata())
        .build();
    assert!(result.is_err());
}

#[test]
fn test_report_markdown_generation() {
    let report = sample_report();
    let markdown = nemue::reporting::MarkdownReportGenerator::generate(&report);

    assert!(markdown.contains("# Security Scan Report"));
    assert!(markdown.contains("## Executive Summary"));
    assert!(markdown.contains("## Findings"));
}

#[test]
fn test_report_pdf_generation() {
    let report = sample_report();
    let pdf = nemue::reporting::PdfReportGenerator::generate(&report);

    assert!(!pdf.is_empty());
    assert!(pdf.starts_with(b"%PDF"));
}

#[test]
fn test_report_json_roundtrip() {
    let report = sample_report();
    let json = report.to_json().unwrap();
    let parsed: ScanReport = serde_json::from_str(&json).unwrap();

    assert_eq!(report.metadata.scan_id, parsed.metadata.scan_id);
    assert_eq!(report.findings.len(), parsed.findings.len());
    assert_eq!(
        report.executive_summary.total_hosts,
        parsed.executive_summary.total_hosts
    );
}
