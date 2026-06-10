// Performance Benchmarks for Nemue Scanner
// Run with: cargo bench

use chrono::Utc;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nemue::fingerprint::{OsDetector, OsFamily};
use nemue::performance::{AtomicFlag, BoundedQueue, LockFreeQueue, MetricsCollector};
use nemue::reporting::{
    ComplianceStatus, ExecutiveSummary, Finding, PdfReportGenerator, Priority, Recommendation,
    ReportBuilder, ReportMetadata, ScanMetrics, ScanReport, ScanSnapshot, Severity,
    TrendAnalyzer as ReportingTrendAnalyzer, VulnerabilityMetrics as ReportingVulnMetrics,
    VulnerabilitySummary,
};
use nemue::scanner::{PortParser, TargetParser, TimingTemplate};
use nemue::scanner::{PortState, Protocol, ScanHistory, ScanResult, ScanResults};
use nemue::script::ScriptArgs;
use nemue::service::{
    all_signatures, DetectionConfig, EnhancedServiceDetector, IntensityLevel, ProbeDatabase,
    ServiceDetector,
};
use nemue::vuln::{DefaultCredentials, ScriptEngine, VulnCategory, VulnScript, VulnSeverity};
use std::net::IpAddr;

// =============================================================================
// Port Parsing Benchmarks (expanded)
// =============================================================================
fn benchmark_port_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("port_parsing");

    group.bench_function("single_port", |b| {
        b.iter(|| PortParser::parse(black_box("80")))
    });

    group.bench_function("port_range_small", |b| {
        b.iter(|| PortParser::parse(black_box("1-100")))
    });

    group.bench_function("port_range_large", |b| {
        b.iter(|| PortParser::parse(black_box("1-65535")))
    });

    group.bench_function("mixed_ports", |b| {
        b.iter(|| PortParser::parse(black_box("22,80,443,8000-8100")))
    });

    group.bench_function("common_preset", |b| {
        b.iter(|| PortParser::parse(black_box("common")))
    });

    group.bench_function("top1000_preset", |b| {
        b.iter(|| PortParser::parse(black_box("top1000")))
    });

    group.bench_function("many_comma_separated", |b| {
        b.iter(|| {
            PortParser::parse(black_box(
                "21,22,23,25,53,80,110,143,443,993,995,3306,3389,5432,8080,8443",
            ))
        })
    });

    group.bench_function("overlapping_ranges", |b| {
        b.iter(|| PortParser::parse(black_box("1-1000,80-443,22-80")))
    });

    group.bench_function("protocol_spec_tcp_udp", |b| {
        b.iter(|| PortParser::parse_protocol_spec(black_box("T:80,443 U:53,161")))
    });

    group.bench_function("protocol_spec_complex", |b| {
        b.iter(|| {
            PortParser::parse_protocol_spec(black_box("T:22,80,443,8080 U:53,161,162,631 S:22"))
        })
    });

    group.bench_function("filter_by_ratio_09", |b| {
        b.iter(|| PortParser::filter_by_ratio(black_box(0.9)))
    });

    group.bench_function("filter_by_ratio_05", |b| {
        b.iter(|| PortParser::filter_by_ratio(black_box(0.5)))
    });

    group.bench_function("parse_error_invalid_port", |b| {
        b.iter(|| PortParser::parse(black_box("99999")))
    });

    group.bench_function("parse_error_invalid_range", |b| {
        b.iter(|| PortParser::parse(black_box("100-50")))
    });

    group.finish();
}

// =============================================================================
// Target Parsing Benchmarks (expanded)
// =============================================================================
fn benchmark_target_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("target_parsing");

    group.bench_function("single_ip", |b| {
        b.iter(|| TargetParser::parse(black_box("192.168.1.1")))
    });

    group.bench_function("cidr_24", |b| {
        b.iter(|| TargetParser::parse(black_box("192.168.1.0/24")))
    });

    group.bench_function("cidr_16", |b| {
        b.iter(|| TargetParser::parse(black_box("192.168.0.0/16")))
    });

    group.bench_function("ipv6_single", |b| {
        b.iter(|| TargetParser::parse(black_box("fe80::1")))
    });

    group.bench_function("ip_range", |b| {
        b.iter(|| TargetParser::parse(black_box("192.168.1.1-100")))
    });

    group.bench_function("hostname", |b| {
        b.iter(|| TargetParser::parse(black_box("example.com")))
    });

    group.bench_function("multiple_targets", |b| {
        b.iter(|| TargetParser::parse(black_box("192.168.1.1,192.168.1.2,10.0.0.1")))
    });

    group.bench_function("mixed_formats", |b| {
        b.iter(|| TargetParser::parse(black_box("192.168.1.0/24,10.0.0.1-10,example.com")))
    });

    group.bench_function("octet_range_small", |b| {
        b.iter(|| TargetParser::parse(black_box("192.168.1.1-10")))
    });

    group.bench_function("octet_range_medium", |b| {
        b.iter(|| TargetParser::parse(black_box("192.168.1-2.1-50")))
    });

    group.bench_function("octet_range_two_octets", |b| {
        b.iter(|| TargetParser::parse(black_box("192.168.1-5.1-20")))
    });

    group.finish();
}

// =============================================================================
// Target Scaling Benchmarks
// =============================================================================
fn benchmark_target_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("target_scaling");

    for prefix_len in [30, 28, 26, 24].iter() {
        let cidr = format!("192.168.0.0/{}", prefix_len);
        group.bench_with_input(BenchmarkId::from_parameter(&cidr), &cidr, |b, cidr| {
            b.iter(|| TargetParser::parse(black_box(cidr)))
        });
    }

    group.finish();
}

// =============================================================================
// Timing Configuration Benchmarks
// =============================================================================
fn benchmark_timing(c: &mut Criterion) {
    let mut group = c.benchmark_group("timing");

    group.bench_function("template_creation", |b| {
        b.iter(|| {
            for i in 0..=5 {
                let _ = TimingTemplate::from_number(black_box(i));
            }
        })
    });

    group.bench_function("template_to_config", |b| {
        let template = TimingTemplate::Aggressive;
        b.iter(|| black_box(&template).to_config())
    });

    group.bench_function("config_validation", |b| {
        b.iter(|| {
            let mut config = TimingTemplate::Normal.to_config();
            config.validate();
        })
    });

    group.bench_function("all_templates", |b| {
        b.iter(|| {
            for i in 0..=5u8 {
                if let Some(t) = TimingTemplate::from_number(i) {
                    let _ = t.to_config();
                }
            }
        })
    });

    group.finish();
}

// =============================================================================
// Script Arguments Parsing Benchmarks
// =============================================================================
fn benchmark_script_args(c: &mut Criterion) {
    let mut group = c.benchmark_group("script_args");

    group.bench_function("parse_simple", |b| {
        b.iter(|| ScriptArgs::parse(black_box("user=admin,pass=test")))
    });

    group.bench_function("parse_complex", |b| {
        b.iter(|| {
            ScriptArgs::parse(black_box(
                "user=admin,pass=test123,timeout=30,url=http://example.com,debug=true",
            ))
        })
    });

    group.bench_function("parse_quoted", |b| {
        b.iter(|| {
            ScriptArgs::parse(black_box(
                r#"msg="hello world",url='http://example.com',data="key=value""#,
            ))
        })
    });

    group.bench_function("to_lua_table", |b| {
        let args = ScriptArgs::parse("user=admin,pass=test,timeout=30").unwrap();
        b.iter(|| black_box(&args).to_lua_table())
    });

    group.bench_function("parse_empty", |b| {
        b.iter(|| ScriptArgs::parse(black_box("")))
    });

    group.bench_function("parse_many_args", |b| {
        b.iter(|| {
            ScriptArgs::parse(black_box(
                "a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9,j=10,k=11,l=12",
            ))
        })
    });

    group.finish();
}

// =============================================================================
// String Operations Benchmarks
// =============================================================================
fn benchmark_string_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_ops");

    group.bench_function("ip_addr_parsing", |b| {
        b.iter(|| {
            let _: IpAddr = black_box("192.168.1.1").parse().unwrap();
        })
    });

    group.bench_function("ipv6_parsing", |b| {
        b.iter(|| {
            let _: IpAddr = black_box("fe80::1").parse().unwrap();
        })
    });

    group.finish();
}

// =============================================================================
// Memory Allocation Benchmarks
// =============================================================================
fn benchmark_allocations(c: &mut Criterion) {
    let mut group = c.benchmark_group("allocations");

    group.bench_function("vec_small", |b| {
        b.iter(|| {
            let _v: Vec<u16> = (1..=100).collect();
        })
    });

    group.bench_function("vec_large", |b| {
        b.iter(|| {
            let _v: Vec<u16> = (1..=10000).collect();
        })
    });

    group.bench_function("hashmap_insert", |b| {
        b.iter(|| {
            let mut map = std::collections::HashMap::new();
            for i in 0..100 {
                map.insert(format!("key{}", i), format!("value{}", i));
            }
        })
    });

    group.finish();
}

// =============================================================================
// Port Range Scaling Benchmarks
// =============================================================================
fn benchmark_port_range_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("port_range_scaling");

    for size in [10, 100, 1000, 10000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let range = format!("1-{}", size);
            b.iter(|| PortParser::parse(black_box(&range)))
        });
    }

    group.finish();
}

// =============================================================================
// CIDR Scaling Benchmarks
// =============================================================================
fn benchmark_cidr_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("cidr_scaling");

    let cidrs = vec![
        ("cidr_30", "192.168.1.0/30"),
        ("cidr_28", "192.168.1.0/28"),
        ("cidr_24", "192.168.1.0/24"),
        ("cidr_22", "192.168.0.0/22"),
    ];

    for (name, cidr) in cidrs {
        group.bench_function(name, |b| b.iter(|| TargetParser::parse(black_box(cidr))));
    }

    group.finish();
}

// =============================================================================
// Service Detection Benchmarks (PRIORITY)
// =============================================================================
fn benchmark_service_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("service_detection");

    // Detector initialization (loads 200+ signatures)
    group.bench_function("detector_creation", |b| {
        b.iter(|| ServiceDetector::new(black_box(1000)))
    });

    // ServiceDetector::detect is the public API for service detection
    // It connects to the target, grabs banners, and analyzes them.
    // For benchmarks we test the creation and internal operations
    // that don't require network access.

    // Benchmark the detector creation with different timeouts
    group.bench_function("detector_creation_timeout_100", |b| {
        b.iter(|| ServiceDetector::new(black_box(100)))
    });

    group.bench_function("detector_creation_timeout_5000", |b| {
        b.iter(|| ServiceDetector::new(black_box(5000)))
    });

    group.finish();
}

// =============================================================================
// Enhanced Service Detection Benchmarks
// =============================================================================
fn benchmark_enhanced_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("enhanced_detection");

    group.bench_function("enhanced_detector_creation", |b| {
        b.iter(|| EnhancedServiceDetector::new(DetectionConfig::default()))
    });

    group.bench_function("enhanced_detector_light", |b| {
        b.iter(|| EnhancedServiceDetector::new(DetectionConfig::light()))
    });

    group.bench_function("enhanced_detector_all", |b| {
        b.iter(|| EnhancedServiceDetector::new(DetectionConfig::all()))
    });

    let detector = EnhancedServiceDetector::new(DetectionConfig::default());

    group.bench_function("probe_statistics", |b| {
        b.iter(|| detector.probe_statistics())
    });

    group.finish();
}

// =============================================================================
// Probe Database Benchmarks
// =============================================================================
fn benchmark_probe_database(c: &mut Criterion) {
    let mut group = c.benchmark_group("probe_database");

    group.bench_function("probe_db_creation", |b| b.iter(ProbeDatabase::new));

    let db = ProbeDatabase::new();

    group.bench_function("all_probes", |b| b.iter(|| db.all_probes().len()));

    group.bench_function("probes_for_port_http", |b| {
        b.iter(|| db.probes_for_port(black_box(80)).len())
    });

    group.bench_function("probes_for_port_ssh", |b| {
        b.iter(|| db.probes_for_port(black_box(22)).len())
    });

    group.bench_function("probes_for_port_mysql", |b| {
        b.iter(|| db.probes_for_port(black_box(3306)).len())
    });

    group.bench_function("probes_for_port_unknown", |b| {
        b.iter(|| db.probes_for_port(black_box(9999)).len())
    });

    group.bench_function("generic_probes", |b| b.iter(|| db.generic_probes().len()));

    // Benchmark probes_for_port across many ports
    group.bench_function("probes_for_port_100_ports", |b| {
        b.iter(|| {
            for port in 1..=100 {
                let _ = db.probes_for_port(black_box(port));
            }
        })
    });

    group.finish();
}

// =============================================================================
// Signature Database Benchmarks
// =============================================================================
fn benchmark_signatures(c: &mut Criterion) {
    let mut group = c.benchmark_group("signatures");

    group.bench_function("load_all_signatures", |b| b.iter(all_signatures));

    let sigs = all_signatures();
    group.throughput(Throughput::Elements(sigs.len() as u64));
    group.bench_function("signature_count", |b| b.iter(|| sigs.len()));

    // Test regex matching against common patterns
    group.bench_function("regex_match_http_server", |b| {
        let pattern = regex::bytes::Regex::new(r"Server: nginx/(\d+\.\d+\.\d+)").unwrap();
        let data = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 0\r\n";
        b.iter(|| pattern.captures(black_box(data)))
    });

    group.bench_function("regex_match_ssh_banner", |b| {
        let pattern = regex::bytes::Regex::new(r"SSH-2.0-OpenSSH_([\d.p]+)").unwrap();
        let data = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";
        b.iter(|| pattern.captures(black_box(data)))
    });

    group.bench_function("regex_match_ftp_banner", |b| {
        let pattern = regex::bytes::Regex::new(r"220.*vsFTPd (\d+\.\d+\.\d+)").unwrap();
        let data = b"220 (vsFTPd 3.0.3)";
        b.iter(|| pattern.captures(black_box(data)))
    });

    group.bench_function("regex_compile_http", |b| {
        b.iter(|| regex::bytes::Regex::new(black_box(r"Server: nginx/(\d+\.\d+\.\d+)")))
    });

    group.bench_function("regex_compile_ssh", |b| {
        b.iter(|| regex::bytes::Regex::new(black_box(r"SSH-2.0-OpenSSH_([\d.p]+)")))
    });

    group.finish();
}

// =============================================================================
// OS Fingerprinting Benchmarks (PRIORITY)
// =============================================================================
fn benchmark_os_fingerprinting(c: &mut Criterion) {
    let mut group = c.benchmark_group("os_fingerprinting");

    let detector = OsDetector::new();

    // TTL-based detection
    group.bench_function("os_from_ttl_linux", |b| {
        b.iter(|| OsFamily::from_ttl(black_box(64)))
    });

    group.bench_function("os_from_ttl_windows", |b| {
        b.iter(|| OsFamily::from_ttl(black_box(128)))
    });

    group.bench_function("os_from_ttl_solaris", |b| {
        b.iter(|| OsFamily::from_ttl(black_box(255)))
    });

    group.bench_function("os_from_ttl_unknown", |b| {
        b.iter(|| OsFamily::from_ttl(black_box(42)))
    });

    // OsFamily::as_str
    group.bench_function("os_family_as_str", |b| {
        b.iter(|| black_box(&OsFamily::Linux).as_str())
    });

    // Simple detection
    group.bench_function("detect_linux_simple", |b| {
        b.iter(|| {
            detector.detect(
                black_box(64),
                black_box(Some(29200)),
                black_box(vec!["mss".to_string(), "sackOK".to_string()]),
            )
        })
    });

    group.bench_function("detect_windows_simple", |b| {
        b.iter(|| {
            detector.detect(
                black_box(128),
                black_box(Some(64240)),
                black_box(vec![
                    "mss".to_string(),
                    "nop".to_string(),
                    "sackOK".to_string(),
                ]),
            )
        })
    });

    // Advanced detection (full fingerprinting)
    group.bench_function("detect_advanced_linux", |b| {
        b.iter(|| {
            detector.detect_advanced(
                black_box(64),
                black_box(Some(29200)),
                black_box(vec![
                    "mss".to_string(),
                    "sackOK".to_string(),
                    "timestamp".to_string(),
                    "nop".to_string(),
                    "wscale".to_string(),
                ]),
                black_box(Some(12345678)),
                black_box(Some(7)),
                black_box(Some(1460)),
            )
        })
    });

    group.bench_function("detect_advanced_windows10", |b| {
        b.iter(|| {
            detector.detect_advanced(
                black_box(128),
                black_box(Some(64240)),
                black_box(vec![
                    "mss".to_string(),
                    "nop".to_string(),
                    "sackOK".to_string(),
                ]),
                black_box(Some(1000)),
                black_box(Some(8)),
                black_box(Some(1460)),
            )
        })
    });

    group.bench_function("detect_advanced_macos", |b| {
        b.iter(|| {
            detector.detect_advanced(
                black_box(64),
                black_box(Some(65535)),
                black_box(vec![
                    "mss".to_string(),
                    "timestamp".to_string(),
                    "sackOK".to_string(),
                ]),
                black_box(Some(50000)),
                black_box(None),
                black_box(Some(1460)),
            )
        })
    });

    group.bench_function("detect_advanced_unknown", |b| {
        b.iter(|| {
            detector.detect_advanced(
                black_box(42),
                black_box(Some(8192)),
                black_box(vec![]),
                black_box(None),
                black_box(None),
                black_box(None),
            )
        })
    });

    // Multi-probe detection
    group.bench_function("detect_from_multiple_consistent", |b| {
        b.iter(|| {
            detector.detect_from_multiple(black_box(vec![
                (
                    64,
                    Some(29200),
                    vec!["mss".to_string(), "sackOK".to_string()],
                ),
                (
                    64,
                    Some(29200),
                    vec!["mss".to_string(), "timestamp".to_string()],
                ),
                (
                    64,
                    Some(29200),
                    vec!["mss".to_string(), "wscale".to_string()],
                ),
            ]))
        })
    });

    group.bench_function("detect_from_multiple_inconsistent", |b| {
        b.iter(|| {
            detector.detect_from_multiple(black_box(vec![
                (64, Some(29200), vec!["mss".to_string()]),
                (128, Some(64240), vec!["mss".to_string()]),
            ]))
        })
    });

    group.bench_function("detect_from_multiple_single", |b| {
        b.iter(|| {
            detector.detect_from_multiple(black_box(vec![(
                64,
                Some(29200),
                vec!["mss".to_string(), "sackOK".to_string()],
            )]))
        })
    });

    group.bench_function("detect_from_multiple_empty", |b| {
        b.iter(|| detector.detect_from_multiple(black_box(vec![])))
    });

    // Banner-based OS detection
    group.bench_function("os_from_banner_windows_iis", |b| {
        b.iter(|| OsFamily::from_banner(black_box("Server: Microsoft-IIS/10.0")))
    });

    group.bench_function("os_from_banner_linux_nginx", |b| {
        b.iter(|| OsFamily::from_banner(black_box("Server: nginx/1.18.0 (Ubuntu)")))
    });

    group.bench_function("os_from_banner_ssh_ubuntu", |b| {
        b.iter(|| OsFamily::from_banner(black_box("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")))
    });

    group.bench_function("os_from_banner_cisco", |b| {
        b.iter(|| OsFamily::from_banner(black_box("SSH-2.0-Cisco-1.25")))
    });

    group.bench_function("os_from_banner_none", |b| {
        b.iter(|| OsFamily::from_banner(black_box("random data with no OS indicators")))
    });

    // Passive OS detection
    group.bench_function("detect_passive_http_windows", |b| {
        b.iter(|| {
            detector.detect_passive(black_box("Server: Microsoft-IIS/10.0"), black_box("http"))
        })
    });

    group.bench_function("detect_passive_ssh_ubuntu", |b| {
        b.iter(|| {
            detector.detect_passive(
                black_box("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"),
                black_box("ssh"),
            )
        })
    });

    group.bench_function("detect_passive_ssh_cisco", |b| {
        b.iter(|| detector.detect_passive(black_box("SSH-2.0-Cisco-1.25"), black_box("ssh")))
    });

    group.bench_function("detect_passive_no_indicators", |b| {
        b.iter(|| detector.detect_passive(black_box("some generic banner"), black_box("unknown")))
    });

    group.finish();
}

// =============================================================================
// Vulnerability Scanning Benchmarks
// =============================================================================
fn benchmark_vuln_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("vuln_scanning");

    // Default credentials database
    group.bench_function("credentials_db_creation", |b| {
        b.iter(DefaultCredentials::new)
    });

    let cred_db = DefaultCredentials::new();

    group.bench_function("credentials_count", |b| b.iter(|| cred_db.count()));

    group.bench_function("credentials_service_count", |b| {
        b.iter(|| cred_db.service_count())
    });

    group.bench_function("get_credentials_mysql", |b| {
        b.iter(|| cred_db.get_credentials(black_box("mysql")))
    });

    group.bench_function("get_credentials_ssh", |b| {
        b.iter(|| cred_db.get_credentials(black_box("ssh")))
    });

    group.bench_function("get_credentials_nonexistent", |b| {
        b.iter(|| cred_db.get_credentials(black_box("nonexistent")))
    });

    group.bench_function("all_credentials", |b| b.iter(|| cred_db.all_credentials()));

    // VulnScript matching
    let script = VulnScript::new(
        "test-auth",
        "Auth Test",
        "Tests for authentication issues",
        VulnCategory::Authentication,
    )
    .with_ports(vec![22, 23, 3306, 5432])
    .with_services(vec!["ssh".to_string(), "mysql".to_string()]);

    group.bench_function("script_match_port_service", |b| {
        b.iter(|| script.matches(black_box(22), black_box(Some("ssh"))))
    });

    group.bench_function("script_match_no_match", |b| {
        b.iter(|| script.matches(black_box(80), black_box(Some("http"))))
    });

    group.bench_function("script_match_port_only", |b| {
        b.iter(|| script.matches(black_box(3306), black_box(None)))
    });

    // VulnSeverity
    group.bench_function("severity_from_cvss_critical", |b| {
        b.iter(|| VulnSeverity::from_cvss(black_box(9.5)))
    });

    group.bench_function("severity_from_cvss_high", |b| {
        b.iter(|| VulnSeverity::from_cvss(black_box(7.8)))
    });

    group.bench_function("severity_from_cvss_medium", |b| {
        b.iter(|| VulnSeverity::from_cvss(black_box(5.5)))
    });

    group.bench_function("severity_from_cvss_low", |b| {
        b.iter(|| VulnSeverity::from_cvss(black_box(2.1)))
    });

    group.bench_function("severity_as_str", |b| {
        b.iter(|| black_box(&VulnSeverity::High).as_str())
    });

    // VulnCategory
    group.bench_function("category_as_str", |b| {
        b.iter(|| black_box(&VulnCategory::RemoteCodeExecution).as_str())
    });

    // Script engine
    group.bench_function("script_engine_creation", |b| b.iter(ScriptEngine::new));

    let mut engine = ScriptEngine::new();
    for i in 0..20 {
        engine.register(VulnScript::new(
            format!("script-{}", i),
            format!("Script {}", i),
            "Test script",
            match i % 5 {
                0 => VulnCategory::Authentication,
                1 => VulnCategory::InfoDisclosure,
                2 => VulnCategory::RemoteCodeExecution,
                3 => VulnCategory::SqlInjection,
                _ => VulnCategory::Misconfiguration,
            },
        ));
    }

    group.bench_function("script_engine_list_scripts", |b| {
        b.iter(|| engine.list_scripts())
    });

    group.bench_function("script_engine_get_existing", |b| {
        b.iter(|| engine.get(black_box("script-5")))
    });

    group.bench_function("script_engine_get_nonexistent", |b| {
        b.iter(|| engine.get(black_box("nonexistent")))
    });

    group.bench_function("script_engine_list_by_category", |b| {
        b.iter(|| engine.list_by_category(black_box(&VulnCategory::Authentication)))
    });

    // Exploit database benchmarks
    group.bench_function("exploit_db_creation", |b| {
        b.iter(nemue::vuln::ExploitDatabase::new)
    });

    let exploit_db = nemue::vuln::ExploitDatabase::new();

    group.bench_function("exploit_get_log4shell", |b| {
        b.iter(|| exploit_db.get_exploit(black_box("CVE-2021-44228")))
    });

    group.bench_function("exploit_get_eternalblue", |b| {
        b.iter(|| exploit_db.get_exploit(black_box("CVE-2017-0144")))
    });

    group.bench_function("exploit_get_nonexistent", |b| {
        b.iter(|| exploit_db.get_exploit(black_box("CVE-9999-9999")))
    });

    // Credential database scaling
    group.bench_function("get_credentials_all_services", |b| {
        b.iter(|| {
            for svc in &[
                "mysql",
                "postgresql",
                "mongodb",
                "redis",
                "tomcat",
                "cisco",
                "ssh",
                "ftp",
            ] {
                let _ = cred_db.get_credentials(black_box(svc));
            }
        })
    });

    group.bench_function("credentials_count_fast", |b| b.iter(|| cred_db.count()));

    group.bench_function("credentials_service_count_fast", |b| {
        b.iter(|| cred_db.service_count())
    });

    // Multiple severity lookups
    group.bench_function("severity_batch_classify", |b| {
        b.iter(|| {
            for score in [0.0, 1.5, 3.8, 5.5, 7.2, 9.1, 10.0] {
                let _ = VulnSeverity::from_cvss(black_box(score));
            }
        })
    });

    // Multiple category lookups
    group.bench_function("category_batch_as_str", |b| {
        b.iter(|| {
            for cat in &[
                VulnCategory::Authentication,
                VulnCategory::InfoDisclosure,
                VulnCategory::RemoteCodeExecution,
                VulnCategory::SqlInjection,
                VulnCategory::Misconfiguration,
                VulnCategory::Cryptography,
            ] {
                let _ = black_box(cat).as_str();
            }
        })
    });

    group.finish();
}

// =============================================================================
// Report Generation Benchmarks
// =============================================================================
fn create_sample_report() -> ScanReport {
    let mut findings = Vec::new();
    for i in 0..10 {
        findings.push(Finding {
            id: format!("finding-{:03}", i),
            severity: match i % 5 {
                0 => Severity::Critical,
                1 => Severity::High,
                2 => Severity::Medium,
                3 => Severity::Low,
                _ => Severity::Info,
            },
            title: format!("Vulnerability {}", i),
            description: format!("Description for vulnerability {}", i),
            affected_hosts: vec![format!("192.168.1.{}", i + 1)],
            cvss_score: Some(5.0 + (i as f64 * 0.5)),
            cve_ids: vec![format!("CVE-2024-{:04}", i)],
            remediation: format!("Remediation for vulnerability {}", i),
        });
    }

    ReportBuilder::new()
        .metadata(ReportMetadata {
            scan_id: "bench-scan-001".to_string(),
            report_id: "bench-report-001".to_string(),
            generated_at: Utc::now(),
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 100,
            version: "0.2.1".to_string(),
        })
        .summary(ExecutiveSummary {
            total_hosts: 100,
            hosts_up: 85,
            total_ports: 1000,
            open_ports: 450,
            vulnerabilities: VulnerabilitySummary {
                critical: 3,
                high: 8,
                medium: 15,
                low: 20,
                info: 50,
            },
            risk_score: 7.2,
            compliance_score: 78.5,
        })
        .compliance(ComplianceStatus {
            frameworks: vec![],
            overall_score: 78.5,
        })
        .add_finding(findings.remove(0))
        .add_finding(findings.remove(0))
        .add_finding(findings.remove(0))
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

fn create_large_report(finding_count: usize) -> ScanReport {
    let mut builder = ReportBuilder::new()
        .metadata(ReportMetadata {
            scan_id: "bench-scan-large".to_string(),
            report_id: "bench-report-large".to_string(),
            generated_at: Utc::now(),
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 1000,
            version: "0.2.1".to_string(),
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
        .compliance(ComplianceStatus {
            frameworks: vec![],
            overall_score: 78.5,
        });

    for i in 0..finding_count {
        builder = builder.add_finding(Finding {
            id: format!("finding-{:04}", i),
            severity: match i % 5 {
                0 => Severity::Critical,
                1 => Severity::High,
                2 => Severity::Medium,
                3 => Severity::Low,
                _ => Severity::Info,
            },
            title: format!("Vulnerability {} - {}", i, match i % 7 {
                0 => "Remote Code Execution via Deserialization",
                1 => "SQL Injection in User Authentication",
                2 => "Cross-Site Scripting in Search Parameter",
                3 => "Default Credentials on Database Server",
                4 => "Unencrypted Communication Channel",
                5 => "Missing Security Headers",
                _ => "Information Disclosure via Error Messages",
            }),
            description: format!("Detailed description for vulnerability {} affecting multiple hosts in the network infrastructure", i),
            affected_hosts: (0..5).map(|h| format!("192.168.{}.{}", i % 256, h + 1)).collect(),
            cvss_score: Some(3.0 + (i as f64 * 0.07) % 7.0),
            cve_ids: vec![format!("CVE-2024-{:04}", i)],
            remediation: format!("Apply security patch or update to latest version for vulnerability {}", i),
        });
    }

    for i in 0..5 {
        builder = builder.add_recommendation(Recommendation {
            priority: match i % 4 {
                0 => Priority::Critical,
                1 => Priority::High,
                2 => Priority::Medium,
                _ => Priority::Low,
            },
            category: [
                "Patch",
                "Configuration",
                "Authentication",
                "Encryption",
                "Monitoring",
            ][i % 5]
                .to_string(),
            title: format!("Recommendation {}", i),
            description: format!(
                "Detailed recommendation for improving security posture {}",
                i
            ),
            impact: ["High", "Medium", "Low"][i % 3].to_string(),
            effort: ["Low", "Medium", "High"][i % 3].to_string(),
        });
    }

    builder.build().unwrap()
}

fn benchmark_report_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("report_generation");

    let report = create_sample_report();

    group.bench_function("report_to_json", |b| b.iter(|| report.to_json()));

    group.bench_function("report_to_text", |b| b.iter(|| report.to_text()));

    group.bench_function("report_to_csv", |b| b.iter(|| report.to_csv()));

    group.bench_function("report_to_xml", |b| b.iter(|| report.to_xml()));

    group.bench_function("report_to_markdown", |b| {
        b.iter(|| nemue::reporting::MarkdownReportGenerator::generate(black_box(&report)))
    });

    // Report building
    group.bench_function("report_builder_build", |b| {
        b.iter(|| {
            ReportBuilder::new()
                .metadata(ReportMetadata {
                    scan_id: "s".to_string(),
                    report_id: "r".to_string(),
                    generated_at: Utc::now(),
                    scan_start: Utc::now(),
                    scan_end: Utc::now(),
                    target_count: 10,
                    version: "0.1.0".to_string(),
                })
                .summary(ExecutiveSummary {
                    total_hosts: 10,
                    hosts_up: 8,
                    total_ports: 100,
                    open_ports: 50,
                    vulnerabilities: VulnerabilitySummary {
                        critical: 1,
                        high: 2,
                        medium: 3,
                        low: 4,
                        info: 5,
                    },
                    risk_score: 5.0,
                    compliance_score: 80.0,
                })
                .compliance(ComplianceStatus {
                    frameworks: vec![],
                    overall_score: 80.0,
                })
                .build()
        })
    });

    group.finish();
}

// =============================================================================
// PDF Report Generation Benchmarks
// =============================================================================
fn benchmark_pdf_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("pdf_generation");

    let report = create_sample_report();

    group.bench_function("pdf_generate", |b| {
        b.iter(|| PdfReportGenerator::generate(black_box(&report)))
    });

    group.bench_function("pdf_generate_size", |b| {
        b.iter(|| {
            let pdf = PdfReportGenerator::generate(black_box(&report));
            black_box(pdf.len())
        })
    });

    // Large report benchmarks
    group.bench_function("report_to_json_large", |b| {
        let large_report = create_large_report(100);
        b.iter(|| large_report.to_json())
    });

    group.bench_function("report_to_text_large", |b| {
        let large_report = create_large_report(100);
        b.iter(|| large_report.to_text())
    });

    group.bench_function("report_to_csv_large", |b| {
        let large_report = create_large_report(100);
        b.iter(|| large_report.to_csv())
    });

    group.bench_function("report_to_xml_large", |b| {
        let large_report = create_large_report(100);
        b.iter(|| large_report.to_xml())
    });

    group.bench_function("report_to_markdown_large", |b| {
        let large_report = create_large_report(100);
        b.iter(|| nemue::reporting::MarkdownReportGenerator::generate(black_box(&large_report)))
    });

    group.bench_function("pdf_generate_large", |b| {
        let large_report = create_large_report(50);
        b.iter(|| PdfReportGenerator::generate(black_box(&large_report)))
    });

    group.finish();
}

// =============================================================================
// Scan History Benchmarks
// =============================================================================
fn create_test_scan_results(port: u16, state: PortState, service: Option<&str>) -> ScanResults {
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

fn create_multi_port_results(ports: &[(u16, PortState, Option<&str>)]) -> ScanResults {
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

fn benchmark_scan_history(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_history");

    group.bench_function("history_creation", |b| b.iter(ScanHistory::new));

    // Add entry benchmark
    group.bench_function("add_entry_single_port", |b| {
        b.iter_batched(
            ScanHistory::new,
            |mut history| {
                history.add_entry(
                    "192.168.1.1".to_string(),
                    create_test_scan_results(80, PortState::Open, Some("http")),
                )
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.bench_function("add_entry_multi_port", |b| {
        let ports: Vec<(u16, PortState, Option<&str>)> = (1..=100)
            .map(|p| (p, PortState::Open, Some("http")))
            .collect();
        b.iter_batched(
            ScanHistory::new,
            |mut history| {
                history.add_entry("192.168.1.1".to_string(), create_multi_port_results(&ports))
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Lookup benchmarks
    let mut history = ScanHistory::new();
    let mut scan_ids = Vec::new();
    for i in 0..50 {
        let id = history.add_entry(
            format!("192.168.1.{}", i % 10),
            create_test_scan_results(80, PortState::Open, Some("http")),
        );
        scan_ids.push(id);
    }

    group.bench_function("get_entry_existing", |b| {
        let scan_id = &scan_ids[25];
        b.iter(|| history.get_entry(black_box(scan_id)))
    });

    group.bench_function("get_entry_nonexistent", |b| {
        b.iter(|| history.get_entry(black_box("nonexistent-id")))
    });

    group.bench_function("get_latest", |b| b.iter(|| history.get_latest()));

    group.bench_function("get_previous", |b| b.iter(|| history.get_previous()));

    group.bench_function("entries_for_target", |b| {
        b.iter(|| history.entries_for_target(black_box("192.168.1.1")))
    });

    group.bench_function("history_len", |b| b.iter(|| history.len()));

    group.bench_function("history_is_empty", |b| b.iter(|| history.is_empty()));

    // Serialization benchmarks
    group.bench_function("serialize_history_json", |b| {
        b.iter(|| serde_json::to_string(black_box(&history)))
    });

    group.bench_function("deserialize_history_json", |b| {
        let json = serde_json::to_string(&history).unwrap();
        b.iter(|| serde_json::from_str::<ScanHistory>(black_box(&json)))
    });

    // Summary generation
    let results = create_multi_port_results(&[
        (22, PortState::Open, Some("ssh")),
        (80, PortState::Open, Some("http")),
        (443, PortState::Closed, None),
        (3306, PortState::Filtered, None),
    ]);

    group.bench_function("summary_from_results", |b| {
        b.iter(|| nemue::scanner::history::ScanSummary::from_results(black_box(&results)))
    });

    // Max entries enforcement
    group.bench_function("max_entries_enforcement", |b| {
        b.iter_batched(
            || ScanHistory::with_max_entries(10),
            |mut history| {
                for i in 0..20 {
                    history.add_entry(
                        format!("target-{}", i),
                        create_test_scan_results(80, PortState::Open, Some("http")),
                    );
                }
                history.len()
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

// =============================================================================
// Trend Analysis Benchmarks
// =============================================================================
fn benchmark_trend_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("trend_analysis");

    // Reporting trend analyzer
    group.bench_function("reporting_trend_analyzer_creation", |b| {
        b.iter(ReportingTrendAnalyzer::new)
    });

    let mut analyzer = ReportingTrendAnalyzer::new();
    for i in 0..30 {
        analyzer.add_snapshot(ScanSnapshot {
            scan_id: format!("scan-{}", i),
            timestamp: chrono::Utc::now() - chrono::Duration::days(30 - i),
            metrics: ScanMetrics {
                total_hosts: 100,
                hosts_up: 80 + (i as usize % 10),
                total_ports: 1000,
                open_ports: 400 + (i as usize % 50),
                vulnerabilities: ReportingVulnMetrics {
                    critical: (10 - (i as usize % 10)),
                    high: 15 - (i as usize % 15),
                    medium: 20,
                    low: 10,
                    info: 5,
                },
                risk_score: 8.0 - (i as f64 * 0.1),
            },
        });
    }

    group.bench_function("reporting_trend_analyze_30d", |b| {
        b.iter(|| analyzer.analyze(black_box(30)))
    });

    group.bench_function("reporting_trend_analyze_7d", |b| {
        b.iter(|| analyzer.analyze(black_box(7)))
    });

    group.bench_function("reporting_trend_add_snapshot", |b| {
        b.iter_batched(
            ReportingTrendAnalyzer::new,
            |mut a| {
                a.add_snapshot(ScanSnapshot {
                    scan_id: "test".to_string(),
                    timestamp: Utc::now(),
                    metrics: ScanMetrics {
                        total_hosts: 10,
                        hosts_up: 8,
                        total_ports: 100,
                        open_ports: 50,
                        vulnerabilities: ReportingVulnMetrics {
                            critical: 1,
                            high: 2,
                            medium: 3,
                            low: 4,
                            info: 5,
                        },
                        risk_score: 5.0,
                    },
                })
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Snapshot count scaling
    group.bench_function("reporting_trend_analyze_100_snapshots", |b| {
        let mut large_analyzer = ReportingTrendAnalyzer::new();
        for i in 0..100 {
            large_analyzer.add_snapshot(ScanSnapshot {
                scan_id: format!("scan-{}", i),
                timestamp: chrono::Utc::now() - chrono::Duration::days(100 - i),
                metrics: ScanMetrics {
                    total_hosts: 100,
                    hosts_up: 80,
                    total_ports: 1000,
                    open_ports: 400,
                    vulnerabilities: ReportingVulnMetrics {
                        critical: 5,
                        high: 10,
                        medium: 20,
                        low: 10,
                        info: 5,
                    },
                    risk_score: 6.0,
                },
            });
        }
        b.iter(|| large_analyzer.analyze(black_box(90)))
    });

    group.finish();
}

// =============================================================================
// Intensity Level Benchmarks
// =============================================================================
fn benchmark_intensity_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("intensity_levels");

    group.bench_function("intensity_creation_all_levels", |b| {
        b.iter(|| {
            for i in 0..=9 {
                let _ = IntensityLevel::new(black_box(i));
            }
        })
    });

    group.bench_function("intensity_should_use_probe", |b| {
        let level = IntensityLevel::new(5).unwrap();
        b.iter(|| {
            for i in 0..=9 {
                let _ = level.should_use_probe(black_box(i));
            }
        })
    });

    group.bench_function("intensity_description", |b| {
        let level = IntensityLevel::new(7).unwrap();
        b.iter(|| level.description())
    });

    group.bench_function("intensity_estimated_probes", |b| {
        let level = IntensityLevel::new(7).unwrap();
        b.iter(|| level.estimated_probes())
    });

    group.bench_function("intensity_time_multiplier", |b| {
        let level = IntensityLevel::new(7).unwrap();
        b.iter(|| level.time_multiplier())
    });

    group.bench_function("intensity_display", |b| {
        let level = IntensityLevel::new(7).unwrap();
        b.iter(|| format!("{}", level))
    });

    // DetectionConfig benchmarks
    group.bench_function("detection_config_default", |b| {
        b.iter(DetectionConfig::default)
    });

    group.bench_function("detection_config_light", |b| b.iter(DetectionConfig::light));

    group.bench_function("detection_config_all", |b| b.iter(DetectionConfig::all));

    group.finish();
}

// =============================================================================
// Performance Subsystem Benchmarks
// =============================================================================
fn benchmark_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("performance");

    // LockFreeQueue benchmarks
    group.bench_function("lockfree_queue_push_pop", |b| {
        let queue = LockFreeQueue::new();
        b.iter(|| {
            queue.push(black_box(42u64));
            let _ = queue.pop();
        })
    });

    group.bench_function("lockfree_queue_batch_100", |b| {
        let queue = LockFreeQueue::new();
        b.iter(|| {
            for i in 0..100u64 {
                queue.push(black_box(i));
            }
            for _ in 0..100 {
                let _ = queue.pop();
            }
        })
    });

    group.bench_function("lockfree_queue_len", |b| {
        let queue = LockFreeQueue::new();
        for i in 0..50 {
            queue.push(i);
        }
        b.iter(|| queue.len())
    });

    // BoundedQueue benchmarks
    group.bench_function("bounded_queue_push_pop", |b| {
        let queue = BoundedQueue::new(1024);
        b.iter(|| {
            let _ = queue.push(black_box(42u64));
            let _ = queue.pop();
        })
    });

    group.bench_function("bounded_queue_full_push", |b| {
        let queue = BoundedQueue::new(16);
        for i in 0..16 {
            let _ = queue.push(i);
        }
        b.iter(|| {
            let _ = queue.push(black_box(99u64));
        })
    });

    // AtomicFlag benchmarks
    group.bench_function("atomic_flag_set_get", |b| {
        let flag = AtomicFlag::new(false);
        b.iter(|| {
            flag.set(black_box(true));
            flag.get()
        })
    });

    group.bench_function("atomic_flag_swap", |b| {
        let flag = AtomicFlag::new(false);
        b.iter(|| flag.swap(black_box(true)))
    });

    // MetricsCollector benchmarks
    group.bench_function("metrics_increment_packets_sent", |b| {
        let metrics = MetricsCollector::new();
        b.iter(|| metrics.increment_packets_sent(black_box(1)))
    });

    group.bench_function("metrics_increment_packets_received", |b| {
        let metrics = MetricsCollector::new();
        b.iter(|| metrics.increment_packets_received(black_box(1)))
    });

    group.bench_function("metrics_add_bytes_sent", |b| {
        let metrics = MetricsCollector::new();
        b.iter(|| metrics.add_bytes_sent(black_box(1500)))
    });

    group.bench_function("metrics_increment_active_connections", |b| {
        let metrics = MetricsCollector::new();
        b.iter(|| metrics.increment_active_connections())
    });

    group.bench_function("metrics_increment_errors", |b| {
        let metrics = MetricsCollector::new();
        b.iter(|| metrics.increment_errors())
    });

    group.bench_function("metrics_reset", |b| {
        let metrics = MetricsCollector::new();
        metrics.increment_packets_sent(1000);
        metrics.add_bytes_sent(1_500_000);
        b.iter(|| metrics.reset())
    });

    group.finish();
}

// =============================================================================
// Scan Diff Benchmarks
// =============================================================================
fn benchmark_scan_diff(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_diff");

    let scan_a = create_multi_port_results(&[
        (22, PortState::Open, Some("ssh")),
        (80, PortState::Open, Some("http")),
        (443, PortState::Open, Some("https")),
        (3306, PortState::Open, Some("mysql")),
        (8080, PortState::Closed, None),
    ]);

    let scan_b = create_multi_port_results(&[
        (22, PortState::Open, Some("ssh")),
        (80, PortState::Open, Some("nginx")),
        (443, PortState::Open, Some("https")),
        (3306, PortState::Filtered, None),
        (8080, PortState::Open, Some("http-proxy")),
        (9090, PortState::Open, Some("prometheus")),
    ]);

    group.bench_function("compare_scans_small", |b| {
        b.iter(|| nemue::scanner::diff::compare_scans(black_box(&scan_a), black_box(&scan_b)))
    });

    // Larger diff
    let ports_a: Vec<(u16, PortState, Option<&str>)> = (1..=100)
        .map(|p| {
            (
                p,
                if p % 3 == 0 {
                    PortState::Open
                } else {
                    PortState::Closed
                },
                Some("http"),
            )
        })
        .collect();
    let ports_b: Vec<(u16, PortState, Option<&str>)> = (1..=100)
        .map(|p| {
            (
                p,
                if p % 2 == 0 {
                    PortState::Open
                } else {
                    PortState::Filtered
                },
                Some("http"),
            )
        })
        .collect();
    let large_a = create_multi_port_results(&ports_a);
    let large_b = create_multi_port_results(&ports_b);

    group.bench_function("compare_scans_100_ports", |b| {
        b.iter(|| nemue::scanner::diff::compare_scans(black_box(&large_a), black_box(&large_b)))
    });

    group.finish();
}

// =============================================================================
// Criterion Groups
// =============================================================================
criterion_group!(
    benches,
    benchmark_port_parsing,
    benchmark_target_parsing,
    benchmark_target_scaling,
    benchmark_timing,
    benchmark_script_args,
    benchmark_string_operations,
    benchmark_allocations,
    benchmark_port_range_scaling,
    benchmark_cidr_scaling,
    benchmark_service_detection,
    benchmark_enhanced_detection,
    benchmark_probe_database,
    benchmark_signatures,
    benchmark_os_fingerprinting,
    benchmark_vuln_scanning,
    benchmark_report_generation,
    benchmark_pdf_generation,
    benchmark_scan_history,
    benchmark_trend_analysis,
    benchmark_intensity_levels,
    benchmark_performance,
    benchmark_scan_diff,
);

criterion_main!(benches);
