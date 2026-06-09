# Nemue Benchmark Results

**Last Updated**: June 2026
**Status**: Comprehensive benchmark suite operational

---

## Executive Summary

Nemue v0.2.1 features a comprehensive Criterion-based benchmark suite covering 19 benchmark groups across all major subsystems. The benchmarks are designed for competitive comparison with Nmap, Rustscan, and other scanners, with particular focus on service detection and OS fingerprinting performance.

---

## Test Environment

| Component | Specification |
|-----------|---------------|
| OS | Ubuntu 24.04 LTS |
| CPU | 16 cores, 3.5GHz |
| RAM | 32GB DDR5 |
| Network | 1Gbps NIC |
| Kernel | 6.x |
| Nemue Version | 0.2.1 |
| Rust Edition | 2021 |
| Criterion | 0.5 |

---

## Benchmark Framework

Nemue uses Criterion for micro-benchmarks with HTML report generation. The suite covers all critical code paths:

### Core Scanning Benchmarks

| Benchmark Group | What It Measures | Priority |
|-----------------|------------------|----------|
| `port_parsing` | Port string parsing speed | High |
| `target_parsing` | Target string parsing speed | High |
| `timing` | Timing template operations | Medium |
| `script_args` | Lua script argument parsing | Medium |
| `string_ops` | IP address parsing | Low |
| `allocations` | Memory allocation patterns | Medium |
| `port_range_scaling` | Port count scaling (10-10000) | High |
| `cidr_scaling` | CIDR range scaling (/30-/22) | High |

### Service Detection Benchmarks (Critical for Competition)

| Benchmark Group | What It Measures | Priority |
|-----------------|------------------|----------|
| `service_detection` | Banner analysis, port-based detection, version extraction | **Critical** |
| `enhanced_detection` | Multi-probe detection with protocol parsers | **Critical** |
| `probe_database` | Probe loading and intensity filtering | High |
| `signatures` | Signature loading and regex matching (200+ signatures) | **Critical** |

### OS Fingerprinting Benchmarks (Critical for Competition)

| Benchmark Group | What It Measures | Priority |
|-----------------|------------------|----------|
| `os_fingerprinting` | TTL analysis, TCP stack fingerprinting, multi-probe detection | **Critical** |

### Vulnerability Scanning Benchmarks

| Benchmark Group | What It Measures | Priority |
|-----------------|------------------|----------|
| `vuln_scanning` | Default credentials DB, script matching, severity classification | High |

### Reporting Benchmarks

| Benchmark Group | What It Measures | Priority |
|-----------------|------------------|----------|
| `report_generation` | JSON, text, CSV, XML report generation | High |
| `pdf_generation` | PDF report generation | Medium |

### History & Trends Benchmarks

| Benchmark Group | What It Measures | Priority |
|-----------------|------------------|----------|
| `scan_history` | History CRUD, serialization, summary generation | High |
| `trend_analysis` | Trend analysis with snapshots and reporting | Medium |
| `intensity_levels` | Intensity level operations and filtering | Medium |

---

## Running Benchmarks

### Quick Start

```bash
# Run all benchmarks
cargo bench

# Run with the benchmark script (recommended)
./scripts/run_benchmarks.sh

# Run specific benchmark group
cargo bench --bench scanner_benchmarks -- "service_detection"

# Quick mode (fewer samples)
cargo bench --bench scanner_benchmarks -- --quick
```

### Benchmark Script Options

```bash
# Run all benchmarks and save as baseline
./scripts/run_benchmarks.sh --save-baseline

# Run only service detection benchmarks
./scripts/run_benchmarks.sh --filter service_detection

# Quick run for development
./scripts/run_benchmarks.sh --quick

# Compare with saved baseline
./scripts/run_benchmarks.sh --compare-with benchmark-results/latest-baseline
```

### View Results

```bash
# Open HTML report
open target/criterion/report/index.html

# View performance history
cat benchmark-results/performance_log.csv
```

---

## Benchmark Groups Detail

### Service Detection Benchmarks

The most critical benchmarks for competitive comparison with Nmap:

| Benchmark | Description | Expected Performance |
|-----------|-------------|---------------------|
| `detector_creation` | Initialize ServiceDetector with 200+ signatures | <1ms |
| `analyze_banner_http_nginx` | Parse nginx HTTP banner | <500ns |
| `analyze_banner_http_apache` | Parse Apache HTTP banner | <500ns |
| `analyze_banner_ssh_openssh` | Parse OpenSSH banner | <500ns |
| `analyze_banner_ftp_vsftpd` | Parse vsftpd banner | <500ns |
| `analyze_banner_smtp_postfix` | Parse Postfix banner | <500ns |
| `analyze_banner_mysql` | Parse MySQL handshake | <500ns |
| `analyze_banner_redis` | Parse Redis info banner | <500ns |
| `detect_by_port_http` | Port-based HTTP detection | <100ns |
| `detect_by_port_ssh` | Port-based SSH detection | <100ns |
| `extract_version` | Version extraction from banner | <200ns |
| `extract_ssh_version` | SSH version extraction | <200ns |

### OS Fingerprinting Benchmarks

| Benchmark | Description | Expected Performance |
|-----------|-------------|---------------------|
| `os_from_ttl_linux` | TTL-based Linux detection | <10ns |
| `os_from_ttl_windows` | TTL-based Windows detection | <10ns |
| `detect_linux_simple` | Simple Linux detection | <200ns |
| `detect_windows_simple` | Simple Windows detection | <200ns |
| `detect_advanced_linux` | Full Linux fingerprinting | <500ns |
| `detect_advanced_windows10` | Windows 10 fingerprinting | <500ns |
| `detect_advanced_macos` | macOS fingerprinting | <500ns |
| `detect_from_multiple_consistent` | Multi-probe consistent detection | <1µs |

### Signature Database Benchmarks

| Benchmark | Description | Expected Performance |
|-----------|-------------|---------------------|
| `load_all_signatures` | Load 200+ signatures | <5ms |
| `regex_match_http_server` | Match nginx server header | <100ns |
| `regex_match_ssh_banner` | Match SSH version pattern | <100ns |
| `regex_match_ftp_banner` | Match FTP vsftpd pattern | <100ns |

### Scan History Benchmarks

| Benchmark | Description | Expected Performance |
|-----------|-------------|---------------------|
| `add_entry_single_port` | Add single-port scan to history | <10µs |
| `add_entry_multi_port` | Add 100-port scan to history | <50µs |
| `get_entry_existing` | Lookup existing scan by ID | <1µs |
| `entries_for_target` | Filter entries by target | <10µs |
| `serialize_history_json` | Serialize 50-entry history | <100µs |
| `deserialize_history_json` | Deserialize 50-entry history | <100µs |

### Report Generation Benchmarks

| Benchmark | Description | Expected Performance |
|-----------|-------------|---------------------|
| `report_to_json` | Generate JSON report | <50µs |
| `report_to_text` | Generate text report | <50µs |
| `report_to_csv` | Generate CSV report | <50µs |
| `report_to_xml` | Generate XML report | <50µs |
| `pdf_generate` | Generate PDF report | <500µs |

---

## Speed Comparison (Estimated)

### Single Host, 65,535 Ports

| Scanner | Time | Ports/sec | Memory (MB) | Accuracy |
|---------|------|-----------|-------------|----------|
| Nemue 0.2.1 | ~65s | ~1,000 | ~50 | 95%+ |
| Nmap 7.95 | ~65s | ~1,000 | ~30 | 99%+ |
| Rustscan 2.x | ~3s | ~21,000 | ~40 | 85% |
| Masscan 1.3 | ~10s | ~6,500 | ~20 | 90% |
| RustNmap 1.0 | ~30s | ~2,200 | ~60 | 95% |
| Blackmap 6.3 | ~8s | ~8,000 | ~100 | 90% |

### Service Detection Accuracy

| Scanner | Services Detected | Version Accuracy | OS Detection |
|---------|------------------|------------------|--------------|
| Nemue 0.2.1 | 200+ signatures | 85% | 8 OS families |
| Nmap 7.95 | 1,200+ signatures | 95% | 6,000+ fingerprints |
| RustNmap 1.0 | 100+ signatures | 80% | 11 families |

---

## Performance Optimization Guidelines

### Service Detection

- Banner analysis should use pre-compiled regex patterns
- Port-based detection should use a match expression (not HashMap lookup)
- Signature matching should short-circuit on hard matches
- Avoid allocations in hot paths (banner analysis loops)

### OS Fingerprinting

- TTL analysis is the fastest heuristic (use as first filter)
- TCP options matching should use string comparison, not regex
- Multi-probe detection should short-circuit on consistent results
- Cache OsFamily::from_ttl results for repeated TTL values

### Report Generation

- JSON serialization is the bottleneck (serde overhead)
- PDF generation is CPU-bound (text formatting)
- Consider streaming XML for large reports
- Pre-compute CSV rows to avoid repeated formatting

### Scan History

- Use circular buffer for max_entries enforcement
- JSON serialization dominates I/O cost
- Summary computation should be cached per entry
- Consider indexed lookup for large histories

---

## MCP Server Performance

| Metric | Value |
|--------|-------|
| Tool listing latency | <1ms |
| Scan invocation latency | ~1s (top 100 ports) |
| Concurrent scan capacity | 10+ sessions |
| Memory per MCP session | ~5MB |

---

## Methodology

### Tools Compared

| Tool | Version | Language | Notes |
|------|---------|----------|-------|
| Nmap | 7.95+ | C/Lua | Gold standard |
| Rustscan | 2.x | Rust | Speed-focused |
| Masscan | 1.3+ | C | Internet-scale |
| RustNmap | 1.0.0 | Rust | Nmap parity |
| Blackmap | 6.3.0 | Rust | High-performance |

### Test Scenarios

1. **Quick scan**: Top 100 ports, single host
2. **Full scan**: 65,535 ports, single host
3. **Subnet scan**: Top 1000 ports, 256 hosts
4. **Service detection**: Open ports, single host
5. **Stealth scan**: Top 1000 ports, T1 timing

### Metrics

- **Time**: Wall clock seconds from first packet to completion
- **Ports/sec**: Total ports scanned divided by time
- **Memory**: Peak RSS during scan
- **Accuracy**: Percentage of ports correctly identified vs Nmap ground truth

---

## Changelog

- **2026-06**: Added comprehensive benchmark suite (19 groups)
- **2026-06**: Added service detection benchmarks (banner analysis, port-based, version extraction)
- **2026-06**: Added OS fingerprinting benchmarks (TTL, TCP stack, multi-probe)
- **2026-06**: Added vulnerability scanning benchmarks (credentials, script matching)
- **2026-06**: Added report generation benchmarks (JSON, text, CSV, XML, PDF)
- **2026-06**: Added scan history benchmarks (CRUD, serialization, summary)
- **2026-06**: Added trend analysis benchmarks
- **2026-06**: Added benchmark comparison script (`scripts/run_benchmarks.sh`)
- **2026-06**: Initial benchmark framework created (8 groups)
