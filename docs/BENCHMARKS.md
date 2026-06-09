# Nemue Benchmark Results

**Last Updated**: June 2026
**Status**: Framework ready, awaiting automated benchmark runs

---

## Executive Summary

Nemue v0.2.0 introduces parallel target scanning, fixed adaptive rate limiting, proper buffer pooling, and MCP server integration. Benchmarks will be populated after CI/CD pipeline is operational.

---

## Test Environment

| Component | Specification |
|-----------|---------------|
| OS | Ubuntu 24.04 LTS |
| CPU | 16 cores, 3.5GHz |
| RAM | 32GB DDR5 |
| Network | 1Gbps NIC |
| Kernel | 6.x |
| Nemue Version | 0.2.0 |

---

## Speed Comparison

### Single Host, 65,535 Ports

| Scanner | Time | Ports/sec | Memory (MB) | Accuracy |
|---------|------|-----------|-------------|----------|
| Nemue 0.2.0 | TBD | TBD | TBD | TBD |
| Nmap 7.95 | TBD | TBD | TBD | TBD |
| Rustscan 2.x | TBD | TBD | TBD | TBD |
| Masscan 1.3 | TBD | TBD | TBD | TBD |
| RustNmap 1.0 | TBD | TBD | TBD | TBD |
| Blackmap 6.3 | TBD | TBD | TBD | TBD |
| OpenOrb | TBD | TBD | TBD | TBD |
| Portex | TBD | TBD | TBD | TBD |

### Top 1000 Ports, Single Host

| Scanner | Time | Ports/sec | Memory (MB) |
|---------|------|-----------|-------------|
| Nemue 0.2.0 | TBD | TBD | TBD |
| Nmap 7.95 | TBD | TBD | TBD |
| Rustscan 2.x | TBD | TBD | TBD |
| Masscan 1.3 | TBD | TBD | TBD |

### Subnet Scan (256 hosts, Top 1000 ports)

| Scanner | Time | Hosts/sec | Memory (MB) |
|---------|------|-----------|-------------|
| Nemue 0.2.0 | TBD | TBD | TBD |
| Nmap 7.95 | TBD | TBD | TBD |
| Rustscan 2.x | TBD | TBD | TBD |
| Masscan 1.3 | TBD | TBD | TBD |

---

## Service Detection Accuracy

| Scanner | Services Detected | Version Accuracy | OS Detection |
|---------|------------------|------------------|--------------|
| Nemue 0.2.0 | TBD | TBD | TBD |
| Nmap 7.95 | TBD | TBD | TBD |
| RustNmap 1.0 | TBD | TBD | TBD |

---

## MCP Server Performance

| Metric | Value |
|--------|-------|
| Tool listing latency | TBD |
| Scan invocation latency | TBD |
| Concurrent scan capacity | TBD |
| Memory per MCP session | TBD |

---

## Methodology

### Tools Compared

| Tool | Version | Language | Notes |
|------|---------|----------|-------|
| Nmap | 7.95+ | C/Lua | Gold standard |
| Rustscan | 2.x | Rust | Speed-focused |
| Masscan | 1.3+ | C | Internet-scale |
| RustNmap | 1.0.0 | Rust | 100% Nmap parity |
| Blackmap | 6.3.0 | Rust | 1M+ pps |
| OpenOrb | latest | Rust | AF_PACKET |
| Portex | latest | Go | AI-augmented |

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

### Automation

Benchmarks run via `cargo bench` and `.github/workflows/benchmark.yml`. Results are committed to this file after each run.

---

## Changelog

- **2026-06**: Initial benchmark framework created
