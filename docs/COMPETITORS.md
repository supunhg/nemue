# Nemue Competitive Gap Analysis

**Last Updated**: June 2026
**Status**: Living document - updated with each release

---

## Executive Summary

Nemue v0.2.0 is a Rust-based security testing framework with 35K+ lines of code, 630+ tests, and broad feature coverage. This analysis compares Nemue against the leading network scanners and identifies honest gaps that need closing.

**Key Finding**: Nemue's greatest risk is not missing features -- it is the gap between documented capability and actual implementation depth. This document tracks that gap honestly.

---

## Competitor Overview

| Scanner | Language | Speed | Stars | Key Strength | Key Weakness |
|---------|----------|-------|-------|--------------|--------------|
| **Nmap** | C/Lua | ~1-5K pps | De facto standard | 25 years of signatures, 600+ NSE scripts | Slow, no modern integration |
| **RustScan** | Rust | ~21K pps | 19.9K | Sub-3s full port scan, adaptive learning | Requires Nmap for deep analysis |
| **Masscan** | C | 1.6-10M pps | 25.8K | Internet-scale speed, own TCP/IP stack | No service detection, no OS fingerprinting |
| **RustNmap** | Rust | ~10K pps | Niche | 100% Nmap parity goal | Limited adoption |
| **Blackmap** | Rust | 1M+ pps | Niche | Masscan-level speed + detection | New project |
| **OpenOrb** | Rust | 1-5M pps | Niche | AF_PACKET, NVD matching | New project |
| **Portex** | Go | 5000 goroutines | Niche | AI-augmented (RL, LLM) | Go, not Rust |

---

## Scorecard

| Dimension | Weight | Nmap | RustScan | Masscan | Nemue |
|-----------|--------|------|----------|---------|-------|
| Raw Speed | 15% | 6/10 | 9/10 | 10/10 | 3/10 |
| Accuracy/Depth | 25% | 10/10 | 3/10 | 4/10 | 5/10 |
| Feature Breadth | 20% | 8/10 | 3/10 | 2/10 | 8/10 |
| AI/MCP Integration | 10% | 0/10 | 0/10 | 0/10 | 7/10 |
| Enterprise Features | 10% | 3/10 | 1/10 | 1/10 | 8/10 |
| Community/Ecosystem | 10% | 10/10 | 7/10 | 7/10 | 1/10 |
| Cross-Platform | 5% | 10/10 | 9/10 | 7/10 | 3/10 |
| Documentation | 5% | 10/10 | 7/10 | 6/10 | 5/10 |
| **Weighted Score** | **100%** | **6.75** | **4.40** | **4.20** | **5.20** |

---

## Table-Stakes Features (Must Have)

| Feature | Nmap | RustScan | Masscan | Nemue | Status |
|---------|------|----------|---------|-------|--------|
| TCP SYN scan | Yes | Via Nmap | Yes | Yes | OK |
| TCP Connect scan | Yes | Yes | No | Yes | OK |
| UDP scan | Yes | No | No | Yes | OK |
| Service detection | Deep | No | Basic | Basic | **GAP** |
| OS fingerprinting | Deep | No | No | Heuristic | **GAP** |
| JSON output | Yes | Yes | Yes | Yes | OK |
| XML output | Yes | No | Yes | Yes | OK |
| CIDR notation | Yes | Yes | Yes | Yes | OK |
| Port ranges | Yes | Yes | Yes | Yes | OK |
| Rate limiting | Yes | Adaptive | Yes | Adaptive | OK |
| IPv6 support | Full | Yes | Yes | Partial | **GAP** |
| Cross-platform | Yes | Yes | Yes | Linux only | **GAP** |
| Progress indicators | Yes | Yes | No | Yes | OK |

---

## Differentiator Features (Nemue Leads)

| Feature | Nmap | RustScan | Masscan | Nemue | Status |
|---------|------|----------|---------|-------|--------|
| MCP/AI Integration | No | No | No | Yes | **NEMUE LEADS** |
| Compliance Reporting | No | No | No | Yes (7) | **NEMUE LEADS** |
| Web Fuzzing | No | No | No | Yes (8 modes) | **NEMUE LEADS** |
| REST API | No | No | No | Yes | **NEMUE LEADS** |
| Continuous Monitoring | No | No | No | Yes | **NEMUE LEADS** |
| Vulnerability Scanning | Via NSE | No | No | Yes | OK |
| SSL/TLS Analysis | Via NSE | No | No | Yes | OK |

---

## Critical Gaps

### GAP 1: Performance (CRITICAL)

| Metric | Nemue | RustScan | Masscan | Gap Factor |
|--------|-------|----------|---------|------------|
| 65K ports, single host | ~65s (est.) | ~3s | ~10-15s | 20-50x |
| Top 1000 ports | ~1s (est.) | ~0.5s | ~0.1s | 2-10x |
| 256-host subnet | ~Minutes | ~30s | ~5-10s | 10-60x |
| Packets per second | ~1K | ~21K | 1.6-10M | 20-10,000x |

**Root Cause**: Per-port `tokio::spawn` + per-port `Semaphore::acquire` + blocking `rx.next()` in async context.

**Target**: 50K-100K pps (enough for enterprise networks, compete on depth not speed).

### GAP 2: OS Fingerprinting Depth (HIGH)

| Aspect | Nmap | Nemue |
|--------|------|-------|
| Method | 16+ crafted TCP probes, 100+ response attributes | TTL/window-size heuristics from open ports |
| Signatures | 6,000+ | 6 heuristic families |
| Accuracy | 95%+ | ~60% (heuristic) |

**Target**: Implement real TCP/IP stack probing with 200+ signatures.

### GAP 3: Service Detection Depth (HIGH)

| Aspect | Nmap | Nemue |
|--------|------|-------|
| Signatures | 1,200+ version signatures | 100+ probes, basic matching |
| Version extraction | Regex-based from banners | HTTP, SSH, FTP, SMTP only |
| Community | 25 years of traffic analysis | New project |

**Target**: Build `nemue-service-probes` file format, 500+ signatures.

### GAP 4: No Real Benchmarks (CRITICAL)

- BENCHMARKS.md has every cell marked "TBD"
- No comparison data against any competitor
- Claims cannot be validated

**Target**: Run actual benchmarks and publish honest results.

### GAP 5: Cross-Platform Support (MEDIUM)

| Platform | Nmap | RustScan | Masscan | Nemue |
|----------|------|----------|---------|-------|
| Linux | Yes | Yes | Yes | Yes |
| macOS | Yes | Yes | Yes | Planned |
| Windows | Yes | Yes | Yes | Planned |

**Target**: macOS and Windows support via platform abstraction layer.

---

## Nemue's Unique Advantages

1. **MCP Integration (First Mover)**: Only network scanner with native MCP server support. As AI assistants become standard in security workflows, this becomes a moat.

2. **All-in-One Platform**: Port scanning + fuzzing + vuln scanning + compliance in one binary. No competitor offers this breadth.

3. **Compliance-First Reporting**: Seven compliance frameworks (PCI-DSS, NIST, CIS, ISO 2701, HIPAA, SOC 2, GDPR). Enterprise buyers need this.

4. **Built-in Web Fuzzing**: 8 fuzzing modes with 10 built-in wordlists. Eliminates need for ffuf/gobuster.

5. **REST API Server**: Full API for DevSecOps pipeline integration.

---

## Strategic Positioning

**Recommended Position**: "Nemue is the AI-native security platform that discovers, analyzes, and reports -- from port scan to compliance report, in one Rust binary."

**What NOT to compete on**:
- Pure Speed vs. Masscan: Different architecture, target 50-100K pps
- Signature Database vs. Nmap: Focus on modern services (containers, cloud, APIs)
- Simplicity vs. RustScan: Embrace complexity with good defaults

---

## Roadmap to Close Gaps

| Phase | Timeline | Target | Impact |
|-------|----------|--------|--------|
| Fix bugs, benchmarks | Month 1-2 | Honest data, 9/9 MCP tools | Trust |
| Performance optimization | Month 2-4 | 10K-50K pps | Speed |
| OS fingerprinting | Month 4-6 | 200+ signatures | Accuracy |
| Service signatures | Month 6-8 | 500+ signatures | Depth |
| Cross-platform | Month 8-10 | macOS, Windows | Reach |
| Community building | Month 10+ | 1K stars, 100+ scripts | Ecosystem |
