# Nemue Project Status

**Last Updated**: June 2026
**Current Version**: 0.1.0 (Cargo.toml) / 0.2.0 (docs - needs reconciliation)
**Branch**: dev
**Tests**: 2047 passing, 0 failing

---

## Quick Start

```bash
cargo build --release
./target/release/nemue scan -p top1000 -V scanme.nmap.org
./target/release/nemue mcp  # Start MCP server
```

---

## Actual Metrics (Verified)

| Metric | Count | Notes |
|--------|-------|-------|
| **Tests** | 2,047 | `cargo test --lib` |
| **Lua Scripts** | 605 | `ls scripts/*.lua` |
| **Service Signatures** | ~3,055 | `grep -c 'm("' src/service/signatures.rs` |
| **OS Signatures** | 203 | `grep -c "os_name:" src/fingerprint/stack.rs` |
| **Compile Warnings** | 0 | `cargo build` |
| **Source Files** | 100+ | Rust source files |

---

## What Actually Works (Verified)

### Core Scanning
- [x] TCP Connect scan
- [x] SYN scan (requires root)
- [x] UDP scan
- [x] SCTP scan
- [x] IP Protocol scan
- [x] Idle scan (-sI zombie)
- [x] FTP bounce scan (-b)
- [x] Parallel target scanning
- [x] Scan resume (--resume)
- [x] Scan diff/compare (`nemue diff`)
- [x] Packet trace (--packet-trace)
- [x] Filtered ports shown by default

### Service Detection
- [x] 3,055 service signatures with regex matching
- [x] SSH version extraction with OS details
- [x] HTTP server detection with version
- [x] nping-echo detection (port 9929)
- [x] tcpwrapped detection (port 31337)
- [x] Real probe sending in enhanced detector
- [x] nmap-service-probes parser

### OS Fingerprinting
- [x] 203 OS signatures (heuristic, not real TCP probes)
- [x] TCP/IP stack analysis (window size, TTL, options)
- [x] Passive OS detection from banners

### MCP Server
- [x] 7 working tools (scan, quick_scan, service_detect, os_detect, ssl_check, host_discovery, vuln_scan)
- [x] stdio transport
- [x] `nemue mcp` CLI command
- [ ] Traceroute tool (stub)
- [ ] Fuzz tool (stub)

### Reporting
- [x] JSON, XML, CSV, Markdown, HTML, PDF output
- [x] SARIF, JUnit, CycloneDX, SPDX formats
- [x] 7 compliance frameworks
- [x] Report templates

### Enterprise Features
- [x] REST API with 20+ endpoints
- [x] WebSocket, GraphQL support
- [x] Webhooks (Slack, Discord, Teams)
- [x] SIEM integration
- [x] CI/CD integration
- [x] Jira, ServiceNow, PagerDuty, GitHub integrations

### Cloud/Container/Wireless/IoT/Mobile
- [x] AWS/Azure/GCP scanning
- [x] Docker/Kubernetes scanning
- [x] WiFi/Bluetooth/Zigbee scanning
- [x] Modbus/DNP3/BACnet scanning
- [x] Android/iOS scanning

### ML & Automation
- [x] Anomaly detection
- [x] Threat intelligence
- [x] Predictive analytics
- [x] NLP entity extraction
- [x] Playbooks, workflows, rules, macros

---

## Real Benchmarks vs Nmap 7.98

| Metric | Nmap | Nemue | Speedup |
|--------|------|-------|---------|
| Top 1000 + service detection | 20.19s | **8.96s** | **2.25x** |
| Full 65K ports | 511.6s | **157.7s** | **3.24x** |

**Accuracy on scanme.nmap.org**: 5/5 ports match (100%)

---

## Known Issues

1. **Version mismatch**: Cargo.toml says 0.1.0, docs say 0.2.0
2. **OS signatures are heuristic**: Uses TTL/window-size, not real TCP probes
3. **2 MCP tools are stubs**: traceroute and fuzz return "not implemented"
4. **No cross-platform testing**: Only tested on Linux
5. **Some features are thin**: Many modules have basic implementations

---

## Honest Assessment

**Is this an MVP?** Yes. It scans ports, detects services, and is faster than Nmap on the test target. The MCP integration is unique. The core scanning works.

**Can you merge and freeze?** Yes, with caveats:
- The code compiles and tests pass
- The benchmarks are real (tested against Nmap 7.98)
- The docs need cleanup (version mismatch, inconsistent counts)
- Some features are thin implementations

**What needs fixing before merge:**
1. Fix version in Cargo.toml to 0.2.0
2. Clean up STATUS.md to match actual counts
3. Update README.md with accurate numbers

---

## For Next AI Session

If picking up this project:
1. Run `cargo test --lib` to verify 2047 tests pass
2. Run `cargo build --release` to build
3. Check `docs/COMPETITORS.md` for gap analysis
4. Check `docs/BENCHMARKS.md` for benchmark methodology
5. Focus on OS signatures (203 vs Nmap's 6000+) and performance
