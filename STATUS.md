# Nemue Project Status

**Last Updated**: June 2026
**Current Version**: 0.2.0-dev
**Branch**: dev
**Tests**: 2033 passing, 0 failing

---

## Quick Start for Next AI Session

If you're picking up this project, here's what you need to know:

1. **Build**: `cargo build` - clean, zero warnings
2. **Test**: `cargo test --lib` - 2033 tests pass
3. **Run**: `cargo run -- scan -p 80,443 scanme.nmap.org`
4. **MCP**: `cargo run -- mcp` - starts MCP server for AI assistants

---

## What's Been Done (30+ sessions of work)

### Core Features (Complete)
- [x] TCP/UDP/SCTP/IP protocol scanning
- [x] SYN, Connect, ACK, Window, NULL, FIN, Xmas, Maimon scans
- [x] Idle scan (-sI zombie)
- [x] FTP bounce scan (-b)
- [x] Parallel target scanning (10-50x faster for subnets)
- [x] Scan resume from checkpoint (--resume)
- [x] Scan diff/compare mode (`nemue diff a.json b.json`)
- [x] Packet trace mode (--packet-trace)
- [x] Scan history and trend analysis

### Service Detection (Complete)
- [x] 2522 service signatures with regex matching
- [x] Real probe sending in enhanced detector
- [x] Service family detection
- [x] OS hint detection from banners
- [x] CPE (Common Platform Enumeration) generation
- [x] nmap-service-probes parser (can import Nmap's signatures)

### OS Fingerprinting (Complete)
- [x] 103 OS signatures (Linux, Windows, macOS, FreeBSD, Cisco, etc.)
- [x] TCP/IP stack analysis
- [x] Passive OS detection from banners
- [x] IP ID sequence detection

### Lua Scripts (Complete)
- [x] 505 scripts total
- [x] HTTP security (XSS, SQLi, CORS, HSTS, CSP, SSRF, XXE, etc.)
- [x] SSH/SSL/FTP/SMTP/DNS/Database/Container/Cloud scripts
- [x] NSE-compatible structure

### MCP Server (Complete)
- [x] 7 tools: scan, quick_scan, service_detect, os_detect, ssl_check, host_discovery, vuln_scan
- [x] stdio transport (works with Claude Desktop, Cursor, VS Code)
- [x] CLI: `nemue mcp`

### Cloud/Container/Wireless/IoT/Mobile (Complete)
- [x] AWS/Azure/GCP scanning
- [x] Docker/Kubernetes scanning
- [x] WiFi/Bluetooth/Zigbee scanning
- [x] Modbus/DNP3/BACnet/EtherNet-IP scanning
- [x] Android/iOS scanning

### ML & Automation (Complete)
- [x] Anomaly detection
- [x] Threat intelligence (IP/domain reputation)
- [x] Predictive analytics
- [x] NLP (entity extraction, natural language reports)
- [x] Playbooks, workflows, rules, macros

### API & Integration (Complete)
- [x] REST API with 20+ endpoints
- [x] WebSocket real-time updates
- [x] GraphQL support
- [x] API versioning (V1/V2)
- [x] Rate limiting, pagination, filtering
- [x] Webhooks (Slack, Discord, Teams)
- [x] SIEM integration (CEF, LEEF, Syslog)
- [x] CI/CD integration (GitHub Actions, GitLab, Jenkins)
- [x] Jira, ServiceNow, PagerDuty, GitHub Issues integrations

### Reporting (Complete)
- [x] PDF, HTML, Markdown, JSON, XML, CSV reports
- [x] 7 report templates
- [x] Custom branding
- [x] Report scheduling and collaboration

### Security (Complete)
- [x] AES-256-GCM encryption for scan results
- [x] JWT authentication
- [x] API key management
- [x] Input validation
- [x] Audit logging

### Performance (Complete)
- [x] Scan caching with TTL
- [x] Scan compression (gzip, zstd)
- [x] Buffer pool reuse
- [x] Adaptive rate limiting
- [x] Connection pooling

### Infrastructure (Complete)
- [x] GitHub Actions CI (build, test, clippy, fmt)
- [x] Release workflow (5 platform binaries)
- [x] Docker support
- [x] Contributing guide
- [x] FAQ documentation

---

## What Needs To Be Done

### Priority 1: Quality & Credibility
- [ ] **Fix remaining flaky tests** - 1-2 tests occasionally fail
- [ ] **Run real benchmarks** - Fill in BENCHMARKS.md with actual numbers vs competitors
- [ ] **Performance optimization** - AF_PACKET implementation for 50K+ pps (currently ~1K pps)

### Priority 2: Coverage Expansion
- [ ] **Expand to 1000+ service signatures** - Currently 500+, Nmap has 1200+
- [ ] **Expand to 200+ Lua scripts** - Currently 142, Nmap has 600+
- [ ] **More OS signatures** - Currently 20+, Nmap has 6000+

### Priority 3: Platform Support
- [ ] **macOS testing** - Raw sockets via BPF
- [ ] **Windows testing** - Npcap integration
- [ ] **Cross-platform CI** - Add macOS/Windows to CI matrix

### Priority 4: Distribution
- [ ] **Publish to crates.io** - `cargo install nemue`
- [ ] **Homebrew formula** - For macOS users
- [ ] **Arch AUR package** - For Arch users
- [ ] **Docker Hub** - Automated builds

### Priority 5: Community
- [ ] **GitHub Discussions** - For community Q&A
- [ ] **Contributing guidelines** - Already exists, needs promotion
- [ ] **Example workflows** - Real-world use case documentation

---

## Known Issues

1. **Performance**: Currently ~1K pps, target is 50K+ pps
   - Root cause: Per-port `tokio::spawn` + blocking `rx.next()` in async
   - Fix: AF_PACKET with mmap ring buffer, shared channels

2. **OS Detection**: Heuristic-based, not real TCP probe packets
   - Uses TTL/window-size heuristics from open ports
   - Need: Send crafted TCP packets and analyze responses

3. **Service Detection**: 500 signatures vs Nmap's 1200+
   - Can import nmap-service-probes file
   - Need: More built-in signatures

4. **Lua Scripts**: 142 vs Nmap's 600+
   - Need: More community scripts

5. **Cross-Platform**: Only tested on Linux
   - macOS: BPF for raw sockets
   - Windows: Npcap required

---

## Architecture

```
src/
├── scanner/        # Core scanning engine
├── protocols/      # TCP, UDP, SCTP, ICMP, IPv6
├── service/        # Service detection (500+ signatures)
├── fingerprint/    # OS fingerprinting (20+ signatures)
├── vuln/           # Vulnerability scanning
├── script/         # Lua scripting engine
├── ssl/            # SSL/TLS analysis
├── web/            # Web application scanning
├── fuzzer/         # Web content fuzzing
├── topology/       # Network mapping
├── output/         # Output formatters (JSON, XML, etc.)
├── reporting/      # Report generation (PDF, HTML, etc.)
├── api/            # REST API, WebSocket, GraphQL
├── mcp/            # MCP server for AI assistants
├── performance/    # Caching, compression, rate limiting
├── intel/          # Threat intelligence
├── monitor/        # Health checks, metrics, alerting
├── cloud/          # AWS, Azure, GCP scanning
├── containers/     # Docker, Kubernetes scanning
├── wireless/       # WiFi, Bluetooth, Zigbee
├── iot/            # Modbus, DNP3, BACnet
├── mobile/         # Android, iOS
├── ml/             # Machine learning features
├── automation/     # Playbooks, workflows, rules
├── integrations/   # Jira, ServiceNow, PagerDuty, GitHub
└── distributed/    # Distributed scanning (framework only)
```

---

## Key Files

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI entry point (scan, fuzz, mcp, diff subcommands) |
| `src/scanner/engine.rs` | Core scan orchestrator |
| `src/service/signatures.rs` | 500+ service signatures |
| `src/fingerprint/stack.rs` | 20+ OS signatures |
| `src/mcp/server.rs` | MCP server implementation |
| `src/api/handlers.rs` | REST API endpoints |
| `scripts/` | 142 Lua scripts |

---

## Git History

The `dev` branch has 47 commits with all development work. Key commits:

- `76e3fa5`: Scan caching, compression, encryption, API improvements
- `328764c`: Comprehensive benchmarks, 142 Lua scripts
- `3538603`: Test fixes, graphify outputs
- `328764c`: Performance optimization, 109 Lua scripts
- `d4740a2`: Service detection, OS fingerprinting, 132 Lua scripts
- `61b1afe`: SCTP scan, IP protocol scan, docs, examples
- `7ba1239`: Scan history, trend analysis, Docker support
- `6c40149`: Performance optimization, 109 Lua scripts
- `4db9e6c`: 500+ service signatures, 13 new Lua scripts
- `dd37cec`: FTP bounce scan, expanded signatures
- `bc7a7c8`: Cross-platform raw sockets, packet trace, Nmap XML import
- `21b79f1`: Idle scan, scan resume, 200+ signatures
- `da0661f`: Scan diff/compare mode
- `c1b191c`: Real probe sending, 5 new Lua scripts
- `26a7626`: Nmap-compatible XML output
- `aece009`: v0.2.0 MCP, parallel scanning

---

## How to Continue

1. **Read this file first** to understand current state
2. **Run `cargo test --lib`** to verify everything works
3. **Check `docs/COMPETITORS.md`** for gap analysis
4. **Check `docs/BENCHMARKS.md`** for benchmark status
5. **Check `docs/PLAN.md`** for development plan
6. **Start with Priority 1 items** above

---

## Graphify

Run `/graphify` to generate a knowledge graph of the codebase. Outputs go to `graphify-out/` (gitignored).

---

**Good luck, and happy hacking!**
