# Nemue

An advanced security testing framework built in Rust, featuring high-performance network scanning, service detection, OS fingerprinting, and MCP server integration for AI assistants.

**Version**: 0.2.0  
**Tests**: 2,047 passing | **Lua Scripts**: 605 | **Service Signatures**: 3,055+  
**Speed**: 2.25x faster than Nmap on top-1000 scans

---

## Quick Start

```bash
# Build
cargo build --release

# Scan with service detection
./target/release/nemue scan -p top1000 -V scanme.nmap.org

# Start MCP server for AI assistants
./target/release/nemue mcp

# Compare two scan results
./target/release/nemue diff scan1.json scan2.json
```

---

## Key Features

### Scanning
- TCP Connect, SYN, UDP, SCTP, IP Protocol scans
- Idle scan (-sI zombie), FTP bounce scan (-b)
- Parallel target scanning (10-50x faster for subnets)
- Scan resume (--resume), scan diff/compare
- Packet trace (--packet-trace)
- Filtered ports shown by default

### Service Detection
- 3,055+ service signatures with regex matching
- SSH, HTTP, FTP, SMTP, DNS, database detection
- Version extraction with OS details
- nmap-service-probes parser

### OS Fingerprinting
- 203 OS signatures (Linux, Windows, macOS, BSD, Cisco, etc.)
- TCP/IP stack analysis (window size, TTL, options)
- Passive OS detection from banners

### MCP Server (AI Integration)
- 7 tools for Claude, Cursor, VS Code
- stdio transport, `nemue mcp` command
- First Rust network scanner with MCP support

### Lua Scripts
- 605 NSE-compatible scripts
- HTTP security, network protocols, databases
- IoT/ICS, cloud/container, wireless scanning

### Reporting
- JSON, XML, CSV, Markdown, HTML, PDF output
- SARIF, JUnit, CycloneDX, SPDX formats
- 7 compliance frameworks

### Enterprise
- REST API, WebSocket, GraphQL
- Webhooks (Slack, Discord, Teams)
- SIEM integration (CEF, LEEF, Syslog)
- CI/CD integration
- Jira, ServiceNow, PagerDuty integrations

---

## CLI Commands

```bash
# Basic scan
nemue scan -p 80,443 target.com

# Service detection
nemue scan -p top1000 -V target.com

# OS detection
nemue scan -p top100 -O target.com

# Idle scan via zombie
nemue scan -sI zombie_ip target.com

# FTP bounce scan
nemue scan -b ftp_server target.com

# Resume interrupted scan
nemue scan --resume <scan-id> target.com

# Compare scans
nemue diff scan1.json scan2.json

# Start MCP server
nemue mcp

# Web fuzzing
nemue fuzz https://target.com -m dir
```

---

## Benchmarks (vs Nmap 7.98)

| Metric | Nmap | Nemue | Speedup |
|--------|------|-------|---------|
| Top 1000 + service detection | 20.19s | **8.96s** | **2.25x** |
| Full 65K ports | 511.6s | **157.7s** | **3.24x** |

**Accuracy**: 5/5 ports match on scanme.nmap.org (100%)

---

## Installation

```bash
# From source
git clone https://github.com/supunhg/Nemue.git
cd Nemue
cargo build --release

# Binary releases
# Download from GitHub Releases page
```

---

## Documentation

- [STATUS.md](STATUS.md) - Current project status
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md) - Benchmark results
- [docs/COMPETITORS.md](docs/COMPETITORS.md) - Gap analysis
- [docs/FAQ.md](docs/FAQ.md) - Common questions
- [docs/USAGE.md](docs/USAGE.md) - Usage guide
- [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute

---

## License

MIT
