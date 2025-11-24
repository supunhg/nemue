# Nemue 🌊

A high-performance network scanner built in Rust, designed to surpass Nmap with modern architecture, blazing speed, and powerful features.

## Features

### Core Scanning
- ⚡ **True SYN Stealth Scanning** - Raw socket implementation via pnet datalink layer
- 🔌 **Multi-Protocol Support** - TCP, UDP, ICMP across IPv4 and IPv6
- 🎯 **High Performance** - Async/await with Tokio, configurable concurrency
- 🌐 **Modern Protocols** - Full IPv6 support alongside IPv4

### Advanced Detection
- 🖥️ **Advanced OS Fingerprinting** - TCP timestamps, window scaling, MSS analysis, 11 OS families
- 🔍 **Service Detection** - 112+ services (databases, containers, message queues, web frameworks)
- 📊 **Banner Grabbing** - Automatic version extraction for HTTP, SSH, FTP, SMTP
- 💡 **Confidence Scoring** - Transparent reliability metrics for detections

### Stealth & Evasion
- 🥷 **6 Timing Templates** - T0 (Paranoid) to T5 (Insane)
- 🎭 **Decoy Scanning** - Confuse IDS/IPS with decoy sources
- 🎲 **Randomization** - Host and port randomization
- 🔧 **TTL Manipulation** - Custom TTL values
- 🎯 **Source Port Spoofing** - Custom source ports (e.g., port 53 to appear as DNS)

### Scripting & Extensibility  
- 🐍 **Lua Script Engine** - Full Lua 5.4 support (vendored)
- 📜 **NSE-Compatible API** - Write Nmap-style scripts
- 🔬 **Vulnerability Detection** - Built-in framework with severity scoring
- 📦 **5 Example Scripts** - HTTP headers, SSL checks, SSH banner, FTP anon, DB defaults

### Intelligence & Analysis
- 🛡️ **CVE Database Integration** - Automatic vulnerability lookup for detected services
- 🕵️ **Threat Intelligence** - IP reputation checks against known malicious infrastructure
- ⚖️ **Risk Scoring Engine** - Comprehensive risk assessment combining multiple factors
- 🔍 **Passive Reconnaissance** - Query Shodan/Censys before active scanning
- 📊 **Actionable Recommendations** - Prioritized security findings with remediation guidance

### Enterprise Features
- 🌐 **REST API Server** - Full API with 7 endpoints for automation
- 📡 **Continuous Monitoring** - Periodic rescanning with change detection
- 🔔 **Alert System** - Notifications for new ports, services, vulnerabilities
- 💼 **Session Management** - Multiple concurrent monitoring sessions
- 📈 **Historical Tracking** - Track network changes over time
- 🔄 **Distributed Scanning** - Multi-node coordinator for horizontal scaling
- 📊 **Report Generation** - Executive, Technical, and Compliance templates

### User Experience
- 🎨 **Beautiful Colored Output** - Nmap-style formatting with RGB colors
- 📊 **Multiple Formats** - JSON, XML export
- 💻 **Modern CLI** - Intuitive commands with detailed help
- ⏱️ **Progress Indicators** - Real-time scan progress

## Installation

### Prerequisites
- Rust 1.70 or higher
- Root/sudo privileges (for raw socket SYN scans)
- Linux/macOS (Windows support planned)

### Build from source
```bash
git clone https://github.com/supunhg/Nemue.git
cd Nemue
cargo build --release

# The binary will be at target/release/nemue
sudo ./target/release/nemue --help
```

## Usage

### Basic Scanning

```bash
# TCP SYN scan (requires root for raw sockets)
sudo ./target/release/nemue scan 192.168.1.1 -p 80,443 --raw

# TCP connect scan (no root required)
./target/release/nemue scan 192.168.1.1 -p 1-1000

# UDP scanning with service-specific probes
sudo ./target/release/nemue scan 192.168.1.1 -p 53,123,161 --scan-type udp

# IPv6 scanning
sudo ./target/release/nemue scan fe80::1 -p 80,443 --raw
```

### Stealth Scanning

```bash
# Paranoid timing (5 min between packets)
sudo ./target/release/nemue scan target.com -p 1-1000 --timing paranoid --raw

# Sneaky scan (15 sec between packets)  
sudo ./target/release/nemue scan target.com -p 1-65535 --timing sneaky --raw

# Custom source port to evade firewalls
sudo ./target/release/nemue scan target.com -p 80,443 --source-port 53 --raw

# With decoy addresses
sudo ./target/release/nemue scan target.com -p 80 --decoys 192.168.1.5,192.168.1.6 --raw
```

### Service & OS Detection

```bash
# Full scan with service and OS detection
sudo ./target/release/nemue scan 192.168.1.1 -p 1-1000 -S true -O true --raw

# Service detection only (faster)
./target/release/nemue scan 192.168.1.1 -p 22,80,443,3306,5432 -O false

# OS detection only
sudo ./target/release/nemue scan 192.168.1.1 -p 22,80,443 -S false --raw
```

### Output Options

```bash
# Save to JSON
./target/release/nemue scan 192.168.1.1 -p 80,443 -o results.json

# Save to XML (Nmap compatible)
./target/release/nemue scan 192.168.1.1 -p 80,443 -o results.xml --format xml

# Quiet mode (no banner)
./target/release/nemue scan 192.168.1.1 -p 80 --no-banner

# Verbose output
./target/release/nemue scan 192.168.1.1 -p 1-100 --verbose
```

### Lua Scripting

```bash
# Run vulnerability detection scripts
./target/release/nemue script run scripts/ssl-version-check.lua 192.168.1.1 443
./target/release/nemue script run scripts/db-default-creds.lua 192.168.1.1 3306

# List available scripts
./target/release/nemue script list

# Run all scripts in category
./target/release/nemue script run-category vuln 192.168.1.1
```

### Intelligence & Risk Analysis

```bash
# Scan with automatic CVE lookup
./target/release/nemue scan 192.168.1.1 -p 22,80,443 --check-vulns

# Include threat intelligence checks
./target/release/nemue scan 192.168.1.1 -p 1-1000 --threat-intel

# Full risk assessment (CVE + threat intel + exposure analysis)
./target/release/nemue scan 192.168.1.1 -p 1-1000 --risk-assessment

# Passive reconnaissance before active scan (requires API keys)
./target/release/nemue scan 192.168.1.1 --passive-first --shodan-key YOUR_KEY

# Generate security report with recommendations
./target/release/nemue scan 192.168.1.1 -p 1-1000 --risk-report -o security_report.json
```

### REST API Server

```bash
# Start the API server
./target/release/nemue api --bind 0.0.0.0:8080

# Health check
curl http://localhost:8080/health

# Start a new scan via API
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.1"],
    "ports": [80, 443],
    "scan_type": "tcp",
    "timing": "normal"
  }'

# Get scan status
curl http://localhost:8080/api/v1/scans/{scan_id}

# List all scans
curl http://localhost:8080/api/v1/scans?page=1&per_page=20
```

### Continuous Monitoring

```bash
# Start continuous monitoring (rescans every 5 minutes)
./target/release/nemue monitor start \
  --name "Production Network" \
  --targets 192.168.1.0/24 \
  --ports 22,80,443,3306 \
  --interval 300 \
  --alert-on-changes

# List monitoring sessions
./target/release/nemue monitor list

# Pause a monitoring session
./target/release/nemue monitor pause {session_id}

# Resume monitoring
./target/release/nemue monitor resume {session_id}

# View detected changes
./target/release/nemue monitor changes {session_id}
```

### Distributed Scanning

```bash
# Start a distributed coordinator
./target/release/nemue distributed coordinator --bind 0.0.0.0:9000

# Register scanning nodes
curl -X POST http://localhost:9000/api/nodes \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Scanner-Node-1",
    "capabilities": {
      "max_concurrent_scans": 10,
      "supports_syn": true,
      "supports_udp": true,
      "supports_ipv6": true
    }
  }'

# Submit large scan job
curl -X POST http://localhost:9000/api/scans/distributed \
  -d '{
    "targets": ["10.0.0.0/16"],
    "ports": [1-65535],
    "chunk_size": 256
  }'
```

### Report Generation

```bash
# Generate executive summary
./target/release/nemue report executive -i scan_results.json -o executive.md

# Technical detailed report
./target/release/nemue report technical -i scan_results.json -o technical.md

# Compliance mapping report (PCI-DSS, NIST CSF, CIS Controls)
./target/release/nemue report compliance -i scan_results.json -o compliance.md
```

## Beautiful Output Example

```
    _   __                          
   / | / /__  ____ ___  __  _____  
  /  |/ / _ \/ __ `__ \/ / / / _ \ 
 / /|  /  __/ / / / / / /_/ /  __/ 
/_/ |_/\___/_/ /_/ /_/\__,_/\___/  

→ Scan report for 192.168.1.1
• Ports: 22,80,443 | Rate: 1000 pps

┌─ Scan Results for 192.168.1.1
│ 2 open | 1 closed | 0 filtered
│
│ PORT     STATE      SERVICE      VERSION              PRODUCT
│ ───────────────────────────────────────────────────────────────────────────
│ 22/tcp   open       ssh          8.2p1                OpenSSH
│ 80/tcp   open       http         2.4.41               nginx
│ 443/tcp  closed     -            -                    -
│
└─

✓ Scan completed in 0.45s
• 3 ports scanned across 1 target(s)
• 2 open port(s) discovered
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design documentation.

## Usage Guide

**📖 Complete usage documentation available in [USAGE.md](USAGE.md)**

Quick examples:

```bash
# Basic scan
nemue scan 192.168.1.1 -p 80,443

# Vulnerability scan
nemue vuln-scan 192.168.1.1 -p 1-1000

# Start monitoring
nemue monitor start --name "Production" --targets 192.168.1.0/24

# Start API server
nemue api --bind 0.0.0.0:8080
```

See [USAGE.md](USAGE.md) for comprehensive documentation on all features.

## Development Status

- [x] **Phase 1: Core Scanner** ✅ **COMPLETE**
  - [x] High-performance async TCP scanning
  - [x] Rate limiting & concurrency control
  - [x] Target & port parsing
  - [x] JSON & XML output
  - [x] CLI interface

- [x] **Phase 2: Enhanced Discovery** ✅ **COMPLETE**
  - [x] OS fingerprinting (TTL-based)
  - [x] Service detection & banner grabbing
  - [x] Version identification
  - [x] Beautiful colored output

- [x] **Phase 3: Advanced Protocols** ✅ **COMPLETE**
  - [x] UDP scanning with service probes
  - [x] ICMP host discovery
  - [x] Expanded service database (112+ services)

- [x] **Phase 4: Professional Features** ✅ **COMPLETE**
  - [x] Advanced OS fingerprinting (TCP timestamps, window scaling, MSS)
  - [x] Lua scripting engine (NSE-compatible)
  - [x] True SYN stealth scanning (raw sockets)
  - [x] IPv6 full support
  - [x] Stealth techniques (timing, decoys, TTL)

- [x] **Phase 5: Intelligence & Analysis** ✅ **COMPLETE**
  - [x] CVE database integration with version matching
  - [x] Threat intelligence feeds (local blacklist, extensible to AbuseIPDB/VirusTotal)
  - [x] Comprehensive risk scoring engine
  - [x] Passive reconnaissance framework (Shodan/Censys ready)
  - [x] Actionable security recommendations

- [x] **Phase 6: Enterprise Features** ✅ **COMPLETE**
  - [x] REST API server with 7 endpoints
  - [x] Continuous monitoring with change detection
  - [x] Distributed scanning coordinator
  - [x] Report generation (Executive/Technical/Compliance templates)
  - [x] Session management and alerting

- [x] **Phase 7: Advanced Scripting** ✅ **COMPLETE**
  - [x] Vulnerability detection framework with 11 categories
  - [x] 26 vulnerability detection scripts
  - [x] Critical CVE detection (Log4Shell, EternalBlue, Heartbleed, BlueKeep, Ghostcat)
  - [x] Web vulnerabilities (SQL injection, XSS, directory traversal, XXE, SSRF)
  - [x] Information disclosure (Git/SVN exposure, backup files, .env, AWS credentials)
  - [x] Default credentials database (70+ entries, 25+ services)
  - [x] Exploit database (10+ critical CVEs)
  - [x] NVD integration with CVSS v3.1 scoring
  - [x] Parallel script execution engine

## Statistics

| Metric | Value |
|--------|-------|
| **Total Code** | 10,041+ lines |
| **Tests** | 112/112 passing ✅ |
| **Modules** | 13 (scanner, protocols, intel, api, monitor, distributed, report, vuln, web) |
| **Services Detected** | 112+ |
| **OS Families** | 11 |
| **Protocols** | TCP, UDP, ICMP (IPv4 + IPv6) |
| **NSE Lua Scripts** | 18 (HTTP, SSL, SSH, FTP, MySQL, PostgreSQL, MongoDB, Redis, ElasticSearch, Docker, SMB, DNS, SMTP, RDP, robots.txt, db-creds) |
| **Vuln Detection Scripts** | 26 (critical CVEs, web vulns, info disclosure) |
| **Vulnerability Categories** | 11 (RCE, SQLi, XSS, Auth, InfoDisclosure, etc.) |
| **Default Credentials** | 70+ entries across 25+ services |
| **Exploit Database** | 10+ critical CVEs with exploit info |
| **NVD CVE Entries** | 6 with CVSS v3.1 metrics |
| **Intelligence Modules** | 4 (CVE, Threat, Risk, Passive) |
| **API Endpoints** | 7 REST endpoints |
| **Report Templates** | 3 (Executive, Technical, Compliance) |
| **Binary Size** | 1.4 MB (optimized) |
| **Build Time** | ~60 seconds |
| **Current Phase** | Phase 8 - Web Application Scanning 🔄 |

## License

MIT
