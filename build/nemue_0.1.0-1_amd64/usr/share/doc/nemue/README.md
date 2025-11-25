# Nemue 🌊

An advanced security testing framework built in Rust, featuring high-performance network scanning, service detection, OS fingerprinting, and extensible scripting capabilities.

**Version**: 0.1.0  
**Stats**: 78,239 lines Rust + 59 Lua scripts | 631 tests (100% pass) | 16/16 phases complete ✅  
**Status**: PRODUCTION READY 🎉

## ✨ Key Features

### 🔍 **Advanced Service Detection**
- 🎯 **100+ Service Probes** - Comprehensive protocol detection (HTTP/2, SMB, RDP, databases)
- 🔬 **Protocol Parsers** - Deep inspection of SMB, RDP, MySQL, PostgreSQL, Redis
- 📊 **Version Detection** - Accurate service and application version identification
- 💡 **Confidence Scoring** - Reliability metrics for every detection

### 🖥️ **OS Fingerprinting**
- 🔍 **TCP/IP Stack Analysis** - Advanced nmap-style OS detection
- 📡 **Passive Detection** - p0f-style traffic analysis
- 🎯 **6 OS Signatures** - Linux, Windows, macOS, BSD, Cisco IOS
- 🔢 **CPE Generation** - NVD-compatible vulnerability correlation
- ⚡ **True SYN Stealth Scanning** - Raw socket implementation via pnet datalink layer
- 🔌 **Multi-Protocol Support** - TCP, UDP, ICMP across IPv4 and IPv6
- 🎯 **High Performance** - Async/await with Tokio, configurable concurrency
- 🌐 **Complete IPv6 Support** - All scan types (SYN, ACK, Window, NULL, FIN, Xmas)
- 🔍 **Advanced Scan Types** - 10+ scan techniques including stealth and firewall detection

### Advanced Detection
- 🖥️ **Advanced OS Fingerprinting** - TCP timestamps, window scaling, MSS analysis, 11 OS families
- 🔍 **Service Detection** - 112+ services (databases, containers, message queues, web frameworks)
- 📊 **Banner Grabbing** - Automatic version extraction for HTTP, SSH, FTP, SMTP
- 💡 **Confidence Scoring** - Transparent reliability metrics for detections
- 🌐 **IPv6 Discovery** - ICMPv6 Echo, Neighbor Discovery Protocol

### Stealth & Evasion
- 🥷 **6 Timing Templates** - T0 (Paranoid) to T5 (Insane)
- ⚙️ **Fine-Grained Timing** - 13 timing parameters (RTT, parallelism, delays, retries)
- 🎭 **Decoy Scanning** - Confuse IDS/IPS with decoy sources
- 🎲 **Randomization** - Host and port randomization
- 🔧 **TTL Manipulation** - Custom TTL values
- 🎯 **Source Manipulation** - Custom source ports, IPs, and MAC addresses
- 📦 **Fragmentation** - IP fragmentation with custom MTU
- 🔗 **Proxy Support** - HTTP/SOCKS4/SOCKS5 proxy chains

### Scripting & Extensibility  
- 🐍 **Lua Script Engine** - Full Lua 5.4 support (vendored)
- 📜 **NSE-Compatible API** - Write Nmap-style scripts
- 🔬 **Vulnerability Detection** - Built-in framework with severity scoring
- 📦 **5 Example Scripts** - HTTP headers, SSL checks, SSH banner, FTP anon, DB defaults
- 🔧 **Script Arguments** - Pass parameters via --script-args or file
- 🐛 **Script Tracing** - Debug script execution in real-time
- 📚 **Script Database** - Auto-indexing and help system

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
- 📋 **Compliance Mapping** - 7 frameworks (PCI-DSS, NIST CSF, CIS, ISO 27001, HIPAA, SOC 2, GDPR)
- 🔍 **Audit Trails** - Evidence collection with chain of custody
- 📈 **Trend Analysis** - Historical comparison and predictive analytics
- 📊 **Interactive Dashboards** - Real-time metrics and visualizations

### User Experience
- 🎨 **Beautiful Colored Output** - Nmap-style formatting with RGB colors
- 📊 **Multiple Formats** - JSON, XML, CSV, Markdown, HTML export
- 💻 **Modern CLI** - Intuitive commands with detailed help
- ⏱️ **Progress Indicators** - Real-time scan progress with ETA

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

**📖 Documentation:**
- **Usage Guide** → [USAGE.md](USAGE.md) - Comprehensive feature documentation  
- **Development** → [ROADMAP.md](ROADMAP.md) - Complete! All 12 phases (100%)
- **Nmap Parity** → [NMAP_FEATURE_PARITY.md](NMAP_FEATURE_PARITY.md) - Feature comparison (76%)
- **Architecture** → [ARCHITECTURE.md](ARCHITECTURE.md) - System design and technical details
- **Man Pages** → [docs/man/](docs/man/) - Traditional Unix man page documentation

## Usage

### Command Comparison: Nemue vs Nmap

Nemue uses **simpler, shorter commands** than nmap:

| Task | Nmap | Nemue |
|------|------|-------|
| **Basic scan** | `nmap 192.168.1.1` | `nemue scan 192.168.1.1` |
| **Specific ports** | `nmap -p 80,443 target` | `nemue scan target -p 80,443` |
| **Port range** | `nmap -p 1-1000 target` | `nemue scan target -p 1-1000` |
| **Aggressive scan** | `sudo nmap -A target` | `sudo nemue scan target -A` |
| **Service detection** | `nmap -sV target` | `nemue scan target -V` |
| **OS detection** | `nmap -O target` | `nemue scan target -O` |
| **Exclude ports** | `nmap -p- --exclude-ports 22,80 target` | `nemue scan target -p 1-65535 -e 22,80` |
| **UDP scan** | `sudo nmap -sU -p 53,161 target` | `sudo nemue scan target -p 53,161 -s udp` |
| **Stealth SYN** | `sudo nmap -sS target` | `sudo nemue scan target --raw` |
| **Verbose output** | `nmap -v target` | `nemue scan target -v` |
| **Save output** | `nmap -oN file target` | `nemue scan target -o file` |
| **No banner** | `nmap --no-stylesheet target` | `nemue scan target -q` |
| **Show closed** | `nmap --open target` (inverse) | `nemue scan target -c` |

**Key advantages**: Shorter flags (`-e` vs `--exclude-ports`, `-V` vs `-sV`, `-q` vs `--no-stylesheet`), cleaner defaults (only shows open ports), modern async architecture.

### Basic Scanning

```bash
# Simple scan (common ports, clean output)
nemue scan 192.168.1.1

# Specific ports
nemue scan 192.168.1.1 -p 80,443

# Port range
nemue scan 192.168.1.1 -p 1-1000

# Common ports preset (21 frequently used ports)
nemue scan 192.168.1.1 -p common

# Aggressive scan (like nmap -A) - requires root
sudo nemue scan 192.168.1.1 -A

# Exclude ports from scan
nemue scan 192.168.1.1 -p 1-1000 -e 80,443

# UDP scanning
sudo nemue scan 192.168.1.1 -p 53,123,161 -s udp

# Quiet mode (no banner)
nemue scan 192.168.1.1 -p common -q
```

### Web Content Discovery & Fuzzing

```bash
# Directory fuzzing with built-in wordlist
nemue fuzz https://example.com -b dirs1k

# File discovery with custom wordlist
nemue fuzz https://example.com -m file -w /path/to/wordlist.txt

# Recursive directory scanning
nemue fuzz https://example.com -b dirs10k -R --max-depth 3

# Extension fuzzing
nemue fuzz https://example.com/index -m ext -e php,asp,jsp,html

# Subdomain enumeration
nemue fuzz example.com -m subdomain -b subdomains

# AWS S3 bucket enumeration
nemue fuzz company -m s3 -b dirs1k

# With filtering and concurrency
nemue fuzz https://example.com -b dirs1k -s 200,301,302 -c 100 -r 50

# Parameter fuzzing (GET)
nemue fuzz "https://api.example.com/users?id=FUZZ" -b params

# Apply wordlist mutations
nemue fuzz https://example.com -b dirs1k --mutate

# Save results to JSON
nemue fuzz https://example.com -b dirs10k -o json -O results.json

# HTML report with custom headers
nemue fuzz https://example.com -b wordpress -o html -H "Cookie: session=abc123" -O report.html
```

**Available built-in wordlists:**
- `dirs1k` - 1,000+ common directories
- `dirs10k` - 10,000+ extended directories  
- `files` - Common files (backups, configs)
- `extensions` - 40+ file extensions
- `subdomains` - Common subdomains
- `params` - GET/POST parameters
- `wordpress` - WordPress-specific paths
- `joomla` - Joomla CMS paths
- `laravel` - Laravel framework paths
- `api` - REST/GraphQL endpoints
```

**Note**: By default, Nemue only displays **open ports** for clean, actionable output. Use `--show-closed` or `--show-filtered` flags to see all port states.

### Stealth Scanning

```bash
# Raw SYN scan (stealthiest)
sudo nemue scan target.com -p 1-1000 --raw

# Slower scan to avoid detection
sudo nemue scan target.com -p 1-1000 --raw -r 100

# Exclude common ports to blend in
sudo nemue scan target.com -p 1-10000 -e 80,443,22 --raw
```

### Service & OS Detection

```bash
# Full scan with service and OS detection (aggressive mode)
sudo nemue scan 192.168.1.1 -A

# Service/version detection only
nemue scan 192.168.1.1 -p 22,80,443 -V

# OS detection only
nemue scan 192.168.1.1 -p 22,80,443 -O

# Both service and OS detection
nemue scan 192.168.1.1 -p common -V -O
```

### Output & Display

```bash
# Show closed ports too
nemue scan 192.168.1.1 -p common -c

# Show filtered ports too
nemue scan 192.168.1.1 -p 1-1000 -F

# Show everything
nemue scan 192.168.1.1 -p common -c -F

# Save to file
nemue scan 192.168.1.1 -p common -o results.json

# Verbose output
nemue scan 192.168.1.1 -p common -v

# Quiet mode (no banner)
nemue scan 192.168.1.1 -p common -q
```

### Advanced Output

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

See [ROADMAP.md](ROADMAP.md) for detailed development progress and feature tracking.

**Status**: ✅ All 12 phases complete - Production ready!
**Progress**: 100% (12/12 phases)
**Latest**: Phase 12 - Compliance & Advanced Reporting complete

## Statistics

| Metric | Value |
|--------|-------|
| **Total Code** | ~36,500 lines Rust + 4,658 lines Lua |
| **Tests** | 575/575 passing ✅ |
| **Modules** | 30+ modules across 12 phases |
| **Services Detected** | 112+ |
| **OS Families** | 11 |
| **Protocols** | TCP, UDP, ICMP (IPv4 + IPv6) |
| **Lua Scripts** | 56 NSE-compatible scripts |
| **CVE Patterns** | 40+ vulnerabilities (2008-2024) |
| **Default Credentials** | 70+ service credentials |
| **Compliance Frameworks** | 7 (PCI-DSS, NIST, CIS, ISO, HIPAA, SOC2, GDPR) |
| **Fuzzing Modes** | 8 (dir, file, ext, vhost, subdomain, S3, Azure, GCP) |
| **Built-in Wordlists** | 10 comprehensive lists |
| **Output Formats** | 7 (Text, JSON, CSV, Markdown, HTML, XML, Dashboard) |
| **Nmap Parity** | 106/140 features (76%) |

## License

MIT
