# Nemue Usage Guide

Complete guide for using Nemue network scanner with all features.

**Version**: 1.0.0 - Production Release ✅ (All 12 phases complete)  
**Last Updated**: November 25, 2025

---

## Table of Contents

1. [Installation](#installation)
2. [Basic Scanning](#basic-scanning)
3. [Advanced Scanning](#advanced-scanning)
4. [Stealth Techniques](#stealth-techniques)
5. [Service & OS Detection](#service--os-detection)
6. [Vulnerability Scanning](#vulnerability-scanning)
7. [Intelligence & Risk Analysis](#intelligence--risk-analysis)
8. [Lua Scripting](#lua-scripting)
9. [REST API](#rest-api)
10. [Continuous Monitoring](#continuous-monitoring)
11. [Distributed Scanning](#distributed-scanning)
12. [Report Generation](#report-generation)
13. [Output Formats](#output-formats)
14. [Performance Tuning](#performance-tuning)
15. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- **Rust**: 1.70 or higher
- **Operating System**: Linux or macOS (Windows support planned)
- **Permissions**: Root/sudo for raw socket operations (SYN scans)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/supunhg/Nemue.git
cd Nemue

# Build release binary
cargo build --release

# Binary location
./target/release/nemue

# Optional: Install system-wide
sudo cp target/release/nemue /usr/local/bin/
```

### Verify Installation

```bash
nemue --version
nemue --help
```

---

## Basic Scanning

### Simple TCP Scan

```bash
# Default scan (ports 1-1000, only shows open ports)
nemue scan 192.168.1.1

# Specific ports
nemue scan 192.168.1.1 -p 80,443,22

# Port range
nemue scan 192.168.1.1 -p 1-1000

# Common ports preset (21 ports)
nemue scan 192.168.1.1 -p common

# Top 100 ports
nemue scan 192.168.1.1 -p top100

# Top 1000 ports
nemue scan 192.168.1.1 -p top1000
```

### Multiple Targets

```bash
# Multiple IPs
nemue scan 192.168.1.1,192.168.1.2,192.168.1.3 -p 80,443

# CIDR notation
nemue scan 192.168.1.0/24 -p 22,80,443

# IP ranges
nemue scan 192.168.1.1-254 -p 80

# From file
nemue scan -f targets.txt -p 80,443
```

### UDP Scanning

```bash
# UDP scan (requires root)
sudo nemue scan 192.168.1.1 -p 53,123,161 -s udp

# Common UDP ports
sudo nemue scan 192.168.1.1 -p 53,67,68,123,161,162,500 -s udp
```

### ICMP Host Discovery

```bash
# Ping sweep
sudo nemue scan 192.168.1.0/24 --scan-type icmp

# Skip host discovery (assume host is up)
nemue scan 192.168.1.1 -p 1-65535 --no-ping
```

---

## Advanced Scanning

### SYN Stealth Scanning

True SYN scanning using raw sockets (requires root):

```bash
# SYN scan (stealthiest)
sudo nemue scan 192.168.1.1 -p 1-1000 --raw

# SYN scan with OS detection
sudo nemue scan 192.168.1.1 -p 1-1000 --raw -O true

# Full stealth scan
sudo nemue scan 192.168.1.1 -p 1-65535 --raw --timing paranoid
```

### IPv6 Scanning

```bash
# IPv6 target (all scan types supported)
sudo nemue scan fe80::1 -p 80,443 --raw

# IPv6 ACK scan (firewall detection)
sudo nemue scan 2001:db8::1 -p 1-1000 --scan-type ack --raw

# IPv6 Window scan
sudo nemue scan fe80::1 -p 22,80,443 --scan-type window --raw

# IPv6 NULL scan (stealth)
sudo nemue scan 2001:db8::1 -p 1-1000 --scan-type null --raw

# IPv6 FIN scan
sudo nemue scan fe80::1 -p 80,443 --scan-type fin --raw

# IPv6 Xmas scan (FIN+PSH+URG)
sudo nemue scan 2001:db8::1 -p 1-1000 --scan-type xmas --raw

# IPv6 CIDR
sudo nemue scan 2001:db8::/64 -p 22,80,443

# IPv6 with service detection
nemue scan fe80::1 -p 1-1000 -S true

# ICMPv6 Echo discovery
sudo nemue scan 2001:db8::/64 --discovery icmpv6-echo

# IPv6 Neighbor Discovery
sudo nemue scan fe80::/64 --discovery ipv6-nd
```

**New Port States for IPv6 Scans**:
- **Unfiltered**: Port accessible but cannot determine if open/closed (ACK scan)
- **Open|Filtered**: Cannot distinguish between open and filtered (NULL/FIN/Xmas scans)

### Custom Port Specifications

```bash
# Common ports preset (21 ports)
nemue scan 192.168.1.1 -p common

# Top 100 ports
nemue scan 192.168.1.1 -p top100

# Top 1000 ports
nemue scan 192.168.1.1 -p top1000

# All ports
nemue scan 192.168.1.1 -p 1-65535

# Exclude specific ports
nemue scan 192.168.1.1 -p 1-1000 -e 80,443

# Exclude port ranges
nemue scan 192.168.1.1 -p 1-1000 -e 1-100,500-600

# Scan common ports but exclude MySQL
nemue scan 192.168.1.1 -p common -e 3306
```

### Output Filtering

By default, Nemue only shows **open ports** for cleaner, actionable output:

```bash
# Default: Only show open ports (cleanest output)
nemue scan 192.168.1.1 -p 1-1000

# Show closed ports too
nemue scan 192.168.1.1 -p 1-1000 -c

# Show filtered ports too
nemue scan 192.168.1.1 -p 1-1000 -F

# Show everything (all port states)
nemue scan 192.168.1.1 -p 1-1000 -c -F
```

**Note**: This prevents terminal flooding when scanning large port ranges. The actual scan still tests all ports; only the display is filtered.

### Aggressive/Comprehensive Scan

The `-A` flag enables a comprehensive scan similar to `nmap -A`:

```bash
# Aggressive scan (equivalent to nmap -A)
sudo nemue scan 192.168.1.1 -A

# This automatically enables:
# - Service detection (-S)
# - OS detection (-O)  
# - Raw sockets/SYN scan (--raw)
# - top1000 ports (if no ports specified)

# Aggressive scan with custom ports
sudo nemue scan 192.168.1.1 -A -p 1-10000

# Aggressive scan excluding certain ports
sudo nemue scan 192.168.1.1 -A -e 22,3306

# Aggressive + verbose + save results
sudo nemue scan 192.168.1.1 -A -v -o results.json
```

**Comparison with nmap**:
- `nmap -A target` → `nemue scan target -A` (requires sudo)
- Enables OS detection, service/version detection, and uses stealth SYN scan
- Scans top 1000 most common ports by default

---

## Stealth Techniques

### Timing Templates

Control scan speed and stealth level with fine-grained options:

```bash
# T0: Paranoid (5 minutes between packets)
sudo nemue scan target.com -p 1-1000 --timing paranoid --raw

# T1: Sneaky (15 seconds between packets)
sudo nemue scan target.com -p 1-1000 --timing sneaky --raw

# T2: Polite (0.4 seconds between packets)
nemue scan target.com -p 1-1000 --timing polite

# T3: Normal (default)
nemue scan target.com -p 1-1000 --timing normal

# T4: Aggressive (parallel scanning)
nemue scan target.com -p 1-65535 --timing aggressive

# T5: Insane (maximum speed)
nemue scan target.com -p 1-65535 --timing insane
```

### Fine-Grained Timing Control

Override timing templates with specific parameters:

```bash
# Custom RTT timeouts
sudo nemue scan target.com -p 1-1000 \
  --min-rtt-timeout 100ms \
  --max-rtt-timeout 2s \
  --initial-rtt-timeout 500ms

# Probe parallelization
sudo nemue scan target.com -p 1-65535 \
  --min-parallelism 10 \
  --max-parallelism 100

# Host group sizes
sudo nemue scan 192.168.1.0/24 -p 80,443 \
  --min-hostgroup 16 \
  --max-hostgroup 256

# Rate limiting
sudo nemue scan target.com -p 1-1000 \
  --min-rate 100 \
  --max-rate 1000

# Scan delays
sudo nemue scan target.com -p 1-1000 \
  --scan-delay 100ms \
  --max-scan-delay 1s

# Per-host timeout
sudo nemue scan 192.168.1.0/24 -p 1-1000 \
  --host-timeout 15m

# Max retries
sudo nemue scan target.com -p 1-65535 \
  --max-retries 3

# Combined fine-tuning
sudo nemue scan target.com -p 1-65535 \
  --timing aggressive \
  --max-rate 5000 \
  --min-parallelism 50 \
  --max-rtt-timeout 500ms \
  --max-retries 2
```

**Time Suffixes**: `ms` (milliseconds), `s` (seconds), `m` (minutes), `h` (hours)  
Examples: `100ms`, `1.5s`, `2m`, `1h`

### Decoy Scanning

Confuse IDS/IPS with decoy sources:

```bash
# Manual decoys
sudo nemue scan target.com -p 80 --decoys 192.168.1.5,192.168.1.6 --raw

# Random decoys
sudo nemue scan target.com -p 80 --decoys RND:5 --raw

# Decoys + stealth timing
sudo nemue scan target.com -p 1-1000 --decoys RND:10 --timing sneaky --raw
```

### Source Port Spoofing

Use specific source port to evade firewalls:

```bash
# Appear as DNS traffic
sudo nemue scan target.com -p 80,443 --source-port 53 --raw

# Appear as HTTP
sudo nemue scan target.com -p 22 --source-port 80 --raw
```

### TTL Manipulation

```bash
# Custom TTL value
sudo nemue scan target.com -p 80 --ttl 64 --raw

# Low TTL for traceroute-style
sudo nemue scan target.com -p 80 --ttl 5 --raw
```

### Randomization

```bash
# Randomize host order
nemue scan 192.168.1.0/24 -p 80 --randomize-hosts

# Randomize port order
nemue scan 192.168.1.1 -p 1-1000 --randomize-ports
```

---

## Service & OS Detection

### Service Detection

```bash
# Basic service detection
nemue scan 192.168.1.1 -p 22,80,443,3306 -S true

# Service detection only (no OS detection)
nemue scan 192.168.1.1 -p 1-1000 -S true -O false

# Aggressive service detection
nemue scan 192.168.1.1 -p 1-1000 -S aggressive

# Service version detection
nemue scan 192.168.1.1 -p 22,80,3306,5432 --version-detect
```

Detected services include:
- Web: HTTP, HTTPS, nginx, Apache
- Databases: MySQL, PostgreSQL, MongoDB, Redis
- SSH, FTP, Telnet, SMTP
- Containers: Docker, Kubernetes
- Message queues: RabbitMQ, Kafka
- 112+ services total

### OS Fingerprinting

```bash
# OS detection only
sudo nemue scan 192.168.1.1 -p 22,80,443 -O true -S false --raw

# Full detection (OS + services)
sudo nemue scan 192.168.1.1 -p 1-1000 -O true -S true --raw

# Advanced OS fingerprinting
sudo nemue scan 192.168.1.1 -p 22,80,443 -O advanced --raw
```

Detected OS families:
- Linux, Windows, macOS, FreeBSD, OpenBSD
- Cisco IOS, Juniper, HP-UX
- Solaris, AIX, Android

---

## Vulnerability Scanning

### Run All Vulnerability Scripts

```bash
# Scan with all vulnerability scripts
nemue vuln-scan 192.168.1.1 -p 1-1000

# Scan with specific port
nemue vuln-scan 192.168.1.1 -p 8080

# Multiple targets
nemue vuln-scan 192.168.1.0/24 -p 80,443,8080
```

### Critical CVE Detection

```bash
# Check for Log4Shell (CVE-2021-44228)
nemue vuln-check log4shell 192.168.1.1 8080

# Check for EternalBlue (CVE-2017-0144)
nemue vuln-check eternalblue 192.168.1.1 445

# Check for Heartbleed (CVE-2014-0160)
nemue vuln-check heartbleed 192.168.1.1 443

# Check for BlueKeep (CVE-2019-0708)
nemue vuln-check bluekeep 192.168.1.1 3389

# Check for Ghostcat (CVE-2020-1938)
nemue vuln-check ghostcat 192.168.1.1 8009
```

### Web Vulnerability Scanning

```bash
# SQL Injection check
nemue vuln-check sql-injection 192.168.1.1 80

# XSS detection
nemue vuln-check xss-detection 192.168.1.1 80

# Directory traversal
nemue vuln-check dir-traversal 192.168.1.1 80

# Security headers
nemue vuln-check sec-headers 192.168.1.1 80

# All web vulnerabilities
nemue vuln-scan 192.168.1.1 -p 80,443 --category web
```

### Information Disclosure

```bash
# Check for exposed .git
nemue vuln-check git-exposed 192.168.1.1 80

# Check for backup files
nemue vuln-check backup-files 192.168.1.1 80

# Check for .env exposure
nemue vuln-check dotenv-exposed 192.168.1.1 80

# Check for AWS credentials
nemue vuln-check aws-creds-exposed 192.168.1.1 80

# Admin panel discovery
nemue vuln-check admin-panel 192.168.1.1 80

# All info disclosure checks
nemue vuln-scan 192.168.1.1 -p 80 --category info-disclosure
```

### Default Credentials Check

```bash
# Check for default credentials
nemue vuln-check default-creds 192.168.1.1 22

# Check MySQL defaults
nemue vuln-check default-creds 192.168.1.1 3306

# Check SSH defaults
nemue vuln-check default-creds 192.168.1.1 22

# List all default credentials for a service
nemue creds-list mysql
nemue creds-list ssh
nemue creds-list tomcat
```

### Vulnerability Scanning by Category

```bash
# Remote Code Execution
nemue vuln-scan 192.168.1.1 --category rce

# Authentication issues
nemue vuln-scan 192.168.1.1 --category auth

# SQL Injection
nemue vuln-scan 192.168.1.1 --category sqli

# Cross-Site Scripting
nemue vuln-scan 192.168.1.1 --category xss

# Cryptography issues
nemue vuln-scan 192.168.1.1 --category crypto

# All categories
nemue vuln-scan 192.168.1.1 --all-categories
```

---

## Intelligence & Risk Analysis

### CVE Database Lookup

```bash
# Check for CVEs in detected services
nemue scan 192.168.1.1 -p 22,80,443 --check-vulns

# Get CVE details
nemue cve-info CVE-2021-44228

# List all critical CVEs
nemue cve-list --severity critical

# Check CVSS score
nemue cvss-score CVE-2021-44228
```

### Threat Intelligence

```bash
# Check IP reputation
nemue threat-check 192.168.1.1

# Scan with threat intel
nemue scan 192.168.1.1 -p 1-1000 --threat-intel

# Bulk IP reputation check
nemue threat-check -f ip-list.txt
```

### Risk Assessment

```bash
# Full risk assessment
nemue scan 192.168.1.1 -p 1-1000 --risk-assessment

# Generate risk report
nemue scan 192.168.1.1 -p 1-65535 --risk-report -o risk-report.json

# Risk scoring only
nemue risk-score 192.168.1.1 -p 1-1000
```

### Passive Reconnaissance

```bash
# Shodan lookup (requires API key)
nemue passive 192.168.1.1 --shodan-key YOUR_API_KEY

# Censys lookup
nemue passive 192.168.1.1 --censys-key YOUR_API_KEY

# Passive recon before active scan
nemue scan 192.168.1.1 -p 1-1000 --passive-first --shodan-key YOUR_KEY
```

---

## Lua Scripting

### Script Management

```bash
# Update script database (scan for new scripts)
nemue scan 192.168.1.1 --script-updatedb

# Show help for a specific script
nemue scan 192.168.1.1 --script-help http-headers

# List all scripts in database
ls scripts/  # Scripts are stored in ./scripts/ directory
```

### Running Scripts with Arguments

```bash
# Pass arguments to scripts
nemue scan 192.168.1.1 -p 80 --script http-check \\
  --script-args "url=http://192.168.1.1,timeout=10"

# Multiple arguments (comma or semicolon separated)
nemue scan 192.168.1.1 -p 3306 --script mysql-check \\
  --script-args "user=root,pass=toor,database=test"

# Load arguments from file
nemue scan 192.168.1.1 --script custom-check \\
  --script-args-file script-config.txt

# Enable script execution tracing (debug mode)
nemue scan 192.168.1.1 --script http-vuln \\
  --script-args "target=admin" \\
  --script-trace
```

### Script Arguments File Format

Create `script-args.txt`:
```
# MySQL connection arguments
user=root
password=test123
database=production

# HTTP check settings
url=http://example.com
timeout=30  # seconds
follow_redirects=true
```

Use it:
```bash
nemue scan 192.168.1.1 -p 3306 --script-args-file script-args.txt
```

### Running Scripts

```bash
# Run single script
nemue script run scripts/http-headers.lua 192.168.1.1 80

# Run all scripts in category
nemue script run-category vuln 192.168.1.1

# List available scripts
nemue script list

# Get script info
nemue script info http-headers
```

### Script Documentation Format

Scripts can include documentation using special comments:

```lua
name = "http-check"
description = "Checks HTTP service for vulnerabilities"
author = "Your Name"
categories = {"http", "vuln"}

--@usage nemue scan <target> --script http-check --script-args url=http://example.com
--@arg url required The URL to check
--@arg timeout optional default=30 Request timeout in seconds
--@arg user_agent optional default=Nemue/1.0 Custom User-Agent header
--@example nemue scan 192.168.1.1 --script http-check --script-args url=http://192.168.1.1
--@output Returns HTTP status code, headers, and detected vulnerabilities

function action(args)
    local url = args.url or "http://localhost"
    local timeout = args.timeout or 30
    
    -- Script logic here
    return {
        output = "HTTP service OK",
        vulnerability = nil,
        severity = nil
    }
end
```

View documentation:
```bash
nemue scan 192.168.1.1 --script-help http-check
```

### Example Scripts (13 Available)

**1. HTTP Headers (scripts/http-headers.lua)**
```bash
nemue script run scripts/http-headers.lua 192.168.1.1 80
```

**2. SSL Certificate Info (scripts/ssl-cert-info.lua)**
```bash
nemue script run scripts/ssl-cert-info.lua 192.168.1.1 443
```

**3. SSH Authentication Methods (scripts/ssh-auth-methods.lua)**
```bash
nemue script run scripts/ssh-auth-methods.lua 192.168.1.1 22
```

**4. FTP Anonymous (scripts/ftp-anon.lua)**
```bash
nemue script run scripts/ftp-anon.lua 192.168.1.1 21
```

**5. MySQL Info (scripts/mysql-info.lua)**
```bash
nemue script run scripts/mysql-info.lua 192.168.1.1 3306
```

**6. PostgreSQL Info (scripts/postgresql-info.lua)**
```bash
nemue script run scripts/postgresql-info.lua 192.168.1.1 5432
```

**7. MongoDB Info (scripts/mongodb-info.lua)**
```bash
nemue script run scripts/mongodb-info.lua 192.168.1.1 27017
```

**8. Redis Info (scripts/redis-info.lua)**
```bash
nemue script run scripts/redis-info.lua 192.168.1.1 6379
```

**9. ElasticSearch Info (scripts/elasticsearch-info.lua)**
```bash
nemue script run scripts/elasticsearch-info.lua 192.168.1.1 9200
```

**10. SMB OS Discovery (scripts/smb-os-discovery.lua)**
```bash
nemue script run scripts/smb-os-discovery.lua 192.168.1.1 445
```

**11. DNS Zone Transfer (scripts/dns-zone-transfer.lua)**
```bash
nemue script run scripts/dns-zone-transfer.lua dns-server.com 53
```

**12. SMTP User Enum (scripts/smtp-enum-users.lua)**
```bash
nemue script run scripts/smtp-enum-users.lua 192.168.1.1 25
```

**13. robots.txt Analysis (scripts/http-robots-txt.lua)**
```bash
nemue script run scripts/http-robots-txt.lua 192.168.1.1 80
```

### Custom Script Development

Create your own Lua scripts compatible with Nmap NSE:

```lua
-- custom-script.lua
description = "Custom vulnerability check"
categories = {"vuln", "safe"}

-- Port rule
portrule = function(port)
    return port.number == 80 or port.number == 443
end

-- Action
action = function(host, port)
    -- Your detection logic here
    return "Vulnerability found!"
end
```

Run custom script:
```bash
nemue script run custom-script.lua 192.168.1.1 80
```

---

## REST API

### Starting the API Server

```bash
# Start API server on default port (8080)
nemue api

# Custom bind address and port
nemue api --bind 0.0.0.0:9000

# With CORS enabled
nemue api --bind 0.0.0.0:8080 --cors
```

### API Endpoints

**1. Health Check**
```bash
curl http://localhost:8080/health
```

**2. Start Scan**
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.1"],
    "ports": [80, 443, 22],
    "scan_type": "tcp",
    "timing": "normal"
  }'
```

**3. Get Scan Status**
```bash
curl http://localhost:8080/api/v1/scans/{scan_id}
```

**4. Get Scan Results**
```bash
curl http://localhost:8080/api/v1/scans/{scan_id}/results
```

**5. Cancel Scan**
```bash
curl -X DELETE http://localhost:8080/api/v1/scans/{scan_id}
```

**6. List All Scans**
```bash
curl http://localhost:8080/api/v1/scans?page=1&per_page=20
```

**7. Delete Scan**
```bash
curl -X DELETE http://localhost:8080/api/v1/scans/{scan_id}/delete
```

### API Integration Example (Python)

```python
import requests
import time

API_URL = "http://localhost:8080/api/v1"

# Start scan
response = requests.post(f"{API_URL}/scans", json={
    "targets": ["192.168.1.1"],
    "ports": [80, 443, 22, 3306],
    "scan_type": "tcp",
    "timing": "normal"
})

scan_id = response.json()["scan_id"]
print(f"Scan started: {scan_id}")

# Poll for completion
while True:
    status = requests.get(f"{API_URL}/scans/{scan_id}").json()
    if status["status"] == "completed":
        break
    time.sleep(5)

# Get results
results = requests.get(f"{API_URL}/scans/{scan_id}/results").json()
print(results)
```

---

## Continuous Monitoring

### Starting Monitoring

```bash
# Start monitoring session
nemue monitor start \
  --name "Production Network" \
  --targets 192.168.1.0/24 \
  --ports 22,80,443,3306 \
  --interval 300 \
  --alert-on-changes

# With vulnerability scanning
nemue monitor start \
  --name "Web Servers" \
  --targets 192.168.1.0/24 \
  --ports 80,443,8080 \
  --interval 600 \
  --vuln-scan \
  --alert-email admin@example.com
```

### Managing Sessions

```bash
# List monitoring sessions
nemue monitor list

# Get session details
nemue monitor info {session_id}

# Pause monitoring
nemue monitor pause {session_id}

# Resume monitoring
nemue monitor resume {session_id}

# Stop monitoring
nemue monitor stop {session_id}

# Delete session
nemue monitor delete {session_id}
```

### Viewing Changes

```bash
# View detected changes
nemue monitor changes {session_id}

# View changes for specific host
nemue monitor changes {session_id} --host 192.168.1.1

# Export changes
nemue monitor changes {session_id} -o changes.json
```

### Alert Configuration

```bash
# Email alerts
nemue monitor start \
  --name "Critical Systems" \
  --targets 192.168.1.1-10 \
  --alert-email security@example.com

# Slack alerts
nemue monitor start \
  --name "Dev Environment" \
  --targets 10.0.0.0/24 \
  --alert-slack https://hooks.slack.com/services/YOUR/WEBHOOK

# Webhook alerts
nemue monitor start \
  --name "Production" \
  --targets 192.168.1.0/24 \
  --alert-webhook https://your-server.com/webhook
```

---

## Distributed Scanning

### Starting Coordinator

```bash
# Start coordinator node
nemue distributed coordinator --bind 0.0.0.0:9000

# With authentication
nemue distributed coordinator \
  --bind 0.0.0.0:9000 \
  --auth-token your-secret-token
```

### Registering Scanner Nodes

```bash
# Register scanning node
curl -X POST http://coordinator:9000/api/nodes \
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
```

### Submitting Distributed Scans

```bash
# Large network scan
curl -X POST http://coordinator:9000/api/scans/distributed \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["10.0.0.0/16"],
    "ports": [1-65535],
    "chunk_size": 256,
    "scan_type": "tcp"
  }'

# Internet-wide scan
curl -X POST http://coordinator:9000/api/scans/distributed \
  -d '{
    "targets": ["0.0.0.0/0"],
    "ports": [80, 443],
    "chunk_size": 1024
  }'
```

### Monitoring Distributed Scans

```bash
# Get scan status
curl http://coordinator:9000/api/scans/{scan_id}

# Get node status
curl http://coordinator:9000/api/nodes

# Get node details
curl http://coordinator:9000/api/nodes/{node_id}
```

---

## Report Generation

### Executive Summary

```bash
# Generate executive report
nemue report executive \
  -i scan-results.json \
  -o executive-summary.md

# With company branding
nemue report executive \
  -i scan-results.json \
  -o report.md \
  --company "Acme Corp" \
  --logo logo.png
```

### Technical Report

```bash
# Detailed technical report
nemue report technical \
  -i scan-results.json \
  -o technical-report.md

# Filter by severity
nemue report technical \
  -i scan-results.json \
  -o critical-findings.md \
  --min-severity high
```

### Compliance Report

```bash
# PCI-DSS compliance
nemue report compliance \
  -i scan-results.json \
  -o pci-dss-report.md \
  --framework pci-dss

# NIST Cybersecurity Framework
nemue report compliance \
  -i scan-results.json \
  -o nist-csf-report.md \
  --framework nist-csf

# CIS Controls
nemue report compliance \
  -i scan-results.json \
  -o cis-controls-report.md \
  --framework cis

# Multiple frameworks
nemue report compliance \
  -i scan-results.json \
  -o compliance-report.md \
  --frameworks pci-dss,nist-csf,cis
```

### Custom Reports

```bash
# Custom template
nemue report generate \
  -i scan-results.json \
  -t custom-template.md \
  -o custom-report.md

# Multiple formats
nemue report generate \
  -i scan-results.json \
  --formats md,html,pdf \
  -o report
```

---

## Output Formats

### JSON Output

```bash
# Save as JSON
nemue scan 192.168.1.1 -p 80,443 -o results.json

# Pretty print JSON
nemue scan 192.168.1.1 -p 80,443 -o results.json --pretty

# JSON to stdout
nemue scan 192.168.1.1 -p 80,443 --format json
```

### XML Output (Nmap-compatible)

```bash
# Save as XML
nemue scan 192.168.1.1 -p 80,443 -o results.xml --format xml

# Nmap-compatible XML
nemue scan 192.168.1.1 -p 1-1000 -o scan.xml --format nmap-xml
```

### Text Output

```bash
# Human-readable output
nemue scan 192.168.1.1 -p 80,443

# Save to file
nemue scan 192.168.1.1 -p 80,443 -o results.txt

# Disable colors
nemue scan 192.168.1.1 -p 80,443 --no-color
```

### Grepable Output

```bash
# Grepable format
nemue scan 192.168.1.1 -p 1-1000 --format grep -o results.gnmap

# Extract open ports
grep "open" results.gnmap
```

---

## Performance Tuning

### Concurrency

```bash
# Adjust concurrent workers (default: based on CPU cores)
nemue scan 192.168.1.0/24 -p 1-1000 --workers 100

# Single-threaded
nemue scan 192.168.1.1 -p 1-65535 --workers 1

# Maximum concurrency
nemue scan 192.168.1.0/24 -p 1-1000 --workers 1000
```

### Rate Limiting

```bash
# Limit packets per second
nemue scan 192.168.1.0/24 -p 1-1000 --rate 1000

# Slow scan (100 pps)
nemue scan 192.168.1.1 -p 1-65535 --rate 100

# Fast scan (10000 pps)
nemue scan 192.168.1.0/24 -p 1-1000 --rate 10000
```

### Timeout Configuration

```bash
# Custom timeout (milliseconds)
nemue scan 192.168.1.1 -p 1-1000 --timeout 5000

# Fast timeout for local network
nemue scan 192.168.1.0/24 -p 80 --timeout 500

# Long timeout for slow networks
nemue scan remote-host.com -p 1-1000 --timeout 10000
```

### Memory Optimization

```bash
# Stream results (don't store in memory)
nemue scan 192.168.1.0/16 -p 1-65535 --stream -o results.json

# Batch processing
nemue scan 192.168.1.0/24 -p 1-65535 --batch-size 100
```

---

## Troubleshooting

### Permission Issues

```bash
# Error: "Permission denied"
# Solution: Use sudo for raw sockets
sudo nemue scan 192.168.1.1 -p 80 --raw

# Alternative: Set capabilities (Linux only)
sudo setcap cap_net_raw=eip /path/to/nemue
```

### Connection Issues

```bash
# Enable verbose output
nemue scan 192.168.1.1 -p 80 --verbose

# Enable debug logging
RUST_LOG=debug nemue scan 192.168.1.1 -p 80

# Test connectivity
nemue ping 192.168.1.1
```

### Performance Issues

```bash
# Reduce concurrency
nemue scan 192.168.1.0/24 -p 1-1000 --workers 10

# Increase timeout
nemue scan 192.168.1.1 -p 1-65535 --timeout 10000

# Use faster timing
nemue scan 192.168.1.0/24 -p 80,443 --timing aggressive
```

### Output Issues

```bash
# Force color output
nemue scan 192.168.1.1 -p 80 --color always

# Disable banner
nemue scan 192.168.1.1 -p 80 --no-banner

# Quiet mode (minimal output)
nemue scan 192.168.1.1 -p 80 --quiet
```

### Firewall/IDS Evasion

```bash
# Combination of stealth techniques
sudo nemue scan target.com \
  -p 1-1000 \
  --raw \
  --timing sneaky \
  --decoys RND:5 \
  --source-port 53 \
  --randomize-hosts \
  --randomize-ports \
  --fragment

# Bypass rate limiting
nemue scan target.com -p 1-65535 --timing paranoid --rate 10
```

---

## Best Practices

### Security Testing Workflow

```bash
# 1. Passive reconnaissance
nemue passive target.com --shodan-key YOUR_KEY

# 2. Light discovery
nemue scan target.com -p common

# 3. Full port scan
sudo nemue scan target.com -p 1-65535 --raw

# 4. Service detection
nemue scan target.com -p <open-ports> -S true -O true

# 5. Vulnerability scanning
nemue vuln-scan target.com --all-categories

# 6. Generate report
nemue report technical -i results.json -o report.md
```

### Network Mapping

```bash
# 1. Discover live hosts
sudo nemue scan 192.168.1.0/24 --scan-type icmp

# 2. Scan common ports on live hosts
nemue scan <live-hosts> -p common -S true

# 3. Full scan of critical systems
sudo nemue scan <critical-hosts> -p 1-65535 --raw

# 4. Generate network map
nemue map generate -i results.json -o network-map.svg
```

### Compliance Auditing

```bash
# 1. Full scan with all features
sudo nemue scan 192.168.1.0/24 -p 1-65535 --raw -S true -O true

# 2. Vulnerability assessment
nemue vuln-scan 192.168.1.0/24 --all-categories

# 3. Generate compliance reports
nemue report compliance -i results.json --frameworks pci-dss,nist-csf,cis

# 4. Track changes over time
nemue monitor start --name "Compliance Monitoring" \
  --targets 192.168.1.0/24 --interval 86400 --vuln-scan
```

---

## Environment Variables

```bash
# API keys
export NEMUE_SHODAN_API_KEY=your_key
export NEMUE_CENSYS_API_KEY=your_key

# Default options
export NEMUE_DEFAULT_TIMING=normal
export NEMUE_DEFAULT_WORKERS=100
export NEMUE_DEFAULT_TIMEOUT=5000

# Logging
export RUST_LOG=info          # info, debug, trace
export RUST_BACKTRACE=1       # Enable backtraces
```

---

## Configuration File

Create `~/.nemue/config.toml`:

```toml
[scan]
default_timing = "normal"
default_workers = 100
default_timeout = 5000

[api_keys]
shodan = "your_api_key"
censys = "your_api_key"

[output]
default_format = "json"
color = true
banner = true

[api]
bind_address = "0.0.0.0"
port = 8080
enable_cors = true

[monitoring]
default_interval = 300
enable_alerts = true

[distributed]
coordinator_port = 9000
max_nodes = 100
```

---

## Examples

### Example 1: Web Application Security Scan

```bash
#!/bin/bash
TARGET="webapp.example.com"

# 1. Discover web ports
sudo nemue scan $TARGET -p 80,443,8080,8443 --raw

# 2. Service detection
nemue scan $TARGET -p 80,443,8080,8443 -S true

# 3. Web vulnerability scan
nemue vuln-scan $TARGET -p 80,443,8080,8443 --category web

# 4. Information disclosure
nemue vuln-scan $TARGET -p 80,443 --category info-disclosure

# 5. Generate report
nemue report technical -i results.json -o web-security-report.md
```

### Example 2: Infrastructure Audit

```bash
#!/bin/bash
NETWORK="192.168.1.0/24"

# 1. Host discovery
sudo nemue scan $NETWORK --scan-type icmp -o live-hosts.json

# 2. Port scan
sudo nemue scan $NETWORK -p 1-65535 --raw -o port-scan.json

# 3. Service and OS detection
nemue scan $NETWORK -p common -S true -O true -o services.json

# 4. Vulnerability assessment
nemue vuln-scan $NETWORK --all-categories -o vulns.json

# 5. Compliance report
nemue report compliance -i vulns.json --frameworks pci-dss,nist-csf
```

### Example 3: Continuous Monitoring Setup

```bash
#!/bin/bash

# Start monitoring for critical systems
nemue monitor start \
  --name "Critical Infrastructure" \
  --targets 192.168.1.1-10 \
  --ports 22,80,443,3306,5432 \
  --interval 600 \
  --vuln-scan \
  --alert-email security@example.com \
  --alert-slack https://hooks.slack.com/services/YOUR/WEBHOOK

# Monitor external perimeter
nemue monitor start \
  --name "External Perimeter" \
  --targets perimeter-hosts.txt \
  --ports 80,443 \
  --interval 3600 \
  --threat-intel \
  --alert-email security@example.com
```

---

## Support & Resources

- **Documentation**: https://github.com/supunhg/Nemue/wiki
- **Issues**: https://github.com/supunhg/Nemue/issues
- **Discussions**: https://github.com/supunhg/Nemue/discussions
- **Security**: Report vulnerabilities to security@nemue.dev

---

**Last Updated**: November 24, 2025  
**Version**: Phase 8.5.4 Complete ✅ (IPv6, Script Engine, 74% Nmap Parity)
