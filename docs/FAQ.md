# Nemue FAQ (Frequently Asked Questions)

**Last Updated**: June 2026  
**Version**: v0.2.0

---

## Table of Contents

1. [General Questions](#general-questions)
2. [Installation & Build](#installation--build)
3. [Scanning & Features](#scanning--features)
4. [Performance](#performance)
5. [Troubleshooting](#troubleshooting)
6. [Docker](#docker)
7. [MCP Server](#mcp-server)
8. [Comparison with Other Tools](#comparison-with-other-tools)

---

## General Questions

### What is Nemue?

Nemue is an advanced security testing framework built in Rust. It provides network scanning, service detection, OS fingerprinting, web fuzzing, vulnerability scanning, and compliance reporting in a single binary.

### Is Nemue free?

Yes, Nemue is open-source under the MIT license.

### What platforms does Nemue support?

Nemue currently supports Linux. macOS and Windows support is planned.

### What are the system requirements?

- **OS**: Linux (Debian/Ubuntu recommended)
- **Rust**: 1.70 or higher (for building from source)
- **Memory**: 512MB minimum, 2GB+ recommended for large scans
- **Permissions**: Root/sudo for raw socket operations (SYN scans)

### How does Nemue compare to Nmap?

Nemue offers:
- Modern async architecture (Tokio)
- Built-in web fuzzing (8 modes)
- MCP server for AI assistants
- Compliance reporting (7 frameworks)
- REST API for automation

Nmap has:
- 25+ years of development
- 600+ NSE scripts
- Cross-platform support
- Larger community

See [COMPETITORS.md](COMPETITORS.md) for detailed comparison.

---

## Installation & Build

### How do I install Nemue?

**Option 1: Build from source**
```bash
git clone https://github.com/supunhg/Nemue.git
cd Nemue
cargo build --release
sudo cp target/release/nemue /usr/local/bin/
```

**Option 2: Debian package**
```bash
./build-deb-simple.sh
sudo dpkg -i nemue_0.1.0-1_amd64.deb
```

**Option 3: Docker**
```bash
docker build -t nemue .
docker run --rm nemue --help
```

### Build fails with "pkg-config" error

Install OpenSSL development libraries:
```bash
# Debian/Ubuntu
sudo apt-get install pkg-config libssl-dev

# RHEL/CentOS
sudo yum install openssl-devel
```

### How do I update Nemue?

```bash
git pull
cargo build --release
sudo cp target/release/nemue /usr/local/bin/
```

---

## Scanning & Features

### How do I scan a single host?

```bash
nemue scan 192.168.1.1 -p common
```

### How do I scan multiple hosts?

```bash
# Comma-separated
nemue scan 192.168.1.1,192.168.1.2,192.168.1.3 -p 80,443

# CIDR notation
nemue scan 192.168.1.0/24 -p 22,80,443

# IP range
nemue scan 192.168.1.1-254 -p 80
```

### How do I scan all ports?

```bash
nemue scan 192.168.1.1 -p 1-65535
```

### What is the difference between SYN scan and Connect scan?

- **SYN scan** (`--raw`): Uses raw sockets, stealthier, requires root
- **Connect scan**: Uses TCP connect(), no root required, less stealthy

### How do I detect services?

```bash
nemue scan 192.168.1.1 -p 22,80,443 -V
```

### How do I detect the operating system?

```bash
sudo nemue scan 192.168.1.1 -p 22,80,443 -O
```

### How do I run vulnerability scans?

```bash
# All vulnerabilities
nemue vuln-scan 192.168.1.1 -p 1-1000

# Specific CVE
nemue vuln-check log4shell 192.168.1.1 8080

# Web vulnerabilities
nemue vuln-scan 192.168.1.1 -p 80,443 --category web
```

### How do I fuzz web applications?

```bash
# Directory fuzzing
nemue fuzz https://example.com -b dirs1k

# Subdomain enumeration
nemue fuzz example.com -m subdomain -b subdomains

# File discovery
nemue fuzz https://example.com -m file -b files
```

### How do I save scan results?

```bash
# JSON output
nemue scan 192.168.1.1 -p common -o results.json

# XML output
nemue scan 192.168.1.1 -p common -o results.xml --format xml

# CSV output
nemue scan 192.168.1.1 -p common -o results.csv --format csv
```

---

## Performance

### How do I speed up scans?

```bash
# Use faster timing
nemue scan 192.168.1.1 -p 1-65535 --timing aggressive

# Increase parallelism
nemue scan 192.168.1.0/24 -p 80 --max-parallelism 100

# Scan fewer ports
nemue scan 192.168.1.1 --top-ports 100
```

### How do I slow down scans (avoid detection)?

```bash
# Paranoid timing
sudo nemue scan 192.168.1.1 -p 1-1000 --raw --timing paranoid

# Rate limiting
sudo nemue scan 192.168.1.1 -p 1-1000 --raw --max-rate 100
```

### How do I adjust concurrency?

```bash
# Set worker count
nemue scan 192.168.1.0/24 -p 80 --workers 100
```

### How do I handle timeouts?

```bash
# Custom timeout (milliseconds)
nemue scan 192.168.1.1 -p 1-1000 --timeout 5000

# Long timeout for slow networks
nemue scan remote-host.com -p 1-1000 --timeout 10000
```

---

## Troubleshooting

### "Permission denied" error

Raw socket operations require root:
```bash
sudo nemue scan 192.168.1.1 -p 80 --raw
```

Or set capabilities:
```bash
sudo setcap cap_net_raw=eip /path/to/nemue
```

### No results returned

1. Check if target is up: `nemue ping 192.168.1.1`
2. Check firewall rules
3. Increase verbosity: `nemue scan 192.168.1.1 -v`
4. Try connect scan: `nemue scan 192.168.1.1 -p 80` (no --raw)

### Scan is very slow

1. Reduce port range: `nemue scan 192.168.1.1 --top-ports 100`
2. Use faster timing: `--timing aggressive`
3. Increase timeout: `--timeout 5000`
4. Check network connectivity

### Output is not colored

```bash
# Force color
nemue scan 192.168.1.1 -p 80 --color always

# Disable color
nemue scan 192.168.1.1 -p 80 --no-color
```

### Script execution fails

1. Check script exists: `ls scripts/`
2. Verify script syntax: `nemue script check <script.lua>`
3. Enable debug: `RUST_LOG=debug nemue script run <script.lua>`

### Memory usage is high

```bash
# Stream results
nemue scan 192.168.1.0/16 -p 1-65535 --stream -o results.json

# Batch processing
nemue scan 192.168.1.0/24 -p 1-65535 --batch-size 100
```

---

## Docker

### How do I build the Docker image?

```bash
docker build -t nemue .
```

### How do I run scans in Docker?

```bash
docker run --rm nemue scan 192.168.1.1 -p 80,443
```

### How do I save results from Docker?

```bash
docker run --rm -v ./output:/output nemue scan 192.168.1.1 -o /output/results.json
```

### How do I use custom scripts in Docker?

```bash
docker run --rm -v ./scripts:/usr/local/share/nemue/scripts nemue script list
```

### How do I run MCP server in Docker?

```bash
docker run --rm -i nemue mcp
```

### Docker image is too large

The multi-stage build already optimizes size. If needed:
```bash
# Build with smaller base
docker build --build-arg BASE_IMAGE=rust:1.96-alpine -t nemue .
```

---

## MCP Server

### What is MCP?

MCP (Model Context Protocol) is a protocol for AI assistants to use external tools. Nemue implements MCP to allow AI assistants like Claude, Cursor, and VS Code Copilot to perform network scans.

### How do I start the MCP server?

```bash
nemue mcp
```

### How do I configure Claude Desktop?

Add to `~/.claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "nemue": {
      "command": "nemue",
      "args": ["mcp"]
    }
  }
}
```

### How do I configure Cursor?

Add to `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "nemue": {
      "command": "nemue",
      "args": ["mcp"]
    }
  }
}
```

### What MCP tools are available?

- `nemue_scan` - Full port scan
- `nemue_quick_scan` - Fast top-ports scan
- `nemue_service_detect` - Service detection
- `nemue_os_detect` - OS fingerprinting
- `nemue_ssl_check` - SSL/TLS analysis
- `nemue_host_discovery` - Ping sweep
- `nemue_traceroute` - Network path discovery
- `nemue_fuzz` - Web content fuzzing
- `nemue_vuln_scan` - Vulnerability scanning

### Can I use MCP server with Docker?

```bash
docker run --rm -i nemue mcp
```

---

## Comparison with Other Tools

### Nemue vs Nmap

| Feature | Nemue | Nmap |
|---------|-------|------|
| Language | Rust | C/Lua |
| Speed | ~1K pps | ~1-5K pps |
| Web Fuzzing | Yes (8 modes) | No |
| MCP Server | Yes | No |
| Compliance | 7 frameworks | No |
| Scripts | 56+ Lua | 600+ NSE |
| Platform | Linux | Cross-platform |

### Nemue vs RustScan

| Feature | Nemue | RustScan |
|---------|-------|----------|
| Speed | ~1K pps | ~21K pps |
| Service Detection | Yes | No (needs Nmap) |
| OS Fingerprinting | Yes | No |
| Web Fuzzing | Yes | No |
| MCP Server | Yes | No |

### Nemue vs Masscan

| Feature | Nemue | Masscan |
|---------|-------|---------|
| Speed | ~1K pps | 1.6-10M pps |
| Service Detection | Yes | Basic |
| OS Fingerprinting | Yes | No |
| Accuracy | High | Lower |
| Use Case | Enterprise | Internet-scale |

### When should I use Nemue?

Use Nemue when you need:
- All-in-one security testing
- AI assistant integration (MCP)
- Compliance reporting
- Web application fuzzing
- Modern async architecture

### When should I use Nmap?

Use Nmap when you need:
- Cross-platform support
- Extensive script library (600+)
- Mature, battle-tested tool
- Specific NSE script functionality

### When should I use Masscan?

Use Masscan when you need:
- Internet-scale scanning
- Maximum speed (millions of pps)
- Port discovery only (no deep analysis)

---

## Still Have Questions?

- **Issues**: https://github.com/supunhg/Nemue/issues
- **Discussions**: https://github.com/supunhg/Nemue/discussions
- **Documentation**: See [USAGE.md](USAGE.md) for comprehensive guide
