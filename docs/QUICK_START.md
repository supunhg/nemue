# Nemue Quick Start Guide

Quick reference for getting started with Nemue security testing framework.

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/nemue.git
cd nemue

# Build release version
cargo build --release

# Binary location
./target/release/nemue
```

## Common Scan Commands

### Basic Scans

```bash
# Quick scan single target
nemue 192.168.1.1

# Scan multiple targets
nemue 192.168.1.1 192.168.1.2 192.168.1.3

# Scan range
nemue 192.168.1.1-254

# Scan CIDR
nemue 192.168.1.0/24
```

### Port Scanning

```bash
# Scan specific ports
nemue 192.168.1.1 -p 22,80,443

# Scan port range
nemue 192.168.1.1 -p 1-1000

# Scan all ports
nemue 192.168.1.1 -p 1-65535

# Top 1000 ports (default)
nemue 192.168.1.1
```

### Scan Techniques

```bash
# TCP SYN scan (default, requires root)
sudo nemue 192.168.1.1 -sS

# TCP Connect scan (no root required)
nemue 192.168.1.1 -sT

# UDP scan
sudo nemue 192.168.1.1 -sU

# Version detection
nemue 192.168.1.1 -sV

# OS detection
sudo nemue 192.168.1.1 -O

# Aggressive scan (OS + version + scripts + traceroute)
sudo nemue 192.168.1.1 -A
```

### Performance Tuning

```bash
# Fast scan (fewer ports)
nemue 192.168.1.1 -F

# Timing templates (0=slowest, 5=fastest)
nemue 192.168.1.1 -T4

# Custom parallelism
nemue 192.168.1.1 --max-parallel 200
```

### Output Formats

```bash
# Normal output (default)
nemue 192.168.1.1

# XML output
nemue 192.168.1.1 -oX scan.xml

# JSON output
nemue 192.168.1.1 -oJ scan.json

# Grepable output
nemue 192.168.1.1 -oG scan.grep

# All formats
nemue 192.168.1.1 -oA scan_results
```

### Script Scanning

```bash
# Default scripts
nemue 192.168.1.1 -sC

# Specific script
nemue 192.168.1.1 --script http-title

# Multiple scripts
nemue 192.168.1.1 --script "http-*,ssh-*"

# Script categories
nemue 192.168.1.1 --script "safe,discovery"
```

## Real-World Examples

### Web Server Scan
```bash
# Full web server analysis
nemue example.com -p 80,443 -sV -sC --script "http-*"
```

### Network Discovery
```bash
# Discover live hosts
sudo nemue 192.168.1.0/24 -sn

# Quick port scan of network
nemue 192.168.1.0/24 -F -T4
```

### Vulnerability Assessment
```bash
# Comprehensive security scan
sudo nemue 192.168.1.1 -p- -sV -sC -O --script "vuln,exploit" -oA full_scan
```

### SSH Server Analysis
```bash
# SSH enumeration
nemue 192.168.1.1 -p 22 -sV --script "ssh-*"
```

### Stealth Scan
```bash
# Slow, stealthy scan
sudo nemue 192.168.1.1 -sS -T0 -f --data-length 32
```

## Performance Guidelines

| Scan Type | Speed | Noise Level | Root Required |
|-----------|-------|-------------|---------------|
| `-sT` | Medium | High | No |
| `-sS` | Fast | Medium | Yes |
| `-sU` | Slow | Low | Yes |
| `-sV` | Slow | High | No |
| `-O` | Medium | Medium | Yes |
| `-A` | Slow | High | Yes |

## Timing Templates

| Template | Speed | Scan Rate | Use Case |
|----------|-------|-----------|----------|
| `-T0` | Paranoid | 1 port/5min | IDS evasion |
| `-T1` | Sneaky | 1 port/15s | IDS evasion |
| `-T2` | Polite | 1 port/0.4s | Low bandwidth |
| `-T3` | Normal | Default | Standard scan |
| `-T4` | Aggressive | Fast | Fast networks |
| `-T5` | Insane | Very fast | Fast LAN only |

## Common Use Cases

### Quick Check
```bash
# Is host up? What ports are open?
nemue 192.168.1.1 -F
```

### Deep Scan
```bash
# Everything we can find
sudo nemue 192.168.1.1 -p- -A -oA deep_scan
```

### Service Inventory
```bash
# What services are running?
nemue 192.168.1.0/24 -sV -oX services.xml
```

### Security Audit
```bash
# Find vulnerabilities
sudo nemue 192.168.1.1 -sV --script "vuln" -oA security_audit
```

## Tips & Best Practices

1. **Use sudo for better results**: SYN scans and OS detection require root
2. **Save your results**: Always use `-oA` to save multiple formats
3. **Start broad, then focus**: Quick scan first, deep scan on interesting hosts
4. **Respect rate limits**: Use `-T2` or `-T3` for production networks
5. **Check script help**: `nemue --script-help <script-name>`
6. **Combine techniques**: `-sV -sC` gives best service information
7. **Monitor bandwidth**: UDP scans can be noisy
8. **Legal authorization**: Only scan systems you own or have permission to test

## Troubleshooting

### Permission Denied
```bash
# Solution: Use sudo for raw socket operations
sudo nemue 192.168.1.1 -sS
```

### Slow Scans
```bash
# Solution: Increase timing or reduce ports
nemue 192.168.1.1 -T4 -F
```

### No Results
```bash
# Solution: Check firewall, increase verbosity
nemue 192.168.1.1 -v
```

## Getting Help

```bash
# Full help
nemue --help

# Script documentation
nemue --script-help <script-name>

# List all scripts
ls scripts/

# Version info
nemue --version
```

## Quick Docker Start

### Build and Run

```bash
# Build Docker image
docker build -t nemue .

# Run scan
docker run --rm nemue scan 192.168.1.1 -p 80,443

# Get help
docker run --rm nemue --help
```

### Docker with Volume Mounting

```bash
# Save results to host
docker run --rm -v ./output:/output nemue scan 192.168.1.1 -o /output/results.json

# Use custom scripts
docker run --rm -v ./scripts:/usr/local/share/nemue/scripts nemue script list
```

### Docker Compose

```bash
# Build and run with docker-compose
docker-compose up --build

# Run scan
docker-compose run nemue scan 192.168.1.1 -p 80,443
```

---

## Quick MCP Start

### Start MCP Server

```bash
# Start MCP server (stdio mode)
nemue mcp
```

### Configure Claude Desktop

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

### Configure Cursor

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

### Configure VS Code

Add to `.vscode/mcp.json`:
```json
{
  "servers": {
    "nemue": {
      "command": "nemue",
      "args": ["mcp"]
    }
  }
}
```

### Docker MCP Server

```bash
# Run MCP server in Docker
docker run --rm -i nemue mcp
```

---

## Quick History & Trends Start

### View Scan History

```bash
# List recent scans
nemue history list

# Show history for specific target
nemue history list --target 192.168.1.1

# Show scan details
nemue history show <scan_id>
```

### Save Scan to History

```bash
# Scan and save to history
nemue scan 192.168.1.1 -p common --save-history
```

### Analyze Trends

```bash
# Analyze trends for a target
nemue trends analyze 192.168.1.1

# Trends over last 7 days
nemue trends analyze 192.168.1.1 --period 7d

# Save trend report
nemue trends analyze 192.168.1.1 -o trends.json
```

### Compare Scans

```bash
# Compare two scans
nemue history diff <scan_id_1> <scan_id_2>
```

---

## Next Steps

- Read the [full documentation](USAGE.md)
- Check the [architecture guide](ARCHITECTURE.md)
- Review [NSE script guide](docs/NSE_GUIDE.md)
- See [complete examples](../examples/)

---

**Note**: Always ensure you have proper authorization before scanning any network or system. Unauthorized scanning may be illegal in your jurisdiction.
