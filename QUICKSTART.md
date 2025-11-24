# Nemue Quick Start Guide

**Simple, powerful network scanning with shorter commands than nmap**

---

## Installation

```bash
git clone https://github.com/supunhg/Nemue.git
cd Nemue
cargo build --release
sudo cp target/release/nemue /usr/local/bin/
```

---

## Basic Usage

### 1. Simple Scan (Just Get Started!)

```bash
# Scan default ports (1-1000), shows only open ports
nemue scan 192.168.1.1

# Scan common ports (21 frequently used ports)
nemue scan 192.168.1.1 -p common

# Scan specific ports
nemue scan 192.168.1.1 -p 80,443,22,3306
```

### 2. Aggressive Scan (Like `nmap -A`)

```bash
# Full comprehensive scan - requires root
sudo nemue scan 192.168.1.1 -A

# This automatically:
# ✓ Scans top 1000 ports
# ✓ Detects services & versions
# ✓ Detects operating system
# ✓ Uses stealth SYN scanning
```

### 3. Port Selection

```bash
# Port range
nemue scan 192.168.1.1 -p 1-1000

# Common ports preset (21 ports)
nemue scan 192.168.1.1 -p common

# Top 100 most common ports
nemue scan 192.168.1.1 -p top100

# Top 1000 most common ports
nemue scan 192.168.1.1 -p top1000

# All ports (takes a while!)
nemue scan 192.168.1.1 -p 1-65535
```

### 4. Exclude Ports

```bash
# Skip certain ports
nemue scan 192.168.1.1 -p 1-1000 -e 80,443

# Scan common ports except MySQL
nemue scan 192.168.1.1 -p common -e 3306

# Exclude port ranges
nemue scan 192.168.1.1 -p 1-10000 -e 1-100,500-600
```

### 5. Service & OS Detection

```bash
# Detect services/versions
nemue scan 192.168.1.1 -p 22,80,443 -V

# Detect operating system
nemue scan 192.168.1.1 -p common -O

# Both service and OS detection
nemue scan 192.168.1.1 -p common -V -O
```

### 6. Control Output

```bash
# Default: only show open ports (cleanest!)
nemue scan 192.168.1.1 -p common

# Show closed ports too
nemue scan 192.168.1.1 -p common -c

# Show filtered ports too
nemue scan 192.168.1.1 -p common -F

# Show everything
nemue scan 192.168.1.1 -p common -c -F

# Quiet mode (no banner)
nemue scan 192.168.1.1 -p common -q

# Verbose output
nemue scan 192.168.1.1 -p common -v
```

### 7. Save Results

```bash
# Save to JSON (default)
nemue scan 192.168.1.1 -p common -o results.json

# Save to XML
nemue scan 192.168.1.1 -p common -o results.xml -f xml
```

### 8. Different Scan Types

```bash
# TCP SYN scan (default)
nemue scan 192.168.1.1 -p 80,443

# TCP connect scan (no root required)
nemue scan 192.168.1.1 -p 80,443 -s connect

# UDP scan (requires root)
sudo nemue scan 192.168.1.1 -p 53,123,161 -s udp

# Raw socket SYN scan (stealthiest, requires root)
sudo nemue scan 192.168.1.1 -p 1-1000 --raw
```

### 9. Performance Tuning

```bash
# Slow scan (100 packets/sec)
nemue scan 192.168.1.1 -p 1-1000 -r 100

# Fast scan (5000 packets/sec)
nemue scan 192.168.1.1 -p 1-1000 -r 5000

# Custom timeout (500ms)
nemue scan 192.168.1.1 -p 1-1000 --timeout 500
```

---

## Common Tasks

### Find Web Servers

```bash
# Quick web server scan
nemue scan 192.168.1.0/24 -p 80,443,8080,8443
```

### Find Databases

```bash
# Common database ports
nemue scan 192.168.1.0/24 -p 3306,5432,27017,6379,1433
```

### Full Network Scan

```bash
# Comprehensive network discovery
sudo nemue scan 192.168.1.0/24 -A -q -o network-scan.json
```

### Security Audit

```bash
# Aggressive scan excluding known services
sudo nemue scan target.com -A -e 80,443 -v -o audit.json
```

---

## Command Comparison: Nemue vs Nmap

| What You Want | Nmap | Nemue | Improvement |
|---------------|------|-------|-------------|
| Basic scan | `nmap 192.168.1.1` | `nemue scan 192.168.1.1` | ✓ Same length |
| Aggressive | `sudo nmap -A target` | `sudo nemue scan target -A` | ✓ Same flags |
| Exclude ports | `nmap --exclude-ports 22,80 target` | `nemue scan target -e 22,80` | ✓ **Much shorter** |
| Service detect | `nmap -sV target` | `nemue scan target -V` | ✓ **Simpler flag** |
| OS detect | `nmap -O target` | `nemue scan target -O` | ✓ Same |
| UDP scan | `sudo nmap -sU -p 53 target` | `sudo nemue scan target -p 53 -s udp` | ✓ **Clearer** |
| Stealth SYN | `sudo nmap -sS target` | `sudo nemue scan target --raw` | ✓ **More obvious** |
| Verbose | `nmap -v target` | `nemue scan target -v` | ✓ Same |
| Save JSON | `nmap -oJ file target` | `nemue scan target -o file` | ✓ **Default format** |
| Quiet | `nmap --no-stylesheet target` | `nemue scan target -q` | ✓ **Much shorter** |
| Show closed | `nmap target` (shows all) | `nemue scan target -c` | ✓ **Better default** |

**Key Advantages:**
- ✅ **Shorter flags**: `-e` vs `--exclude-ports`, `-V` vs `-sV`, `-q` vs `--no-stylesheet`
- ✅ **Better defaults**: Only shows open ports (no noise!)
- ✅ **Clearer syntax**: `-s udp` instead of `-sU`
- ✅ **Faster**: Async Rust vs single-threaded C
- ✅ **Modern output**: Beautiful colored terminal display

---

## Tips & Tricks

### 1. Only Show What Matters
By default, Nemue only shows **open ports**. No more scrolling through 998 closed ports!

### 2. Port Presets Save Time
```bash
# Instead of: nemue scan target -p 21,22,23,25,53,80,110,...
# Just use:
nemue scan target -p common
```

### 3. Combine Flags for Power
```bash
# Aggressive scan + exclude known ports + save results + quiet
sudo nemue scan target -A -e 80,443 -o results.json -q
```

### 4. Start Simple, Add Flags
```bash
# Start with:
nemue scan 192.168.1.1

# Need more info? Add flags:
nemue scan 192.168.1.1 -V -O

# Want it all?
sudo nemue scan 192.168.1.1 -A
```

---

## Web Content Discovery (Fuzzing)

### Basic Fuzzing

```bash
# Directory discovery with built-in wordlist
nemue fuzz https://example.com -b dirs1k

# Recursive directory scan
nemue fuzz https://example.com -b dirs10k -R --max-depth 3

# Subdomain enumeration
nemue fuzz example.com -m subdomain -b subdomains

# File discovery
nemue fuzz https://example.com -m file -b files
```

### Advanced Fuzzing

```bash
# High-speed with filtering
nemue fuzz https://example.com -b dirs1k -c 100 -s 200,301,302

# Parameter fuzzing
nemue fuzz "https://api.example.com/users?id=FUZZ" -b params

# Save results to JSON
nemue fuzz https://example.com -b dirs1k -o json -O results.json
```

---

## Need Help?

```bash
# General help
nemue --help

# Scan command help
nemue scan --help

# Fuzz command help
nemue fuzz --help

# Check version
nemue --version
```

---

## Next Steps

- Read [USAGE.md](USAGE.md) for comprehensive documentation
- Check [README.md](README.md) for full feature list
- See [ROADMAP.md](ROADMAP.md) for upcoming features
- View man pages: `man docs/man/nemue.1`

**Happy scanning! 🌊**
