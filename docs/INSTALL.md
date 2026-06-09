# Nemue Installation Guide

Complete installation instructions for all supported methods.

---

## Quick Install (Debian/Ubuntu)

```bash
# Download and install
wget https://github.com/supunhg/Nemue/releases/download/v0.1.0/nemue_0.1.0-1_amd64.deb
sudo dpkg -i nemue_0.1.0-1_amd64.deb

# If dependencies missing
sudo apt-get install -f

# Verify
nemue --version
```

---

## Installation Methods

### Method 1: Debian Package (.deb) - **Recommended**

**Advantages:**
- ✅ Quick and easy installation
- ✅ Automatic dependency management
- ✅ System-wide installation
- ✅ Easy to uninstall
- ✅ Includes all scripts and documentation
- ✅ Proper file permissions

**Requirements:**
- Debian-based system (Debian, Ubuntu, Kali, etc.)
- dpkg package manager

**Steps:**

1. **Download the package:**
   ```bash
   wget https://github.com/supunhg/Nemue/releases/download/v0.1.0/nemue_0.1.0-1_amd64.deb
   ```

2. **Install:**
   ```bash
   sudo dpkg -i nemue_0.1.0-1_amd64.deb
   ```

3. **Fix dependencies (if needed):**
   ```bash
   sudo apt-get install -f
   ```

4. **Verify installation:**
   ```bash
   nemue --version
   nemue --help
   ```

**What gets installed:**
- Binary: `/usr/bin/nemue`
- Scripts: `/usr/share/nemue/scripts/` (59 Lua scripts)
- Documentation: `/usr/share/doc/nemue/`
  - README.md
  - QUICK_START.md
  - USAGE.md
  - ARCHITECTURE.md
  - changelog.gz

**To uninstall:**
```bash
sudo dpkg -r nemue
```

---

### Method 2: Build .deb Package Yourself

**Advantages:**
- ✅ Latest source code
- ✅ Verify the code before installing
- ✅ Same benefits as Method 1

**Requirements:**
- Git
- Rust/Cargo
- dpkg-deb

**Steps:**

1. **Clone repository:**
   ```bash
   git clone https://github.com/supunhg/Nemue.git
   cd Nemue
   ```

2. **Build the package:**
   ```bash
   # Simple method (recommended)
   ./build-deb-simple.sh
   
   # Or using dpkg-buildpackage (requires dpkg-dev)
   ./build-deb.sh
   ```

3. **Install:**
   ```bash
   sudo dpkg -i nemue_0.1.0-1_amd64.deb
   ```

4. **Verify:**
   ```bash
   nemue --version
   ```

---

### Method 3: Build from Source

**Advantages:**
- ✅ Works on any Linux distribution
- ✅ Latest features
- ✅ Custom installation location
- ✅ Development and testing

**Requirements:**
- Rust 1.70 or higher
- Git
- Root/sudo privileges (for raw socket scans)

**Steps:**

1. **Install Rust (if not already installed):**
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

2. **Clone repository:**
   ```bash
   git clone https://github.com/supunhg/Nemue.git
   cd Nemue
   ```

3. **Build release binary:**
   ```bash
   cargo build --release
   ```

4. **Run tests (optional but recommended):**
   ```bash
   cargo test --release
   ```

5. **Install manually:**
   ```bash
   # Copy binary
   sudo cp target/release/nemue /usr/local/bin/
   
   # Copy scripts
   sudo mkdir -p /usr/local/share/nemue
   sudo cp -r scripts /usr/local/share/nemue/
   
   # Set permissions
   sudo chmod +x /usr/local/bin/nemue
   ```

6. **Verify:**
   ```bash
   nemue --version
   ```

**To uninstall:**
```bash
sudo rm /usr/local/bin/nemue
sudo rm -rf /usr/local/share/nemue
```

---

## Platform-Specific Instructions

### Debian / Ubuntu / Kali Linux

**Use Method 1 (Debian Package) - Recommended**

```bash
wget https://github.com/supunhg/Nemue/releases/download/v0.1.0/nemue_0.1.0-1_amd64.deb
sudo dpkg -i nemue_0.1.0-1_amd64.deb
sudo apt-get install -f  # if needed
```

### Arch Linux / Manjaro

**Build from source:**

```bash
# Install Rust
sudo pacman -S rust cargo git

# Build
git clone https://github.com/supunhg/Nemue.git
cd Nemue
cargo build --release
sudo cp target/release/nemue /usr/local/bin/
```

### Fedora / RHEL / CentOS

**Build from source:**

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Build
git clone https://github.com/supunhg/Nemue.git
cd Nemue
cargo build --release
sudo cp target/release/nemue /usr/local/bin/
```

### macOS

**Build from source:**

```bash
# Install Rust (if not already)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Build
git clone https://github.com/supunhg/Nemue.git
cd Nemue
cargo build --release

# Install
sudo cp target/release/nemue /usr/local/bin/
```

**Note:** macOS may require additional permissions for raw socket operations.

---

## Post-Installation

### Verify Installation

```bash
# Check version
nemue --version

# View help
nemue --help

# List available scripts
ls /usr/share/nemue/scripts/  # if installed via .deb
ls scripts/                    # if built from source

# Test basic scan (localhost)
nemue 127.0.0.1 -p 22,80
```

### First Scan

```bash
# Simple scan (no root required)
nemue 192.168.1.1 -p 80,443

# SYN scan (requires root)
sudo nemue 192.168.1.1 -sS -p 1-1000

# Service detection
nemue 192.168.1.1 -sV -p 22,80,443

# Full scan with scripts
sudo nemue 192.168.1.1 -A
```

### Read Documentation

```bash
# If installed via .deb
ls /usr/share/doc/nemue/

# View quick start guide
cat /usr/share/doc/nemue/QUICK_START.md

# Or from repository
cat QUICK_START.md
cat USAGE.md
```

---

## Troubleshooting

### "Permission denied" errors

**Problem:** Cannot create raw sockets

**Solution:** Run with sudo for SYN scans:
```bash
sudo nemue 192.168.1.1 -sS
```

Or use TCP Connect scan (no root required):
```bash
nemue 192.168.1.1 -sT
```

### "Command not found"

**Problem:** Binary not in PATH

**Solution:**
```bash
# If installed via .deb, add to path
export PATH=$PATH:/usr/bin

# If built from source
export PATH=$PATH:/usr/local/bin

# Or run with full path
/usr/bin/nemue --help
```

### Missing dependencies (Debian)

**Problem:** dpkg shows missing dependencies

**Solution:**
```bash
sudo apt-get install -f
```

### Build errors (Rust)

**Problem:** Compilation fails

**Solutions:**
```bash
# Update Rust
rustup update

# Clean and rebuild
cargo clean
cargo build --release

# Check Rust version (need 1.70+)
rustc --version
```

### Scripts not found

**Problem:** --script option shows errors

**Solution:**
```bash
# If installed via .deb, scripts are at:
ls /usr/share/nemue/scripts/

# Set NEMUE_SCRIPTS environment variable
export NEMUE_SCRIPTS=/usr/share/nemue/scripts

# Or run from source directory
cd /path/to/Nemue
./target/release/nemue --script http-title
```

---

## Upgrading

### From .deb package

```bash
# Download new version
wget https://github.com/supunhg/Nemue/releases/download/v0.2.0/nemue_0.2.0-1_amd64.deb

# Install (automatically upgrades)
sudo dpkg -i nemue_0.2.0-1_amd64.deb
```

### From source

```bash
cd Nemue
git pull origin main
cargo build --release
sudo cp target/release/nemue /usr/local/bin/
```

---

## Complete Uninstallation

### If installed via .deb

```bash
sudo dpkg -r nemue
```

### If installed from source

```bash
sudo rm /usr/local/bin/nemue
sudo rm -rf /usr/local/share/nemue
```

### Clean build artifacts

```bash
cd Nemue
cargo clean
rm -f nemue_*.deb
rm -rf build/
```

---

## System Requirements

### Minimum Requirements
- **OS**: Linux (any distribution), macOS 10.15+
- **CPU**: 1 core
- **RAM**: 512 MB
- **Disk**: 50 MB

### Recommended Requirements
- **OS**: Debian/Ubuntu (for .deb package)
- **CPU**: 2+ cores
- **RAM**: 2+ GB
- **Disk**: 100 MB
- **Network**: 100 Mbps+

### For Development
- **Rust**: 1.70 or higher
- **Cargo**: Latest version
- **Git**: Any recent version
- **Disk**: 2+ GB (for dependencies and builds)

---

## Security Considerations

### Permissions

Nemue requires root/sudo for:
- ✅ SYN scans (raw socket creation)
- ✅ OS fingerprinting (TCP/IP stack analysis)
- ✅ Packet fragmentation
- ✅ Custom source addresses

No root required for:
- ✅ TCP Connect scans
- ✅ Service detection (with Connect scan)
- ✅ Script execution
- ✅ Output generation

### Firewall Configuration

Some scans may be blocked by:
- Host firewall (iptables, ufw, firewalld)
- Network firewall
- IDS/IPS systems

Ensure proper authorization before scanning any network.

---

## Support

- **Documentation**: [README.md](README.md), [QUICK_START.md](QUICK_START.md), [USAGE.md](USAGE.md)
- **Issues**: https://github.com/supunhg/Nemue/issues
- **Discussions**: https://github.com/supunhg/Nemue/discussions

---

## Legal Notice

⚠️ **IMPORTANT**: Only use Nemue on networks and systems you own or have explicit permission to test. Unauthorized scanning may be illegal in your jurisdiction.

Always ensure:
- ✅ Written authorization for security testing
- ✅ Clear scope of engagement
- ✅ Compliance with local laws and regulations
- ✅ Responsible disclosure of findings

---

**Version**: 0.1.0  
**Last Updated**: November 2024
