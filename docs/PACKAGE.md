## 📦 Nemue Debian Package - Quick Reference

### Package Information
- **Name**: nemue
- **Version**: 0.1.0-1
- **Architecture**: amd64
- **Size**: 1.3 MB (compressed)
- **Installed Size**: ~4 MB

---

### Installation

```bash
# Install
sudo dpkg -i nemue_0.1.0-1_amd64.deb

# Fix dependencies (if needed)
sudo apt-get install -f

# Verify
nemue --version
```

---

### What Gets Installed

```
/usr/bin/nemue                          # Main binary (3.4 MB)
/usr/share/nemue/scripts/               # 59 Lua scripts
/usr/share/doc/nemue/                   # Documentation
  ├── README.md
  ├── QUICK_START.md
  ├── USAGE.md
  ├── ARCHITECTURE.md
  └── changelog.gz
```

---

### Quick Start

```bash
# Basic scan
nemue 192.168.1.1 -p 80,443

# Service detection
nemue 192.168.1.1 -sV

# Full scan (requires root)
sudo nemue 192.168.1.1 -A

# Network scan
sudo nemue 192.168.1.0/24 -F -T4
```

---

### Common Commands

```bash
# View help
nemue --help

# List scripts
ls /usr/share/nemue/scripts/

# Read docs
cat /usr/share/doc/nemue/QUICK_START.md

# Check package
dpkg -l | grep nemue
dpkg -L nemue  # List all files
```

---

### Uninstall

```bash
# Remove package
sudo dpkg -r nemue

# Purge (remove config too)
sudo dpkg -P nemue
```

---

### Troubleshooting

**Permission denied:**
```bash
sudo nemue 192.168.1.1 -sS
```

**Scripts not found:**
```bash
export NEMUE_SCRIPTS=/usr/share/nemue/scripts
```

**Missing dependencies:**
```bash
sudo apt-get install -f
```

---

### Build Your Own Package

```bash
git clone https://github.com/supunhg/Nemue.git
cd Nemue
./build-deb-simple.sh
sudo dpkg -i nemue_0.1.0-1_amd64.deb
```

---

**Documentation**: Full guides at `/usr/share/doc/nemue/`  
**Scripts**: Available at `/usr/share/nemue/scripts/`  
**Support**: https://github.com/supunhg/Nemue/issues
