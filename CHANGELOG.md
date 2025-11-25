# Nemue Changelog

All notable changes to the Nemue project are documented here.

---

## [Unreleased]

### 🐛 Bug Fixes
- **Aggressive scan (-A) now works without sudo**: Automatically falls back to Connect scan when not running as root, with helpful warning message
- **MySQL service detection improved**: Enhanced banner grabbing to properly detect MySQL handshake and extract version information
- **Service detection timeout increased**: Changed from 1000ms to 2000ms for better reliability with databases and slow services

### ✨ Enhancements
- **Better MySQL version extraction**: Now properly parses MySQL handshake protocol and extracts version from server greeting
- **Smarter aggressive mode**: Detects privilege level and adjusts scan type accordingly
- **Improved banner detection**: Added special handling for MySQL, PostgreSQL, and other database protocols

---

## [0.1.0] - 2024-11-25 🎉

### 🚀 Initial Production Release

**Major Milestone**: Complete implementation of all 16 development phases!

### ✨ Features Implemented

#### Core Scanning (Phases 1-4)
- ✅ **High-performance async scanning** with Tokio runtime
- ✅ **8 scan types**: SYN, Connect, UDP, FIN, Xmas, Null, ACK, Window
- ✅ **Raw socket implementation** via pnet for stealth scanning
- ✅ **Complete IPv6 support** across all scan types
- ✅ **Parallel port scanning** with configurable concurrency
- ✅ **Host discovery**: ICMP Echo, ARP, TCP/UDP ping
- ✅ **Port specification**: Individual, ranges, top ports

#### Service Detection (Phases 5-8)
- ✅ **1000+ service signatures** for protocol detection
- ✅ **Protocol parsers**: HTTP, SSH, FTP, SMTP, SMB, RDP, MySQL, PostgreSQL, Redis
- ✅ **Banner grabbing** with version extraction
- ✅ **Confidence scoring** for detection reliability
- ✅ **100+ service probes** covering major protocols

#### OS Fingerprinting (Phases 9-12, 15)
- ✅ **TCP/IP stack analysis**: TTL, window size, IP ID sequence
- ✅ **Passive fingerprinting**: p0f-style traffic analysis
- ✅ **11 OS families**: Linux, Windows, macOS, BSD, Cisco, etc.
- ✅ **CPE generation** for NVD vulnerability correlation
- ✅ **Advanced TCP analysis**: Timestamps, window scaling, MSS

#### Output & Formats (Phases 10-12)
- ✅ **4 output formats**: Normal (Nmap-style), XML, JSON, Grepable
- ✅ **Colored terminal output** with RGB support
- ✅ **Progress indicators** with ETA
- ✅ **Script results integration** in all formats

#### Scripting Engine (Phases 13-14, 16)
- ✅ **Full Lua 5.4 support** (vendored, no external deps)
- ✅ **NSE-compatible API** for Nmap script compatibility
- ✅ **59 Lua scripts** included:
  - Service detection scripts
  - Vulnerability checks
  - Default credentials testing
  - SSL/TLS analysis
  - Database enumeration
- ✅ **Script arguments** via CLI and files
- ✅ **Script tracing** for debugging
- ✅ **Script categories** and database

#### Advanced Features
- ✅ **Timing templates**: T0 (Paranoid) to T5 (Insane)
- ✅ **Stealth techniques**: Decoy scanning, fragmentation, TTL manipulation
- ✅ **Proxy support**: HTTP, SOCKS4, SOCKS5 with chaining
- ✅ **Rate limiting** and bandwidth control
- ✅ **CVE database integration** for vulnerability lookup
- ✅ **Threat intelligence** with IP reputation checks
- ✅ **Risk scoring engine** for security assessment
- ✅ **REST API server** with 7 endpoints
- ✅ **Continuous monitoring** with change detection
- ✅ **Compliance mapping**: PCI-DSS, NIST, CIS, ISO 27001, HIPAA, SOC 2, GDPR
- ✅ **Report generation**: Executive, Technical, Compliance templates

### 📦 Packaging & Distribution

#### New
- ✅ **Debian package** (.deb) for easy installation
- ✅ **Two build scripts**: `build-deb.sh` and `build-deb-simple.sh`
- ✅ **Complete installation guide**: [INSTALL.md](INSTALL.md)
- ✅ **Package quick reference**: [PACKAGE.md](PACKAGE.md)
- ✅ **Automated dependency handling**
- ✅ **Proper file permissions** and system integration

### 📚 Documentation

#### New Documentation
- ✅ **INSTALL.md** (8.6 KB) - Comprehensive installation guide
- ✅ **PACKAGE.md** (1.9 KB) - Debian package quick reference
- ✅ **QUICK_START.md** (5.0 KB) - 5-minute getting started guide
- ✅ **USAGE.md** (31 KB) - Complete feature documentation
- ✅ **ARCHITECTURE.md** (4.9 KB) - System design details
- ✅ **ROADMAP.md** (53 KB) - All 16 development phases
- ✅ **RELEASE_CHECKLIST.md** (6.7 KB) - Deployment guide

#### Removed Documentation (Cleanup)
- 🗑️ PROJECT_COMPLETE.md (duplicate)
- 🗑️ PROJECT_COMPLETE_FINAL.md (duplicate)
- 🗑️ RELEASE_NOTES.md (redundant with changelog)
- 🗑️ DOCUMENTATION_INDEX.md (redundant)
- 🗑️ PROJECT_SUMMARY.md (consolidated into other docs)

### 🔧 Technical Improvements

- ✅ **78,239 lines** of production Rust code
- ✅ **631 comprehensive tests** (100% pass rate)
- ✅ **3.4 MB optimized binary** (release build)
- ✅ **Zero critical bugs** in final release
- ✅ **Memory efficient** async I/O
- ✅ **High performance**: 1000+ packets/second scan rate

### 📊 Statistics

| Metric | Value |
|--------|-------|
| Rust Source Files | 112 |
| Rust Code Lines | 78,239 |
| Lua Scripts | 59 |
| Tests | 631 (100% pass) |
| Binary Size | 3.4 MB |
| Phases Complete | 16/16 (100%) |
| Nmap Feature Parity | 79% (110/140) |
| Documentation | 7 comprehensive guides |

### 🎯 Nmap Feature Parity

**Implemented (79%)**:
- ✅ Scan types: SYN, Connect, UDP, FIN, Xmas, Null, ACK, Window
- ✅ Service detection with version probes
- ✅ OS fingerprinting (TCP/IP stack)
- ✅ NSE-compatible scripting engine
- ✅ Output formats: Normal, XML, JSON, Grepable
- ✅ Timing controls (T0-T5)
- ✅ Port specifications and ranges
- ✅ Host discovery
- ✅ IPv6 support
- ✅ Stealth techniques

**Not Yet Implemented**:
- ❌ Idle scan (IPID zombie)
- ❌ FTP bounce scan
- ❌ Full IPv6 OS fingerprinting database
- ❌ Some advanced evasion techniques

### 🔒 Security

- ✅ **Safe Rust** practices (minimal unsafe code)
- ✅ **Input validation** on all user inputs
- ✅ **Robust error handling** with anyhow
- ✅ **No hardcoded credentials**
- ✅ **Dependency auditing** with cargo-audit
- ✅ **Legal disclaimers** for authorized use only

### 🐛 Known Issues

- ⚠️ Some compile warnings (non-critical, 72 total)
- ⚠️ macOS may require additional permissions for raw sockets
- ⚠️ Windows support not yet implemented

### 📝 Installation

```bash
# Debian/Ubuntu (Recommended)
wget https://github.com/supunhg/Nemue/releases/download/v0.1.0/nemue_0.1.0-1_amd64.deb
sudo dpkg -i nemue_0.1.0-1_amd64.deb

# From source
git clone https://github.com/supunhg/Nemue.git
cd Nemue
cargo build --release
```

### 🙏 Acknowledgments

This release represents a complete implementation of a modern security testing framework, featuring:
- Modern async architecture with Tokio
- Comprehensive service detection
- Advanced OS fingerprinting
- Extensible NSE scripting
- Production-ready quality

---

## Development Timeline

- **Phase 1-4** (Foundation): Core scanning engine, IPv4/IPv6 support
- **Phase 5-8** (Detection): Service detection, banner grabbing
- **Phase 9-12** (Intelligence): OS fingerprinting, output formats
- **Phase 13-14** (Scripting): NSE engine, script integration
- **Phase 15** (Advanced): TCP/IP stack OS fingerprinting
- **Phase 16** (Polish): Final integration, packaging, documentation

**Total Development**: 16 phases, 100% complete ✅

---

## Future Roadmap

### Version 0.2.0 (Planned)
- Windows support
- Enhanced IPv6 OS fingerprinting
- Additional evasion techniques
- Performance optimizations
- More NSE scripts (target: 100+)

### Version 0.3.0 (Planned)
- Web UI dashboard
- Database backend for results
- Scheduled scanning
- Email notifications
- Advanced reporting

---

**For full documentation, see**: [README.md](README.md)  
**For installation help, see**: [INSTALL.md](INSTALL.md)  
**For quick start, see**: [QUICK_START.md](QUICK_START.md)

---

**Format**: [Keep a Changelog](https://keepachangelog.com/)  
**Versioning**: [Semantic Versioning](https://semver.org/)
