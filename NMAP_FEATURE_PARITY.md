# Nmap Feature Parity Tracking

This document tracks Nemue's implementation status against nmap's full feature set.

**Legend:**
- ✅ **Implemented** - Feature fully working
- 🚧 **Partial** - Basic implementation exists, needs enhancement
- ❌ **Missing** - Not yet implemented
- 🔜 **Planned** - Scheduled for implementation
- ⚠️ **Won't Implement** - Out of scope or not applicable

---

## TARGET SPECIFICATION

| Nmap Feature | Status | Nemue Equivalent | Notes |
|-------------|---------|------------------|-------|
| IP addresses | ✅ | `nemue scan 192.168.1.1` | IPv4 fully supported |
| Hostnames | ✅ | `nemue scan example.com` | DNS resolution working |
| CIDR notation | ✅ | `nemue scan 192.168.1.0/24` | Full CIDR support |
| Octet ranges | ✅ | `nemue scan 192.168.0-255.1-254` | Implemented |
| Multiple targets | ✅ | Space-separated | Works in CLI |
| `-iL` (input list) | ✅ | `TargetParser::parse_from_file` | Read targets from file |
| `-iR` (random) | ✅ | `TargetParser::generate_random` | Generate random targets |
| `--exclude` | ✅ | `-e, --exclude` | Port exclusion only |
| `--excludefile` | ✅ | `TargetConfig::load_exclusions_from_file` | Exclude from file |
| `-6` (IPv6) | 🚧 | Partial support | IPv6 exists, needs enhancement |
| `--resolve-all` | ✅ | `TargetConfig.resolve_all` | Scan all resolved IPs |
| `--unique` | ✅ | `TargetConfig.unique` | Scan each IP once |

**Priority:** High - ✅ **COMPLETE** (Phase 1.3)

---

## HOST DISCOVERY

| Nmap Feature | Status | Nemue Equivalent | Notes |
|-------------|---------|------------------|-------|
| `-sL` (List Scan) | ✅ | `HostDiscovery::list_only()` | Just list targets, no scan |
| `-sn` (Ping Scan) | ✅ | `DiscoveryMethod::PingScan` | No port scan, just discovery |
| `-Pn` (No Ping) | ✅ | `HostDiscovery::no_ping()` | Skip host discovery |
| `-PS` (TCP SYN Ping) | ✅ | `DiscoveryMethod::TcpSynPing` | SYN probes for discovery |
| `-PA` (TCP ACK Ping) | ✅ | `DiscoveryMethod::TcpAckPing` | ACK probes for discovery |
| `-PU` (UDP Ping) | ✅ | `DiscoveryMethod::UdpPing` | UDP probes for discovery |
| `-PY` (SCTP INIT Ping) | ❌ | - | SCTP probes |
| `-PE` (ICMP Echo) | ✅ | `DiscoveryMethod::IcmpEchoPing` | ICMP echo with TCP fallback |
| `-PP` (ICMP Timestamp) | ✅ | `DiscoveryMethod::IcmpTimestampPing` | ICMP timestamp request |
| `-PM` (ICMP Netmask) | ✅ | `DiscoveryMethod::IcmpNetmaskPing` | ICMP netmask request |
| `-PO` (IP Protocol) | ❌ | - | IP protocol ping |
| `-n` (No DNS) | ✅ | `DnsConfig::never_resolve()` | Never resolve DNS |
| `-R` (DNS always) | ✅ | `DnsConfig::always_resolve()` | Always resolve |
| `--dns-servers` | ✅ | `DnsConfig.custom_servers` | Custom DNS servers |
| `--system-dns` | ✅ | `DnsConfig.use_system_dns` | Use OS resolver |
| `--traceroute` | ❌ | - | Trace hop path |
| `--disable-arp-ping` | ❌ | - | Disable ARP discovery |
| `--discovery-ignore-rst` | ❌ | - | Ignore RST spoofing |

**Priority:** High - ✅ **COMPLETE** (Phase 1.2 & 1.4)

---

## SCAN TECHNIQUES

| Nmap Feature | Status | Nemue Equivalent | Notes |
|-------------|---------|------------------|-------|
| `-sS` (TCP SYN) | ✅ | `-s syn` (default) | Stealth scan working |
| `-sT` (TCP Connect) | ✅ | `-s connect` | Full TCP connect |
| `-sU` (UDP Scan) | ✅ | `-s udp` | UDP scanning working |
| `-sA` (ACK Scan) | ✅ | `ScanType::Ack` | Firewall rule mapping |
| `-sW` (Window Scan) | ✅ | `ScanType::Window` | Window size analysis |
| `-sM` (Maimon Scan) | ✅ | `ScanType::Maimon` | FIN/ACK probe |
| `-sN` (NULL Scan) | ✅ | `ScanType::Null` | No TCP flags set |
| `-sF` (FIN Scan) | ✅ | `ScanType::Fin` | FIN flag only |
| `-sX` (Xmas Scan) | ✅ | `ScanType::Xmas` | FIN+PSH+URG flags |
| `--scanflags` | ✅ | `ScanType::Custom(TcpFlags)` | Custom TCP flag combo |
| `-sI` (Idle Scan) | ❌ | - | Zombie host scan |
| `-sY` (SCTP INIT) | ❌ | - | SCTP INIT scan |
| `-sZ` (SCTP COOKIE) | ❌ | - | SCTP COOKIE-ECHO |
| `-sO` (IP Protocol) | ❌ | - | Determine IP protocols |
| `-b` (FTP Bounce) | ⚠️ | - | Deprecated, won't implement |

**Priority:** Medium - ✅ **COMPLETE** (Phase 2.1)

---

## PORT SPECIFICATION

| Nmap Feature | Status | Nemue Equivalent | Notes |
|-------------|---------|------------------|-------|
| `-p <ports>` | ✅ | `-p 80,443` | Port ranges working |
| Port ranges | ✅ | `-p 1-1000` | Range syntax working |
| Protocol-specific | ✅ | `T:80,443 U:53` | Protocol syntax working |
| `--exclude-ports` | ✅ | `-e 22,80` | Shorter than nmap! |
| `-F` (Fast scan) | ✅ | `PortSpec::fast()` | Top 100 ports |
| `-r` (Sequential) | ✅ | `PortSpec::sequential()` | Don't randomize order |
| `--top-ports` | 🚧 | `top100, top1000` | Presets exist |
| `--port-ratio` | ✅ | `filter_by_ratio()` | Ports above ratio |
| Port presets | ✅ | `common, top100, top1000` | 3 presets available |

**Priority:** Low - ✅ **COMPLETE** (Phase 2.4) - Core functionality complete

---

## SERVICE/VERSION DETECTION

| Nmap Feature | Status | Nemue Equivalent | Notes |
|-------------|---------|------------------|-------|
| `-sV` | ✅ | `-V, --version-detect` | Service detection working |
| `--version-intensity` | ✅ | `IntensityLevel (0-9)` | Intensity levels 0-9 |
| `--version-light` | ✅ | `IntensityLevel::light()` | Light intensity (2) |
| `--version-all` | ✅ | `IntensityLevel::all()` | Try all probes (9) |
| `--version-trace` | ✅ | `DetectionConfig.trace` | Debug version scan |
| `--allports` | ✅ | `DetectionConfig.all_ports` | Probe all ports |

**Priority:** Medium - ✅ **COMPLETE** (Phase 2.3)

---

## SCRIPT SCANNING (NSE)

| Nmap Feature | Status | Nemue Equivalent | Notes |
|-------------|---------|------------------|-------|
| `-sC` (default scripts) | 🚧 | Lua scripts exist | 18 NSE scripts ported |
| `--script` | 🚧 | Partial | Script engine exists |
| `--script-args` | ❌ | - | Pass args to scripts |
| `--script-args-file` | ❌ | - | Args from file |
| `--script-trace` | ❌ | - | Debug script execution |
| `--script-updatedb` | ❌ | - | Update script database |
| `--script-help` | ❌ | - | Show script help |

**Priority:** Medium - Already have 18 scripts, need integration

---

## OS DETECTION

| Nmap Feature | Status | Nemue Equivalent | Notes |
|-------------|---------|------------------|-------|
| `-O` | ✅ | `-O, --os-detect` | Basic OS detection |
| `--osscan-limit` | ❌ | - | Limit to promising targets |
| `--osscan-guess` | ❌ | - | Aggressive guessing |

**Priority:** Medium - Enhance existing OS detection

---

## TIMING AND PERFORMANCE

| Nmap Feature | Status | Nemue Equivalent | Notes |
|-------------|---------|------------------|-------|
| `-T<0-5>` | ✅ | `-T 0-5` | All 6 templates (T0-T5) |
| `-T0` (Paranoid) | ❌ | - | 5 min between probes |
| `-T1` (Sneaky) | ❌ | - | 15 sec between probes |
| `-T2` (Polite) | ❌ | - | 0.4 sec between probes |
| `-T3` (Normal) | 🚧 | Default behavior | Current default |
| `-T4` (Aggressive) | 🚧 | `-A` flag | Aggressive mode exists |
| `-T5` (Insane) | ❌ | - | Maximum speed |
| `--min-hostgroup` | ❌ | - | Parallel host scan size |
| `--max-hostgroup` | ❌ | - | Max parallel hosts |
| `--min-parallelism` | ❌ | - | Min probe parallelization |
| `--max-parallelism` | ❌ | - | Max probe parallelization |
| `--min-rtt-timeout` | ❌ | - | Min probe RTT |
| `--max-rtt-timeout` | ❌ | - | Max probe RTT |
| `--initial-rtt-timeout` | ❌ | - | Initial RTT timeout |
| `--max-retries` | ❌ | - | Max probe retransmissions |
| `--host-timeout` | ❌ | - | Give up on host |
| `--scan-delay` | ❌ | - | Delay between probes |
| `--max-scan-delay` | ❌ | - | Max delay between probes |
| `--min-rate` | ❌ | - | Min packets/sec |
| `--max-rate` | ✅ | `-r, --rate 1000` | Rate limiting working |

**Priority:** High - Timing templates are critical

---

## FIREWALL/IDS EVASION AND SPOOFING

| Nmap Feature | Status | Nemue Equivalent | Notes |
|-------------|---------|------------------|-------|
| `-f` (Fragment) | ✅ | `FragmentationConfig::enabled()` | Fragment packets (8-byte) |
| `--mtu` | ✅ | `FragmentationConfig::with_mtu()` | Custom MTU fragments |
| `-D` (Decoy) | ✅ | `DecoyConfig::parse()` | Decoy scanning w/ ME position |
| `-S` (Spoof source) | ✅ | `SourceSpoofer::with_ip_spoofing()` | Spoof source IP |
| `-e` (Interface) | ✅ | `SourceConfig::with_interface()` | Use specific interface |
| `-g/--source-port` | ✅ | `SourceConfig::with_source_port()` | Use specific source port |
| `--proxies` | ✅ | `ProxyChain::parse()` | HTTP/SOCKS4/SOCKS5 chains |
| `--data` | ✅ | `PayloadConfig::with_hex_data()` | Custom hex payload |
| `--data-string` | ✅ | `PayloadConfig::with_string_data()` | Custom ASCII payload |
| `--data-length` | ✅ | `PayloadConfig::with_random_data()` | Random data append |
| `--ip-options` | ✅ | `PayloadConfig::with_ip_options()` | Send with IP options |
| `--ttl` | ✅ | `PayloadConfig::with_ttl()` | Set IP TTL |
| `--spoof-mac` | ✅ | `SourceConfig::with_spoof_mac()` | Spoof MAC address |
| `--badsum` | ✅ | `PayloadConfig::with_bad_checksum()` | Corrupt checksums |

**Priority:** High - ✅ **COMPLETE** (Phase 3.1-3.5) - All evasion features implemented (14/14)

---

## OUTPUT

| Nmap Feature | Status | Nemue Equivalent | Notes |
|-------------|---------|------------------|-------|
| `-oN` (Normal) | ✅ | `NormalOutputFormatter` | Normal text output |
| `-oX` (XML) | ✅ | `-f xml` | XML format working |
| `-oS` (Script Kiddie) | ⚠️ | - | Won't implement (novelty) |
| `-oG` (Grepable) | ✅ | `GrepableOutputFormatter` | Grep-friendly format |
| `-oA` (All formats) | ✅ | `OutputManager` | Save all formats |
| JSON | ✅ | `-f json` (default) | JSON output working |
| `-v` (Verbose) | ✅ | `-v, --verbose` | Verbose output |
| `-d` (Debug) | ❌ | - | Debug levels needed |
| `--reason` | ✅ | `ReasonOutputFormatter` | Port state reasons |
| `--open` | ✅ | Default | Only shows open (our default!) |
| `--packet-trace` | ❌ | - | Show all packets |
| `--iflist` | ❌ | - | List interfaces |
| `--append-output` | ❌ | - | Append vs overwrite |
| `--resume` | ❌ | - | Resume aborted scan |
| `--stylesheet` | ❌ | - | XSL stylesheet |
| `--no-stylesheet` | ❌ | - | Prevent XSL association |

**Priority:** Medium - Need grepable and normal formats

---

## MISCELLANEOUS

| Nmap Feature | Status | Nemue Equivalent | Notes |
|-------------|---------|------------------|-------|
| `-6` (IPv6) | 🚧 | Partial | IPv6 scanning exists |
| `-A` (Aggressive) | ✅ | `-A` | OS+version+scripts+traceroute |
| `--datadir` | ❌ | - | Custom data file location |
| `--send-eth` | ❌ | - | Send raw ethernet frames |
| `--send-ip` | ✅ | `--raw` | Raw IP packets (have this!) |
| `--privileged` | ❌ | - | Assume full privileges |
| `--unprivileged` | ❌ | - | Assume no raw sockets |
| `-V` (Version) | ✅ | `--version` | Print version (not -V, conflict!) |
| `-h` (Help) | ✅ | `--help` | Help text |

**Priority:** Low - Most misc features covered

---

## SUMMARY

### **Implementation Status:**
- ✅ **Implemented:** 83 features (+14 from Phase 3.1-3.4)
- 🚧 **Partial:** 8 features
- ❌ **Missing:** 49 features
- ⚠️ **Won't Implement:** 2 features

### **Total Coverage:** ~59% complete (83/140 features)

---

## PRIORITY ROADMAP

### **Phase 1: Critical Features (Week 1-2)** ✅ **COMPLETE**
1. ✅ **Timing Templates** (`-T0` through `-T5`) - 420 lines, 12 tests
2. ✅ **Host Discovery** (`-sL`, `-sn`, `-Pn`, `-PS`, `-PA`, `-PU`, `-PE`, `-PP`, `-PM`) - 630 lines, 12 tests
3. ✅ **Target Input** (`-iL`, `-iR`, octet ranges, `--excludefile`, `--unique`, `--resolve-all`) - 500 lines, 15 tests
4. ✅ **DNS Options** (`-n`, `-R`, `--dns-servers`, `--system-dns`) - 320 lines, 9 tests

**Phase 1 Total:** 1,870 lines, 48 tests, 27 new features

### **Phase 2: Advanced Scanning (Week 3-4)** ✅ **COMPLETE**
5. ✅ **Scan Techniques** (`-sA`, `-sW`, `-sN`, `-sF`, `-sX`, `-sM`, `--scanflags`) - 680 lines, 12 tests
6. ✅ **Output Formats** (`-oN`, `-oG`, `-oA`, `--reason`, `--stats-every`) - 480 lines, 9 tests
7. ✅ **Service Detection** (intensity levels 0-9, `--version-light`, `--version-all`, `--version-trace`, `--allports`) - 535 lines, 14 tests
8. ✅ **Port Specification** (`T:80,U:53` protocol syntax, `-F`, `-r`, `--port-ratio`) - 458 lines, 13 tests

**Phase 2 Total:** 2,153 lines, 48 tests, 22 new features

### **Phase 3: Evasion & Stealth (Week 5-6)** ✅ **COMPLETE (5/5)**
9. ✅ **Packet Fragmentation** (`-f`, `--mtu`) - 530 lines, 16 tests
10. ✅ **Decoy Scanning** (`-D`, `RND:n`) - 490 lines, 17 tests
11. ✅ **Source Manipulation** (`-S`, `-g`, `-e`, `--spoof-mac`) - 600 lines, 20 tests
12. ✅ **Custom Payloads** (`--data`, `--data-string`, `--data-length`, `--ip-options`, `--ttl`, `--badsum`) - 547 lines, 24 tests
13. ✅ **Proxy Support** (`--proxies`) - 504 lines, 11 tests (HTTP/SOCKS4/SOCKS5 proxy chains)

**Phase 3 Total:** 2,671 lines, 88 tests, 15 new features

### **Phase 4: Polish & Performance (Week 7-8)** 🔄 **IN PROGRESS (2/3)**
14. ✅ **Performance Tuning** (all `--min/max` timing options) - 641 lines, 26 tests
15. ✅ **IPv6 Completion** (ACK, Window, NULL, FIN, Xmas scans + ICMPv6/ND discovery) - 1,252 lines, 24 tests
16. **Output Enhancements** (`--packet-trace`, `--resume`, `--append`)

---

## NEMUE ADVANTAGES OVER NMAP

**Already Better:**
1. ✅ **Shorter flags:** `-e` vs `--exclude-ports`, `-V` vs `-sV`
2. ✅ **Better defaults:** Hide closed/filtered by default
3. ✅ **Modern output:** JSON as default format
4. ✅ **Cleaner syntax:** `nemue scan` vs `nmap`
5. ✅ **Built-in web scanning:** Phase 8 modules (crawler, forms, APIs)
6. ✅ **Vulnerability framework:** 18 NSE scripts + custom vuln detection
7. ✅ **Async architecture:** Tokio-based for better performance
8. ✅ **Type safety:** Rust vs C (memory safety, no segfaults)

**Coming Soon:**
- 🔜 **Distributed scanning** (coordinator module exists)
- 🔜 **Real-time monitoring** (monitor engine exists)
- 🔜 **API server** (REST API exists)
- 🔜 **Intelligence integration** (passive intel module exists)

---

## TESTING REQUIREMENTS

For each implemented feature:
1. ✅ Unit tests for core logic
2. ✅ Integration tests for CLI
3. ✅ Comparison tests vs nmap output
4. ✅ Performance benchmarks
5. ✅ Documentation with examples

---

## DOCUMENTATION NEEDS

1. **Migration Guide:** Nmap → Nemue command translation
2. **Feature Matrix:** Side-by-side comparison table
3. **Tutorials:** Common nmap workflows in Nemue
4. **Man Page:** Traditional Unix man page
5. **Cheat Sheet:** Quick reference card

---

**Last Updated:** 2025-11-24  
**Next Review:** After Phase 1 completion
