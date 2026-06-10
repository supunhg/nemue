# Nemue Revival Plan: Speed First, Then MCP

**Created**: June 2026
**Priority**: Speed optimization → MCP integration → Competitive benchmarks → Release
**Status**: PLANNING COMPLETE - Ready for build mode

---

## Table of Contents

1. [Phase 0: Foundation Cleanup](#phase-0-foundation-cleanup)
2. [Phase 1: Speed Optimization](#phase-1-speed-optimization)
3. [Phase 2: MCP Server Integration](#phase-2-mcp-server-integration)
4. [Phase 3: Competitive Benchmarks](#phase-3-competitive-benchmarks)
5. [Phase 4: Feature Parity & Polish](#phase-4-feature-parity--polish)
6. [Phase 5: Release & Distribution](#phase-5-release--distribution)
7. [Bug Fixes (Critical)](#bug-fixes-critical)
8. [Architecture Decisions](#architecture-decisions)

---

## Phase 0: Foundation Cleanup

**Duration**: 1-2 days
**Goal**: Clean compilation, working CI, no technical debt

### Tasks

1. **Fix all 72 compile warnings**
   - Run `cargo build 2>&1 | grep warning` and fix each
   - Remove dead code (not suppress with `#[allow(dead_code)]`)
   - Fix unused imports, variables, mutability

2. **Remove overlapping modules**
   - `src/report/` and `src/reporting/` overlap
   - Consolidate into `src/reporting/` only
   - Delete `src/report/mod.rs` and `src/report/generator.rs`

3. **Fix ARCHITECTURE.md**
   - Currently contains roadmap content, not architecture
   - Write actual architecture documentation

4. **Add GitHub Actions CI**
   - Create `.github/workflows/ci.yml`
   - Steps: checkout, rust-toolchain, cargo fmt --check, cargo clippy -- -D warnings, cargo test, cargo bench (no runs)
   - Run on push/PR to main

5. **Commit Cargo.lock**
   - Remove from `.gitignore`
   - Required for reproducible builds

---

## Phase 1: Speed Optimization

**Duration**: 2-3 weeks
**Goal**: 10-50x faster than current, competitive with Masscan/Blackmap

### 1.1: Fix Critical Performance Bugs

**Priority**: P0 - These are blocking all other optimizations

#### Bug 1: Adaptive Rate Limiter Governor Never Updated
- **File**: `src/performance/rate_limiter.rs:20`
- **Problem**: `governor::RateLimiter` is created once with initial quota; `increase_rate()`/`decrease_rate()` update `current_rate` field but never update the governor's actual quota
- **Fix**: Recreate the governor limiter on each adjustment, OR use a custom implementation with atomic token counting
- **Impact**: Rate adaptation is completely non-functional

#### Bug 2: Buffer Pool Never Returns Buffers
- **File**: `src/performance/memory.rs:50-63`
- **Problem**: `PooledBuffer` has no `Drop` impl; `return_buffer` is private; buffers are never returned to pool
- **Fix**: Make `return_buffer` public, store `Arc<BufferPool>` in `PooledBuffer`, implement `Drop` that calls `return_buffer`
- **Impact**: Constant allocation instead of reuse; pool depletes immediately

#### Bug 3: CSV/TSV Output Broken
- **File**: `src/performance/streaming.rs:67-72`
- **Problem**: CSV and TSV match arms serialize as JSON, not delimited data
- **Fix**: Implement proper CSV/TSV serialization with `csv` crate or manual delimiter handling
- **Impact**: Output format is incorrect

### 1.2: Shared AF_PACKET Channel with BPF Filtering

**Priority**: P0 - Biggest single speed improvement

**Current Problem**:
- `tcp.rs` creates a new `pnet::datalink::channel()` per scan invocation
- Each channel is a new AF_PACKET socket
- No BPF filter applied - ALL packets processed in userspace
- `rx.next()` is blocking inside async context

**Solution**: Create a shared packet I/O layer

```
src/scanner/
├── packet_io.rs          # NEW: Shared AF_PACKET channel manager
├── bpf.rs                # NEW: BPF filter builder
└── channel_pool.rs       # NEW: Channel pool for concurrent scans
```

**Implementation**:

1. **`PacketIO` struct** - Singleton per interface
   - One AF_PACKET socket per interface, shared across all scans
   - Configurable read/write buffer sizes (default: 2MB ring)
   - BPF filter applied at kernel level

2. **BPF Filter Builder**
   - Generate BPF programs for target-specific filtering
   - Example: "tcp port 80 and dst host 10.0.0.1"
   - Reduces userspace packet processing by 90%+

3. **Async Receive Adapter**
   - Wrap pnet's blocking `rx.next()` with `tokio::task::spawn_blocking`
   - Use `tokio::sync::mpsc` to bridge blocking receive to async
   - Or use `mio` for proper epoll integration

4. **Batch Send**
   - Collect multiple SYN packets before sending
   - Use `sendmmsg()` equivalent for batch transmission
   - Target: 10K+ packets per batch

**Expected Impact**: 5-10x speed improvement from BPF + shared channels

### 1.3: Zero-Copy Packet Construction

**Priority**: P1

**Current Problem**:
- Each SYN scan allocates `vec![0u8; 40]` per packet
- Each RST allocates another `vec![0u8; 40]`
- Probes allocate `Vec<u8>` per port

**Solution**:

1. **Pre-allocated Buffer Pool**
   - Use the existing `BufferPool` from `performance/memory.rs` (after fixing Bug 2)
   - Pre-allocate 10K buffers of 64 bytes each
   - Zero-cost buffer reuse

2. **Static Probe Data**
   - UDP probes (DNS, NTP, SNMP) should be `static` references via `once_cell::sync::Lazy`
   - No allocation per port

3. **Packet Template System**
   - Pre-build packet templates per scan type
   - Only modify variable fields (src port, dst port, seq num)
   - In-place modification, no allocation

**Expected Impact**: 2-3x reduction in allocation overhead

### 1.4: Parallel Target Scanning

**Priority**: P0

**Current Problem**:
- `engine.rs:82` scans targets sequentially: `for target_ip in targets`
- 256 hosts = 256 sequential scans

**Solution**:

1. **Target-level parallelism**
   - Use `futures::stream::buffer_unordered(concurrency)`
   - Configurable target concurrency (default: number of CPU cores)

2. **Adaptive batch sizing**
   - Scan targets in batches based on network capacity
   - Monitor RTT and adjust batch size dynamically

3. **Work-stealing pool**
   - Replace current semaphore pattern with work-stealing
   - Use `tokio::task::spawn` with `JoinSet` for automatic load balancing

**Expected Impact**: 10-50x for multi-target scans (proportional to target count)

### 1.5: Integrate Existing Performance Module

**Priority**: P1

**Current Problem**: The performance module has 13 files (~2,265 lines) that are **completely unused** by the scanner engine.

**Integration Plan**:

1. **Worker Pool** (`performance/workers.rs`)
   - Replace current `Semaphore` + `tokio::spawn` pattern
   - Fix single-receiver bottleneck (currently all workers share one `mpsc::Receiver`)
   - Use per-worker channels for work-stealing

2. **Lock-Free Queue** (`performance/lockfree.rs`)
   - Use for scan task dispatch
   - Replace `Vec<JoinHandle>` collection with lock-free queue

3. **Adaptive Rate Limiter** (`performance/rate_limiter.rs`)
   - After fixing Bug 1, integrate into scan engine
   - Replace static `governor` rate limiter

4. **Buffer Pool** (`performance/memory.rs`)
   - After fixing Bug 2, use for packet construction
   - Pool size: 10K buffers for high-concurrency scans

5. **Profiler** (`performance/profiler.rs`)
   - Enable by default in debug builds
   - Add p50/p95/p99 percentile tracking
   - Use for continuous performance regression detection

### 1.6: SIMD Packet Processing (Optional, High Effort)

**Priority**: P2 - Only if phases 1.2-1.5 aren't fast enough

- Use `std::simd` (nightly) or `packed_simd` for:
  - Checksum computation (TCP/UDP)
  - Pattern matching in response parsing
  - Byte-level packet header parsing
- Target: 2x speedup for packet construction/parsing

### 1.7: io_uring Support (Optional, Very High Effort)

**Priority**: P3 - Long-term optimization

- Use `tokio-uring` or `io-uring` crate
- Register AF_PACKET sockets with io_uring
- Use `IORING_OP_SENDMSG`/`IORING_OP_RECVMSG` for batched async I/O
- Eliminates blocking `rx.next()` problem entirely
- Requires Linux 5.10+

---

## Phase 2: MCP Server Integration

**Duration**: 1-2 weeks
**Goal**: Expose Nemue as MCP server for AI tool integration

### 2.1: Add MCP SDK Dependency

```toml
# Cargo.toml additions
[dependencies]
rmcp = { version = "0.16", features = ["server"] }
```

### 2.2: Create MCP Module

```
src/mcp/
├── mod.rs          # Module exports
├── server.rs       # MCP server handler (ServerHandler impl)
├── tools.rs        # Tool definitions
├── resources.rs    # Resource definitions
└── prompts.rs      # Prompt templates
```

### 2.3: Define MCP Tools

Each tool wraps existing Nemue functionality:

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `nemue_scan` | Full port scan with service detection | target, ports, scan_type, timing, output_format |
| `nemue_quick_scan` | Fast top-ports scan | target, top_ports |
| `nemue_service_detect` | Service/version detection on specific ports | target, ports |
| `nemue_os_detect` | OS fingerprinting | target |
| `nemue_vuln_scan` | Vulnerability scanning | target, ports |
| `nemue_ssl_check` | SSL/TLS analysis | target, port |
| `nemue_fuzz` | Web content fuzzing | target, mode, wordlist |
| `nemue_traceroute` | Network path discovery | target |
| `nemue_host_discovery` | Ping sweep | target/cidr |

### 2.4: JSON Structured Output

All MCP tools return structured JSON:

```json
{
  "scan_id": "uuid",
  "target": "10.0.0.1",
  "timestamp": "2026-06-09T00:00:00Z",
  "results": {
    "open_ports": [...],
    "services": [...],
    "os_detection": {...},
    "vulnerabilities": [...]
  },
  "metadata": {
    "scan_duration_ms": 1234,
    "packets_sent": 5000,
    "packets_received": 1200
  }
}
```

### 2.5: CLI Integration

Add `nemue mcp` subcommand:

```bash
# Start MCP server over stdio (for Claude Desktop)
nemue mcp

# Start MCP server over HTTP (for remote access)
nemue mcp --transport http --port 3000
```

### 2.6: Configuration

Add to `~/.config/nemue/config.toml`:

```toml
[mcp]
enabled = true
transport = "stdio"  # or "http"
tools = ["scan", "fuzz", "ssl"]  # subset of tools to expose
max_concurrent_scans = 10
require_root = true  # for SYN scans
```

---

## Phase 3: Competitive Benchmarks

**Duration**: 1 week
**Goal**: Documented, reproducible benchmarks against ALL competitors

### 3.1: Benchmark Infrastructure

```
benches/
├── scanner_benchmarks.rs      # Existing (update)
├── speed_benchmarks.rs        # NEW: Packet rate, scan time
├── memory_benchmarks.rs       # NEW: RSS, allocation count
└── accuracy_benchmarks.rs     # NEW: Port/service detection accuracy

tests/
├── competition/
│   ├── nmap_comparison.rs     # Output parity vs Nmap
│   ├── rustscan_comparison.rs # Speed vs Rustscan
│   ├── masscan_comparison.rs  # Speed vs Masscan
│   ├── rustnmap_comparison.rs # Feature parity vs RustNmap
│   ├── blackmap_comparison.rs # Speed vs Blackmap
│   └── openorb_comparison.rs  # Speed vs OpenOrb
└── benchmarks/
    └── run_all.sh             # Benchmark runner script
```

### 3.2: Benchmark Methodology

**Test Environment** (document in BENCHMARKS.md):
- OS: Ubuntu 24.04 LTS
- CPU: 16 cores, 3.5GHz
- RAM: 32GB
- Network: 1Gbps NIC
- Kernel: 6.x

**Test Targets**:
1. `scanme.nmap.org` (45.33.32.156) - Internet host
2. Local /24 subnet (10.0.0.0/24) - LAN
3. localhost - Baseline

**Test Scenarios**:

| Scenario | Ports | Targets | Purpose |
|----------|-------|---------|---------|
| Quick scan | Top 100 | 1 | Speed baseline |
| Full scan | 65535 | 1 | Maximum coverage |
| Subnet scan | Top 1000 | 256 | Multi-target scaling |
| Service detection | Open ports | 1 | Accuracy measurement |
| Stealth scan | Top 1000 | 1 | Evasion testing |

**Metrics to Capture**:
- Time to completion (seconds)
- Packets per second (pps)
- Memory usage (peak RSS, MB)
- Accuracy (% ports detected correctly)
- Service detection accuracy (% services identified)
- Binary size (MB)

### 3.3: Comparison Targets

| Tool | Version | Language | Notes |
|------|---------|----------|-------|
| Nmap | 7.95+ | C/Lua | Gold standard |
| Rustscan | 2.x | Rust | Speed-focused |
| Masscan | 1.3+ | C | Internet-scale |
| RustNmap | 1.0.0 | Rust | 100% Nmap parity goal |
| Blackmap | 6.3.0 | Rust | 1M+ pps |
| OpenOrb | latest | Rust | AF_PACKET, NVD matching |
| Portex | latest | Go | AI-augmented |

### 3.4: Benchmark Output Format

**BENCHMARKS.md** (living document):

```markdown
# Nemue Benchmark Results

Last Updated: YYYY-MM-DD

## Executive Summary
- Nemue v0.2.0: X.XX seconds for 65K ports (X,XXX pps)
- vs Nmap: X.Xx faster
- vs Rustscan: X.Xx faster (with service detection)
- vs Masscan: X.Xx (within Y% for small targets)

## Speed Comparison
| Scanner | 65K ports | 1000 ports top | 256 hosts | pps |
|---------|-----------|----------------|-----------|-----|
| Nemue 0.2.0 | X.XXs | X.XXs | X.XXs | XXXX |
| Nmap 7.95 | X.XXs | X.XXs | X.XXs | XXXX |
| Rustscan 2.x | X.XXs | X.XXs | X.XXs | XXXX |
| Masscan 1.3 | X.XXs | X.XXs | X.XXs | XXXX |

## Accuracy Comparison
...

## Memory Usage
...

## Test Environment
...
```

### 3.5: Automated Benchmark Pipeline

Create `.github/workflows/benchmark.yml`:
- Run on schedule (weekly) or manual trigger
- Run all comparison tests
- Generate BENCHMARKS.md diff
- Post results as PR comment
- Track regression over time

---

## Phase 4: Feature Parity & Polish

**Duration**: 1-2 weeks
**Goal**: Close remaining gaps with Nmap

### 4.1: Missing Nmap Features

| Feature | Priority | Effort | Impact |
|---------|----------|--------|--------|
| Idle scan (IPID zombie) | P1 | High | Stealth capability |
| FTP bounce scan | P2 | Medium | Legacy network support |
| Full IPv6 OS fingerprinting | P1 | Medium | IPv6 parity |
| CPE generation | P2 | Low | Standardized identification |

### 4.2: Configuration File Support

**File**: `~/.config/nemue/config.toml`

```toml
[scan]
default_timing = "T4"
default_scan_type = "syn"
max_concurrent_ports = 1000
max_concurrent_targets = 16
timeout_ms = 1000
retries = 2

[detection]
service_detection = true
os_fingerprinting = true
version_detection = true
script_scanning = false

[output]
default_format = "json"
color = true
progress_bars = true

[mcp]
enabled = false
transport = "stdio"

[performance]
use_raw_sockets = true
buffer_pool_size = 10000
adaptive_rate = true
```

### 4.3: Fix Overlapping Modules

- Merge `src/report/` into `src/reporting/`
- Update all imports
- Delete redundant code

### 4.4: Code Quality

- Run `cargo clippy -- -D warnings`
- Run `cargo fmt`
- Add `rustfmt.toml` with project style
- Add `clippy.toml` with pedantic lints

---

## Phase 5: Release & Distribution

**Duration**: 3-5 days
**Goal**: GitHub release with pre-built binaries

### 5.1: Version Bump

- Update `Cargo.toml` version to `0.2.0`
- Update CHANGELOG.md

### 5.2: GitHub Release Workflow

Create `.github/workflows/release.yml`:
- Trigger on tag push (`v*`)
- Build matrix:
  - Linux x86_64 (ubuntu-latest)
  - Linux aarch64 (ubuntu-latest, cross-compile)
  - macOS x86_64 (macos-latest)
  - macOS aarch64 (macos-latest)
  - Windows x86_64 (windows-latest)
- Build release binary with `cargo build --release`
- Strip debug symbols
- Create GitHub release with binaries attached
- Generate checksums (SHA256)

### 5.3: Binary Naming

```
nemue-{version}-{target}.tar.gz
├── nemue                          # Linux/macOS binary
├── nemue.exe                      # Windows binary
├── README.md
└── LICENSE
```

Targets:
- `nemue-0.2.0-x86_64-unknown-linux-gnu.tar.gz`
- `nemue-0.2.0-aarch64-unknown-linux-gnu.tar.gz`
- `nemue-0.2.0-x86_64-apple-darwin.tar.gz`
- `nemue-0.2.0-aarch64-apple-darwin.tar.gz`
- `nemue-0.2.0-x86_64-pc-windows-msvc.zip`

### 5.4: Documentation

- Update README.md with:
  - MCP integration guide
  - Benchmark results summary
  - Download links
- Update USAGE.md with MCP examples
- Create CHEATSHEET.md (quick reference)

---

## Bug Fixes (Critical)

These must be fixed before any speed work:

| Bug | File:Line | Problem | Fix |
|-----|-----------|---------|-----|
| Rate limiter governor never updated | `performance/rate_limiter.rs:20` | Adjustments don't affect actual limiting | Recreate governor on adjustment |
| Buffer pool never returns | `performance/memory.rs:50-63` | No Drop impl, private return_buffer | Add Drop, store pool ref |
| CSV/TSV output broken | `performance/streaming.rs:67-72` | Writes JSON not CSV/TSV | Implement proper serialization |
| Blocking rx.next() in async | `protocols/tcp.rs:78-137` | Blocks Tokio worker thread | spawn_blocking or mio adapter |
| Sequential target scanning | `scanner/engine.rs:82` | Targets scanned one at a time | buffer_unordered parallelism |

---

## Architecture Decisions

### 1. Why AF_PACKET over pnet?

pnet uses AF_PACKET internally but:
- No BPF filter support exposed
- No batch send/receive
- No mmap ring buffer
- Blocking receive

Direct AF_PACKET gives:
- Kernel-level packet filtering (BPF)
- mmap zero-copy ring buffers
- sendmmsg/recvmmsg batch operations
- Proper async integration via mio/io_uring

**Decision**: Keep pnet for packet construction, use raw AF_PACKET for I/O.

### 2. Why stdio MCP only initially?

- Streamable HTTP adds complexity (auth, CORS, session management)
- stdio covers Claude Desktop, Cursor, VS Code
- Can add HTTP transport later without breaking changes
- Focus on tool quality, not transport complexity

### 3. Why GitHub-only release?

- crates.io requires API review and documentation standards
- Faster iteration cycle
- Can publish later once stable
- GitHub releases are sufficient for user adoption

### 4. Why pre-built binaries for all platforms?

- Rust cross-compilation is well-supported
- Users shouldn't need Rust toolchain
- Binary distribution is standard for security tools (nmap, masscan)
- Covers developer and operator use cases

---

## Execution Order

```
Phase 0 (Days 1-2)
  ├── Fix compile warnings
  ├── Remove overlapping modules
  ├── Fix ARCHITECTURE.md
  ├── Add CI workflow
  └── Commit Cargo.lock

Phase 1 (Days 3-21)
  ├── 1.1 Fix critical bugs (Days 3-5)
  ├── 1.2 Shared AF_PACKET + BPF (Days 6-10)
  ├── 1.4 Parallel target scanning (Days 11-13)
  ├── 1.3 Zero-copy packets (Days 14-16)
  ├── 1.5 Integrate performance module (Days 17-19)
  └── 1.6 SIMD (optional, Days 20-21)

Phase 2 (Days 22-35)
  ├── 2.1 Add rmcp dependency
  ├── 2.2 Create MCP module
  ├── 2.3 Define tools
  ├── 2.4 JSON output
  ├── 2.5 CLI integration
  └── 2.6 Configuration

Phase 3 (Days 36-42)
  ├── 3.1 Benchmark infrastructure
  ├── 3.2 Run all comparisons
  ├── 3.3 Document results
  └── 3.4 Automated pipeline

Phase 4 (Days 43-56)
  ├── 4.1 Missing features
  ├── 4.2 Config file support
  ├── 4.3 Module cleanup
  └── 4.4 Code quality

Phase 5 (Days 57-61)
  ├── 5.1 Version bump
  ├── 5.2 Release workflow
  ├── 5.3 Binary naming
  └── 5.4 Documentation
```

---

## Success Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Scan speed (65K ports) | < 5 seconds | ~20 seconds |
| Packets per second | 50K+ pps | ~1K pps |
| Memory usage | < 100MB | Unknown |
| Nmap feature parity | 85%+ | 79% |
| MCP tools | 9 tools | 0 |
| Compile warnings | 0 | 72 |
| CI/CD | Yes | No |
| Benchmark docs | Living BENCHMARKS.md | None |
| Release binaries | 5 targets | 0 |
| Tests passing | 100% | Claimed 100% |

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| AF_PACKET requires root | Users need sudo | Implement fallback to connect scan |
| io_uring Linux-only | No macOS/Windows | Make optional feature flag |
| MCP SDK breaking changes | Version drift | Pin rmcp version, test upgrades |
| Benchmark environment variance | Inconsistent results | Docker containerization |
| Cross-compilation issues | Binary builds fail | Use GitHub Actions matrix |

---

**PLAN COMPLETE - Ready for build mode execution.**
