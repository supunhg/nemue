#!/usr/bin/env bash
# Nemue Benchmark Runner
# Runs all benchmarks, compares with previous results, and generates reports.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BENCH_DIR="$PROJECT_DIR/target/criterion"
RESULTS_DIR="$PROJECT_DIR/benchmark-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$RESULTS_DIR/benchmark_report_${TIMESTAMP}.md"
COMPARISON_FILE="$RESULTS_DIR/comparison_${TIMESTAMP}.md"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_header() {
    echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}\n"
}

# Ensure results directory exists
mkdir -p "$RESULTS_DIR"

# Parse command line arguments
FILTER=""
SAVE_BASELINE=false
COMPARE_WITH=""
QUICK=false
NO_HTML=false
BENCH_NAME="scanner_benchmarks"

while [[ $# -gt 0 ]]; do
    case $1 in
        --filter)
            FILTER="$2"
            shift 2
            ;;
        --save-baseline)
            SAVE_BASELINE=true
            shift
            ;;
        --compare-with)
            COMPARE_WITH="$2"
            shift 2
            ;;
        --quick)
            QUICK=true
            shift
            ;;
        --no-html)
            NO_HTML=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --filter PATTERN    Only run benchmarks matching PATTERN"
            echo "  --save-baseline     Save results as baseline for future comparisons"
            echo "  --compare-with DIR  Compare with a previous criterion baseline directory"
            echo "  --quick             Run benchmarks with fewer samples (faster)"
            echo "  --no-html           Skip HTML report generation"
            echo "  --help              Show this help message"
            echo ""
            echo "Benchmark Groups:"
            echo "  port_parsing         Port string parsing (single, range, mixed, presets, protocol)"
            echo "  target_parsing       Target string parsing (IP, CIDR, IPv6, hostname, octet range)"
            echo "  target_scaling       CIDR range scaling benchmarks"
            echo "  timing               Timing template operations"
            echo "  script_args          Lua script argument parsing"
            echo "  string_ops           IP address and string parsing"
            echo "  allocations          Memory allocation patterns"
            echo "  port_range_scaling   Port count scaling (10 to 10000)"
            echo "  cidr_scaling         CIDR range scaling (/30 to /22)"
            echo "  service_detection    Service detection (banner, port-based, family, OS hints)"
            echo "  enhanced_detection   Enhanced multi-probe service detection"
            echo "  probe_database       Probe database operations"
            echo "  signatures           Signature loading and regex matching"
            echo "  os_fingerprinting    OS fingerprinting (TTL, TCP, banner, passive)"
            echo "  vuln_scanning        Vulnerability scanning (creds, exploits, severity)"
            echo "  report_generation    Report generation (JSON, text, CSV, XML, Markdown)"
            echo "  pdf_generation       PDF report generation"
            echo "  scan_history         Scan history (add, lookup, serialize, summary)"
            echo "  trend_analysis       Trend analysis with snapshots"
            echo "  intensity_levels     Intensity level operations"
            echo "  performance          Lock-free queues, metrics, atomic operations"
            echo "  scan_diff            Scan comparison/diff operations"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Build the benchmark command
BENCH_CMD="cargo bench --bench $BENCH_NAME"

if [[ -n "$FILTER" ]]; then
    BENCH_CMD="$BENCH_CMD -- $FILTER"
fi

if [[ "$QUICK" == true ]]; then
    if [[ -n "$FILTER" ]]; then
        BENCH_CMD="$BENCH_CMD --quick"
    else
        BENCH_CMD="$BENCH_CMD -- --quick"
    fi
fi

# Print header
log_header "Nemue Benchmark Suite"
echo -e "  Timestamp:  ${TIMESTAMP}"
echo -e "  Filter:     ${FILTER:-none}"
echo -e "  Quick mode: ${QUICK}"
echo -e "  HTML:       ${NO_HTML:+disabled}${NO_HTML:-enabled}"
echo ""

# Compile check first
log_info "Verifying benchmarks compile..."
if ! cargo bench --bench "$BENCH_NAME" --no-run 2>&1 | tail -5; then
    log_error "Benchmarks failed to compile!"
    exit 1
fi
log_success "Compilation OK"
echo ""

# Run benchmarks
log_header "Running Benchmarks"
log_info "Command: $BENCH_CMD"

BENCH_START=$(date +%s)

if eval "$BENCH_CMD" 2>&1; then
    BENCH_END=$(date +%s)
    BENCH_DURATION=$((BENCH_END - BENCH_START))
    log_success "Benchmarks completed in ${BENCH_DURATION}s"
else
    log_error "Benchmarks failed!"
    exit 1
fi

echo ""

# Generate summary report
log_header "Generating Report"

cat > "$REPORT_FILE" << EOF
# Nemue Benchmark Report

**Generated**: $(date '+%Y-%m-%d %H:%M:%S %Z')
**Duration**: ${BENCH_DURATION}s
**Filter**: ${FILTER:-none}
**Quick mode**: ${QUICK}

## Benchmark Groups

The following benchmark groups were executed:

### Core Scanning
| Group | Description | Priority |
|-------|-------------|----------|
| \`port_parsing\` | Port string parsing (single, range, mixed, presets, protocol spec, error handling) | High |
| \`target_parsing\` | Target string parsing (IP, CIDR, IPv6, hostname, octet ranges) | High |
| \`target_scaling\` | CIDR range scaling (/30 to /24) | High |
| \`timing\` | Timing template operations | Medium |
| \`script_args\` | Lua script argument parsing | Medium |
| \`string_ops\` | IP address and string parsing | Low |
| \`allocations\` | Memory allocation patterns | Medium |
| \`port_range_scaling\` | Port count scaling (10 to 10000) | High |
| \`cidr_scaling\` | CIDR range scaling (/30 to /22) | High |

### Service Detection (Competitive Advantage)
| Group | Description | Priority |
|-------|-------------|----------|
| \`service_detection\` | Banner analysis, port-based detection, family/OS hints, CPE generation | **Critical** |
| \`enhanced_detection\` | Multi-probe detection with protocol parsers | **Critical** |
| \`probe_database\` | Probe loading and intensity filtering | High |
| \`signatures\` | Signature loading and regex matching (200+ signatures) | **Critical** |

### OS Fingerprinting (Competitive Advantage)
| Group | Description | Priority |
|-------|-------------|----------|
| \`os_fingerprinting\` | TTL analysis, TCP stack, banner-based, passive detection | **Critical** |

### Vulnerability Scanning
| Group | Description | Priority |
|-------|-------------|----------|
| \`vuln_scanning\` | Default credentials, exploit DB, script matching, severity, categories | High |

### Report Generation
| Group | Description | Priority |
|-------|-------------|----------|
| \`report_generation\` | JSON, text, CSV, XML, Markdown (+ large report variants) | High |
| \`pdf_generation\` | PDF report generation (standard + large) | Medium |

### History & Trends
| Group | Description | Priority |
|-------|-------------|----------|
| \`scan_history\` | History CRUD, serialization, summary generation | High |
| \`trend_analysis\` | Trend analysis with snapshots and reporting | Medium |
| \`intensity_levels\` | Intensity level operations and filtering | Medium |

### Performance Infrastructure
| Group | Description | Priority |
|-------|-------------|----------|
| \`performance\` | Lock-free queues, bounded queues, atomic flags, metrics collector | High |
| \`scan_diff\` | Scan comparison/diff operations | High |

## Results

Full benchmark results are available in:
- **Criterion HTML**: \`target/criterion/report/index.html\`
- **Raw data**: \`target/criterion/\`

## Key Metrics (Competitive Advantage)

1. **service_detection** - Banner analysis with 200+ regex signatures
2. **os_fingerprinting** - TTL + TCP stack + banner + passive detection
3. **signatures** - Regex matching performance across 200+ patterns
4. **performance** - Lock-free data structures for concurrent scanning
5. **report_generation** - Multi-format output including PDF and Markdown

## Optimization Notes

- Service detection banner analysis targets <500ns per banner
- OS fingerprinting TTL check targets <10ns
- Signature regex matching targets <100ns per pattern
- Lock-free queue push/pop targets <50ns
- Report generation scales linearly with findings count
EOF

log_success "Report saved to: $REPORT_FILE"

# Compare with previous results if available
LATEST_BASELINE="$RESULTS_DIR/latest-baseline"
if [[ -d "$LATEST_BASELINE" ]] && [[ "$SAVE_BASELINE" != true ]]; then
    log_header "Comparison"
    log_info "Previous baseline found at: $LATEST_BASELINE"
    echo "  Use 'cargo bench' output above for detailed comparison."
    echo "  Look for 'change' columns in the Criterion output."
    echo ""
    echo "  To compare manually:"
    echo "    open target/criterion/report/index.html"
elif [[ -n "$COMPARE_WITH" ]] && [[ -d "$COMPARE_WITH" ]]; then
    log_header "Comparison"
    log_info "Comparing with: $COMPARE_WITH"
    echo "  Use Criterion HTML report for detailed comparison."
fi

# Save baseline if requested
if [[ "$SAVE_BASELINE" == true ]]; then
    log_header "Saving Baseline"
    log_info "Saving current results as baseline..."
    rm -rf "$LATEST_BASELINE"
    cp -r "$BENCH_DIR" "$LATEST_BASELINE"
    log_success "Baseline saved to: $LATEST_BASELINE"
fi

# Performance tracking
PERF_LOG="$RESULTS_DIR/performance_log.csv"
if [[ ! -f "$PERF_LOG" ]]; then
    echo "timestamp,duration_s,filter,groups" > "$PERF_LOG"
fi
echo "${TIMESTAMP},${BENCH_DURATION},${FILTER:-all},$(echo port_parsing,target_parsing,service_detection,os_fingerprinting,vuln_scanning,report_generation,performance)" >> "$PERF_LOG"

# Summary
log_header "Summary"
echo -e "  Duration:    ${BENCH_DURATION}s"
echo -e "  Report:      ${REPORT_FILE}"
echo -e "  HTML:        target/criterion/report/index.html"
echo -e "  Perf log:    ${PERF_LOG}"
echo ""
echo "Next steps:"
echo "  1. View HTML report:  open target/criterion/report/index.html"
echo "  2. Save as baseline:  $0 --save-baseline"
echo "  3. Quick re-run:      $0 --quick --filter service_detection"
echo "  4. Compare results:   $0 --compare-with benchmark-results/latest-baseline"
echo ""
log_success "All done!"
