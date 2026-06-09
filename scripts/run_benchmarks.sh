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

# Ensure results directory exists
mkdir -p "$RESULTS_DIR"

# Parse command line arguments
FILTER=""
SAVE_BASELINE=false
COMPARE_WITH=""
QUICK=false
NO_HTML=false

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
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Build the benchmark command
BENCH_CMD="cargo bench --bench scanner_benchmarks"

if [[ -n "$FILTER" ]]; then
    BENCH_CMD="$BENCH_CMD -- $FILTER"
fi

if [[ "$QUICK" == true ]]; then
    BENCH_CMD="$BENCH_CMD -- --quick"
fi

# Run benchmarks
log_info "Running benchmarks..."
log_info "Command: $BENCH_CMD"
echo ""

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
log_info "Generating benchmark report..."

cat > "$REPORT_FILE" << EOF
# Nemue Benchmark Report

**Generated**: $(date '+%Y-%m-%d %H:%M:%S %Z')
**Duration**: ${BENCH_DURATION}s
**Filter**: ${FILTER:-none}
**Quick mode**: ${QUICK}

## Benchmark Groups

The following benchmark groups were executed:

| Group | Description |
|-------|-------------|
| \`port_parsing\` | Port string parsing (single, range, mixed, presets) |
| \`target_parsing\` | Target string parsing (IP, CIDR, IPv6, hostname) |
| \`timing\` | Timing template operations |
| \`script_args\` | Lua script argument parsing |
| \`string_ops\` | IP address and string parsing |
| \`allocations\` | Memory allocation patterns |
| \`port_range_scaling\` | Port count scaling (10 to 10000) |
| \`cidr_scaling\` | CIDR range scaling (/30 to /22) |
| \`service_detection\` | **Service detection (banner analysis, port-based, version extraction)** |
| \`enhanced_detection\` | Enhanced multi-probe service detection |
| \`probe_database\` | Probe database operations |
| \`signatures\` | Signature loading and regex matching |
| \`os_fingerprinting\` | **OS fingerprinting (TTL, TCP stack, multi-probe)** |
| \`vuln_scanning\` | Vulnerability scanning (credentials, script matching, severity) |
| \`report_generation\` | Report generation (JSON, text, CSV, XML) |
| \`pdf_generation\` | PDF report generation |
| \`scan_history\` | Scan history (add, lookup, serialize, summary) |
| \`trend_analysis\` | Trend analysis (snapshots, analysis, reporting) |
| \`intensity_levels\` | Intensity level operations |

## Results

Full benchmark results are available in:
- **Criterion HTML**: \`target/criterion/report/index.html\`
- **Raw data**: \`target/criterion/\`

## Key Metrics to Watch

1. **service_detection** - Core competitive differentiator vs Nmap
2. **os_fingerprinting** - Critical for accuracy comparison
3. **signatures** - Regex matching performance with 200+ signatures
4. **report_generation** - User-facing output performance
5. **scan_history** - History management for large scan datasets

## Optimization Notes

- Service detection should stay under 1µs for banner analysis
- OS fingerprinting should stay under 500ns for simple detection
- Signature loading is O(n) but only runs once at initialization
- Report generation scales linearly with findings count
EOF

log_success "Report saved to: $REPORT_FILE"

# Compare with previous results if available
LATEST_BASELINE="$RESULTS_DIR/latest-baseline"
if [[ -d "$LATEST_BASELINE" ]] && [[ "$SAVE_BASELINE" != true ]]; then
    log_info "Previous baseline found. Comparison notes:"
    echo "  Baseline: $LATEST_BASELINE"
    echo "  Current:  $BENCH_DIR"
    echo ""
    echo "  Use 'cargo bench' output above for detailed comparison."
    echo "  Look for 'change' columns in the Criterion output."
elif [[ -n "$COMPARE_WITH" ]] && [[ -d "$COMPARE_WITH" ]]; then
    log_info "Comparing with: $COMPARE_WITH"
    echo "  Use Criterion HTML report for detailed comparison."
fi

# Save baseline if requested
if [[ "$SAVE_BASELINE" == true ]]; then
    log_info "Saving current results as baseline..."
    rm -rf "$LATEST_BASELINE"
    cp -r "$BENCH_DIR" "$LATEST_BASELINE"
    log_success "Baseline saved to: $LATEST_BASELINE"
fi

# Performance tracking
PERF_LOG="$RESULTS_DIR/performance_log.csv"
if [[ ! -f "$PERF_LOG" ]]; then
    echo "timestamp,duration_s,filter" > "$PERF_LOG"
fi
echo "${TIMESTAMP},${BENCH_DURATION},${FILTER:-all}" >> "$PERF_LOG"

echo ""
log_success "All done!"
echo ""
echo "Next steps:"
echo "  1. View HTML report:  open target/criterion/report/index.html"
echo "  2. Save as baseline:  $0 --save-baseline"
echo "  3. Quick re-run:      $0 --quick --filter service_detection"
