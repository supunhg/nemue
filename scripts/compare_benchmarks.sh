#!/usr/bin/env bash
# Nemue Benchmark Comparison Tool
# Compares current benchmark results with previous baselines and tracks performance over time.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BENCH_DIR="$PROJECT_DIR/target/criterion"
RESULTS_DIR="$PROJECT_DIR/benchmark-results"
BASELINE_DIR="$RESULTS_DIR/baselines"
PERF_LOG="$RESULTS_DIR/performance_log.csv"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$RESULTS_DIR/comparison_report_${TIMESTAMP}.md"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_header() { echo -e "\n${BOLD}${CYAN}━━━ $1 ━━━${NC}\n"; }

usage() {
    cat << 'USAGE'
Nemue Benchmark Comparison Tool

Usage:
  compare_benchmarks.sh [OPTIONS]

Options:
  --run                Run benchmarks before comparing
  --baseline NAME      Compare against specific baseline (default: latest)
  --save NAME          Save current results as named baseline
  --list               List all saved baselines
  --delete NAME        Delete a saved baseline
  --trend              Show performance trend over time
  --threshold PCT      Regression threshold percentage (default: 5.0)
  --group GROUP        Filter to specific benchmark group
  --csv                Output comparison as CSV
  --help               Show this help message

Examples:
  compare_benchmarks.sh --run --save v0.2.1
  compare_benchmarks.sh --baseline v0.2.0 --group service_detection
  compare_benchmarks.sh --trend
  compare_benchmarks.sh --list
USAGE
}

# Parse arguments
RUN_BENCH=false
BASELINE_NAME="latest"
SAVE_NAME=""
LIST_BASELINES=false
DELETE_NAME=""
SHOW_TREND=false
THRESHOLD=5.0
FILTER_GROUP=""
OUTPUT_CSV=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --run) RUN_BENCH=true; shift ;;
        --baseline) BASELINE_NAME="$2"; shift 2 ;;
        --save) SAVE_NAME="$2"; shift 2 ;;
        --list) LIST_BASELINES=true; shift ;;
        --delete) DELETE_NAME="$2"; shift 2 ;;
        --trend) SHOW_TREND=true; shift ;;
        --threshold) THRESHOLD="$2"; shift 2 ;;
        --group) FILTER_GROUP="$2"; shift 2 ;;
        --csv) OUTPUT_CSV=true; shift ;;
        --help) usage; exit 0 ;;
        *) log_error "Unknown option: $1"; usage; exit 1 ;;
    esac
done

mkdir -p "$RESULTS_DIR" "$BASELINE_DIR"

# ─── List baselines ──────────────────────────────────────────────────────────
if [[ "$LIST_BASELINES" == true ]]; then
    log_header "Saved Baselines"
    if [[ -d "$BASELINE_DIR" ]] && [[ -n "$(ls -A "$BASELINE_DIR" 2>/dev/null)" ]]; then
        for dir in "$BASELINE_DIR"/*/; do
            name=$(basename "$dir")
            size=$(du -sh "$dir" 2>/dev/null | cut -f1)
            date=$(stat -c '%y' "$dir" 2>/dev/null | cut -d' ' -f1)
            echo -e "  ${BOLD}$name${NC}  ($size, $date)"
        done
    else
        echo -e "  ${DIM}No saved baselines.${NC}"
        echo -e "  ${DIM}Run: $0 --run --save <name>${NC}"
    fi
    echo ""
    exit 0
fi

# ─── Delete baseline ─────────────────────────────────────────────────────────
if [[ -n "$DELETE_NAME" ]]; then
    if [[ -d "$BASELINE_DIR/$DELETE_NAME" ]]; then
        rm -rf "$BASELINE_DIR/$DELETE_NAME"
        log_success "Deleted baseline: $DELETE_NAME"
    else
        log_error "Baseline not found: $DELETE_NAME"
        exit 1
    fi
    exit 0
fi

# ─── Show performance trend ──────────────────────────────────────────────────
if [[ "$SHOW_TREND" == true ]]; then
    log_header "Performance Trend"
    if [[ ! -f "$PERF_LOG" ]]; then
        log_warn "No performance history found. Run benchmarks first."
        exit 0
    fi

    echo -e "${BOLD}Timestamp            Duration  Filter${NC}"
    echo "─────────────────────────────────────────────"
    tail -20 "$PERF_LOG" | while IFS=',' read -r ts dur filter groups; do
        printf "%-20s %7ss  %s\n" "$ts" "$dur" "$filter"
    done
    echo ""

    # Show trend summary
    TOTAL_RUNS=$(tail -n +2 "$PERF_LOG" | wc -l)
    if [[ "$TOTAL_RUNS" -gt 1 ]]; then
        AVG_DURATION=$(tail -n +2 "$PERF_LOG" | awk -F',' '{sum+=$2; n++} END {printf "%.0f", sum/n}')
        LAST_DURATION=$(tail -1 "$PERF_LOG" | cut -d',' -f2)
        echo -e "  Total runs:  $TOTAL_RUNS"
        echo -e "  Avg duration: ${AVG_DURATION}s"
        echo -e "  Last duration: ${LAST_DURATION}s"
    fi
    echo ""
    exit 0
fi

# ─── Run benchmarks if requested ─────────────────────────────────────────────
if [[ "$RUN_BENCH" == true ]]; then
    log_header "Running Benchmarks"
    BENCH_CMD="cargo bench --bench scanner_benchmarks"
    if [[ -n "$FILTER_GROUP" ]]; then
        BENCH_CMD="$BENCH_CMD -- $FILTER_GROUP"
    fi
    log_info "Command: $BENCH_CMD"

    BENCH_START=$(date +%s)
    eval "$BENCH_CMD" 2>&1
    BENCH_END=$(date +%s)
    BENCH_DURATION=$((BENCH_END - BENCH_START))
    log_success "Completed in ${BENCH_DURATION}s"

    # Log to performance history
    if [[ ! -f "$PERF_LOG" ]]; then
        echo "timestamp,duration_s,filter,groups" > "$PERF_LOG"
    fi
    echo "${TIMESTAMP},${BENCH_DURATION},${FILTER_GROUP:-all},scanner_benchmarks" >> "$PERF_LOG"
    echo ""
fi

# ─── Save baseline ───────────────────────────────────────────────────────────
if [[ -n "$SAVE_NAME" ]]; then
    SAVE_DIR="$BASELINE_DIR/$SAVE_NAME"
    if [[ -d "$BENCH_DIR" ]]; then
        log_info "Saving baseline as: $SAVE_NAME"
        rm -rf "$SAVE_DIR"
        cp -r "$BENCH_DIR" "$SAVE_DIR"
        log_success "Baseline saved to: $SAVE_DIR"
    else
        log_error "No benchmark results found. Run benchmarks first: $0 --run"
        exit 1
    fi
    exit 0
fi

# ─── Compare with baseline ───────────────────────────────────────────────────
log_header "Benchmark Comparison"

# Resolve baseline path
if [[ "$BASELINE_NAME" == "latest" ]]; then
    if [[ -d "$BASELINE_DIR/latest" ]]; then
        BASELINE_PATH="$BASELINE_DIR/latest"
    elif [[ -d "$PROJECT_DIR/benchmark-results/latest-baseline" ]]; then
        BASELINE_PATH="$PROJECT_DIR/benchmark-results/latest-baseline"
    else
        log_error "No baseline found. Save one first: $0 --run --save <name>"
        exit 1
    fi
else
    BASELINE_PATH="$BASELINE_DIR/$BASELINE_NAME"
fi

if [[ ! -d "$BASELINE_PATH" ]]; then
    log_error "Baseline not found: $BASELINE_PATH"
    exit 1
fi

if [[ ! -d "$BENCH_DIR" ]]; then
    log_error "No current results. Run benchmarks first: $0 --run"
    exit 1
fi

log_info "Baseline: $BASELINE_PATH"
log_info "Current:  $BENCH_DIR"
log_info "Threshold: ${THRESHOLD}%"
echo ""

# Parse Criterion estimates files and compare
BENCHMARK_GROUPS=(
    "port_parsing"
    "target_parsing"
    "target_scaling"
    "timing"
    "script_args"
    "string_ops"
    "allocations"
    "port_range_scaling"
    "cidr_scaling"
    "service_detection"
    "enhanced_detection"
    "probe_database"
    "signatures"
    "os_fingerprinting"
    "vuln_scanning"
    "report_generation"
    "pdf_generation"
    "scan_history"
    "trend_analysis"
    "intensity_levels"
    "performance"
    "scan_diff"
)

REGRESSIONS=0
IMPROVEMENTS=0
STABLE=0
TOTAL=0

if [[ "$OUTPUT_CSV" == true ]]; then
    echo "group,benchmark,baseline_ns,current_ns,change_pct,status"
fi

for group in "${BENCHMARK_GROUPS[@]}"; do
    if [[ -n "$FILTER_GROUP" && "$group" != *"$FILTER_GROUP"* ]]; then
        continue
    fi

    GROUP_BASE="$BASELINE_PATH/$group"
    GROUP_CURR="$BENCH_DIR/$group"

    if [[ ! -d "$GROUP_BASE" ]] || [[ ! -d "$GROUP_CURR" ]]; then
        continue
    fi

    GROUP_HEADER_PRINTED=false

    for bench_dir in "$GROUP_CURR"/*/; do
        [[ ! -d "$bench_dir" ]] && continue
        bench_name=$(basename "$bench_dir")
        [[ "$bench_name" == "report" ]] && continue

        CURR_EST="$bench_dir/new/estimates.json"
        BASE_EST="$GROUP_BASE/$bench_name/new/estimates.json"

        if [[ ! -f "$CURR_EST" ]] || [[ ! -f "$BASE_EST" ]]; then
            continue
        fi

        # Extract mean from estimates.json (Criterion format)
        CURR_MEAN=$(python3 -c "
import json, sys
try:
    with open('$CURR_EST') as f:
        d = json.load(f)
    print(d.get('mean', {}).get('point_estimate', 0))
except:
    print(0)
" 2>/dev/null)

        BASE_MEAN=$(python3 -c "
import json, sys
try:
    with open('$BASE_EST') as f:
        d = json.load(f)
    print(d.get('mean', {}).get('point_estimate', 0))
except:
    print(0)
" 2>/dev/null)

        [[ "$CURR_MEAN" == "0" || "$BASE_MEAN" == "0" ]] && continue

        # Calculate change percentage
        CHANGE=$(python3 -c "
curr = float('$CURR_MEAN')
base = float('$BASE_MEAN')
if base > 0:
    pct = ((curr - base) / base) * 100
    print(f'{pct:.1f}')
else:
    print('0.0')
" 2>/dev/null)

        TOTAL=$((TOTAL + 1))

        # Determine status
        STATUS="stable"
        ABS_CHANGE=$(python3 -c "print(abs(float('$CHANGE')))" 2>/dev/null)
        if python3 -c "exit(0 if float('$ABS_CHANGE') > float('$THRESHOLD') else 1)" 2>/dev/null; then
            if python3 -c "exit(0 if float('$CHANGE') > 0 else 1)" 2>/dev/null; then
                STATUS="REGRESSION"
                REGRESSIONS=$((REGRESSIONS + 1))
            else
                STATUS="IMPROVEMENT"
                IMPROVEMENTS=$((IMPROVEMENTS + 1))
            fi
        else
            STABLE=$((STABLE + 1))
        fi

        if [[ "$OUTPUT_CSV" == true ]]; then
            echo "$group,$bench_name,$BASE_MEAN,$CURR_MEAN,$CHANGE,$STATUS"
        else
            # Format output
            if [[ "$GROUP_HEADER_PRINTED" == false ]]; then
                echo -e "${BOLD}[$group]${NC}"
                GROUP_HEADER_PRINTED=true
            fi

            CURR_FMT=$(python3 -c "
ns = float('$CURR_MEAN')
if ns < 1000: print(f'{ns:.0f}ns')
elif ns < 1000000: print(f'{ns/1000:.1f}µs')
elif ns < 1000000000: print(f'{ns/1000000:.1f}ms')
else: print(f'{ns/1000000000:.1f}s')
" 2>/dev/null)

            BASE_FMT=$(python3 -c "
ns = float('$BASE_MEAN')
if ns < 1000: print(f'{ns:.0f}ns')
elif ns < 1000000: print(f'{ns/1000:.1f}µs')
elif ns < 1000000000: print(f'{ns/1000000:.1f}ms')
else: print(f'{ns/1000000000:.1f}s')
" 2>/dev/null)

            CHANGE_STR=$(python3 -c "
c = float('$CHANGE')
print(f'+{c:.1f}%' if c >= 0 else f'{c:.1f}%')
" 2>/dev/null)

            case "$STATUS" in
                REGRESSION)  STATUS_COLOR="$RED" ;;
                IMPROVEMENT) STATUS_COLOR="$GREEN" ;;
                *)           STATUS_COLOR="$DIM" ;;
            esac

            printf "  %-30s  %10s → %10s  ${STATUS_COLOR}%+7s  %s${NC}\n" \
                "$bench_name" "$BASE_FMT" "$CURR_FMT" "$CHANGE_STR" "$STATUS"
        fi
    done
done

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
log_header "Summary"
echo -e "  Total benchmarks compared:  ${BOLD}$TOTAL${NC}"
echo -e "  ${GREEN}Improvements:${NC}              $IMPROVEMENTS"
echo -e "  ${RED}Regressions:${NC}               $REGRESSIONS"
echo -e "  ${DIM}Stable:${NC}                    $STABLE"

if [[ "$REGRESSIONS" -gt 0 ]]; then
    echo ""
    log_warn "Found $REGRESSIONS regression(s) above ${THRESHOLD}% threshold!"
fi

# ─── Save comparison report ──────────────────────────────────────────────────
cat > "$REPORT_FILE" << EOF
# Benchmark Comparison Report

**Generated**: $(date '+%Y-%m-%d %H:%M:%S %Z')
**Baseline**: $BASELINE_NAME
**Threshold**: ${THRESHOLD}%

## Summary

| Metric | Count |
|--------|-------|
| Total compared | $TOTAL |
| Improvements | $IMPROVEMENTS |
| Regressions | $REGRESSIONS |
| Stable | $STABLE |

## How to Interpret

- **IMPROVEMENT**: Current is faster than baseline (lower is better)
- **REGRESSION**: Current is slower than baseline (exceeds ${THRESHOLD}% threshold)
- **STABLE**: Within ±${THRESHOLD}% of baseline

## Methodology

Comparisons use Criterion's mean point estimate from bootstrap analysis.
Each benchmark runs multiple iterations with statistical outlier removal.
Results are machine-specific — compare on the same hardware.
EOF

log_success "Report saved to: $REPORT_FILE"
echo ""
