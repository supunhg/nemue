#!/bin/bash
# Basic scanning examples for Nemue
# These examples demonstrate common scanning patterns

set -e

TARGET="${1:-192.168.1.1}"

echo "=== Basic Scanning Examples ==="
echo "Target: $TARGET"
echo ""

# 1. Quick scan of common ports
echo "[1] Quick scan (common ports):"
nemue scan "$TARGET" -p common -q
echo ""

# 2. Specific ports
echo "[2] Specific ports (22, 80, 443):"
nemue scan "$TARGET" -p 22,80,443 -q
echo ""

# 3. Port range
echo "[3] Port range (1-1000):"
nemue scan "$TARGET" -p 1-1000 -q
echo ""

# 4. Top 100 ports
echo "[4] Top 100 ports:"
nemue scan "$TARGET" --top-ports 100 -q
echo ""

# 5. Service detection
echo "[5] Service detection:"
nemue scan "$TARGET" -p 22,80,443 -V -q
echo ""

# 6. OS detection (requires root)
echo "[6] OS detection:"
sudo nemue scan "$TARGET" -p 22,80,443 -O -q
echo ""

# 7. Aggressive scan (service + OS + scripts)
echo "[7] Aggressive scan:"
sudo nemue scan "$TARGET" -A -q
echo ""

# 8. Save results to JSON
echo "[8] Save to JSON:"
nemue scan "$TARGET" -p common -o scan_results.json -q
echo "Results saved to scan_results.json"
echo ""

# 9. Multiple targets
echo "[9] Multiple targets:"
nemue scan "$TARGET,127.0.0.1" -p 22,80 -q
echo ""

# 10. CIDR notation
echo "[10] CIDR scan (first 10 hosts):"
nemue scan "${TARGET%.*}.0/28" -p 22,80 -q
echo ""

echo "=== Basic scanning examples complete ==="
