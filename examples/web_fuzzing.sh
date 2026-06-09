#!/bin/bash
# Web fuzzing examples for Nemue
# These examples demonstrate directory/file/subdomain discovery

set -e

TARGET="${1:-https://example.com}"

echo "=== Web Fuzzing Examples ==="
echo "Target: $TARGET"
echo ""

# 1. Basic directory fuzzing
echo "[1] Directory fuzzing (dirs1k wordlist):"
nemue fuzz "$TARGET" -b dirs1k -q
echo ""

# 2. Extended directory fuzzing
echo "[2] Extended directory fuzzing (dirs10k):"
nemue fuzz "$TARGET" -b dirs10k -c 50 -q
echo ""

# 3. File discovery
echo "[3] File discovery:"
nemue fuzz "$TARGET" -m file -b files -q
echo ""

# 4. Extension fuzzing
echo "[4] Extension fuzzing (php,asp,jsp):"
nemue fuzz "$TARGET/index" -m ext -e php,asp,jsp,html -q
echo ""

# 5. Recursive directory scanning
echo "[5] Recursive scan (max depth 3):"
nemue fuzz "$TARGET" -b dirs1k -R --max-depth 3 -q
echo ""

# 6. Status code filtering
echo "[6] Filter by status codes (200,301,302):"
nemue fuzz "$TARGET" -b dirs1k -s 200,301,302 -q
echo ""

# 7. Custom concurrency
echo "[7] High concurrency (100 threads):"
nemue fuzz "$TARGET" -b dirs1k -c 100 -q
echo ""

# 8. Custom headers
echo "[8] With custom headers:"
nemue fuzz "$TARGET" -b dirs1k -H "Authorization: Bearer token123" -q
echo ""

# 9. Save results to JSON
echo "[9] Save to JSON:"
nemue fuzz "$TARGET" -b dirs1k -o json -O fuzz_results.json -q
echo "Results saved to fuzz_results.json"
echo ""

# 10. HTML report
echo "[10] Generate HTML report:"
nemue fuzz "$TARGET" -b dirs1k -o html -O fuzz_report.html -q
echo "Report saved to fuzz_report.html"
echo ""

# 11. Subdomain enumeration
echo "[11] Subdomain enumeration:"
DOMAIN=$(echo "$TARGET" | sed -E 's|https?://||' | cut -d'/' -f1)
nemue fuzz "$DOMAIN" -m subdomain -b subdomains -q
echo ""

# 12. WordPress scanning
echo "[12] WordPress-specific paths:"
nemue fuzz "$TARGET" -b wordpress -q
echo ""

# 13. API endpoint discovery
echo "[13] API endpoint discovery:"
nemue fuzz "$TARGET" -b api -q
echo ""

# 14. Parameter fuzzing
echo "[14] Parameter fuzzing:"
nemue fuzz "${TARGET}/search?q=FUZZ" -b params -q
echo ""

# 15. Wordlist mutations
echo "[15] With wordlist mutations:"
nemue fuzz "$TARGET" -b dirs1k --mutate -q
echo ""

echo "=== Web fuzzing examples complete ==="
