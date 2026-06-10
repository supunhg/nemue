#!/bin/bash
# Automation examples for Nemue
# These examples demonstrate CI/CD integration and automation

set -e

echo "=== Automation Examples ==="
echo ""

# 1. CI/CD pipeline scan
echo "[1] CI/CD pipeline scan (exit code based):"
cat << 'EOF'
#!/bin/bash
# Scan target and fail if critical vulnerabilities found
TARGET="$1"
nemue vuln-scan "$TARGET" -p 80,443 --severity critical
if [ $? -ne 0 ]; then
  echo "CRITICAL: Vulnerabilities found!"
  exit 1
fi
EOF
echo ""

# 2. Scheduled scan with report
echo "[2] Scheduled scan with report (cron example):"
cat << 'EOF'
# Add to crontab: 0 2 * * * /path/to/scan_script.sh
#!/bin/bash
DATE=$(date +%Y%m%d)
nemue scan 192.168.1.0/24 -p common -o "/reports/scan_$DATE.json"
nemue report executive -i "/reports/scan_$DATE.json" -o "/reports/report_$DATE.md"
EOF
echo ""

# 3. Continuous monitoring setup
echo "[3] Continuous monitoring:"
echo "    nemue monitor start \\"
echo "      --name 'Production' \\"
echo "      --targets 192.168.1.0/24 \\"
echo "      --ports 22,80,443 \\"
echo "      --interval 300 \\"
echo "      --alert-on-changes"
echo ""

# 4. Batch scanning with history
echo "[4] Batch scanning with history tracking:"
cat << 'EOF'
#!/bin/bash
TARGETS=("192.168.1.1" "192.168.1.2" "192.168.1.3")
for target in "${TARGETS[@]}"; do
  echo "Scanning $target..."
  nemue scan "$target" -p common -o "results_${target//\./_}.json"
done
EOF
echo ""

# 5. REST API automation
echo "[5] REST API automation:"
cat << 'EOF'
#!/bin/bash
# Start API server in background
nemue api --bind 0.0.0.0:8080 &
API_PID=$!
sleep 2

# Submit scan via API
SCAN_ID=$(curl -s -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"targets":["192.168.1.1"],"ports":[80,443]}' | jq -r '.scan_id')

echo "Scan started: $SCAN_ID"

# Wait for completion
while true; do
  STATUS=$(curl -s http://localhost:8080/api/v1/scans/$SCAN_ID | jq -r '.status')
  if [ "$STATUS" = "completed" ]; then break; fi
  sleep 5
done

# Get results
curl -s http://localhost:8080/api/v1/scans/$SCANID/results | jq .

kill $API_PID
EOF
echo ""

# 6. Docker automation
echo "[6] Docker automation:"
cat << 'EOF'
#!/bin/bash
# Scan using Docker
docker run --rm \
  -v $(pwd)/results:/results \
  nemue scan 192.168.1.1 -p common -o /results/scan.json

# Generate report
docker run --rm \
  -v $(pwd)/results:/results \
  nemue report executive -i /results/scan.json -o /results/report.md
EOF
echo ""

# 7. Trend analysis automation
echo "[7] Trend analysis (compare scans over time):"
cat << 'EOF'
#!/bin/bash
# Weekly trend analysis
nemue scan 192.168.1.1 -p common -o "scan_week$(date +%V).json"
# Compare with previous week
if [ -f "scan_week$(date -d '7 days ago' +%V).json" ]; then
  nemue diff "scan_week$(date -d '7 days ago' +%V).json" "scan_week$(date +%V).json"
fi
EOF
echo ""

# 8. Compliance scanning
echo "[8] Compliance scanning automation:"
cat << 'EOF'
#!/bin/bash
# PCI-DSS compliance scan
nemue scan 192.168.1.0/24 -p 1-65535 -o full_scan.json
nemue report compliance -i full_scan.json --framework pci-dss -o pci_report.md
nemue report compliance -i full_scan.json --framework nist-csf -o nist_report.md
EOF
echo ""

# 9. Alerting script
echo "[9] Custom alerting:"
cat << 'EOF'
#!/bin/bash
# Alert on new open ports
nemue scan 192.168.1.1 -p 1-1000 -o current.json
if [ -f previous.json ]; then
  DIFF=$(nemue diff previous.json current.json)
  if [ -n "$DIFF" ]; then
    echo "Changes detected!" | mail -s "Scan Alert" admin@example.com
  fi
fi
mv current.json previous.json
EOF
echo ""

# 10. Performance benchmarking
echo "[10] Performance benchmarking:"
cat << 'EOF'
#!/bin/bash
# Benchmark scan speed
time nemue scan 192.168.1.1 -p 1-65535 --timing aggressive -q
time nemue scan 192.168.1.1 --top-ports 100 -q
EOF
echo ""

echo "=== Automation examples complete ==="
