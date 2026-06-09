#!/bin/bash
# Stealth scanning examples for Nemue
# These examples demonstrate evasion techniques

set -e

TARGET="${1:-192.168.1.1}"

echo "=== Stealth Scanning Examples ==="
echo "Target: $TARGET"
echo "NOTE: Most stealth scans require root privileges"
echo ""

# 1. SYN stealth scan (half-open, most隐蔽)
echo "[1] SYN stealth scan:"
sudo nemue scan "$TARGET" -p 1-1000 --raw -q
echo ""

# 2. Slow timing to avoid detection
echo "[2] Paranoid timing (T0 - very slow):"
sudo nemue scan "$TARGET" -p 22,80,443 --raw --timing paranoid -q
echo ""

# 3. Sneaky timing
echo "[3] Sneaky timing (T1):"
sudo nemue scan "$TARGET" -p 22,80,443 --raw --timing sneaky -q
echo ""

# 4. Decoy scanning (mix real scan with decoys)
echo "[4] Decoy scanning:"
sudo nemue scan "$TARGET" -p 80 --decoys 192.168.1.5,192.168.1.6 --raw -q
echo ""

# 5. Random decoys
echo "[5] Random decoys (5 random IPs):"
sudo nemue scan "$TARGET" -p 80 --decoys RND:5 --raw -q
echo ""

# 6. Source port spoofing (appear as DNS traffic)
echo "[6] Source port spoofing (port 53):"
sudo nemue scan "$TARGET" -p 80,443 --source-port 53 --raw -q
echo ""

# 7. TTL manipulation
echo "[7] Custom TTL:"
sudo nemue scan "$TARGET" -p 80 --ttl 64 --raw -q
echo ""

# 8. Randomized scan order
echo "[8] Randomized host and port order:"
nemue scan "$TARGET" -p 1-1000 --randomize-hosts --randomize-ports -q
echo ""

# 9. Fragmented packets
echo "[9] IP fragmentation:"
sudo nemue scan "$TARGET" -p 80 --fragment --raw -q
echo ""

# 10. Combined stealth techniques
echo "[10] Maximum stealth (combined):"
sudo nemue scan "$TARGET" -p 1-1000 \
  --raw \
  --timing sneaky \
  --decoys RND:3 \
  --source-port 53 \
  --randomize-hosts \
  --randomize-ports \
  -q
echo ""

# 11. Rate-limited scan
echo "[11] Rate-limited scan (100 pps):"
sudo nemue scan "$TARGET" -p 1-1000 --raw --max-rate 100 -q
echo ""

# 12. Show reason for port state
echo "[12] Show port state reason:"
sudo nemue scan "$TARGET" -p 22,80,443 --raw --reason -q
echo ""

echo "=== Stealth scanning examples complete ==="
