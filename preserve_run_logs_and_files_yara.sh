#!/bin/bash
set -e

BASE_DIR="/home/kanra/oss-fuzz"
OUT_DIR="$BASE_DIR/build/out/yara"
ARCHIVE_DIR="$BASE_DIR/preserved_logs/logs_$(date +'%Y-%m-%d_%H-%M-%S')"
BUG_DIR="$OUT_DIR/bug_tests"

echo "[*] Preparing to archive fuzzing output."
echo "    Source: $OUT_DIR"
echo "    → Destination: $ARCHIVE_DIR"

# Create directory for bugs inside out/yara
mkdir -p "$BUG_DIR"

# Move all bug files into bug_tests
mv "$OUT_DIR"/{crash-*,oom-*,leak-*} "$BUG_DIR" 2>/dev/null || echo "    [!] No bug files found to move."

# Create archive directory
mkdir -p "$ARCHIVE_DIR"

# Move everything from out/yara to archive dir
mv "$OUT_DIR"/* "$ARCHIVE_DIR"/

echo "[✓] Archive complete:"
echo "    → $ARCHIVE_DIR"

# Clean out/yara
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
echo "    Cleaned: $OUT_DIR is ready for next fuzzing run."
