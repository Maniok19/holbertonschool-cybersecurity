#!/bin/bash

BASELINE_DIR="/var/log/hardening"
DATE=$(date +%Y%m%d)
BASELINE_FILE="$BASELINE_DIR/baseline-$DATE.txt"

mkdir -p "$BASELINE_DIR"

echo "Running Lynis audit..."
lynis audit system --quiet

HARDENING_INDEX=$(grep "^hardening_index=" /var/log/lynis-report.dat | cut -d= -f2)
TESTS=$(grep "^tests_performed=" /var/log/lynis-report.dat | cut -d= -f2)
WARNINGS=$(grep -c "^warning\[\]=" /var/log/lynis-report.dat)
SUGGESTIONS=$(grep -c "^suggestion\[\]=" /var/log/lynis-report.dat)

BAR_LEN=20
FILLED=$((HARDENING_INDEX * BAR_LEN / 100))
EMPTY=$((BAR_LEN - FILLED))
BAR=$(printf "%${FILLED}s" | tr ' ' '#')$(printf "%${EMPTY}s" | tr ' ' '.')

echo ""
echo "Hardening Index: $HARDENING_INDEX [$BAR]"
echo "Tests Performed: $TESTS"
echo "Warnings: $WARNINGS"
echo "Suggestions: $SUGGESTIONS"
echo ""
echo "Critical Findings:"

grep "^warning\[\]=" /var/log/lynis-report.dat | head -4 | while IFS='|' read -r line; do
    MSG=$(echo "$line" | cut -d'|' -f2)
    echo "  [WARNING] $MSG"
done

cp /var/log/lynis-report.dat "$BASELINE_FILE" 2>/dev/null || cat /var/log/lynis-report.dat > "$BASELINE_FILE"
echo ""
echo "Baseline saved to: $BASELINE_FILE"