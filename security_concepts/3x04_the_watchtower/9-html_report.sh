#!/bin/bash

LOG_FILE="$1"
OUTPUT_FILE="$2"

if [ -z "$LOG_FILE" ] || [ -z "$OUTPUT_FILE" ]; then
    echo "Usage: $0 <log_file> <output_html_file>" >&2
    exit 1
fi

if [ ! -f "$LOG_FILE" ]; then
    echo "Error: File '$LOG_FILE' not found." >&2
    exit 1
fi

TOP_ATTACKERS=$(awk '
/Failed password/ {
    for (i = 1; i <= NF; i++) {
        if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) {
            count[$i]++
            break
        }
    }
}
END {
    for (ip in count) {
        print count[ip], ip
    }
}
' "$LOG_FILE" | sort -rn | head -n 5)

cat > $2 <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Report</title>
</head>
<body>
    <h1>Security Report</h1>
    <table border="1" cellpadding="5" cellspacing="0">
        <thead>
            <tr>
                <th>Rank</th>
                <th>IP Address</th>
                <th>Failed Attempts</th>
            </tr>
        </thead>
        <tbody>
EOF

RANK=1
while read -r COUNT IP; do
    [ -z "$IP" ] && continue
    echo "            <tr><td>${RANK}</td><td>${IP}</td><td>${COUNT}</td></tr>" >> $2
    RANK=$((RANK + 1))
done <<< "$TOP_ATTACKERS"

cat >> $2 <<'EOF'
        </tbody>
    </table>
</body>
</html>
EOF

echo "Report written to $OUTPUT_FILE"