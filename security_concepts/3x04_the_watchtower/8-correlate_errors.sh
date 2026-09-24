#!/bin/bash

LOG_FILE="$1"

if [ -z "$LOG_FILE" ]; then
    echo "Usage: $0 <log_file>" >&2
    exit 1
fi

if [ ! -f "$LOG_FILE" ]; then
    echo "Error: File '$LOG_FILE' not found." >&2
    exit 1
fi

awk '
{
    for (i = 1; i <= NF; i++) {
        if ($i ~ /^4[0-9][0-9]$/) {
            for (j = 1; j <= NF; j++) {
                if ($j ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) {
                    ip = $j
                    count[ip]++
                    break
                }
            }
            break
        }
    }
}
END {
    for (ip in count) {
        if (count[ip] > 5) {
            printf "ALERT: IP %s is scanning us!\n", ip
        }
    }
}
' "$LOG_FILE"