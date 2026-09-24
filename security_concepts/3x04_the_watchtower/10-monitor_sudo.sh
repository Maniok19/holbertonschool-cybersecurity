#!/bin/bash

LOG_FILE="/var/log/auth.log"

if [ ! -f "$LOG_FILE" ]; then
    echo "Error: $LOG_FILE not found." >&2
    exit 1
fi

echo "Monitoring $LOG_FILE for sudo violations... (Ctrl+C to stop)"

tail -f "$LOG_FILE" | while read -r LINE; do
    if echo "$LINE" | grep -q "sudo" && echo "$LINE" | grep -q "authentication failure"; then
        echo "ALERT: Sudo violation detected!"
    fi
done