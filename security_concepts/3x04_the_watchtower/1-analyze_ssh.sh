#!/bin/bash
LOG_FILE="$1"
if [ ! -f "$LOG_FILE" ]; then
echo "Error: File '$LOG_FILE' not found."
exit 1
fi

grep "Failed password" "$LOG_FILE" | grep -oE 'from [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | awk '{print $2}' | sort | uniq -c | sort -nr
