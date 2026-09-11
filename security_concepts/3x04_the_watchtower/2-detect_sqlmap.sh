#!/bin/bash

LOG_FILE="$1"

if [ ! -f "$LOG_FILE" ]; then
    echo "Error: File '$LOG_FILE' not found."
    exit 1
fi

grep "sqlmap" "$LOG_FILE" | awk '{print $1","substr($6,2)","$7}'
