#!/bin/bash
FAIL_FILE="/tmp/fw-fail-count"
MAX_FAILS=3
BACKUP="/root/nftables-backup-latest.conf"

if timeout 5 bash -c "echo >/dev/tcp/127.0.0.1/22" 2>/dev/null; then
    echo 0 > "$FAIL_FILE"
    exit 0
fi

COUNT=$(cat "$FAIL_FILE" 2>/dev/null || echo 0)
COUNT=$((COUNT + 1))
echo "$COUNT" > "$FAIL_FILE"

if [ "$COUNT" -lt "$MAX_FAILS" ]; then
    exit 0
fi

if [ -f "$BACKUP" ]; then
    nft -f "$BACKUP" 2>/dev/null
else
    nft flush ruleset 2>/dev/null
fi
echo 0 > "$FAIL_FILE"
