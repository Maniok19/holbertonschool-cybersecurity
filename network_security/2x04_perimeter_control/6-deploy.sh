#!/bin/bash

# Configuration
TARGET_IP="${1:-192.168.1.100}"
REMOTE_USER="${2:-root}"
CONFIG_FILE="skeleton.conf"
PANIC_SCRIPT="2-panic.sh"

scp "$CONFIG_FILE" "${REMOTE_USER}@${TARGET_IP}:/tmp/"

scp "$PANIC_SCRIPT" "${REMOTE_USER}@${TARGET_IP}:/tmp/"

ssh "${REMOTE_USER}@${TARGET_IP}" "bash /tmp/$(basename $PANIC_SCRIPT)"

ssh "${REMOTE_USER}@${TARGET_IP}" "nft -f /tmp/$(basename $CONFIG_FILE)"

ssh "${REMOTE_USER}@${TARGET_IP}" "nft list ruleset"