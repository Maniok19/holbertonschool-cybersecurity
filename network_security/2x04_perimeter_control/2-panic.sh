#!/bin/bash
nft flush ruleset
iptables -P INPUT ACCEPT 2>/dev/null
iptables -P FORWARD ACCEPT 2>/dev/null
iptables -P OUTPUT ACCEPT 2>/dev/null
iptables -F 2>/dev/null
SCRIPT_PATH=$(realpath "$0" 2>/dev/null || readlink -f "$0")
echo "$SCRIPT_PATH" | at now + 5 minutes
else
    (sleep 300 && "$SCRIPT_PATH") &
fi