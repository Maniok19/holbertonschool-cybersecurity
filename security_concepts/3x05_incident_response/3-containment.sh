#!/bin/bash

set -euo pipefail

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "[-] Error: This script must be run as root (required for iptables)." 
   exit 1
fi

# Check argument count
if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <ATTACKER_IP> <PID>"
    exit 1
fi

IP="$1"
PID="$2"

# Validate IP format (basic regex check)
if ! [[ "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "[-] Error: Invalid IP address format: $IP"
    exit 1
fi

# Validate PID format
if ! [[ "$PID" =~ ^[0-9]+$ ]]; then
    echo "[-] Error: Invalid PID format: $PID"
    exit 1
fi

# Check if process exists before trying to pause it
if ! ps -p "$PID" > /dev/null 2>&1; then
    echo "[-] Error: Process with PID $PID does not exist."
    exit 1
fi

echo "[*] Starting containment for IP: $IP and PID: $PID"

# 1. Network Isolation: Drop all incoming and outgoing traffic to/from the IP
echo "[+] Applying iptables rules to block $IP..."
iptables -A INPUT -s "$IP" -j DROP
iptables -A OUTPUT -d "$IP" -j DROP
iptables -A FORWARD -s "$IP" -j DROP
iptables -A FORWARD -d "$IP" -j DROP

# 2. Process Freezing: Send SIGSTOP to pause the process and preserve memory state
echo "[+] Freezing process $PID (SIGSTOP)..."
kill -STOP "$PID"

echo "[SUCCESS] Containment applied. Network traffic blocked, process frozen."
echo "[*] Evidence preserved. Do not kill the process until memory is dumped."
