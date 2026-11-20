#!/bin/bash

# Define the persistent configuration file path
SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"

echo "=== Enabling SYN Cookies ==="
echo ""

# 1. Check current state
echo "Current state:"
CURRENT_STATE=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
echo "  net.ipv4.tcp_syncookies = $CURRENT_STATE"
echo ""

# 2. Apply the change to the running kernel
echo "Enabling SYN cookies..."
sysctl -w -q net.ipv4.tcp_syncookies=1

# Print the applied setting (matching expected output)
echo "  net.ipv4.tcp_syncookies = 1"
echo ""

# 3. Make the change persistent
echo "net.ipv4.tcp_syncookies=1" | tee -a "$SYSCTL_CONF" > /dev/null

echo "Configuration saved to $SYSCTL_CONF"
echo ""

# 4. Verification
CHECK_STATE=$(sysctl -n net.ipv4.tcp_syncookies)

if [ "$CHECK_STATE" -eq 1 ]; then
    echo "SYN flood protection: ENABLED"
else
    echo "SYN flood protection: DISABLED (Error)"
fi
