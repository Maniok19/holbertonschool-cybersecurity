#!/bin/bash

# Define the persistent configuration file path
SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"

echo "=== ICMP Configuration ==="
echo ""

# 1. Disable broadcast ping response
echo "Disabling broadcast ping response (Smurf prevention)..."
sysctl -w -q net.ipv4.icmp_echo_ignore_broadcasts=1
echo "  net.ipv4.icmp_echo_ignore_broadcasts = 1"
echo ""

# 2. Keep unicast ping enabled
echo "Keeping unicast ping enabled for diagnostics."
sysctl -w -q net.ipv4.icmp_echo_ignore_all=0
echo "  net.ipv4.icmp_echo_ignore_all = 0"
echo ""

# 3. Ignore bogus ICMP error responses
echo "Ignoring bogus ICMP error responses..."
sysctl -w -q net.ipv4.icmp_ignore_bogus_error_responses=1
echo "  net.ipv4.icmp_ignore_bogus_error_responses = 1"
echo ""

# 4. Make the changes persistent
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" | tee -a "$SYSCTL_CONF" > /dev/null
echo "net.ipv4.icmp_echo_ignore_all=0" | tee -a "$SYSCTL_CONF" > /dev/null
echo "net.ipv4.icmp_ignore_bogus_error_responses=1" | tee -a "$SYSCTL_CONF" > /dev/null

echo "Configuration saved to $SYSCTL_CONF"
echo ""

# 5. Verification
CHECK_BROADCAST=$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts)
CHECK_UNICAST=$(sysctl -n net.ipv4.icmp_echo_ignore_all)

if [ "$CHECK_BROADCAST" -eq 1 ]; then
    echo "Broadcast ping: DISABLED"
else
    echo "Broadcast ping: ENABLED (Error)"
fi

if [ "$CHECK_UNICAST" -eq 0 ]; then
    echo "Unicast ping: ENABLED"
else
    echo "Unicast ping: DISABLED (Error)"
fi
