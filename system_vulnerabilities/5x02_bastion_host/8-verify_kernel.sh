#!/bin/bash

# Define the persistent configuration file path
SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"

# Initialize counters
PASS_COUNT=0
TOTAL_CHECKS=11

echo "=== Kernel Hardening Verification ==="
echo ""

# Function to check a sysctl value
# Usage: check_sysctl "Parameter Name" "Expected Value" "Section Name"
check_sysctl() {
    local param="$1"
    local expected="$2"
    local section="$3"
    
    # Read the current value from the kernel
    local current=$(sysctl -n "$param" 2>/dev/null)
    
    # If section is provided, print it
    if [ -n "$section" ]; then
        echo "$section:"
    fi
    
    # Compare current with expected
    if [ "$current" = "$expected" ]; then
        echo "  [PASS] $param = $current"
        ((PASS_COUNT++))
    else
        echo "  [FAIL] $param = $current (Expected: $expected)"
    fi
}

# 1. IP Forwarding
check_sysctl "net.ipv4.ip_forward" "0" "IP Forwarding"
check_sysctl "net.ipv6.conf.all.forwarding" "0" ""
echo ""

# 2. ICMP Redirects
check_sysctl "net.ipv4.conf.all.accept_redirects" "0" "ICMP Redirects"
check_sysctl "net.ipv4.conf.all.send_redirects" "0" ""
echo ""

# 3. Reverse Path Filtering
check_sysctl "net.ipv4.conf.all.rp_filter" "1" "Reverse Path Filtering"
echo ""

# 4. SYN Cookies
check_sysctl "net.ipv4.tcp_syncookies" "1" "SYN Cookies"
echo ""

# 5. Source Routing
check_sysctl "net.ipv4.conf.all.accept_source_route" "0" "Source Routing"
echo ""

# 6. ICMP Configuration
check_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1" "ICMP Configuration"
echo ""

# 7. Persistence Check
echo "Persistence Check:"
if [ -f "$SYSCTL_CONF" ]; then
    echo "  [PASS] $SYSCTL_CONF exists"
    ((PASS_COUNT++))
else
    echo "  [FAIL] $SYSCTL_CONF is missing"
fi
echo ""

# Summary
echo "Summary: $PASS_COUNT/$TOTAL_CHECKS checks passed"

if [ "$PASS_COUNT" -eq "$TOTAL_CHECKS" ]; then
    echo "Kernel hardening: COMPLETE"
else
    echo "Kernel hardening: INCOMPLETE (Please review failed checks)"
fi
