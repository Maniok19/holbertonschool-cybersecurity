#!/bin/bash

# Define the persistent configuration file path
SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"

echo "=== Blocking Source Routing ==="
echo ""

# 1. Apply the changes to the running kernel
echo "Disabling source route acceptance..."
sysctl -w -q net.ipv4.conf.all.accept_source_route=0
sysctl -w -q net.ipv4.conf.default.accept_source_route=0
sysctl -w -q net.ipv6.conf.all.accept_source_route=0
sysctl -w -q net.ipv6.conf.default.accept_source_route=0

# Print the applied settings (matching expected output)
echo "  net.ipv4.conf.all.accept_source_route = 0"
echo "  net.ipv4.conf.default.accept_source_route = 0"
echo "  net.ipv6.conf.all.accept_source_route = 0"
echo "  net.ipv6.conf.default.accept_source_route = 0"
echo ""

# 2. Make the changes persistent
echo "net.ipv4.conf.all.accept_source_route=0" | tee -a "$SYSCTL_CONF" > /dev/null
echo "net.ipv4.conf.default.accept_source_route=0" | tee -a "$SYSCTL_CONF" > /dev/null
echo "net.ipv6.conf.all.accept_source_route=0" | tee -a "$SYSCTL_CONF" > /dev/null
echo "net.ipv6.conf.default.accept_source_route=0" | tee -a "$SYSCTL_CONF" > /dev/null

echo "Configuration saved to $SYSCTL_CONF"
echo ""

# 3. Verification
# Check if the running kernel state is now 0
CHECK_IPV4_ALL=$(sysctl -n net.ipv4.conf.all.accept_source_route)
CHECK_IPV4_DEF=$(sysctl -n net.ipv4.conf.default.accept_source_route)

if [ "$CHECK_IPV4_ALL" -eq 0 ] && [ "$CHECK_IPV4_DEF" -eq 0 ]; then
    echo "Source-routed packets: BLOCKED"
else
    echo "Source-routed packets: NOT BLOCKED (Error)"
fi
