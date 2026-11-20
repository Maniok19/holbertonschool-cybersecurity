#!/bin/bash

# Define the persistent configuration file path
SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"

echo "=== Enabling Reverse Path Filtering ==="
echo ""

# 1. Apply the strict mode changes to the running kernel
echo "Setting strict mode (1) for all interfaces..."
sysctl -w -q net.ipv4.conf.all.rp_filter=1
sysctl -w -q net.ipv4.conf.default.rp_filter=1

# Print the applied settings (matching expected output)
echo "  net.ipv4.conf.all.rp_filter = 1"
echo "  net.ipv4.conf.default.rp_filter = 1"
echo ""

# 2. Make the changes persistent
echo "net.ipv4.conf.all.rp_filter=1" | tee -a "$SYSCTL_CONF" > /dev/null
echo "net.ipv4.conf.default.rp_filter=1" | tee -a "$SYSCTL_CONF" > /dev/null

echo "Configuration saved to $SYSCTL_CONF"
echo ""

# 3. Verification
CHECK_ALL=$(sysctl -n net.ipv4.conf.all.rp_filter)
CHECK_DEFAULT=$(sysctl -n net.ipv4.conf.default.rp_filter)

if [ "$CHECK_ALL" -eq 1 ] && [ "$CHECK_DEFAULT" -eq 1 ]; then
    echo "Reverse path filtering: STRICT MODE"
    echo "Spoofed packets will be dropped."
else
    echo "Reverse path filtering: NOT CONFIGURED (Error)"
fi
