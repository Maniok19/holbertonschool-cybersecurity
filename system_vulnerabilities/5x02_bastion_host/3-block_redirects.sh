#!/bin/bash

SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"

echo "=== Blocking ICMP Redirects ==="
echo ""

echo "Disabling redirect acceptance..."
sysctl -w -q net.ipv4.conf.all.accept_redirects=0
sysctl -w -q net.ipv4.conf.default.accept_redirects=0
sysctl -w -q net.ipv6.conf.all.accept_redirects=0
sysctl -w -q net.ipv6.conf.default.accept_redirects=0

echo "  net.ipv4.conf.all.accept_redirects = 0"
echo "  net.ipv4.conf.default.accept_redirects = 0"
echo "  net.ipv6.conf.all.accept_redirects = 0"
echo "  net.ipv6.conf.default.accept_redirects = 0"
echo ""

echo "Disabling redirect sending..."
sysctl -w -q net.ipv4.conf.all.send_redirects=0
sysctl -w -q net.ipv4.conf.default.send_redirects=0

echo "  net.ipv4.conf.all.send_redirects = 0"
echo "  net.ipv4.conf.default.send_redirects = 0"
echo ""

echo "net.ipv4.conf.all.accept_redirects=0" | tee -a "$SYSCTL_CONF" > /dev/null
echo "net.ipv4.conf.default.accept_redirects=0" | tee -a "$SYSCTL_CONF" > /dev/null
echo "net.ipv6.conf.all.accept_redirects=0" | tee -a "$SYSCTL_CONF" > /dev/null
echo "net.ipv6.conf.default.accept_redirects=0" | tee -a "$SYSCTL_CONF" > /dev/null
echo "net.ipv4.conf.all.send_redirects=0" | tee -a "$SYSCTL_CONF" > /dev/null
echo "net.ipv4.conf.default.send_redirects=0" | tee -a "$SYSCTL_CONF" > /dev/null

echo "Configuration saved to $SYSCTL_CONF"
echo ""

CHECK_IPV4_ACCEPT=$(sysctl -n net.ipv4.conf.all.accept_redirects)
CHECK_IPV4_SEND=$(sysctl -n net.ipv4.conf.all.send_redirects)

if [ "$CHECK_IPV4_ACCEPT" -eq 0 ] && [ "$CHECK_IPV4_SEND" -eq 0 ]; then
    echo "ICMP redirects: BLOCKED"
else
    echo "ICMP redirects: NOT BLOCKED (Error)"
fi
