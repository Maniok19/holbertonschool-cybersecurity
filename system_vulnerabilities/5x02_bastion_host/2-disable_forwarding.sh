#!/bin/bash

SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"

echo "=== Disabling IP Forwarding ==="
echo ""

echo "Current state:"
IPV4_CURRENT=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
IPV6_CURRENT=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)

echo "  net.ipv4.ip_forward = $IPV4_CURRENT"
echo "  net.ipv6.conf.all.forwarding = $IPV6_CURRENT"
echo ""

echo "Applying changes..."
sysctl -w -q net.ipv4.ip_forward=0
sysctl -w -q net.ipv6.conf.all.forwarding=0

IPV4_NEW=$(sysctl -n net.ipv4.ip_forward)
IPV6_NEW=$(sysctl -n net.ipv6.conf.all.forwarding)
echo "  net.ipv4.ip_forward = $IPV4_NEW"
echo "  net.ipv6.conf.all.forwarding = $IPV6_NEW"
echo ""

echo "Making persistent in $SYSCTL_CONF..."
echo "net.ipv4.ip_forward=0" | tee -a "$SYSCTL_CONF" > /dev/null
echo "net.ipv6.conf.all.forwarding=0" | tee -a "$SYSCTL_CONF" > /dev/null
echo ""

echo "Verification:"

CHECK_IPV4=$(sysctl -n net.ipv4.ip_forward)
CHECK_IPV6=$(sysctl -n net.ipv6.conf.all.forwarding)

if [ "$CHECK_IPV4" -eq 0 ]; then
    echo "  IPv4 forwarding: DISABLED"
else
    echo "  IPv4 forwarding: ENABLED (Error)"
fi

if [ "$CHECK_IPV6" -eq 0 ]; then
    echo "  IPv6 forwarding: DISABLED"
else
    echo "  IPv6 forwarding: ENABLED (Error)"
fi
