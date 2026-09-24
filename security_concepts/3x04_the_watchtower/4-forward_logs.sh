#!/bin/bash
# Script: 4-forward_logs.sh
# Purpose: Forward ALL logs to a remote server (simulated as 127.0.0.1 via UDP)

CONFIG_FILE="/etc/rsyslog.d/50-default.conf"
SERVER_IP="127.0.0.1"

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

# Create config file if it doesn't exist
touch "$CONFIG_FILE"

# Remove any previous forwarding rules (idempotent)
sed -i '/^# Forward all logs to remote server/d' "$CONFIG_FILE"
sed -i '/^\*\.\* @/d' "$CONFIG_FILE"

# Append the forwarding rule: *.* @host:port (UDP)
echo "# Forward all logs to remote server" >> "$CONFIG_FILE"
echo '*.* @'"${SERVER_IP}"':514' >> "$CONFIG_FILE"

echo "Added forwarding rule to $CONFIG_FILE:"
grep -A1 "Forward all logs" "$CONFIG_FILE"

# Restart rsyslog
echo "Restarting rsyslog..."
systemctl restart rsyslog

if systemctl is-active --quiet rsyslog; then
    echo "rsyslog restarted successfully."
else
    echo "Error: rsyslog failed to restart." >&2
    exit 1
fi

# Generate a test message
echo "Generating test log message..."
logger "Test Log Forwarding"

echo "Done. Test message sent to ${SERVER_IP} via UDP."