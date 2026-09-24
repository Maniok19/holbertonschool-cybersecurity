#!/bin/bash

CONFIG_FILE="/etc/rsyslog.d/50-default.conf"
SERVER_IP="127.0.0.1"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

touch "$CONFIG_FILE"

sed -i '/^# Forward all logs to remote server/d; /^\*\.\* @/d' "$CONFIG_FILE"

echo "# Forward all logs to remote server" >> "$CONFIG_FILE"
echo "*.* @${SERVER_IP}:514" >> "$CONFIG_FILE"

echo "Added forwarding rule to $CONFIG_FILE:"
grep -A1 "Forward all logs" "$CONFIG_FILE"

echo "Restarting rsyslog..."
systemctl restart rsyslog

if systemctl is-active --quiet rsyslog; then
    echo "rsyslog restarted successfully."
else
    echo "Error: rsyslog failed to restart." >&2
    exit 1
fi

echo "Generating test log message..."
logger "Test Log Forwarding"

echo "Done. Test message sent to ${SERVER_IP} via UDP."
