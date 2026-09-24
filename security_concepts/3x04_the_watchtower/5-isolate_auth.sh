#!/bin/bash

CONFIG_FILE="/etc/rsyslog.d/60-auth.conf"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

echo 'authpriv.info /var/log/secure_remote.log' > /etc/rsyslog.d/60-auth.conf

echo "Created config file /etc/rsyslog.d/60-auth.conf:"
cat /etc/rsyslog.d/60-auth.conf

echo "Restarting rsyslog..."
systemctl restart rsyslog

if systemctl is-active --quiet rsyslog; then
    echo "rsyslog restarted successfully."
else
    echo "Error: rsyslog failed to restart." >&2
    exit 1
fi

echo "Done."