#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

cat >> /etc/rsyslog.conf <<'EOF'

template(name="json_fmt" type="string" string="{\"time\":\"%timestamp%\", \"host\":\"%hostname%\", \"msg\":\"%msg%\"}\n")
EOF

echo "Appended json_fmt template to /etc/rsyslog.conf:"
tail -n 3 /etc/rsyslog.conf