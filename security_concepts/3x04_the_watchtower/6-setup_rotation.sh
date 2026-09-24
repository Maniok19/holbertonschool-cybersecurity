#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

cat > /etc/logrotate.d/secure_remote <<'EOF'
/var/log/secure_remote.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0640 root adm
}
EOF

echo "Created /etc/logrotate.d/secure_remote:"
cat /etc/logrotate.d/secure_remote

echo "Testing logrotate configuration..."
logrotate -d /etc/logrotate.d/secure_remote

echo "Done."