#!/bin/bash
mkdir -p $1
chown root:$2 $1
chmod 2750 "$1"
cat << EOF > /etc/logrotate.d/app
$1/*.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    create 0640 root $2
}
EOF