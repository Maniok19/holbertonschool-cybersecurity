#!/bin/bash
if [ -f /etc/run.sh ]; then
    cp /etc/run.sh /etc/run.sh.bak
    sed -i '/^ttyd /s/^/#/' /etc/run.sh
    sed -i '/^openvscode-server/s/^/#/' /etc/run.sh
    sed -i '/^nft flush ruleset/s/^/#/' /etc/run.sh
fi
pkill -f "openvscode-server" 2>/dev/null
pkill -f "ttyd" 2>/dev/null
if [ -f /etc/cron.d/logicorp ]; then
    cp /etc/cron.d/logicorp /etc/cron.d/logicorp.bak
    rm /etc/cron.d/logicorp
fi
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
grep -q "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
grep -q "^PasswordAuthentication" /etc/ssh/sshd_config || echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
grep -q "^PubkeyAuthentication" /etc/ssh/sshd_config || echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
grep -q "^MaxAuthTries" /etc/ssh/sshd_config || echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
grep -q "^MaxSessions" /etc/ssh/sshd_config || echo "MaxSessions 2" >> /etc/ssh/sshd_config
grep -q "^ClientAliveInterval" /etc/ssh/sshd_config || echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
if [ -f /var/run/sshd.pid ]; then
    kill -HUP $(cat /var/run/sshd.pid)
fi
