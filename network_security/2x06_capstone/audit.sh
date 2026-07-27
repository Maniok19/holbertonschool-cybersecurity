#!/bin/bash
echo "=== SYSTEM INFORMATION ==="
cat /etc/os-release
uname -a
hostnamectl
uptime

echo -e "\n=== NETWORK TOPOLOGY ==="
ip addr show
ip route show
ip neighbor show

echo -e "\n=== ATTACK SURFACE ==="
ss -tulpn

echo -e "\n=== SECURITY CONTROLS ==="
sudo ufw status 2>/dev/null
sudo aa-status 2>/dev/null

echo -e "\n=== USER ACCOUNTS ==="
grep -E '/bin/bash|/bin/sh' /etc/passwd
sudo -l

echo -e "\n=== ACTIVE SERVICES ==="
systemctl list-units --type=service --state=running

echo -e "\n=== SCHEDULED TASKS ==="
cat /etc/crontab
ls -la /etc/cron.d/
systemctl list-timers --all