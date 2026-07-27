#!/bin/bash

PASS=0
FAIL=0

check() {
    local desc="$1"
    shift
    if "$@"; then
        echo "[PASS] $desc"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $desc"
        FAIL=$((FAIL + 1))
    fi
}

# ===== FIREWALL =====
check "Firewall default INPUT policy is DROP" \
    nft list chain inet logcorp_firewall INPUT 2>/dev/null | grep -q 'policy drop'

check "Firewall default FORWARD policy is DROP" \
    nft list chain inet logcorp_firewall FORWARD 2>/dev/null | grep -q 'policy drop'

check "Firewall allows established/related connections" \
    nft list chain inet logcorp_firewall INPUT 2>/dev/null | grep -q 'ct state established,related accept'

check "Firewall allows loopback traffic" \
    nft list chain inet logcorp_firewall INPUT 2>/dev/null | grep -q 'iif lo accept'

check "Firewall allows SSH port 22 (rate-limited)" \
    nft list chain inet logcorp_firewall INPUT 2>/dev/null | grep -q 'tcp dport 22'

check "Firewall allows FTPS port 21" \
    nft list chain inet logcorp_firewall INPUT 2>/dev/null | grep -q 'tcp dport 21'

check "Firewall allows WireGuard port 51820" \
    nft list chain inet logcorp_firewall INPUT 2>/dev/null | grep -q 'udp dport 51820'

check "Firewall allows FTP passive ports 30000-30100" \
    nft list chain inet logcorp_firewall INPUT 2>/dev/null | grep -q 'tcp dport 30000-30100'

check "Firewall has rate limiting enabled" \
    nft list chain inet logcorp_firewall INPUT 2>/dev/null | grep -q 'limit rate'

check "Firewall logs dropped packets" \
    nft list chain inet logcorp_firewall INPUT 2>/dev/null | grep -q 'NFT_DROP'

# ===== SERVICES =====
check "SSH service is running" \
    ss -tlnp 2>/dev/null | grep -q ':22 '

check "FTPS service (vsftpd) is running" \
    ss -tlnp 2>/dev/null | grep -q ':21 '

check "WireGuard VPN interface wg0 is UP" \
    ip link show wg0 2>/dev/null | grep -q 'UP'

check "WireGuard is listening on port 51820" \
    ss -ulnp 2>/dev/null | grep -q ':51820'

check "Undocumented port 3000 (openvscode) is closed" \
    ! ss -tlnp 2>/dev/null | grep -q ':3000 '

check "Undocumented port 3001 (ttyd) is closed" \
    ! ss -tlnp 2>/dev/null | grep -q ':3001 '

check "Cron daemon is running" \
    pgrep -x cron >/dev/null 2>&1

check "Fail2ban is running" \
    pgrep -f fail2ban-server >/dev/null 2>&1

# ===== ACCESS CONTROL =====
check "SSH root login is disabled" \
    sshd -T 2>/dev/null | grep -q 'permitrootlogin no'

check "SSH password authentication is disabled" \
    sshd -T 2>/dev/null | grep -q 'passwordauthentication no'

check "SSH pubkey authentication is enabled" \
    sshd -T 2>/dev/null | grep -q 'pubkeyauthentication yes'

check "SSH MaxAuthTries is 3" \
    sshd -T 2>/dev/null | grep -q 'maxauthtries 3'

check "SSH MaxSessions is 2" \
    sshd -T 2>/dev/null | grep -q 'maxsessions 2'

check "Student user has SSH authorized_keys" \
    [ -s /home/student/.ssh/authorized_keys ]

check "Root has sudo access" \
    grep -q '^root.*ALL.*ALL' /etc/sudoers 2>/dev/null || \
    grep -qr '^root.*ALL.*ALL' /etc/sudoers.d/ 2>/dev/null

# ===== NETWORK =====
check "WireGuard wg0 has address 10.99.0.1/24" \
    ip addr show wg0 2>/dev/null | grep -q '10.99.0.1/24'

check "WireGuard has at least 1 peer configured" \
    [ "$(wg show wg0 peers 2>/dev/null | wc -l)" -ge 1 ]

check "Default route exists" \
    ip route show default 2>/dev/null | grep -q 'default'

# ===== BACKDOOR =====
check "Backdoored cron job removed" \
    [ ! -f /etc/cron.d/logicorp ]

check "Firewall watchdog cron is active" \
    [ -f /etc/cron.d/firewall-watchdog ]

# ===== RESULT =====
echo ""
TOTAL=$((PASS + FAIL))
echo "RESULT: ${PASS}/${TOTAL} checks passed"
