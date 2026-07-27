#!/bin/bash
if [ ! -f /usr/local/sbin/fw-watchdog.sh ]; then
    echo "PANIC BUTTON MISSING — deploy fw-watchdog.sh first"
    exit 1
fi
if [ ! -f /etc/cron.d/firewall-watchdog ]; then
    echo "*/5 * * * * root /usr/local/sbin/fw-watchdog.sh" > /etc/cron.d/firewall-watchdog
fi
nft list ruleset > /root/nftables-backup-latest.conf 2>/dev/null || true
command -v nft &>/dev/null || { apt-get update -qq && apt-get install -y nftables; }

cat > /etc/nftables.conf << 'NFTEOF'
#!/usr/sbin/nft -f
flush ruleset

table inet logcorp_firewall {
    chain INPUT {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } accept
        ct state new limit rate 50/second burst 100 packets accept
        ct state new limit rate over 50/second burst 100 packets log prefix "NFT_FLOOD: " drop
        tcp dport 22 ct state new limit rate 3/minute burst 5 packets accept
        tcp dport 21 ct state new accept
        tcp dport 30000-30100 accept
        udp dport 51820 accept
        ct state invalid log prefix "NFT_INVALID: " drop
        log prefix "NFT_DROP: " drop
    }
    chain FORWARD {
        type filter hook forward priority 0; policy drop;
    }
    chain OUTPUT {
        type filter hook output priority 0; policy accept;
        udp dport 53 accept
        tcp dport 53 accept
        udp dport 123 accept
        tcp dport { 80, 443 } accept
        udp sport 51820 accept
        log prefix "NFT_OUT_DROP: " drop
    }
}
NFTEOF

nft -f /etc/nftables.conf
