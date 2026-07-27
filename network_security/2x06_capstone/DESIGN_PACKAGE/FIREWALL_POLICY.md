# Firewall Policy

## Default Chain Policies


1. INPUT:   DROP: Block everything by default  
2. FORWARD: DROP: Not a router — no traffic passes
3. OUTPUT:  ACCEPT

## Input Rules

```
# 1. Allow responses to our requests
ct state established,related accept

# 2. Allow localhost (internal services)
iif lo accept

# 3. Allow basic ICMP (ping, PMTU)
ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } accept

# 4. Rate limit new connections (anti-DDoS)
ct state new limit rate 50/second burst 100 drop

# 5. SSH — max 3 new connections/minute
tcp dport 22 ct state new limit rate 3/minute burst 5 accept

# 6. WireGuard VPN
udp dport 51820 accept

# 7. FTPS
tcp dport 21 accept
tcp dport 30000-30100 accept

# 8. Log and drop everything else
log prefix "NFT_DROP: " drop
```

## Rule Ordering Rationale

1. Established first — replies to our traffic must always return.
2. Loopback second — internal services communicate on 127.0.0.1.
3. Rate limit before service rules — stops floods at kernel level, before app-level (fail2ban).
4. Service rules last — only what is needed.
5. Log before final drop — audit trail for forensics.

## SSH Hardening (sshd_config)

```
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
MaxSessions 2
```

## FTP Hardening (vsftpd.conf)

```
ssl_enable=YES
force_local_data_ssl=YES
force_local_logins_ssl=YES
anonymous_enable=NO
pasv_min_port=30000
pasv_max_port=30100
```

## Services Removed

- Port 3000 (openvscode-server) — killed, removed from startup
- Port 3001 (ttyd web terminal) — killed, removed from startup

## Verification

```bash
nft list ruleset              # check rules loaded
ss -tlnp                      # check ports: only 21, 22, 51820
sshd -T | grep permitroot     # must show "permitrootlogin no"
```

## Rollback

```bash
nft flush ruleset
# flush all rules (allow everything)
# Restore from backup if needed:
nft -f /root/nftables-backup.conf
```
