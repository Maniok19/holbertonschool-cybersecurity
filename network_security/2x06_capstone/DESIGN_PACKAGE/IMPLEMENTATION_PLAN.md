# Implementation Plan

## Principle: Never lock yourself out.

Every step has a rollback. Test before saving.

---

## Phase 1 — Anti-Lockout (5 min)

Install a watchdog cron job. It checks SSH every 5 minutes.
If SSH fails 3 times in a row, it restores the backup firewall.

```bash
echo "*/5 * * * * root /usr/local/sbin/fw-watchdog.sh" > /etc/cron.d/firewall-watchdog
```

Rollback: `rm /etc/cron.d/firewall-watchdog`

---

## Phase 2 — SSH Hardening (5 min)

Disable root login and passwords. Only SSH keys work.

```bash
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
kill -HUP $(cat /var/run/sshd.pid)
```

Test: Open a NEW terminal and try SSH with key. It must work.
Try root login. It must fail.

Rollback: Restore `/etc/ssh/sshd_config` from backup.

---

## Phase 3 — Firewall (10 min)

Apply nftables rules with default DROP.

```bash
# Save current state
nft list ruleset > /root/nftables-backup.conf

# Apply new rules
nft -f /etc/nftables.conf
```

Test immediately:
- SSH still works (from current session)
- Port 3000 and 3001 are blocked (try `nc -zv localhost 3000`)

Rollback: `nft -f /root/nftables-backup.conf`
Fallback: wait 5 min for auto-rollback.

---

## Phase 4 — WireGuard VPN (15 min)

Install and start WireGuard. Generate keys. Add peers.

```bash
apt-get install -y wireguard-tools
wg genkey | tee /etc/wireguard/server-private.key | wg pubkey > /etc/wireguard/server-public.key
# Create /etc/wireguard/wg0.conf (see VPN_DESIGN.md)
wg-quick up wg0
```

Test: `wg show` — interface must be up, listening on 51820.

Rollback: `wg-quick down wg0`

---

## Phase 5 — FTPS (10 min)

Generate certificate. Enforce TLS on vsftpd.

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/ftps/vsftpd.key -out /etc/ssl/ftps/vsftpd.crt \
  -subj "/CN=gateway.logicorp.internal"

# Add to /etc/vsftpd.conf: ssl_enable=YES, force_local_data_ssl=YES
# Restart vsftpd
kill $(cat /var/run/vsftpd/vsftpd.pid)
/usr/sbin/vsftpd /etc/vsftpd.conf &
```

Test: `openssl s_client -starttls ftp -connect localhost:21`

Warning: Finance users must switch to FTPS clients (FileZilla, WinSCP).

Rollback: Restore `/etc/vsftpd.conf` from backup.

---

## Phase 6 — Remove Undocumented Services (5 min)

```bash
pkill -f openvscode-server
pkill -f ttyd
# Remove or comment out from /etc/run.sh
```

Test: `ss -tlnp | grep -E '3000|3001'` — must show nothing.

Rollback: Services restart from `/etc/run.sh` on container reboot.

---

## Phase 7 — IDS Logging (10 min)

Suricata already installed. Add rules.

```bash
# Add custom rules to /etc/suricata/rules/local.rules
# Restart Suricata
pkill -HUP suricata
```

Test: `tail -f /var/log/suricata/fast.log`

Rollback: `rm /etc/suricata/rules/local.rules`

---

## Phase 8 — Final Validation (20 min)

- [ ] SSH key-only login works
- [ ] Root SSH is denied
- [ ] Ports 3000, 3001 are closed
- [ ] Only ports 21, 22, 51820 are open
- [ ] WireGuard tunnel works from client
- [ ] FTPS TLS handshake succeeds
- [ ] Watchdog cron job is active
- [ ] Suricata logs are written

---

## Master Rollback (Emergency)

```bash
nft flush ruleset              # remove all firewall rules
wg-quick down wg0              # stop VPN
cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config  # restore SSH
kill -HUP $(cat /var/run/sshd.pid)
cp /etc/vsftpd.conf.bak /etc/vsftpd.conf           # restore FTP
# Container restart = full reset of running processes
```
