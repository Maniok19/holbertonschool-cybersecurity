# DEFENSE.md

## Challenge 1: FTP vs SFTP

**"Why not force SFTP?"**

Finance uses old software. It only does FTP. Changing it costs money and time. The client said "FTP must work."

What we did:

- Added TLS to FTP (FTPS). Passwords are encrypted now.
- Finance connects through WireGuard VPN first. Double encryption.
- Firewall limits FTP to VPN IPs only. Not open to the internet.

Risk left: if a finance laptop gets hacked, attacker has FTP access.

Phase 2: migrate to SFTP when budget allows.

---

## Challenge 2: Segmentation

**"How does this stop lateral movement?"**

Before: flat network. No firewall. Port 3000 (openvscode) gave root access to everything.

After: three zones.

- WAN: Nothing (dropped)
- DMZ: LAN only via specific ports
- LAN: Only itself

Port 3000 and 3001 are removed. Attacker cannot get in anymore.

If attacker compromises FTPS proxy, they get FTP only — not the database, not SSH.

Defense in depth: firewall drops bad traffic, TLS encrypts data, SSH bans brute-force, Suricata watches everything.

---

## Challenge 3: Single Point of Failure

**"Gateway goes down, what then?"**

Yes, it is a single point. High availability was not in scope. Client wanted security first.

If the gateway crashes, same risk as before our changes. We did not make it worse.

We added a watchdog: if firewall breaks, it auto-rolls back after 15 minutes.

Phase 2: second gateway + load balancer + database replication.
