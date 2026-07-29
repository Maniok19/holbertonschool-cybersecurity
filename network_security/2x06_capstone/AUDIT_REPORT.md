# Audit report

Here is the audit report of the server : 

## Informations searched :

1. System Information: OS version, kernel, hostname, uptime

2. Network Topology: Interfaces, IP addresses, routes, ARP table

3. Attack Surface: Listening ports (TCP/UDP), associated processes

4. Security Controls: Firewall status, SELinux/AppArmor status

5. User Accounts: Local users, sudo configuration, SSH keys

6. Running Services: All active services, especially network-facing ones

7. Scheduled Tasks: Cron jobs, systemd timers

8. Discrepancies: Differences between documentation and reality

## Commands

To get these informations, I created and executed this script :
```sh
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
```

# Structured output


## 1. System Information
* Operating System: Ubuntu 22.04.5 LTS (Jammy Jellyfish)
* Kernel Version: 6.1.176 (x86_64)
* Hostname: 2d5ec77ad8df42e1a63d328b3e48b535-2377118072
* Uptime: 1 hour, 24 minutes (Load Average: 0.03, 0.03, 0.01)
* Init System: Container Runtime / Non-systemd Environment (PID 1 is `/bin/sh`)

## 2. Network Topology
* Loopback (`lo`): `127.0.0.1/8`
* Internal Interface (`eth0`): `169.254.172.2/22`
* Primary Interface (`eth1`): `10.42.66.225/16`
* Default Route: `10.42.0.1` via `eth1`
* ARP Cache (`ip neighbor`): Gateway `10.42.0.1` reachable (`0a:b0:93:32:a4:d0`)

## 3. Attack Surface (Listening Services)
- Port 21 (TCP): FTP (`vsftpd`) — PID 63, `*:21`
- Port 22 (TCP): SSH (`sshd`) — PID 89, `0.0.0.0:22`, `[::]:22`
- Port 3000 (TCP): Web App (`node`) — PID 105, `0.0.0.0:3000`
- Port 3001 (TCP): Web Terminal (`ttyd`) — PID 91, `0.0.0.0:3001`

## 4. Security Controls
* Firewall / AppArmor / SELinux: Not managed via standard `systemd` or user-space tooling; containerized environment delegates network filtering to host infrastructure.

## 5. User Accounts & Privilege Level
* Interactive Accounts (`/etc/passwd`):
  * `root` (UID: 0) - Shell: `/bin/bash`
  * `student` (UID: 1000) - Shell: `/bin/bash`
* Sudo Rights:
  * User `root` has full permissions: `(ALL : ALL) ALL`

## 6. Running Services

- PID 1 (`root`): Container Init Shell — parent 0, N/A. Changes root password on boot via hostname
- PID 27 (`root`): `/etc/run.sh` — parent 1, N/A. Supervisor script for web services
- PID 63 (`root`): `/usr/sbin/vsftpd` — parent 1, Port 21. FTP service with elevated permissions
- PID 78 (`root`): `/usr/sbin/cron -P` — parent 1, N/A. Recurring outbound `curl` requests
- PID 89 / 160 (`root` / `student`): `sshd: student@pts/0` — parent 1 / 149, Port 22. Active SSH session for `student`
- PID 91 (`root`): `ttyd` — parent 27, Port 3001. Passwords exposed in command-line args
- PID 105 (`root`): `openvscode-server` — parent 98, Port 3000. Token exposed in command-line args
- PID 53614 (`root`): `su root` — parent 161, N/A. Privilege escalation from `student` to `root`
- PID 47614 (`student`): `gpg-agent` — parent 1, Local Socket. GPG daemon for user key store

---


## 7. Scheduled Tasks
* Cron Config File: `/etc/crontab` configured with standard hourly/daily/weekly schedules.
* Custom Cron Directory (`/etc/cron.d/`):
  * `e2scrub_all`
  * `logicorp`

## 8. Discrepancies

### 1. Network Subnet and IP Configuration
* Documented State: Document C specifies a flat network operating on the `192.168.1.x` subnet, with `eth0` designated as WAN and `eth1` connected to the internal switch.
* Audit Reality: 
  * `eth0` is configured with a Link-Local address (`169.254.172.2/22`).
  * `eth1` is configured on a `10.42.66.225/16` subnet with default gateway `10.42.0.1`.
  * The documented `192.168.1.x` subnet is completely absent from the gateway's network interfaces.

---

### 2. Undocumented Listening Web Services
* Documented State: Document C and B state that only SSH (Port 22) and FTP (Port 21) are active on the gateway.
* Audit Reality: Two additional undocumented, high-risk web services are publicly exposed on `0.0.0.0`:
  * Port 3000 (TCP): Running `openvscode-server` (Web IDE) under the `root` user, with access tokens exposed in plain text within command-line process arguments.
  * Port 3001 (TCP): Running `ttyd` (Web Terminal) under the `root` user, with cleartext passwords exposed directly in process arguments.

---

### 3. System Environment and Architecture
* Documented State: Document A and D describe a traditional, dedicated Linux Gateway server managing physical routing, firewalling, and network switches.
* Audit Reality: The server is running in a Containerized Environment (PID 1 is `/bin/sh`, not `systemd`). 
  * Standard service management tools (`systemctl`, `ufw`) fail or are non-functional.
  * Network security filtering and firewall controls are delegated to the underlying host infrastructure rather than local kernel tools.

---

### 4. User Accounts and Active Sessions
* Documented State: Document C notes direct `root` SSH access enabled, but mentions no specific local user accounts.
* Audit Reality: 
  * A non-root user account `student` (UID 1000) exists.
  * An active SSH session is currently established by `student` on `pts/0`.
  * The `student` user has actively escalated privileges to `root` via `su root` (PID 53614).
  * An initialization script (`/etc/run.sh`) dynamically changes the `root` password on boot based on the hostname.

---

### 5. Scheduled Tasks and Outbound Traffic
* Documented State: No automated tasks, beacons, or background scripts were reported in the pre-sales specifications.
* Audit Reality: 
  * A custom cron job exists at `/etc/cron.d/logicorp`.
  * The cron daemon (`/usr/sbin/cron`) is actively executing scheduled tasks that make recurring outbound `curl` requests across the network.

## Summary Comparison Table

- IP Subnet: expected `192.168.1.x/24`, reality `10.42.0.0/16` (`eth1`), `169.254.0.0/22` (`eth0`)
- System Architecture: expected Standard Linux Server, reality Container (PID 1 = `/bin/sh`, no systemd)
- Active Ports: expected Ports 21 (FTP), 22 (SSH), reality Ports 21, 22, 3000 (`code-server`), 3001 (`ttyd`)
- Active Users: expected `root` via SSH, reality `root` and `student`
- Scheduled Tasks: expected None, reality `/etc/cron.d/logicorp` executing outbound `curl`