# Gap Analysis Report: LogiCorp Gateway & Network Security Overhaul

**Prepared By:** Mano Delcourt  
**Prepared For:** LogiCorp CEO  
**Date:** 27 July 2026

---

## 1. Executive Summary

Currently, LogiCorp has a serious security problem: everything is connected to a single gateway with no active firewall. Because of this, the critical shipping database, the finance team, and the administrator access are totally exposed to attacks from inside and outside.

To fix this quickly, we need to block all connections by default and divide the network into three separate areas (WAN, LAN, and DMZ). This strategy allows to secure the remote SSH access, keeping the main production running with zero downtime.

---

## 2. Current State Assessment

Based on our initial review of the client's documents, current setup has several security issues:

*  Network Layout:  The network is completely flat (`192.168.1.x`). Everything is plugged into the exact same switch gateway.
*  Documentation:  The diagram we received was wrong, the server is very likely different from the drawing.
*  Firewall:  There is no firewall running on the gateway. The server accepts and routes all network traffic without any filtering.
*  Remote Access:  SSH is open to the entire Internet (`0.0.0.0/0`), and direct login as the `root` user is enabled.
*  Legacy Apps:  The accounting team uploads invoices from home using old, unencrypted FTP. This sends usernames and passwords in plain text across the Internet.
*  Single Point of Failure:  The entire company relies on a single Linux gateway. If this server crashes, the whole network goes down.
---

## 3. Critical Gaps Identified

### Network Architecture Gaps
*   No Network Segmentation: Guest WiFi, office PCs, finance computers, and the main database are all on the same network.
*   No DMZ or Security Zones
*   Because the documentation is unverified, there is a risk that changing rules could accidentally break unknown background services.

### Access Control Gaps
*   SSH Open to the World: SSH is open to the entire Internet without any IP restrictions or jump server.
*   Direct Root Login Enabled: Anyone on the internet can attempt to log in directly as the `root` user, making brute-force attacks much easier.
*   No Default Firewall Rules: Without explicit firewall rules, the gateway accepts and forwards all network traffic by default.

### Encryption Gaps
*   Unencrypted FTP: anyone listening on the Internet connection can steal passwords.
*   Remote Management: Remote administration relies on basic SSH without mandatory SSH keys, IP whitelists, or a VPN tunnel.

### Monitoring Gaps
*   No Logs or Audit Trail: There is no firewall logging, intrusion detection, or centralized log system to detect attacks or investigate past security incidents.
*   No Network Traffic Visibility: Administrators cannot monitor live traffic.

---

## 4. Risk Assessment

### Critical Severity
*   SSH Exposed with Root Enabled: Anyone on the Internet can try to brute-force the `root` password and take complete control of the gateway.
*   Flat Network (Guest WiFi & Database together): A infected device on the  WiFi can easily attack or spread malware directly to the main database.
*   No Active Firewall: Because there are no firewall rules blocking bad traffic, any connection from the Internet can reach servers.

### High Severity
*   Cleartext FTP for Finance: Passwords and sensitive files sent over basic FTP can be spied from the Internet.
*   Unverified Documentation: Making firewall or network changes without knowing the exact live setup could accidentally crash production services.

### Medium Severity
*   No Logs or Monitoring: We cannot detect ongoing attacks or investigate what happened if another breach occurs.

### Low Severity
*   Single Gateway Failure Risk: If the gateway hardware fails, the entire company loses network access.
---

## 5. Preliminary Recommendations & Remediation Strategy

To fix the security issues without breaking applications or stopping daily business, we recommend the following plan:

1. Check the Live System First:
   * Before changing anything, inspect the running gateway using basic diagnostic commands (`ip`, `ss`, `iptables-save`) to see active network interfaces, open ports, and routing rules.

2. Separate the Network into 3 Zones:
   * WAN Zone (`eth0`): The untrusted public Internet.
   * LAN Zone: Internal office computers and database.
   * DMZ / Guest Zone: Isolated zone for Guest WiFi and public services.

3. Apply a "Default Deny" Firewall Policy:
   * Set firewall rules (`iptables` / `nftables`) to block (`DROP`) all incoming and forwarded traffic by default.
   * Only allow necessary traffic and existing connections (`ESTABLISHED, RELATED`).

4. Secure Remote SSH Access:
   * Turn off direct root login (`PermitRootLogin no`).
   * Require SSH keys instead of plain passwords, or restrict access to trusted IP addresses.

5. Protect the FTP Flow:
   * Secure the FTP connection without breaking the finance software by enabling FTPS or using an encrypted proxy tunnel on the gateway.

6. Deployment Safety & Rollback Plan:
   * Prepare automatic rollback scripts to prevent getting locked out during setup.
   * Deploy the final configuration during maintenance window.