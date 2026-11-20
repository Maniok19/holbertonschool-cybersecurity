#!/bin/bash
# ==============================================================================
# Master Hardening Script for Ubuntu 20.04 Bastion Host
# ==============================================================================
# This script automates the security hardening of a fresh Ubuntu server.
# It is modular, idempotent, and logs all actions to a central log file.
# ==============================================================================

# Exit on error, treat unset variables as an error, and fail on pipe errors
set -euo pipefail

# --- Configuration ---
LOG_DIR="/var/log/hardening"
LOG_FILE="$LOG_DIR/master_harden.log"
SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"

# Ensure the script is run as root
if [[ "$EUID" -ne 0 ]]; then
    echo "Error: This script must be run as root (use sudo)." >&2
    exit 1
fi

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# --- Logging Function ---
log_action() {
    local msg="$1"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $msg" | tee -a "$LOG_FILE"
}

log_action "=== Starting Master Hardening Script ==="

# ==============================================================================
# Module 1: Kernel & Network Hardening (Sysctl)
# ==============================================================================
harden_sysctl() {
    log_action "Module 1: Applying Kernel & Network Hardening..."

    # Ensure the sysctl.d directory exists
    mkdir -p /etc/sysctl.d

    # Create the configuration file (overwriting it to ensure idempotency)
    cat << 'EOF' > "$SYSCTL_CONF"
# --- NovaTech Bastion Host Hardening ---

# 1. IP Forwarding (Disable)
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0

# 2. ICMP Redirects (Disable)
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0

# 3. Reverse Path Filtering (Strict)
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

# 4. SYN Cookies (Enable)
net.ipv4.tcp_syncookies=1

# 5. Source Routing (Disable)
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0

# 6. ICMP Configuration
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_echo_ignore_all=0
net.ipv4.icmp_ignore_bogus_error_responses=1
EOF

    # Apply the settings
    sysctl -p "$SYSCTL_CONF" > /dev/null
    log_action " -> Kernel parameters applied via $SYSCTL_CONF"
}

# ==============================================================================
# Module 2: Filesystem Hardening (/tmp, /var/tmp, /dev/shm)
# ==============================================================================
harden_filesystems() {
    log_action "Module 2: Hardening Temporary Filesystems..."

    # 2.1 Secure /tmp
    log_action "  Securing /tmp..."
    if ! mount | grep -q "on /tmp type tmpfs"; then
        # If /tmp is not a separate partition, bind mount it
        if ! grep -q "tmpfs /tmp tmpfs" /etc/fstab; then
            echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
        fi
        mount -o remount,noexec,nosuid,nodev /tmp || mount -o bind,noexec,nosuid,nodev /tmp /tmp
    fi

    # 2.2 Secure /var/tmp (Bind mount to /tmp)
    log_action "  Securing /var/tmp..."
    if ! grep -q "/var/tmp" /etc/fstab; then
        echo "/tmp /var/tmp none bind 0 0" >> /etc/fstab
        mount --bind /tmp /var/tmp
    fi

    # 2.3 Secure /dev/shm
    log_action "  Securing /dev/shm..."
    if ! grep -q "/dev/shm" /etc/fstab; then
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
        mount -o remount,noexec,nosuid,nodev /dev/shm
    else
        sed -i '/\/dev\/shm/ s/defaults/defaults,noexec,nosuid,nodev/' /etc/fstab
        mount -o remount,noexec,nosuid,nodev /dev/shm
    fi
    
    log_action " -> Temporary filesystems hardened."
}

# ==============================================================================
# Module 3: Package Minimization & SUID Neutralization
# ==============================================================================
harden_packages() {
    log_action "Module 3: Package Minimization & Privilege Escalation Defense..."

    # 3.1 Remove Compilers (Ignore errors if they aren't installed)
    log_action "  Removing development tools (gcc, g++, make)..."
    apt-get remove -y -q gcc g++ make > /dev/null 2>&1 || true
    apt-get autoremove -y -q > /dev/null 2>&1 || true

    # 3.2 Restrict Network Tools (if installed)
    log_action "  Restricting network tools to root..."
    local tools=("/usr/bin/nc" "/usr/bin/ncat" "/usr/bin/nmap" "/usr/sbin/tcpdump")
    for tool in "${tools[@]}"; do
        if [ -f "$tool" ]; then
            chmod 0750 "$tool"
            log_action "    Restricted $tool to 0750"
        fi
    done

    # 3.3 SUID Neutralization
    log_action "  Neutralizing non-essential SUID binaries..."
    local non_essential_suid=("/usr/bin/mount" "/usr/bin/umount" "/usr/bin/newgrp" "/usr/local/bin/backup")
    for bin in "${non_essential_suid[@]}"; do
        if [ -f "$bin" ] && [ -u "$bin" ]; then
            chmod u-s "$bin"
            log_action "    Removed SUID from $bin"
        fi
    done
}

# ==============================================================================
# Module 4: Service Minimization
# ==============================================================================
harden_services() {
    log_action "Module 4: Service Minimization..."

    local services=("cups.service" "avahi-daemon.service" "bluetooth.service")
    for svc in "${services[@]}"; do
        # Stop and disable if the service exists
        if systemctl list-unit-files | grep -q "^$svc"; then
            systemctl stop "$svc" > /dev/null 2>&1 || true
            systemctl disable "$svc" > /dev/null 2>&1 || true
            log_action "    Disabled and stopped $svc"
        fi
    done
}

# ==============================================================================
# Module 5: Access Control & Banners
# ==============================================================================
harden_access() {
    log_action "Module 5: Access Control & Banners..."

    # 5.1 Lock Root Account
    log_action "  Locking root account..."
    passwd -l root > /dev/null 2>&1 || true

    # 5.2 Legal Banner
    log_action "  Configuring SSH Legal Banner..."
    cat << 'EOF' > /etc/issue.net
=====================================
AUTHORIZED ACCESS ONLY

This system is the property of NovaTech Solutions.
Unauthorized access is prohibited and will be prosecuted.
All activities are monitored and logged.
=====================================
EOF

    # Update SSH config (idempotently)
    if ! grep -qiE "^\s*Banner\s+/etc/issue.net" /etc/ssh/sshd_config; then
        # Remove any existing Banner lines first
        sed -i '/^\s*Banner\s*/d' /etc/ssh/sshd_config
        echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
    fi

    # Reload SSH to apply the banner
    systemctl reload sshd > /dev/null 2>&1 || systemctl reload ssh > /dev/null 2>&1 || service ssh reload > /dev/null 2>&1 || true
    log_action " -> Access controls applied."
}

# ==============================================================================
# Main Execution Flow
# ==============================================================================
main() {
    harden_sysctl
    harden_filesystems
    harden_packages
    harden_services
    harden_access

    log_action "=== Hardening Completed Successfully ==="
    log_action "Review the log at: $LOG_FILE"
}

# Execute the main function
main
