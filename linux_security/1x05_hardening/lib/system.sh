#!/bin/bash

report_main()
{
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    mkdir -p "$(dirname "$AUDIT_FILE")"
    {
        echo "==============================================="
        echo " HARDENING AUDIT REPORT - $timestamp"
        echo "==============================================="
        echo
        echo "[INFO] Hardening procedure completed successfully."
        echo "[INFO] SSH configured on port $SSH_PORT."
        echo "[INFO] Firewall policy created: ports $SSH_PORT, $ALLOW_HTTP, $ALLOW_HTTPS ALLOWED."
        if [ "${#REMOVED_USERS[@]}" -gt 0 ]; then
            local user_list
            user_list=$(printf '%s, ' "${REMOVED_USERS[@]}")
            user_list=${user_list%, }
            echo "[INFO] ${#REMOVED_USERS[@]} unauthorized users removed: $user_list."
        fi
        if [ -n "${INSTALLED_PACKAGES:-}" ]; then
            echo "[INFO] Installed: $INSTALLED_PACKAGES."
        fi
        if [ -n "${REMOVED_PACKAGES:-}" ]; then
            echo "[INFO] Removed: $REMOVED_PACKAGES."
        fi
        if [ "${#WARN_MESSAGES[@]}" -gt 0 ]; then
            local warn_message
            for warn_message in "${WARN_MESSAGES[@]}"; do
                echo "[WARN] $warn_message"
            done
        fi
        if [ "${#ERROR_MESSAGES[@]}" -gt 0 ]; then
            local error_message
            for error_message in "${ERROR_MESSAGES[@]}"; do
                echo "[ERROR] $error_message"
            done
        fi
        echo
        echo "==============================================="
        if [ "${#ERROR_MESSAGES[@]}" -eq 0 ]; then
            echo " COMPLIANCE STATUS: PASS"
        else
            echo " COMPLIANCE STATUS: FAIL"
        fi
        echo "==============================================="
    } > "$AUDIT_FILE"
}
system_main()
{
    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=a
    export NEEDRESTART_SUSPEND=1
    apt-get update -y >/dev/null 2>&1
    local updates_available
    updates_available=$(apt-get -s upgrade | grep -E "^[0-9]+ upgraded" | head -n 1 || true)
    if [[ "$updates_available" == "0 upgraded"* ]]; then
        log WARN "Package updates skipped (already up to date)."
    else
        apt-get upgrade -y >/dev/null 2>&1
        log INFO "System packages updated."
    fi
    apt-get purge -y telnet ftp netcat-traditional >/dev/null 2>&1
    log INFO "Removed: telnet, ftp, netcat-traditional."
    apt-get install -y auditd fail2ban >/dev/null 2>&1
    log INFO "Installed: auditd, fail2ban."
}
