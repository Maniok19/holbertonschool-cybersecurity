#!/bin/bash
ensure_sshd_setting()
{
    local key="$1"
    local value="$2"
    if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+" "$SSHD_CONFIG" ; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*|${key} ${value}|" "$SSHD_CONFIG"
    else
        printf '%s %s\n' "$key" "$value" >> "$SSHD_CONFIG"
    fi
    log INFO "Updated SSHD config: $key $value"
}
reload_ssh_service()
{
    if [ ! -d /run/systemd/system ]; then
        log WARN "systemd is not available; SSH reload skipped. Changes will apply on reboot."
        return 0
    fi

    if systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1; then
        log INFO "SSH service reloaded."
    else
        log WARN "Unable to reload SSH service; changes will apply on reboot."
    fi
}
ssh_main()
{
    ensure_sshd_setting "PasswordAuthentication" "no"
    ensure_sshd_setting "PubkeyAuthentication" "yes"
    ensure_sshd_setting "PermitRootLogin" "no"
    ensure_sshd_setting "Port" "$SSH_PORT"
    reload_ssh_service
    log INFO "SSH domain hardened: password authentication disabled and root login disabled."
}
