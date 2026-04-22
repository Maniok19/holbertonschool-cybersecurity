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
ssh_main()
{
    ensure_sshd_setting "PasswordAuthentication" "no"
    ensure_sshd_setting "PubkeyAuthentication" "yes"
    ensure_sshd_setting "PermitRootLogin" "no"
    ensure_sshd_setting "Port" "$SSH_PORT"
    log INFO "SSH domain hardened: password authentication disabled and root login disabled."
}
