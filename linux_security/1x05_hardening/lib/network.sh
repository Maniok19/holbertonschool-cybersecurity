#!/bin/bash
ensure_firewall_rule()
{
    local key="$1"
    local value="$2"
    mkdir -p "$(dirname "$FW_POLICY_FILE")"
    if [ -f "$FW_POLICY_FILE" ] && grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$FW_POLICY_FILE"; then
        sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key}=${value}|" "$FW_POLICY_FILE"
    else
        printf '%s=%s\n' "$key" "$value" >> "$FW_POLICY_FILE"
    fi
}
write_firewall_policy()
{
    mkdir -p "$(dirname "$FW_POLICY_FILE")"
    cat > "$FW_POLICY_FILE" <<EOF
DEFAULT_INPUT=$DEFAULT_INPUT
DEFAULT_OUTPUT=$DEFAULT_OUTPUT
ALLOW_TCP=$SSH_PORT
ALLOW_TCP=$ALLOW_HTTP
ALLOW_TCP=$ALLOW_HTTPS
EOF
    log INFO "Firewall policy created at $FW_POLICY_FILE"
}
ensure_sysctl_setting()
{
    local key="$1"
    local value="$2"
    if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$SYSCTL_FILE"; then
        sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$SYSCTL_FILE"
    else
        printf '%s = %s\n' "$key" "$value" >> "$SYSCTL_FILE"
    fi
    log INFO "Updated $SYSCTL_FILE: $key = $value"
}
network_main()
{
    write_firewall_policy
    ensure_sysctl_setting "net.ipv4.ip_forward" "0"
    ensure_sysctl_setting "net.ipv4.icmp_echo_ignore_all" "1"
    log INFO "Kernel parameters updated in $SYSCTL_FILE"
}
