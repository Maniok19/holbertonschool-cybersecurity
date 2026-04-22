#!/bin/bash
ensure_setting() {
    local file="$1"
    local key="$2"
    local value="$3"
    if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+" "$file"; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*|${key} ${value}|" "$file"
    else
        printf '%s %s\n' "$key" "$value" >> "$file"
    fi
}
set_pam_rule() {
    local file="$1"
    local identifier="$2"
    local full_line="$3"
    if grep -q "$identifier" "$file"; then
        sed -i "s|.*$identifier.*|$full_line|" "$file"
    else
        sed -i "1i $full_line" "$file"
    fi
}
rule_i01() {
    ensure_setting "$LOGIN_DEFS_FILE" "PASS_MAX_DAYS" "$PASS_MAX_DAYS"
    local pam_pass="$PAM_PASSWORD_FILE"
    local args="retry=3 minlen=$PASS_MIN_LEN ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"
    set_pam_rule "$pam_pass" "pam_pwquality.so" "password requisite pam_pwquality.so $args"
    log INFO "Rule I-01: Password policy applied (length: $PASS_MIN_LEN, max days: $PASS_MAX_DAYS)."
}
rule_i02() {
    local pam_auth="$PAM_AUTH_FILE"
    local args="deny=$FAIL_LOCK_ATTEMPTS unlock_time=900"
    set_pam_rule "$pam_auth" "pam_faillock.so preauth"  "auth required pam_faillock.so preauth silent $args"
    set_pam_rule "$pam_auth" "pam_faillock.so authfail" "auth [default=die] pam_faillock.so authfail $args"
    set_pam_rule "$pam_auth" "pam_faillock.so authsucc" "auth sufficient pam_faillock.so authsucc $args"
    log INFO "Rule I-02: Account lockout enabled after $FAIL_LOCK_ATTEMPTS failed attempts."
}
rule_i03() {
    local user
    while IFS= read -r user; do
        if ! id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -Eq '^(sudo|wheel)$'; then
            userdel -r "$user" 2>/dev/null
            REMOVED_USERS+=("$user")
            log INFO "Rule I-03: Cleanup - deleted unauthorized user: $user"
        fi
    done < <(awk -F: '$3 > 1000 && $3 != 65534 {print $1}' "$PASSWD_FILE")
}
rule_i04() {
    passwd -l root >/dev/null 2>&1
    log INFO "Rule I-04: Root password locked."
}
id_main()
{
    rule_i01
    rule_i02
    rule_i03
    rule_i04
}
