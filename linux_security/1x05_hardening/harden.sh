#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check_root()
{
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run as root." >&2
        exit 1
    fi
}
log() {
    local level="INFO"
    local message
    if [ "$#" -gt 0 ] && [[ "$1" =~ ^(INFO|WARN|ERROR)$ ]]; then
        level="$1"
        shift
    fi
    message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    touch "$LOG_FILE" 2>/dev/null
    printf '[%s] [%s] %s\n' "$timestamp" "$level" "$message" >> "$LOG_FILE"
    case "$level" in
        WARN) WARN_MESSAGES+=("$message") ;;
        ERROR) ERROR_MESSAGES+=("$message") ;;
    esac
}
check_root
source "$SCRIPT_DIR/config/harden.cfg"
declare -ag REMOVED_USERS=()
declare -ag WARN_MESSAGES=()
declare -ag ERROR_MESSAGES=()
log "Hardening framework initialized"
source "$SCRIPT_DIR/lib/network.sh"
source "$SCRIPT_DIR/lib/ssh.sh"
source "$SCRIPT_DIR/lib/identity.sh"
source "$SCRIPT_DIR/lib/system.sh"
network_main
log "NETWORK configured"
ssh_main
log "SSH configured"
id_main
log "IDENTITY configured"
system_main
log "SYSTEM configured"
report_main
cat "$AUDIT_FILE"
