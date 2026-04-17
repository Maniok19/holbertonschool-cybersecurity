#!/bin/bash

check_services()
{
    for svc in "${SERVICES[@]}" ; do
        if pgrep -f "$svc" > /dev/null; then
            log "SERVICE" "$svc" "OK" "Service is running"
            echo "OK: $svc is running"
        else
            eval "$svc"
            log "SERVICE" "$svc" "FIXED" "Restarted service"
            echo "FIXED: Restarted $svc"
        fi
    done
} 

check_integrity()
{
    for watch in "${FILES_TO_WATCH[@]}"; do
        GOLD=$(md5sum "/var/backups/sentinel/$(basename "$watch").gold")
        MD5=$(md5sum "$watch")
        if [ "$GOLD" == "$MD5" ]; then
            log "INTEGRITY" "$watch" "OK" "Integrity verified"
            echo "OK: $watch integrity verified"
        else
            cp "/var/backups/sentinel/$(basename "$watch").gold" $watch
            log "INTEGRITY" "$watch" "FIXED" "Restored"
            echo  "FIXED: Restored $watch"
        fi
    done
}

check_ports()
{
    PORTS=$(ss -Htnl | awk '{print $4}' | awk -F: '{print $NF}' | sort -u)
    for port in $PORTS; do
        isallow=false
        for allowed in "${ALLOWED_PORTS[@]}"; do
            if [ "$port" == "$allowed" ]; then
                isallow=true
            fi
        done
        if [ "$isallow" = false ]; then
        PID=$(ss -lptn "sport = :$port" | grep -oP 'pid=\K[0-9]+' | head -n 1)
            if [ -n "$PID" ]; then
                kill -9 "$PID"
                log "PORT" "$watch" "ALERT" "Killed rogue process"
                echo "ALERT: Killed rogue process on port $port"
            fi
        fi
    done
}

log() {
    local component=$1
    local target=$2
    local status=$3
    local details=$4
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local json_entry="{\"timestamp\": \"$timestamp\", \"component\": \"$component\", \"target\": \"$target\", \"status\": \"$status\", \"details\": \"$details\"}"

    echo "$json_entry" >> /var/log/sentinel.log
}

if [ ! -f "./sentinel.conf" ] ;then
exit 1

fi
source ./sentinel.conf

if [[ -z "${SERVICES[*]}" || -z "${FILES_TO_WATCH[*]}" ]]; then
exit 2
fi
check_services
check_integrity
check_ports
