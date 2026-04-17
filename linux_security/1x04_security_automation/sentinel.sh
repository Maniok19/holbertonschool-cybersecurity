#!/bin/bash

check_services()
{
    for svc in "${SERVICES[@]}" ; do
        if pgrep -f "$svc" > /dev/null; then
            echo "OK: $svc is running"
        else
            eval "$svc"
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
            echo "OK: $watch integrity verified"
        else
            cp "/var/backups/sentinel/$(basename "$watch").gold" $watch
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
            fuser -k -n tcp "$port" > /dev/null 2>&1
            echo "ALERT: Killed rogue process on port $port"
        fi
    done
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
