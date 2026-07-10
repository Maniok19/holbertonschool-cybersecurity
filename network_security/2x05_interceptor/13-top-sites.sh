#!/bin/bash
awk '{print $7}' /var/log/squid/access.log | \
    grep -oP 'https?://([^/]+)' | \
    sed 's|https\?://||' | \
    sort | \
    uniq -c | \
    sort -rn | \
    head -10