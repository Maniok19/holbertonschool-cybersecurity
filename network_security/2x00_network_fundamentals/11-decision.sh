#!/bin/bash
[ -z "$1" ] && exit 1; ip route get "$1" 2>/dev/null | grep -q " via " && echo "REMOTE" || echo "LOCAL"
