#!/bin/bash
if ! ls $1 &>/dev/null;then
    exit 1
else
    mkdir "$1/backups/" &>/dev/null
    ls $1/*.log 2>/dev/null | while read log;do
        s=$(stat -c%s "$1/$log" 2>/dev/null)
        if [ -n "$s" ] && [ "$s" -gt 1024 ];then
            gzip "$1/$log" &>/dev/null
            mv $1/${log}.gz "$1/backups/" &>/dev/null
        else
            echo "Skipping small file: $log"
        fi
    done 
fi
# for 
# *.log
# ,: wc  +-c | stat 