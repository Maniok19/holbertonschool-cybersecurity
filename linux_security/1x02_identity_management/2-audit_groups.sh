#!/bin/bash
awk -F: '$3>=1000{print $1}' "$1"  | while read u;do
    for g in disk docker shadow;do
        id -nG "$u" |
        grep -qw "$g" && echo "$u:$g";done;done
