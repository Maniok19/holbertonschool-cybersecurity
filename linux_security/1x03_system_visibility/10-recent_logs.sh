#!/bin/bash
awk -v t=$(date -d '30 min ago' +%T) '$3 >= t && /sshd/' "$1"