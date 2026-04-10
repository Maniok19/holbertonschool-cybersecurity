#!/bin/bash
ps -eo pid,pcpu,comm | awk '{print $1" "$3}' | sort -n | head -2
