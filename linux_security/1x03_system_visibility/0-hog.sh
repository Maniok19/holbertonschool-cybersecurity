#!/bin/bash
ps -eo pid,pcpu,comm --sort=-pcpu | awk '{print $1" "$3}' | head -2
