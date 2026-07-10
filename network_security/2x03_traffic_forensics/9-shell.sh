#!/bin/bash
tshark -r "$1" -Y 'frame contains "uid=0" or frame contains "root"' -T fields -e tcp.stream 2>/dev/null