#!/bin/bash
tshark -r "$1" -Y "tcp contains \"uid=0\" or tcp contains \"root\"" -T fields -e tcp.dstport | head -n 1