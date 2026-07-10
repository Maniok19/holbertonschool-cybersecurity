#!/bin/bash
tshark -r "$1" -Y "icmp and frame.len > 100" -T fields -e ip.src