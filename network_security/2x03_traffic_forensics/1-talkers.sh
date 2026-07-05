#!/bin/bash
tshark -n -r "$1" -T fields -e ip.src -e ipv6.src -E occurrence=f
