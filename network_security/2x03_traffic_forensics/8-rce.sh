#!/bin/bash
tshark -r "$1" -Y 'frame contains "/bin/sh"' -T fields -e frame.number 2>/dev/null