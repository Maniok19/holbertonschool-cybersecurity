#!/bin/bash
tshark -r "$1" -Y "http.user_agent" -T fields -e http.user_agent 2>/dev/null|sort -u