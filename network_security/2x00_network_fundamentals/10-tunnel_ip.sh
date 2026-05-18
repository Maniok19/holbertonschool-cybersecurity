#!/bin/bash
ip addr show tun0 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1