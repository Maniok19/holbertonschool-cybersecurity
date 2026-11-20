#!/bin/bash

echo "=== Package Security Audit ==="
echo ""

# Initialize counters
DEV_COUNT=0
NET_COUNT=0
REMOTE_COUNT=0

# Function to check for a binary and print the result
# Usage: check_pkg "binary_name" "Display Name" "Description" "Category"
check_pkg() {
    local bin="$1"
    local name="$2"
    local desc="$3"
    local category="$4"
    
    # Check if the command exists in the system's PATH
    if command -v "$bin" &> /dev/null; then
        echo "  [FOUND] $name ($desc)"
        
        # Increment the appropriate counter
        case "$category" in
            "dev") ((DEV_COUNT++)) ;;
            "net") ((NET_COUNT++)) ;;
            "remote") ((REMOTE_COUNT++)) ;;
        esac
    fi
}

# 1. Check for development tools
echo "Checking for development tools..."
check_pkg "gcc" "gcc" "GNU C Compiler" "dev"
check_pkg "g++" "g++" "GNU C++ Compiler" "dev"
check_pkg "make" "make" "Build automation" "dev"
check_pkg "gdb" "gdb" "Debugger" "dev"
echo ""

# 2. Check for network tools
echo "Checking for network tools..."
check_pkg "nc" "netcat-openbsd" "Network Swiss Army Knife" "net"
check_pkg "nmap" "nmap" "Network scanner" "net"
check_pkg "tcpdump" "tcpdump" "Packet capture" "net"
echo ""

# 3. Check for remote access tools
echo "Checking for remote access tools..."
check_pkg "telnet" "telnet" "Insecure remote access" "remote"
echo ""

# 4. Summary
echo "Summary:"
echo "  Development tools: $DEV_COUNT found"
echo "  Network tools: $NET_COUNT found"
echo "  Remote access: $REMOTE_COUNT found"
echo ""

echo "Recommendation: Review and remove unnecessary packages."
