#!/bin/bash

echo "=== Living off the Land Binaries Audit ==="
echo ""

echo "Checking GTFOBins candidates..."
echo ""

# Function to check a binary and print its permissions
# Usage: check_bin "category_header" "/path/to/binary" "status_message"
print_category() {
    echo "$1"
}

check_bin() {
    local path="$1"
    local status="$2"
    
    if [ -f "$path" ]; then
        # Extract just the permission string (e.g., -rwxr-xr-x)
        local perms=$(ls -ld "$path" | awk '{print $1}')
        echo "  $path: $perms ($status)"
    else
        # Fallback if the binary is not found (useful for cross-distro compatibility)
        echo "  $path: Not found"
    fi
}

# 1. File Readers
print_category "File Readers (can read sensitive files):"
check_bin "/usr/bin/cat" "OK"
check_bin "/usr/bin/less" "OK"
check_bin "/usr/bin/vim" "WARNING: Can escape to shell"
echo ""

# 2. Shell Escapes
print_category "Shell Escapes:"
# Note: Python3 is often at /usr/bin/python3, perl at /usr/bin/perl, awk at /usr/bin/awk
check_bin "/usr/bin/python3" "WARNING: Can spawn shells"
check_bin "/usr/bin/perl" "WARNING: Can spawn shells"
check_bin "/usr/bin/awk" "OK"
echo ""

# 3. Network Tools
print_category "Network Tools:"
check_bin "/usr/bin/wget" "WARNING: Can download payloads"
check_bin "/usr/bin/curl" "WARNING: Can download payloads"
echo ""

echo "Note: These binaries are legitimate but should be monitored."
echo "See https://gtfobins.github.io/ for abuse techniques."
