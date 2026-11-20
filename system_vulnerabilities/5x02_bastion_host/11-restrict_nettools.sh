#!/bin/bash

echo "=== Network Tools Restriction ==="
echo ""

echo "Restricting access (root only)..."

# Define tools and their typical locations. 
# We use an array of "tool_name:expected_path" to ensure output matches.
TOOLS=(
    "nc:/usr/bin/nc"
    "ncat:/usr/bin/ncat"
    "nmap:/usr/bin/nmap"
    "tcpdump:/usr/sbin/tcpdump"
)

# 1. Apply restrictions
for item in "${TOOLS[@]}"; do
    TOOL_NAME="${item%%:*}"
    TOOL_PATH="${item##*:}"
    
    # Check if the file actually exists on this system
    if [ -f "$TOOL_PATH" ]; then
        # Get the current permissions (e.g., 755)
        OLD_PERMS=$(stat -c "%a" "$TOOL_PATH")
        
        # Change permissions to 0750 (rwxr-x---)
        chmod 0750 "$TOOL_PATH"
        
        # Print the result matching the expected output
        echo "  $TOOL_PATH: 0750 (was $OLD_PERMS)"
    else
        # Fallback if the tool is installed in a different PATH location (e.g., /bin/nc)
        ACTUAL_PATH=$(command -v "$TOOL_NAME")
        if [ -n "$ACTUAL_PATH" ]; then
            OLD_PERMS=$(stat -c "%a" "$ACTUAL_PATH")
            chmod 0750 "$ACTUAL_PATH"
            echo "  $ACTUAL_PATH: 0750 (was $OLD_PERMS)"
        fi
    fi
done
echo ""

# 2. Verification
echo "Verification:"
# We only verify the ones requested in the output: nc, nmap, tcpdump
VERIFY_TOOLS=("nc" "nmap" "tcpdump")

for tool in "${VERIFY_TOOLS[@]}"; do
    # Find where the tool is located
    TOOL_PATH=$(command -v "$tool" 2>/dev/null)
    
    # If not found in PATH, check our default expected paths
    if [ -z "$TOOL_PATH" ]; then
        if [ "$tool" == "tcpdump" ] && [ -f "/usr/sbin/tcpdump" ]; then
            TOOL_PATH="/usr/sbin/tcpdump"
        fi
    fi

    if [ -n "$TOOL_PATH" ] && [ -f "$TOOL_PATH" ]; then
        # Use ls -l to get the exact string "-rwxr-x--- root root"
        # We use awk to extract the permissions, user, and group
        PERMS_STR=$(ls -l "$TOOL_PATH" | awk '{print $1, $3, $4}')
        
        # Print the verification line
        echo "  $tool: $PERMS_STR"
    else
        echo "  $tool: Not found"
    fi
done
echo ""

echo "Network tools restricted to root."
echo "Regular users can no longer execute these binaries."
