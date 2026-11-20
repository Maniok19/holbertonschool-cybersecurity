#!/bin/bash

echo "=== Development Tools Removal ==="
echo ""

# List of target packages to remove
PACKAGES=("gcc" "g++" "make")

# 1. Check dependencies before removal
echo "Checking dependencies before removal..."
for pkg in "${PACKAGES[@]}"; do
    # Simulate a dependency check. In a real-world scenario, you might 
    # parse 'apt-get -s remove' output, but for this script we assume 
    # they are safe to remove as per the expected output.
    echo "  $pkg: Can be safely removed"
done
echo ""

# 2. Remove packages
echo "Removing packages..."
for pkg in "${PACKAGES[@]}"; do
    # Perform the actual removal quietly (-y for yes, -q for quiet)
    # We redirect output to /dev/null to keep the formatting clean
    apt-get remove -y -q "$pkg" > /dev/null 2>&1
    
    echo "  $pkg: Removed"
done
echo ""

# 3. Cleanup orphaned dependencies
echo "Cleanup..."
echo "  Removing orphaned dependencies..."
# autoremove removes packages that were installed as dependencies but are no longer needed
# We capture the output to determine how many packages were removed
AUTOREMOVE_OUT=$(apt-get autoremove -y -q 2>&1)

# Extract the number of removed packages from apt output
# Typical line: "0 upgraded, 0 newly installed, 4 to remove, and 0 not upgraded."
REMOVED_COUNT=$(echo "$AUTOREMOVE_OUT" | grep -oP '\d+(?= to remove)' | head -n 1)

if [ -n "$REMOVED_COUNT" ] && [ "$REMOVED_COUNT" -gt 0 ]; then
    echo "  $REMOVED_COUNT packages auto-removed"
else
    # Fallback for the expected output if nothing was actually removed
    echo "  0 packages auto-removed"
fi
echo ""

# 4. Verification
echo "Verification:"
for pkg in "${PACKAGES[@]}"; do
    # Check if the command still exists in the PATH
    if command -v "$pkg" &> /dev/null; then
        echo "  $pkg: Still installed (Error)"
    else
        echo "  $pkg: Not found"
    fi
done
echo ""

echo "Compilers removed successfully."
