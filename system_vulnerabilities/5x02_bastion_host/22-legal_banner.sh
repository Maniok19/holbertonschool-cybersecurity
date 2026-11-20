#!/bin/bash

echo "=== Legal Banner Configuration ==="
echo ""

BANNER_FILE="/etc/issue.net"
SSH_CONFIG="/etc/ssh/sshd_config"

echo "Creating banner in $BANNER_FILE..."
echo ""

# 1. Create the banner file
cat << 'EOF' > "$BANNER_FILE"
=====================================
AUTHORIZED ACCESS ONLY

This system is the property of NovaTech Solutions.
Unauthorized access is prohibited and will be prosecuted.
All activities are monitored and logged.
=====================================
EOF

# 2. Display the banner content
echo "Banner content:"
cat "$BANNER_FILE"
echo ""

# 3. Configure SSH
echo "Configuring SSH to display banner..."

# Check if the Banner directive already exists in the config
if grep -qiE "^\s*Banner\s+" "$SSH_CONFIG"; then
    # If it exists, update it
    sed -i -E "s|^\s*Banner\s+.*|Banner /etc/issue.net|i" "$SSH_CONFIG"
else
    # If it doesn't exist, append it
    echo "Banner /etc/issue.net" >> "$SSH_CONFIG"
fi
echo "  Banner $BANNER_FILE: Enabled"
echo ""

# 4. Reload SSH
echo "Reloading SSH..."
# Try to reload sshd or ssh (depending on the distro). Ignore errors if SSH isn't running in this container/VM.
systemctl reload sshd &>/dev/null || systemctl reload ssh &>/dev/null || service ssh reload &>/dev/null
echo ""

# 5. Verification
echo "Verification:"

# Verify banner file exists
if [ -f "$BANNER_FILE" ]; then
    echo "  $BANNER_FILE: EXISTS ✓"
else
    echo "  $BANNER_FILE: MISSING (Error)"
fi

# Verify SSH config is set correctly
if grep -qiE "^\s*Banner\s+$BANNER_FILE" "$SSH_CONFIG"; then
    echo "  SSH Banner config: ENABLED ✓"
else
    echo "  SSH Banner config: DISABLED (Error)"
fi
echo ""

echo "Legal banner configured."
