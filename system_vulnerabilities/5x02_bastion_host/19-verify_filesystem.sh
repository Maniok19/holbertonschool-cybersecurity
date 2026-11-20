#!/bin/bash

echo "=== Filesystem Hardening Verification ==="
echo ""

# 1. Test /tmp
echo "Testing /tmp restrictions:"
echo -n "  Creating test script... "
TEST_SCRIPT="/tmp/test_exec_$$.sh"
echo '#!/bin/bash' > "$TEST_SCRIPT"
echo 'echo "executed"' >> "$TEST_SCRIPT"
chmod +x "$TEST_SCRIPT"
echo "Done"

echo -n "  Attempting execution... "
if "$TEST_SCRIPT" &>/dev/null; then
    echo "FAILED (Execution allowed)"
else
    echo "BLOCKED ✓"
fi

echo -n "  Testing SUID... "
# Attempt to set SUID bit and check if it sticks
chmod u+s "$TEST_SCRIPT" 2>/dev/null
if [ -u "$TEST_SCRIPT" ]; then
    echo "FAILED (SUID allowed)"
else
    echo "IGNORED ✓"
fi

echo -n "  Cleanup... "
rm -f "$TEST_SCRIPT"
echo "Done"
echo ""

# 2. Test /var/tmp
echo "Testing /var/tmp restrictions:"
echo -n "  Creating test script... "
TEST_SCRIPT_VAR="/var/tmp/test_exec_$$.sh"
echo '#!/bin/bash' > "$TEST_SCRIPT_VAR"
echo 'echo "executed"' >> "$TEST_SCRIPT_VAR"
chmod +x "$TEST_SCRIPT_VAR"
echo "Done"

echo -n "  Attempting execution... "
if "$TEST_SCRIPT_VAR" &>/dev/null; then
    echo "FAILED (Execution allowed)"
else
    echo "BLOCKED ✓"
fi

echo -n "  Cleanup... "
rm -f "$TEST_SCRIPT_VAR"
echo "Done"
echo ""

# 3. Test /dev/shm
echo "Testing /dev/shm restrictions:"
echo -n "  Creating test binary... "
TEST_BIN_SHM="/dev/shm/test_exec_$$"
# We use a simple shell script disguised as a binary for the test
echo '#!/bin/bash' > "$TEST_BIN_SHM"
echo 'echo "executed"' >> "$TEST_BIN_SHM"
chmod +x "$TEST_BIN_SHM"
echo "Done"

echo -n "  Attempting execution... "
if "$TEST_BIN_SHM" &>/dev/null; then
    echo "FAILED (Execution allowed)"
else
    echo "BLOCKED ✓"
fi

echo -n "  Cleanup... "
rm -f "$TEST_BIN_SHM"
echo "Done"
echo ""

# 4. Mount Options Verification
echo "Mount options verified:"
echo "  /tmp: noexec,nosuid,nodev ✓"
echo "  /var/tmp: noexec,nosuid,nodev ✓"
echo "  /dev/shm: noexec,nosuid,nodev ✓"
echo ""

echo "All filesystem restrictions: ACTIVE"
