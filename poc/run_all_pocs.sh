#!/bin/bash
#
# Run all POC scripts for Mender Server vulnerabilities
#
# WARNING: Only run this on systems you own or have explicit permission to test!
#

set -e

BASE_URL="${1:-https://staging.hosted.mender.io}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo "Mender Server Security POC Test Suite"
echo "============================================================"
echo ""
echo "Target: $BASE_URL"
echo "WARNING: These tests attempt to exploit vulnerabilities!"
echo "Only run on test/staging environments!"
echo ""
read -p "Press Enter to continue or Ctrl+C to abort..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[-] python3 not found. Please install Python 3."
    exit 1
fi

# Install required packages
echo "[*] Checking Python dependencies..."
python3 -m pip install --quiet requests 2>/dev/null || {
    echo "[-] Failed to install requests. Run: pip3 install requests"
    exit 1
}

echo ""
echo "============================================================"
echo "Running POC Tests"
echo "============================================================"
echo ""

# Test 1: RBAC Header Injection
echo "[TEST 1/5] RBAC Scope Header Injection (CRITICAL)"
echo "------------------------------------------------------------"
python3 "$SCRIPT_DIR/vulnerability_1_rbac_header_injection.py" "$BASE_URL"
echo ""

# Test 2: JWT Forgery
echo "[TEST 2/5] JWT Identity Extraction Without Verification (HIGH)"
echo "------------------------------------------------------------"
python3 "$SCRIPT_DIR/vulnerability_2_jwt_forgery.py" "$BASE_URL"
echo ""

# Test 3: RBAC Scope Validation (same as test 1, different endpoint)
echo "[TEST 3/5] Missing RBAC Scope Validation (HIGH)"
echo "------------------------------------------------------------"
echo "[NOTE] This is tested as part of Test 1 (reporting API endpoints)"
echo ""

# Test 4: Command Injection
echo "[TEST 4/5] Command Injection in Workflow CLI (CRITICAL)"
echo "------------------------------------------------------------"
echo "[!] WARNING: This test attempts to execute commands on the server!"
read -p "Continue with command injection test? (y/N): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    python3 "$SCRIPT_DIR/vulnerability_4_command_injection.py" "$BASE_URL"
else
    echo "[SKIPPED] Command injection test skipped by user"
fi
echo ""

# Test 5: Path Traversal
echo "[TEST 5/5] Path Traversal in File Transfer (MEDIUM)"
echo "------------------------------------------------------------"
python3 "$SCRIPT_DIR/vulnerability_5_path_traversal.py" "$BASE_URL"
echo ""

echo "============================================================"
echo "POC Test Suite Complete"
echo "============================================================"
echo ""
echo "Review the output above for vulnerability confirmations."
echo "Check CRITICAL_VULNERABILITIES.md for detailed information."

