# Mender Server Security POC Exploits

This directory contains proof-of-concept (POC) scripts to test the security vulnerabilities found in the Mender Server codebase.

## ⚠️ WARNING

**ONLY USE THESE SCRIPTS ON SYSTEMS YOU OWN OR HAVE EXPLICIT PERMISSION TO TEST!**

These scripts are designed to demonstrate security vulnerabilities and should only be run in:
- Controlled test environments
- Staging environments with permission
- Your own development instances

**NEVER run these against production systems or systems you don't own!**

## Prerequisites

- Python 3.6+
- `requests` library: `pip3 install requests`
- Access to a Mender Server test instance
- Valid user credentials for testing

## Vulnerabilities Tested

### 1. RBAC Scope Header Injection (CRITICAL)
**File**: `vulnerability_1_rbac_header_injection.py`

Tests if the system accepts client-controlled `X-MEN-RBAC-Inventory-Groups` headers without validation.

**Usage**:
```bash
python3 vulnerability_1_rbac_header_injection.py <base_url>
```

**Example**:
```bash
python3 vulnerability_1_rbac_header_injection.py https://staging.hosted.mender.io
```

### 2. JWT Identity Extraction Without Verification (HIGH)
**File**: `vulnerability_2_jwt_forgery.py`

Tests if the system accepts unsigned JWT tokens with arbitrary claims.

**Usage**:
```bash
python3 vulnerability_2_jwt_forgery.py <base_url>
```

### 3. Missing RBAC Scope Validation (HIGH)
**File**: Covered in `vulnerability_1_rbac_header_injection.py`

Tests the reporting API endpoints that use RBAC scope without validation.

### 4. Command Injection in Workflow CLI (CRITICAL)
**File**: `vulnerability_4_command_injection.py`

⚠️ **DANGEROUS**: This test attempts to execute commands on the server!

Tests if workflow CLI tasks can execute arbitrary commands through user input.

**Usage**:
```bash
python3 vulnerability_4_command_injection.py <base_url>
```

### 5. Path Traversal in File Transfer (MEDIUM)
**File**: `vulnerability_5_path_traversal.py`

Tests if file download/upload operations are vulnerable to path traversal attacks.

**Usage**:
```bash
python3 vulnerability_5_path_traversal.py <base_url>
```

## Running All Tests

Use the provided shell script to run all POC tests:

```bash
chmod +x run_all_pocs.sh
./run_all_pocs.sh <base_url>
```

Or manually run each test:

```bash
# Test 1: RBAC Header Injection
python3 vulnerability_1_rbac_header_injection.py https://staging.hosted.mender.io

# Test 2: JWT Forgery
python3 vulnerability_2_jwt_forgery.py https://staging.hosted.mender.io

# Test 4: Command Injection (WARNING: Executes commands!)
python3 vulnerability_4_command_injection.py https://staging.hosted.mender.io

# Test 5: Path Traversal
python3 vulnerability_5_path_traversal.py https://staging.hosted.mender.io
```

## Configuration

Before running the tests, you may need to modify the credentials in each script:

```python
USER_EMAIL = "test@example.com"
USER_PASSWORD = "testpassword"
```

Or pass them as environment variables (modify scripts to support this).

## Expected Results

### If Vulnerable:
- Scripts will show `[VULNERABLE]` or `[!] VULNERABILITY CONFIRMED` messages
- Commands may execute (Test 4)
- Unauthorized data may be accessed (Tests 1, 2, 5)

### If Patched:
- Scripts will show `[SECURE]` or `[+] No vulnerabilities found` messages
- Requests will be rejected with 401/403 status codes
- Commands will not execute

## Troubleshooting

### SSL Certificate Errors
The scripts use `verify=False` for testing. In production, use proper certificates.

### Authentication Failures
- Ensure you have valid credentials
- Check that the user has appropriate permissions
- Verify the base URL is correct

### Connection Errors
- Verify the base URL is accessible
- Check network connectivity
- Ensure the Mender Server is running

## Reporting Issues

If you find additional vulnerabilities or issues with these POC scripts:

1. **DO NOT** publicly disclose without permission
2. Follow responsible disclosure practices
3. Contact the Mender security team through proper channels

## Legal Notice

These scripts are provided for security testing and educational purposes only. Unauthorized use against systems you don't own is illegal and may result in criminal prosecution.

The authors and contributors are not responsible for any misuse of these scripts.

