# POC Exploits Summary

This document provides an overview of the proof-of-concept exploits created for each vulnerability.

## Created POC Scripts

### 1. `vulnerability_1_rbac_header_injection.py` (CRITICAL)
**Vulnerability**: RBAC Scope Header Injection / Authorization Bypass

**What it tests**:
- Injects unauthorized device group names in `X-MEN-RBAC-Inventory-Groups` header
- Attempts to access devices from groups the user shouldn't have access to
- Tests both inventory and reporting API endpoints

**How to run**:
```bash
python3 poc/vulnerability_1_rbac_header_injection.py https://staging.hosted.mender.io
```

**Expected vulnerable behavior**:
- System accepts the injected header without validation
- Returns devices from unauthorized groups
- Shows `[VULNERABLE]` messages

**Expected secure behavior**:
- System rejects requests with unauthorized groups
- Returns 403 Forbidden or filters results properly

---

### 2. `vulnerability_2_jwt_forgery.py` (HIGH)
**Vulnerability**: JWT Identity Extraction Without Signature Verification

**What it tests**:
- Creates unsigned JWT tokens with arbitrary claims (admin user, different tenant, etc.)
- Tests if endpoints accept these forged tokens
- Attempts tenant isolation bypass

**How to run**:
```bash
python3 poc/vulnerability_2_jwt_forgery.py https://staging.hosted.mender.io
```

**Expected vulnerable behavior**:
- Endpoints accept unsigned JWT tokens
- Allows access with forged admin claims
- Shows `[VULNERABLE]` messages

**Expected secure behavior**:
- All endpoints reject unsigned tokens with 401 Unauthorized
- Shows `[SECURE]` messages

---

### 3. `vulnerability_4_command_injection.py` (CRITICAL)
**Vulnerability**: Command Injection in Workflow CLI Task Execution

**⚠️ DANGEROUS**: This script attempts to execute commands on the server!

**What it tests**:
- Creates workflows with CLI tasks that execute user-controlled commands
- Tests command injection through workflow input parameters
- Attempts path traversal in file inclusion (`@/etc/passwd`)

**How to run**:
```bash
python3 poc/vulnerability_4_command_injection.py https://staging.hosted.mender.io
```

**Expected vulnerable behavior**:
- Commands execute successfully
- Command output is returned in workflow results
- Shows `[VULNERABLE]` and command output

**Expected secure behavior**:
- Workflow creation is restricted to authorized users
- Commands are sanitized/whitelisted
- Shows errors or rejects malicious commands

**⚠️ WARNING**: This test will execute commands like `id`, `whoami`, `cat /etc/passwd` on the server!

---

### 4. `vulnerability_5_path_traversal.py` (MEDIUM)
**Vulnerability**: Path Traversal in File Transfer Operations

**What it tests**:
- Attempts to download files using path traversal (`/etc/../etc/passwd`)
- Tests file upload with malicious paths
- Tries to access sensitive system files

**How to run**:
```bash
python3 poc/vulnerability_5_path_traversal.py https://staging.hosted.mender.io
```

**Expected vulnerable behavior**:
- File operations succeed with traversal paths
- Sensitive files can be downloaded
- Shows `[VULNERABLE]` messages

**Expected secure behavior**:
- Paths are normalized and validated
- Traversal attempts are rejected with 400 Bad Request
- Shows `[SECURE]` messages

---

## Running All Tests

### Linux/Mac:
```bash
cd poc
chmod +x run_all_pocs.sh
./run_all_pocs.sh https://staging.hosted.mender.io
```

### Windows:
```cmd
cd poc
run_all_pocs.bat https://staging.hosted.mender.io
```

### Manual (any OS):
```bash
# Test 1
python3 poc/vulnerability_1_rbac_header_injection.py <base_url>

# Test 2
python3 poc/vulnerability_2_jwt_forgery.py <base_url>

# Test 4 (WARNING: Executes commands!)
python3 poc/vulnerability_4_command_injection.py <base_url>

# Test 5
python3 poc/vulnerability_5_path_traversal.py <base_url>
```

## Configuration

Before running, update credentials in each script:
- `USER_EMAIL = "test@example.com"`
- `USER_PASSWORD = "testpassword"`

Or modify scripts to accept credentials as command-line arguments or environment variables.

## Interpreting Results

### Vulnerability Confirmed
Look for these indicators:
- `[VULNERABLE]` messages
- `[!] VULNERABILITY CONFIRMED` messages
- Successful unauthorized access
- Command execution (Test 4)
- Data exfiltration

### System Secure
Look for these indicators:
- `[SECURE]` messages
- `[+] No vulnerabilities found` messages
- 401/403 status codes
- Request rejections
- Proper validation errors

## Safety Notes

1. **Only test on systems you own or have permission to test**
2. **Never run against production systems**
3. **Test 4 executes commands - use extreme caution**
4. **Review output carefully before drawing conclusions**
5. **Some tests may require specific environment setup** (e.g., active devices for Test 5)

## Troubleshooting

### Common Issues

**Authentication failures**:
- Verify credentials are correct
- Check user has necessary permissions
- Ensure base URL is correct

**Connection errors**:
- Verify network connectivity
- Check base URL is accessible
- Ensure Mender Server is running

**SSL errors**:
- Scripts use `verify=False` for testing
- In production, use proper certificates
- May need to set `PYTHONHTTPSVERIFY=0` environment variable

**No devices found (Test 5)**:
- Test 5 requires active device connections
- Set up test devices first
- Or skip this test if not applicable

## Next Steps

After running POCs:

1. **Document results**: Note which vulnerabilities are confirmed
2. **Prioritize fixes**: Start with CRITICAL vulnerabilities
3. **Implement fixes**: Follow recommendations in `CRITICAL_VULNERABILITIES.md`
4. **Re-test**: Run POCs again after fixes to verify
5. **Report**: Follow responsible disclosure if reporting to vendor

## Legal Disclaimer

These POC scripts are for security testing and educational purposes only. Unauthorized use against systems you don't own is illegal. Use responsibly and ethically.

