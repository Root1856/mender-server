# Critical Security Vulnerabilities Found

## Summary
This document outlines critical security vulnerabilities discovered in the Mender Server codebase during security review.

---

## 1. RBAC Scope Header Injection / Client-Controlled Authorization Bypass

### Severity: CRITICAL
### CWE: CWE-284 (Improper Access Control), CWE-639 (Authorization Bypass Through User-Controlled Key)

### Description
The RBAC (Role-Based Access Control) system allows client-controlled headers to directly influence authorization scope without proper validation. The `X-MEN-RBAC-Inventory-Groups` and `X-MEN-RBAC-Releases-Tags` headers are extracted from client requests and used to filter resources without verifying that the user has permission to access those groups.

### Location
- **File**: `backend/pkg/rbac/middleware.go`
- **File**: `backend/pkg/rbac/rbac.go`
- **File**: `backend/services/reporting/api/http/management_devices.go` (lines 183-184)
- **File**: `backend/services/reporting/api/http/management_deployments.go` (lines 71, 130)

### Vulnerable Code

**backend/pkg/rbac/middleware.go:20-27**
```go
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if scope := ExtractScopeFromHeader(c.Request); scope != nil {
			ctx := c.Request.Context()
			ctx = WithContext(ctx, scope)
			c.Request = c.Request.WithContext(ctx)
		}
	}
}
```

**backend/pkg/rbac/rbac.go:49-63**
```go
func ExtractScopeFromHeader(r *http.Request) *Scope {
	groupStr := r.Header.Get(ScopeHeader)
	tagsStr := r.Header.Get(ScopeReleaseTagsHeader)
	if len(groupStr) > 0 || len(tagsStr) > 0 {
		scope := Scope{}
		if len(groupStr) > 0 {
			scope.DeviceGroups = strings.Split(groupStr, ",")
		}
		if len(tagsStr) > 0 {
			scope.ReleaseTags = strings.Split(tagsStr, ",")
		}
		return &scope
	}
	return nil
}
```

**backend/services/reporting/api/http/management_devices.go:183-185**
```go
if scope := rbac.ExtractScopeFromHeader(c.Request); scope != nil {
	searchParams.Groups = scope.DeviceGroups
}
```

### Impact
1. **Authorization Bypass**: A user with limited RBAC permissions can inject arbitrary device group names or release tags in the request headers to access resources they should not have access to.
2. **Data Exfiltration**: Users can enumerate and access devices from groups they don't have permission to view.
3. **Privilege Escalation**: Lower-privilege users can potentially access resources restricted to higher-privilege roles.

### Attack Scenario
1. A user with RBAC restrictions (e.g., can only access "group1") authenticates normally.
2. The user sends a request with header: `X-MEN-RBAC-Inventory-Groups: group1,admin-group,sensitive-group`
3. The middleware extracts this header without validation.
4. The application filters devices based on the injected groups, allowing access to unauthorized groups.

### Recommended Fix
1. **Validate RBAC headers against user permissions**: The headers should be validated against the user's actual RBAC permissions stored in the database/token claims.
2. **Remove direct header extraction**: Instead of extracting from request headers directly, the scope should be derived from the authenticated user's permissions.
3. **Server-side validation**: If headers are set by Traefik forwardAuth, ensure they cannot be overridden by client requests and validate them server-side.

### Example Fix
```go
func Middleware(authorizer RBACAuthorizer) gin.HandlerFunc {
	return func(c *gin.Context) {
		identity := identity.FromContext(c.Request.Context())
		if identity == nil {
			return
		}
		
		// Get user's actual permissions from database/token
		userScope, err := authorizer.GetUserScope(c.Request.Context(), identity.Subject)
		if err != nil {
			return
		}
		
		// Validate requested scope against user's actual permissions
		requestedScope := ExtractScopeFromHeader(c.Request)
		if requestedScope != nil {
			validatedScope := validateScope(requestedScope, userScope)
			if validatedScope != nil {
				ctx := WithContext(c.Request.Context(), validatedScope)
				c.Request = c.Request.WithContext(ctx)
			}
		}
	}
}
```

---

## 2. JWT Identity Extraction Without Signature Verification (Potential Bypass)

### Severity: HIGH (if used incorrectly)
### CWE: CWE-345 (Insufficient Verification of Data Authenticity)

### Description
The `ExtractIdentity` function in `backend/pkg/identity/token.go` explicitly does NOT perform JWT signature verification. While this may be intentional if used after Traefik forwardAuth verification, it creates a risk if:
1. The middleware is used in paths that bypass Traefik
2. There are internal service-to-service calls that don't go through Traefik
3. The identity is used for authorization decisions without additional verification

### Location
- **File**: `backend/pkg/identity/token.go` (lines 62-85)
- **File**: `backend/pkg/identity/middleware.go` (lines 50-93, 95-117)
- **File**: `backend/services/deviceconnect/api/http/identity.go` (lines 29-43)

### Vulnerable Code

**backend/pkg/identity/token.go:62-85**
```go
// Generate identity information from given JWT by extracting subject and tenant claims.
// Note that this function does not perform any form of token signature
// verification.
func ExtractIdentity(token string) (id Identity, err error) {
	var (
		claims []byte
		jwt    []string
	)
	jwt = strings.Split(token, ".")
	if len(jwt) != 3 {
		return id, errors.New("identity: incorrect token format")
	}
	claims, err = base64.RawURLEncoding.DecodeString(jwt[1])
	if err != nil {
		return id, errors.Wrap(err,
			"identity: failed to decode base64 JWT claims")
	}
	err = json.Unmarshal(claims, &id)
	if err != nil {
		return id, errors.Wrap(err,
			"identity: failed to decode JSON JWT claims")
	}
	return id, id.Validate()
}
```

### Impact
1. **Token Forgery**: An attacker could craft a JWT with arbitrary claims (tenant ID, user ID, roles) without a valid signature.
2. **Tenant Isolation Bypass**: An attacker could set an arbitrary tenant ID to access other tenants' data.
3. **Privilege Escalation**: An attacker could set `mender.user: true` or modify plan/addon claims.

### Attack Scenario
1. An attacker crafts a JWT with:
   - `sub`: Admin user ID
   - `mender.tenant`: Target tenant ID
   - `mender.user`: true
   - `mender.plan`: "enterprise"
2. If this token is used in a path that bypasses Traefik forwardAuth, the identity middleware will accept it.
3. The attacker gains unauthorized access to the target tenant's resources.

### Recommended Fix
1. **Always verify JWT signatures**: If `ExtractIdentity` is used in security-sensitive contexts, ensure signature verification happens before or after extraction.
2. **Document usage**: Clearly document that this function should only be used after signature verification.
3. **Add signature verification option**: Consider adding an optional signature verification parameter.

### Example Fix
```go
func ExtractIdentityWithVerification(token string, verifier JWTVerifier) (id Identity, err error) {
	// Verify signature first
	if err := verifier.Verify(token); err != nil {
		return id, errors.Wrap(err, "JWT signature verification failed")
	}
	
	// Then extract identity
	return ExtractIdentity(token)
}
```

---

## 3. Missing Validation of RBAC Scope in Search Operations

### Severity: HIGH
### CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)

### Description
The reporting service directly uses client-provided RBAC scope headers without validating them against the user's actual permissions. This allows users to specify arbitrary device groups in search operations.

### Location
- **File**: `backend/services/reporting/api/http/management_devices.go` (line 183)
- **File**: `backend/services/reporting/api/http/management_deployments.go` (lines 71, 130)

### Vulnerable Code

**backend/services/reporting/api/http/management_devices.go:183-185**
```go
if scope := rbac.ExtractScopeFromHeader(c.Request); scope != nil {
	searchParams.Groups = scope.DeviceGroups
}
```

### Impact
- Users can search for devices in groups they don't have access to
- Data leakage across RBAC boundaries
- Violation of least privilege principle

### Recommended Fix
Validate the requested groups against the user's actual RBAC permissions before using them in search operations.

---

## Additional Security Observations

### 1. Artifact Signature Verification
The artifact upload process has a `skipVerify` parameter that bypasses signature verification. This should be carefully controlled and only used in specific, secure contexts.

**Location**: `backend/services/deployments/app/app.go` (line 362)

### 2. Tenant Token Access
According to the program guidelines, all users can access tenant tokens. While this is documented as "working as intended," it's worth noting as a potential security consideration for future improvements.

---

## Testing Recommendations

1. **Test RBAC header injection**: Attempt to access resources by injecting `X-MEN-RBAC-Inventory-Groups` headers with unauthorized group names.
2. **Test JWT token forgery**: Craft unsigned JWTs with arbitrary claims and test if they're accepted in internal service calls.
3. **Test scope validation**: Verify that RBAC scope is properly validated against user permissions in all search/filter operations.

---

## 4. Command Injection in Workflow CLI Task Execution

### Severity: CRITICAL
### CWE: CWE-78 (OS Command Injection)

### Description
The workflow system executes CLI commands from user-controlled input without proper sanitization. While commands are processed through `ProcessJobString` for template variable substitution, there's no validation that prevents command injection through workflow input parameters.

### Location
- **File**: `backend/services/workflows/app/worker/cli.go` (lines 32-77)
- **File**: `backend/services/workflows/app/worker/utils.go` (lines 24-35)

### Vulnerable Code

**backend/services/workflows/app/worker/cli.go:32-57**
```go
func processCLITask(
	cliTask *model.CLITask,
	ps *processor.JobStringProcessor,
	jp *processor.JobProcessor,
) (*model.TaskResult, error) {
	commands := make([]string, 0, 10)
	for _, command := range cliTask.Command {
		command := ps.ProcessJobString(command)
		commands = append(commands, command)
	}
	// ...
	cmd := exec.CommandContext(ctxWithOptionalTimeOut, commands[0], commands[1:]...)
	// ...
}
```

**backend/services/workflows/app/worker/utils.go:24-35**
```go
func processJobStringOrFile(data string, ps *processor.JobStringProcessor) (string, error) {
	data = ps.ProcessJobString(data)
	if strings.HasPrefix(data, "@") {
		filePath := data[1:]
		buffer, err := os.ReadFile(filePath)
		// No path traversal validation!
		// ...
	}
	return data, nil
}
```

### Impact
1. **Remote Code Execution**: An attacker who can create or trigger workflows with CLI tasks can execute arbitrary commands on the server.
2. **Server Compromise**: Full system compromise if the workflow service runs with elevated privileges.
3. **Data Exfiltration**: Access to database credentials, secrets, and sensitive data.
4. **Path Traversal**: The `processJobStringOrFile` function reads files based on user input without path traversal protection.

### Attack Scenario
1. An attacker creates or modifies a workflow with a CLI task.
2. The CLI task command includes workflow input parameters: `["/bin/sh", "-c", "${workflow.input.command}"]`
3. When the workflow is triggered with `command: "rm -rf / || echo 'pwned'"`, the command is executed.
4. Alternatively, using file inclusion: `"@/etc/passwd"` could read sensitive files.

### Recommended Fix
1. **Whitelist allowed commands**: Maintain a list of allowed executables and validate against it.
2. **Sanitize input parameters**: Escape or validate all workflow input parameters before substitution.
3. **Path traversal protection**: Validate file paths in `processJobStringOrFile` to prevent directory traversal.
4. **Restrict workflow creation**: Ensure only authorized users can create/modify workflows with CLI tasks.
5. **Sandbox execution**: Run CLI tasks in a sandboxed environment with minimal privileges.

### Example Fix
```go
var allowedCommands = map[string]bool{
	"/usr/bin/echo": true,
	"/bin/cat": true,
	// ... whitelist
}

func processCLITask(
	cliTask *model.CLITask,
	ps *processor.JobStringProcessor,
	jp *processor.JobProcessor,
) (*model.TaskResult, error) {
	commands := make([]string, 0, 10)
	for _, command := range cliTask.Command {
		command := ps.ProcessJobString(command)
		// Validate first command is whitelisted
		if len(commands) == 0 {
			if !allowedCommands[command] {
				return nil, errors.New("command not allowed")
			}
		}
		// Sanitize arguments
		command = sanitizeCommandArg(command)
		commands = append(commands, command)
	}
	// ...
}

func processJobStringOrFile(data string, ps *processor.JobStringProcessor) (string, error) {
	data = ps.ProcessJobString(data)
	if strings.HasPrefix(data, "@") {
		filePath := data[1:]
		// Validate path to prevent traversal
		if !filepath.IsAbs(filePath) || strings.Contains(filePath, "..") {
			return "", errors.New("invalid file path")
		}
		// Restrict to allowed directories
		if !strings.HasPrefix(filePath, "/allowed/dir/") {
			return "", errors.New("file path not allowed")
		}
		buffer, err := os.ReadFile(filePath)
		// ...
	}
	return data, nil
}
```

---

## 5. Path Traversal in File Transfer Operations

### Severity: MEDIUM
### CWE: CWE-22 (Path Traversal)

### Description
File transfer operations validate that paths are absolute but don't prevent path traversal attacks using `..` sequences. While the validation requires absolute paths, an attacker could potentially use paths like `/etc/../etc/passwd` or `/allowed/path/../../etc/passwd`.

### Location
- **File**: `backend/services/deviceconnect/model/filetransfer.go` (lines 24-38)
- **File**: `backend/services/deviceconnect/api/http/management_filetransfer.go` (lines 905-969)

### Vulnerable Code

**backend/services/deviceconnect/model/filetransfer.go:33-37**
```go
func (f DownloadFileRequest) Validate() error {
	return validation.ValidateStruct(&f,
		validation.Field(&f.Path, validation.Required,
			validation.Match(absolutePathRegexp).Error("must be absolute")),
	)
}
```

The regex `^/` only checks that the path starts with `/`, but doesn't prevent `../` sequences.

### Impact
- Unauthorized file access on devices
- Potential access to sensitive system files
- Information disclosure

### Recommended Fix
- Normalize paths using `filepath.Clean()` and validate against allowed directories
- Reject paths containing `..` sequences
- Implement a whitelist of allowed directories

---

## Priority for Remediation

1. **CRITICAL**: RBAC Scope Header Injection (#1) - Immediate fix required
2. **CRITICAL**: Command Injection in Workflow CLI (#4) - Immediate fix required
3. **HIGH**: Missing RBAC Scope Validation (#3) - Fix in next release
4. **HIGH**: JWT Identity Extraction Without Verification (#2) - Review usage and fix if vulnerable paths exist
5. **MEDIUM**: Path Traversal in File Transfer (#5) - Fix in next release

---

## Notes

- The vulnerabilities assume that Traefik forwardAuth may be bypassed or that internal service calls don't go through Traefik.
- Some vulnerabilities may be mitigated by proper Traefik configuration, but defense-in-depth requires server-side validation.
- The codebase should implement proper authorization checks regardless of reverse proxy configuration.
- Workflow CLI command injection requires investigation into who can create/modify workflows and what access controls exist.

