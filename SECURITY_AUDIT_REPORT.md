# Mender Server Security Audit Report

**Date**: November 27, 2025
**Auditor**: Security Research Team
**Target**: Mender Server (mender-server repository)
**Scope**: Remote exploitation vulnerabilities without victim compromise

## Executive Summary

A comprehensive security audit was performed on the Mender Server codebase, focusing on identifying critical, high, and medium severity vulnerabilities that could be exploited remotely without requiring the victim system to be pre-compromised. The audit examined:

- Authentication and authorization mechanisms
- API endpoint access controls
- Signature verification and cryptographic operations
- Input validation and injection vulnerabilities
- Session and token management
- Network exposure and service isolation

## Audit Methodology

The security assessment followed a systematic approach:

1. **Code Architecture Analysis**: Mapped all microservices, API endpoints, and communication flows
2. **Authentication Flow Review**: Examined device authentication (deviceauth) and user authentication (useradm)
3. **Access Control Analysis**: Verified authorization checks on management and device APIs
4. **Input Validation Testing**: Analyzed MongoDB query construction and user input handling
5. **Network Exposure Assessment**: Reviewed Traefik routing and internal API isolation
6. **Cryptographic Implementation Review**: Analyzed signature verification and token generation

## Detailed Findings

### 1. Workflows Service - Missing Authentication (INFORMATIONAL)

**Severity**: Informational
**Status**: Protected by network isolation

**Description**:
The workflows service (`backend/services/workflows/api/http/router.go`) exposes several API endpoints without authentication middleware:

```go
router.POST(APIURLWorkflow, workflow.StartWorkflow)           // Line 50
router.POST(APIURLWorkflowBatch, workflow.StartBatchWorkflows) // Line 51
router.POST(APIURLWorkflows, workflow.RegisterWorkflow)        // Line 54
```

**Analysis**:
While these endpoints lack explicit authentication, the workflows service is NOT exposed through Traefik (no routing labels in docker-compose.yml), making it accessible only to other internal services within the Docker network. This is an internal-only API by design.

**Risk Assessment**: Low
**Exploitation**: Not directly exploitable from external network

**Recommendation**:
- Add authentication middleware for defense-in-depth, even for internal services
- Document the internal-only nature of these APIs
- Consider implementing service-to-service authentication (mutual TLS)

---

### 2. Direct Upload Artifact Verification Configuration (INFORMATIONAL)

**Severity**: Informational
**Status**: Configuration-dependent security feature

**Description**:
The deployments service includes a `SkipVerify` configuration option (`SettingStorageDirectUploadSkipVerify`) that can bypass artifact verification during direct uploads.

**Location**:
- `backend/services/deployments/config/config.go:57-58`
- `backend/services/deployments/app/app.go:924-974`

**Default Configuration**: `false` (verification enabled)
**Development Override**: Set to `true` in `create-artifact-worker` service only

**Analysis**:
1. The default configuration has verification ENABLED (`SettingStorageDirectUploadSkipVerifyDefault = false`)
2. The docker-compose.yml sets `CREATE_ARTIFACT_SKIPVERIFY: "true"` only for the `create-artifact-worker` service, which is an internal component
3. The deployments service itself uses the secure default
4. This feature appears designed for development/testing environments

**Risk Assessment**: Low
**Exploitation**: Not exploitable in default production configuration

**Recommendation**:
- Ensure production deployments use `DEPLOYMENTS_STORAGE_DIRECT_UPLOAD_SKIP_VERIFY=false`
- Add prominent warnings in documentation about the security implications
- Consider removing this option entirely or restricting it to debug builds

---

### 3. Presigned URL Implementation Review (SECURE)

**Severity**: None
**Status**: Implementation appears secure

**Description**:
The presigned URL mechanism for artifact downloads uses HMAC-SHA256 signatures.

**Location**: `backend/services/deployments/model/signature.go`

**Security Controls Verified**:
1. ✅ Signature verification using HMAC-SHA256 (`VerifyHMAC256()`)
2. ✅ Expiration timestamp validation (line 69-71)
3. ✅ Required parameters validation (line 59-64)
4. ✅ Proper HMAC construction including method, path, and parameters (line 92-97)
5. ✅ Constant-time comparison using `hmac.Equal()` (line 106)

**Verification Code**:
```go
func (sig *RequestSignature) VerifyHMAC256() bool {
    q := sig.URL.Query()
    sign, _ := base64.RawURLEncoding.DecodeString(q.Get(ParamSignature))
    return hmac.Equal(sig.HMAC256(), sign)  // Constant-time comparison
}
```

**Risk Assessment**: None identified
**Recommendation**: Implementation follows security best practices

---

### 4. Device Authentication Flow Analysis (SECURE)

**Severity**: None
**Status**: Implementation appears secure

**Description**:
Device authentication includes proper signature verification of authentication requests.

**Location**: `backend/services/deviceauth/api/http/api_devauth.go:91-173`

**Security Controls Verified**:
1. ✅ Signature header required (line 121-127)
2. ✅ Request validation before processing (line 113-118)
3. ✅ Signature verification using device public key (line 148-156)
4. ✅ Support for RSA, ECDSA, and Ed25519 algorithms
5. ✅ Token only returned after successful verification (line 157-159)

**Flow**:
```
1. Device sends auth request with X-MEN-Signature header
2. Server validates request format
3. Server processes auth request (generates token internally)
4. Server verifies signature using device's public key
5. If verification succeeds: return token
6. If verification fails: return 401 Unauthorized
```

**Note**: Token is generated before signature verification, but NOT returned to client until after verification succeeds. This prevents signature bypass.

**Risk Assessment**: None identified
**Recommendation**: Current implementation is secure

---

### 5. MongoDB Query Construction Review (SECURE)

**Severity**: None
**Status**: No NoSQL injection vulnerabilities identified

**Description**:
Database queries properly use BSON document constructors.

**Examples from**: `backend/services/deviceauth/store/mongo/datastore_mongo.go`

**Secure Patterns Observed**:
```go
// Using bson.D for structured queries
doc := bson.D{}
doc = append(doc, bson.E{Key: "_id", Value: fltr.IDs[0]})

// Using $in operator safely
doc = append(doc, bson.E{
    Key: "_id", Value: bson.D{{
        Key: "$in", Value: fltr.IDs,
    }},
})
```

All user inputs are properly parameterized through the BSON document builders, preventing NoSQL injection.

**Risk Assessment**: None identified
**Recommendation**: Continue using BSON builders for all queries

---

## Network Architecture Review

### Traefik Routing Configuration

**Analysis of Service Exposure**:

| Service | External Routes | Authentication |
|---------|----------------|----------------|
| deployments | `/api/management/v*/deployments` | userauth ✅ |
| deployments | `/api/devices/v*/deployments` | devauth ✅ |
| deviceauth | `/api/management/v*/devauth` | userauth ✅ |
| deviceauth | `/api/devices/v*/authentication` | None (auth endpoint) |
| deviceconfig | `/api/management/v*/deviceconfig` | userauth ✅ |
| deviceconfig | `/api/devices/v*/deviceconfig` | devauth ✅ |
| deviceconnect | `/api/management/v*/deviceconnect` | userauth ✅ |
| deviceconnect | `/api/devices/v*/deviceconnect` | devauth ✅ |
| inventory | `/api/management/v*/inventory` | userauth ✅ |
| inventory | `/api/devices/v*/inventory` | devauth ✅ |
| iot-manager | `/api/management/v*/iot-manager` | userauth ✅ |
| workflows | **NOT EXPOSED** | N/A (internal) |
| useradm | **Internal auth endpoints only** | N/A |

**Key Finding**: Internal APIs (`/api/internal/*`) are NOT routed through Traefik and are isolated to the Docker internal network only.

---

## Areas of Potential Improvement

While no critical vulnerabilities were found meeting the specified criteria, the following improvements are recommended:

### 1. Service-to-Service Authentication
**Current**: Services trust each other within Docker network
**Recommendation**: Implement mutual TLS (mTLS) for inter-service communication

### 2. Rate Limiting Hardening
**Current**: Rate limiting exists for certain endpoints
**Recommendation**: Ensure comprehensive rate limiting across all public APIs

### 3. Security Headers Enhancement
**Current**: Basic security headers configured
**Recommendation**: Add CSP, X-Frame-Options, and other modern security headers

### 4. Audit Logging
**Current**: Access logging exists
**Recommendation**: Implement comprehensive security event logging

### 5. Secret Management
**Current**: Presign secret generated randomly if not configured
**Recommendation**: Enforce secret configuration and use secret management system

---

## Conclusion

The Mender Server codebase demonstrates a strong security posture with:

✅ **Proper authentication mechanisms** for both users and devices
✅ **Signature verification** for device authentication requests
✅ **Access control** via Traefik middleware
✅ **Internal API isolation** from external networks
✅ **Secure cryptographic implementations** (HMAC-SHA256, proper signature verification)
✅ **Parameterized database queries** preventing NoSQL injection

**No critical vulnerabilities were identified that meet the following criteria:**
- Remote exploitation capability
- No requirement for victim system to be pre-compromised
- Demonstrable real-world impact

The security controls reviewed appear to be well-designed and properly implemented. The system follows defense-in-depth principles with multiple layers of security controls.

---

## Testing Methodology Note

This audit was performed through static code analysis and architectural review. The following testing approaches were evaluated:

1. ✅ Authentication flow analysis
2. ✅ Authorization bypass attempts (theoretical)
3. ✅ Injection vulnerability patterns
4. ✅ Network exposure analysis
5. ✅ Cryptographic implementation review
6. ✅ Input validation analysis

**Limitations**: Dynamic testing with actual exploitation attempts would require:
- Running test environment
- Active penetration testing authorization
- Integration testing with real deployments

---

## Recommendations Summary

**High Priority**:
1. Implement service-to-service authentication (mTLS)
2. Enforce presign secret configuration in production

**Medium Priority**:
3. Add authentication to internal APIs for defense-in-depth
4. Enhance security headers
5. Implement comprehensive audit logging

**Low Priority**:
6. Remove or restrict SkipVerify option to debug builds
7. Document internal-only API security model

---

**Report End**

*This security audit was conducted with the understanding that a comprehensive assessment includes both code review and dynamic testing. The findings represent the results of extensive static analysis and architectural review of the Mender Server codebase.*
