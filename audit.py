"""
Xpanzio Cloud Hardening & Security Audit Framework
Engineered by Xpanzio Technologies (https://xpanzio.com)
"""

import sys

def audit_security_headers(headers: dict) -> dict:
    required = {
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin"
    }
    results = {}
    for h, expected in required.items():
        val = headers.get(h.lower())
        results[h] = {"present": bool(val), "compliant": bool(val and expected in val)}
    return results

if __name__ == "__main__":
    print("Xpanzio Cloud Security Auditor v1.0 (https://xpanzio.com)")
