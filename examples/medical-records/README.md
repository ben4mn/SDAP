# Example: Medical Records — HIPAA, PHI, and Audit Trail

Demonstrates the full SDAP compliance story: HIPAA-tagged attestations,
high-security sessions, PHI-classified delegation, and a complete
tamper-evident audit chain.

## What it shows

1. **HIPAA attestations** — both agents carry provider attestations with
   `complianceTags: ["HIPAA", "HITECH", ...]` and `securityLevel: "high"`.
2. **High-security handshake** — the INIT message specifies
   `requiredSecurityLevel: "high"`, ensuring the session cannot be established
   at a lower security level.
3. **PHI delegation** — a delegation token is created with
   `dataClassification: "PHI"`, `requireMFA: true`, `maxUses: 5`, and a narrow
   30-minute expiry window.
4. **Encrypted PHI exchange** — lab results (classified as PHI) are exchanged
   over the AES-256-GCM session with sequence numbers and audit hashes.
5. **Audit chain** — six audit entries (session lifecycle, PHI access,
   delegation creation) form a SHA-256 hash chain, all signed with Ed25519.
6. **Tamper detection** — modifying any field in any audit entry breaks the
   hash chain and is detected immediately.

## Compliance model

| Layer | Mechanism | Standard |
|---|---|---|
| Identity | `did:sdap` DID + Ed25519 keys | NIST SP 800-57 |
| Attestation | JWT with `complianceTags: ["HIPAA"]` | HIPAA §164.312 |
| Session | X25519 ECDH + AES-256-GCM | HIPAA §164.312(a)(2)(iv) |
| Delegation | PHI classification tag + requireMFA | HIPAA minimum-necessary |
| Audit | Tamper-evident hash chain + Ed25519 signatures | HIPAA §164.312(b) |

## Run

```bash
cd sdap-python
PYTHONPATH=src python ../examples/medical-records/example.py
```

## Key APIs used

```python
from sdap.identity import create_attestation, verify_attestation
from sdap.handshake import create_handshake_init, process_handshake_init, create_handshake_confirm, process_handshake_confirm
from sdap.delegation import DelegationConstraints, create_delegation_token, validate_delegation_chain
from sdap.audit import create_audit_entry, verify_audit_chain
from sdap.a2a import wrap_a2a_message, unwrap_a2a_message
```
