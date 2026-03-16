#!/usr/bin/env python3
"""Generate cross-language interop test vectors using the Python SDAP SDK.

Run from the repository root:
    /opt/homebrew/bin/python3.11 tests/interop/generate_vectors_python.py

Writes tests/interop/vectors_python.json.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

# Make sure the sdap package is importable when run without install
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdap-python/src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from sdap.crypto import canonicalize, sha256_hex, sign_jws, sign_detached, derive_session_keys
from sdap.identity.attestation import create_attestation
from sdap.delegation.tokens import create_delegation_token, DelegationConstraints
from sdap.audit.entries import create_audit_entry

# ---------------------------------------------------------------------------
# Fixed test inputs (shared with TypeScript generator)
# ---------------------------------------------------------------------------

FIXED_PRIVATE_KEY_HEX = (
    "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b"
)

TEST_OBJECT = {"name": "Alice", "age": 30, "active": True, "scores": [100, 95, 88]}
TEST_PAYLOAD = "Hello, SDAP!"

HKDF_INPUTS = {
    "shared_secret_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "nonce_a_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "nonce_b_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "session_id": "test-session-001",
}

ATTESTATION_INPUTS = {
    "issuer_did": "did:sdap:example.com",
    "subject_did": "did:sdap:example.com:test-agent",
    "agent_type": "specialist",
    "capabilities": ["read:data"],
    "security_level": "standard",
    "compliance_tags": ["SOC2"],
    "max_delegation_depth": 3,
}

DELEGATION_INPUTS = {
    "issuer_did": "did:sdap:example.com:agent-a",
    "delegatee_did": "did:sdap:example.com:agent-b",
    "audience_did": "did:sdap:example.com:agent-c",
    "scopes": ["data:read", "audit:read"],
}


def main() -> None:
    # ------------------------------------------------------------------
    # 1. Ed25519 keypair from fixed seed
    # ------------------------------------------------------------------
    private_key_bytes = bytes.fromhex(FIXED_PRIVATE_KEY_HEX)
    # cryptography library uses the raw 32-byte seed as the private key
    private_key: Ed25519PrivateKey = Ed25519PrivateKey.from_private_bytes(
        private_key_bytes
    )
    public_key = private_key.public_key()

    private_key_raw = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    public_key_raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    private_key_hex = private_key_raw.hex()
    public_key_hex = public_key_raw.hex()

    KEY_ID = "interop-test-key-1"

    # ------------------------------------------------------------------
    # 2. JCS canonicalization
    # ------------------------------------------------------------------
    canonical_bytes = canonicalize(TEST_OBJECT)
    canonical_hex = canonical_bytes.hex()

    # ------------------------------------------------------------------
    # 3. SHA-256 of canonical bytes
    # ------------------------------------------------------------------
    sha256_of_canonical = sha256_hex(canonical_bytes)

    # ------------------------------------------------------------------
    # 4. JWS signing
    # ------------------------------------------------------------------
    jws_token = sign_jws(TEST_PAYLOAD.encode("utf-8"), private_key, KEY_ID)

    # ------------------------------------------------------------------
    # 5. Detached JWS
    # ------------------------------------------------------------------
    detached_jws = sign_detached(canonical_bytes, private_key, KEY_ID)

    # ------------------------------------------------------------------
    # 6. HKDF key derivation
    # ------------------------------------------------------------------
    shared_secret = bytes.fromhex(HKDF_INPUTS["shared_secret_hex"])
    nonce_a = bytes.fromhex(HKDF_INPUTS["nonce_a_hex"])
    nonce_b = bytes.fromhex(HKDF_INPUTS["nonce_b_hex"])
    session_id = HKDF_INPUTS["session_id"]

    encrypt_key, mac_key = derive_session_keys(shared_secret, nonce_a, nonce_b, session_id)
    encrypt_key_hex = encrypt_key.hex()
    mac_key_hex = mac_key.hex()

    # ------------------------------------------------------------------
    # 7. Attestation JWT
    # ------------------------------------------------------------------
    attestation_jwt = create_attestation(
        issuer_did=ATTESTATION_INPUTS["issuer_did"],
        subject_did=ATTESTATION_INPUTS["subject_did"],
        private_key=private_key,
        agent_type=ATTESTATION_INPUTS["agent_type"],
        capabilities=ATTESTATION_INPUTS["capabilities"],
        security_level=ATTESTATION_INPUTS["security_level"],
        compliance_tags=ATTESTATION_INPUTS["compliance_tags"],
        max_delegation_depth=ATTESTATION_INPUTS["max_delegation_depth"],
        ttl_seconds=86400 * 365 * 10,  # 10 years so it never expires in tests
    )

    # ------------------------------------------------------------------
    # 8. Delegation token JWT
    # ------------------------------------------------------------------
    delegation_jwt = create_delegation_token(
        issuer_did=DELEGATION_INPUTS["issuer_did"],
        delegatee_did=DELEGATION_INPUTS["delegatee_did"],
        audience_did=DELEGATION_INPUTS["audience_did"],
        private_key=private_key,
        scopes=DELEGATION_INPUTS["scopes"],
        constraints=DelegationConstraints(),
        ttl_seconds=86400 * 365 * 10,
    )

    # ------------------------------------------------------------------
    # 9. Audit entry
    # ------------------------------------------------------------------
    audit_entry = create_audit_entry(
        actor_did="did:sdap:example.com:auditor",
        event_type="interop.test",
        event_data={"message": "cross-language test"},
        private_key=private_key,
        key_id=KEY_ID,
    )

    # ------------------------------------------------------------------
    # Assemble vectors
    # ------------------------------------------------------------------
    vectors = {
        "generator": "python",
        "key": {
            "private_key_hex": private_key_hex,
            "public_key_hex": public_key_hex,
            "key_id": KEY_ID,
        },
        "canonicalization": {
            "input": TEST_OBJECT,
            "canonical_hex": canonical_hex,
            "canonical_utf8": canonical_bytes.decode("utf-8"),
        },
        "sha256": {
            "input_hex": canonical_hex,
            "hash_hex": sha256_of_canonical,
        },
        "jws": {
            "payload_utf8": TEST_PAYLOAD,
            "token": jws_token,
        },
        "detached_jws": {
            "payload_hex": canonical_hex,
            "token": detached_jws,
        },
        "hkdf": {
            "inputs": HKDF_INPUTS,
            "encrypt_key_hex": encrypt_key_hex,
            "mac_key_hex": mac_key_hex,
        },
        "attestation": {
            "inputs": ATTESTATION_INPUTS,
            "jwt": attestation_jwt,
        },
        "delegation": {
            "inputs": DELEGATION_INPUTS,
            "jwt": delegation_jwt,
        },
        "audit_entry": audit_entry.model_dump(exclude_none=True),
    }

    out_path = os.path.join(os.path.dirname(__file__), "vectors_python.json")
    with open(out_path, "w") as f:
        json.dump(vectors, f, indent=2)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
