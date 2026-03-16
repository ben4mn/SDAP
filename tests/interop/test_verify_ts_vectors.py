"""pytest tests: verify TypeScript-generated interop vectors using the Python SDAP SDK.

Run from the repository root:
    PYTHONPATH=sdap-python/src /opt/homebrew/bin/python3.11 -m pytest tests/interop/test_verify_ts_vectors.py -v

Or install the package first (pip install -e sdap-python) then:
    pytest tests/interop/test_verify_ts_vectors.py -v
"""

from __future__ import annotations

import json
import os
import sys

import pytest

# Allow running without install
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdap-python/src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sdap.crypto import (
    canonicalize,
    sha256_hex,
    verify_jws,
    verify_detached,
    derive_session_keys,
)
from sdap.identity.attestation import verify_attestation
from sdap.delegation.tokens import decode_delegation_token

# ---------------------------------------------------------------------------
# Load vectors once
# ---------------------------------------------------------------------------

VECTORS_PATH = os.path.join(os.path.dirname(__file__), "vectors_typescript.json")


@pytest.fixture(scope="module")
def vectors() -> dict:
    with open(VECTORS_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def public_key(vectors: dict) -> Ed25519PublicKey:
    raw = bytes.fromhex(vectors["key"]["public_key_hex"])
    return Ed25519PublicKey.from_public_bytes(raw)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestJCSCanonicalization:
    def test_canonical_hex_matches(self, vectors: dict) -> None:
        """Python JCS should produce identical hex to TypeScript for the same input."""
        our_canonical = canonicalize(vectors["canonicalization"]["input"])
        our_hex = our_canonical.hex()
        assert our_hex == vectors["canonicalization"]["canonical_hex"]

    def test_canonical_utf8_matches(self, vectors: dict) -> None:
        our_canonical = canonicalize(vectors["canonicalization"]["input"])
        our_utf8 = our_canonical.decode("utf-8")
        assert our_utf8 == vectors["canonicalization"]["canonical_utf8"]


class TestSHA256:
    def test_sha256_matches(self, vectors: dict) -> None:
        input_bytes = bytes.fromhex(vectors["sha256"]["input_hex"])
        our_hash = sha256_hex(input_bytes)
        assert our_hash == vectors["sha256"]["hash_hex"]


class TestHKDF:
    def test_session_keys_match(self, vectors: dict) -> None:
        inp = vectors["hkdf"]["inputs"]
        shared_secret = bytes.fromhex(inp["shared_secret_hex"])
        nonce_a = bytes.fromhex(inp["nonce_a_hex"])
        nonce_b = bytes.fromhex(inp["nonce_b_hex"])
        session_id = inp["session_id"]

        encrypt_key, mac_key = derive_session_keys(
            shared_secret, nonce_a, nonce_b, session_id
        )
        assert encrypt_key.hex() == vectors["hkdf"]["encrypt_key_hex"]
        assert mac_key.hex() == vectors["hkdf"]["mac_key_hex"]


class TestJWS:
    def test_verify_ts_signed_jws(self, vectors: dict, public_key: Ed25519PublicKey) -> None:
        payload = verify_jws(vectors["jws"]["token"], public_key)
        assert payload.decode("utf-8") == vectors["jws"]["payload_utf8"]

    def test_verify_ts_signed_detached_jws(
        self, vectors: dict, public_key: Ed25519PublicKey
    ) -> None:
        canonical_bytes = bytes.fromhex(vectors["detached_jws"]["payload_hex"])
        valid = verify_detached(
            vectors["detached_jws"]["token"], canonical_bytes, public_key
        )
        assert valid is True


class TestAttestationJWT:
    def test_verify_ts_attestation(
        self, vectors: dict, public_key: Ed25519PublicKey
    ) -> None:
        attestation = verify_attestation(vectors["attestation"]["jwt"], public_key)

        inp = vectors["attestation"]["inputs"]
        assert attestation.iss == inp["issuer_did"]
        assert attestation.sub == inp["subject_did"]
        assert attestation.sdap_attestation.agentType == inp["agent_type"]
        assert attestation.sdap_attestation.capabilities == inp["capabilities"]
        assert attestation.sdap_attestation.securityLevel == inp["security_level"]
        assert attestation.sdap_attestation.complianceTags == inp["compliance_tags"]
        assert attestation.sdap_attestation.maxDelegationDepth == inp["max_delegation_depth"]


class TestDelegationJWT:
    def test_verify_ts_delegation(
        self, vectors: dict, public_key: Ed25519PublicKey
    ) -> None:
        delegation = decode_delegation_token(vectors["delegation"]["jwt"], public_key)

        inp = vectors["delegation"]["inputs"]
        assert delegation.iss == inp["issuer_did"]
        assert delegation.sub == inp["delegatee_did"]
        assert delegation.aud == inp["audience_did"]
        assert delegation.scopes == inp["scopes"]


class TestAuditEntry:
    def test_audit_entry_hash(self, vectors: dict) -> None:
        """Recompute the audit entry hash and verify it matches the stored value."""
        entry = vectors["audit_entry"]

        base: dict = {
            "actorDID": entry["actorDID"],
            "entryId": entry["entryId"],
            "eventData": entry["eventData"],
            "eventType": entry["eventType"],
            "keyId": entry["keyId"],
            "timestamp": entry["timestamp"],
        }
        if "previousHash" in entry:
            base["previousHash"] = entry["previousHash"]
        if "taskId" in entry:
            base["taskId"] = entry["taskId"]
        if "sessionId" in entry:
            base["sessionId"] = entry["sessionId"]

        canonical_base = canonicalize(base)
        expected_hash = sha256_hex(canonical_base)
        assert entry["entryHash"] == expected_hash

    def test_audit_entry_signature(
        self, vectors: dict, public_key: Ed25519PublicKey
    ) -> None:
        """Reconstruct the canonical to-sign bytes and verify the detached signature."""
        entry = vectors["audit_entry"]

        base: dict = {
            "actorDID": entry["actorDID"],
            "entryId": entry["entryId"],
            "eventData": entry["eventData"],
            "eventType": entry["eventType"],
            "keyId": entry["keyId"],
            "timestamp": entry["timestamp"],
        }
        if "previousHash" in entry:
            base["previousHash"] = entry["previousHash"]
        if "taskId" in entry:
            base["taskId"] = entry["taskId"]
        if "sessionId" in entry:
            base["sessionId"] = entry["sessionId"]

        canonical_base = canonicalize(base)
        entry_hash = sha256_hex(canonical_base)

        to_sign = dict(base)
        to_sign["entryHash"] = entry_hash
        canonical_to_sign = canonicalize(to_sign)

        valid = verify_detached(entry["signature"], canonical_to_sign, public_key)
        assert valid is True
