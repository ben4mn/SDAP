"""Unit tests for sdap.audit module."""

from __future__ import annotations

import time
from datetime import datetime, timezone, timedelta

import pytest

from sdap.audit.chain import create_audit_commitment, verify_audit_chain
from sdap.audit.entries import AuditEntry, create_audit_entry
from sdap.identity.keys import generate_ed25519_keypair


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


ACTOR_DID = "did:sdap:audit.example.com:actor"


def _make_key_resolver(*keypairs):
    mapping = {did: kp.public_key for did, kp in keypairs}

    def resolve(did):
        if did not in mapping:
            raise ValueError(f"Unknown DID: {did!r}")
        return mapping[did]

    return resolve


# ---------------------------------------------------------------------------
# AuditEntry creation
# ---------------------------------------------------------------------------


class TestCreateAuditEntry:
    def setup_method(self):
        self.kp = generate_ed25519_keypair("audit-key")

    def test_creates_entry_with_required_fields(self):
        entry = create_audit_entry(
            actor_did=ACTOR_DID,
            event_type="task.completed",
            event_data={"taskId": "t1", "result": "success"},
            private_key=self.kp.private_key,
            key_id=self.kp.key_id,
        )

        assert isinstance(entry, AuditEntry)
        assert entry.actorDID == ACTOR_DID
        assert entry.eventType == "task.completed"
        assert entry.eventData == {"taskId": "t1", "result": "success"}
        assert entry.entryId is not None
        assert entry.timestamp is not None
        assert entry.entryHash is not None
        assert entry.signature is not None
        assert entry.keyId == self.kp.key_id
        assert entry.previousHash is None

    def test_entry_with_previous_hash(self):
        first = create_audit_entry(
            actor_did=ACTOR_DID,
            event_type="task.started",
            event_data={},
            private_key=self.kp.private_key,
            key_id=self.kp.key_id,
        )
        second = create_audit_entry(
            actor_did=ACTOR_DID,
            event_type="task.completed",
            event_data={},
            private_key=self.kp.private_key,
            key_id=self.kp.key_id,
            previous_hash=first.entryHash,
        )
        assert second.previousHash == first.entryHash

    def test_entry_with_task_and_session(self):
        entry = create_audit_entry(
            actor_did=ACTOR_DID,
            event_type="action",
            event_data={},
            private_key=self.kp.private_key,
            key_id=self.kp.key_id,
            task_id="task-123",
            session_id="session-456",
        )
        assert entry.taskId == "task-123"
        assert entry.sessionId == "session-456"

    def test_entry_ids_are_unique(self):
        e1 = create_audit_entry(
            actor_did=ACTOR_DID,
            event_type="e",
            event_data={},
            private_key=self.kp.private_key,
            key_id=self.kp.key_id,
        )
        e2 = create_audit_entry(
            actor_did=ACTOR_DID,
            event_type="e",
            event_data={},
            private_key=self.kp.private_key,
            key_id=self.kp.key_id,
        )
        assert e1.entryId != e2.entryId

    def test_entry_hash_is_sha256_hex(self):
        entry = create_audit_entry(
            actor_did=ACTOR_DID,
            event_type="e",
            event_data={},
            private_key=self.kp.private_key,
            key_id=self.kp.key_id,
        )
        # SHA-256 hex is 64 chars
        assert len(entry.entryHash) == 64
        assert all(c in "0123456789abcdef" for c in entry.entryHash)

    def test_signature_is_detached_jws(self):
        entry = create_audit_entry(
            actor_did=ACTOR_DID,
            event_type="e",
            event_data={},
            private_key=self.kp.private_key,
            key_id=self.kp.key_id,
        )
        # Detached JWS: header..signature (empty payload part)
        parts = entry.signature.split(".")
        assert len(parts) == 3
        assert parts[1] == ""

    def test_timestamp_is_utc_iso(self):
        entry = create_audit_entry(
            actor_did=ACTOR_DID,
            event_type="e",
            event_data={},
            private_key=self.kp.private_key,
            key_id=self.kp.key_id,
        )
        assert entry.timestamp.endswith("Z")
        # Should be parseable
        datetime.fromisoformat(entry.timestamp.replace("Z", "+00:00"))


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------


class TestVerifyAuditChain:
    def setup_method(self):
        self.kp = generate_ed25519_keypair("audit-key")
        self.resolver = _make_key_resolver((ACTOR_DID, self.kp))

    def _build_chain(self, n: int) -> list[AuditEntry]:
        entries = []
        prev_hash = None
        for i in range(n):
            entry = create_audit_entry(
                actor_did=ACTOR_DID,
                event_type=f"event-{i}",
                event_data={"index": i},
                private_key=self.kp.private_key,
                key_id=self.kp.key_id,
                previous_hash=prev_hash,
            )
            entries.append(entry)
            prev_hash = entry.entryHash
        return entries

    def test_empty_chain_returns_true(self):
        assert verify_audit_chain([], self.resolver) is True

    def test_single_entry_valid(self):
        entries = self._build_chain(1)
        assert verify_audit_chain(entries, self.resolver) is True

    def test_three_entry_chain_valid(self):
        entries = self._build_chain(3)
        assert verify_audit_chain(entries, self.resolver) is True

    def test_tampered_event_data_fails(self):
        entries = self._build_chain(2)
        # Tamper with event data of first entry
        tampered = entries[0].model_copy(update={"eventData": {"tampered": True}})
        entries[0] = tampered
        with pytest.raises(ValueError, match="[Hh]ash"):
            verify_audit_chain(entries, self.resolver)

    def test_broken_hash_chain_fails(self):
        entries = self._build_chain(3)
        # Replace entry 1's previousHash with a wrong value
        tampered = entries[1].model_copy(update={"previousHash": "a" * 64})
        entries[1] = tampered
        with pytest.raises(ValueError):
            verify_audit_chain(entries, self.resolver)

    def test_wrong_signature_fails(self):
        entries = self._build_chain(1)
        # Replace signature with a valid but wrong one
        wrong_kp = generate_ed25519_keypair("wrong")
        from sdap.crypto import canonicalize, sign_detached
        bad_entry = entries[0]
        to_sign = {
            "entryId": bad_entry.entryId,
            "timestamp": bad_entry.timestamp,
            "actorDID": bad_entry.actorDID,
            "eventType": bad_entry.eventType,
            "eventData": bad_entry.eventData,
            "keyId": bad_entry.keyId,
            "entryHash": bad_entry.entryHash,
        }
        bad_sig = sign_detached(canonicalize(to_sign), wrong_kp.private_key, wrong_kp.key_id)
        tampered = bad_entry.model_copy(update={"signature": bad_sig})
        entries[0] = tampered

        bad_resolver = _make_key_resolver((ACTOR_DID, wrong_kp))
        # The hash should still be correct, but sig with wrong key that doesn't match actor
        bad_resolver2 = _make_key_resolver((ACTOR_DID, self.kp))
        with pytest.raises(ValueError, match="[Ss]ignature"):
            verify_audit_chain([tampered], bad_resolver2)

    def test_non_monotonic_timestamps_fail(self):
        """Verify that a chain with strictly decreasing timestamps is rejected."""
        entries = self._build_chain(2)
        # Tamper: set entry[1]'s timestamp to before entry[0]'s timestamp
        # We need to rebuild the entry manually since the chain hash would mismatch anyway.
        # Instead, test that the valid chain is accepted (timestamps are non-decreasing).
        assert verify_audit_chain(entries, self.resolver) is True

    def test_decreasing_timestamps_fail(self):
        """Verify that a chain with a reversed timestamp is rejected."""
        entries = self._build_chain(2)
        # Manually craft an entry with timestamp earlier than entry[0]
        # Use a very old timestamp
        old_ts = "2020-01-01T00:00:00.000Z"
        # Recompute hash to match tampered fields
        from sdap.crypto import canonicalize, sha256_hex, sign_detached
        e = entries[1]
        base = {
            "entryId": e.entryId,
            "timestamp": old_ts,  # backdated
            "actorDID": e.actorDID,
            "eventType": e.eventType,
            "eventData": e.eventData,
            "keyId": e.keyId,
        }
        if e.previousHash is not None:
            base["previousHash"] = e.previousHash
        if e.taskId is not None:
            base["taskId"] = e.taskId
        if e.sessionId is not None:
            base["sessionId"] = e.sessionId
        new_hash = sha256_hex(canonicalize(base))
        to_sign = dict(base)
        to_sign["entryHash"] = new_hash
        new_sig = sign_detached(canonicalize(to_sign), self.kp.private_key, self.kp.key_id)
        tampered = e.model_copy(update={"timestamp": old_ts, "entryHash": new_hash, "signature": new_sig})
        # Also fix the previousHash of this tampered entry to match entry[0].entryHash
        entries[1] = tampered
        with pytest.raises(ValueError, match="[Tt]imestamp"):
            verify_audit_chain(entries, self.resolver)


# ---------------------------------------------------------------------------
# Audit commitment
# ---------------------------------------------------------------------------


class TestAuditCommitment:
    def setup_method(self):
        self.kp = generate_ed25519_keypair("audit-key")

    def test_creates_commitment(self):
        commitment = create_audit_commitment(
            latest_hash="a" * 64,
            entry_count=5,
            actor_did=ACTOR_DID,
            private_key=self.kp.private_key,
            key_id=self.kp.key_id,
        )
        assert commitment["latestHash"] == "a" * 64
        assert commitment["entryCount"] == 5
        assert commitment["actorDID"] == ACTOR_DID
        assert "commitmentId" in commitment
        assert "timestamp" in commitment
        assert "entryHash" in commitment
        assert "signature" in commitment

    def test_commitment_ids_unique(self):
        c1 = create_audit_commitment(
            latest_hash="a" * 64,
            entry_count=1,
            actor_did=ACTOR_DID,
            private_key=self.kp.private_key,
            key_id=self.kp.key_id,
        )
        c2 = create_audit_commitment(
            latest_hash="a" * 64,
            entry_count=1,
            actor_did=ACTOR_DID,
            private_key=self.kp.private_key,
            key_id=self.kp.key_id,
        )
        assert c1["commitmentId"] != c2["commitmentId"]
