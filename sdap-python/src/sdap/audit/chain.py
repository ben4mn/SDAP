"""Audit chain verification and commitment creation."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdap.audit.entries import AuditEntry, create_audit_entry
from sdap.crypto import canonicalize, sha256_hex, verify_detached


def _recompute_entry_hash(entry: AuditEntry) -> str:
    """Recompute the entryHash for *entry* using the canonical form."""
    base: dict = {
        "entryId": entry.entryId,
        "timestamp": entry.timestamp,
        "actorDID": entry.actorDID,
        "eventType": entry.eventType,
        "eventData": entry.eventData,
        "keyId": entry.keyId,
    }
    if entry.previousHash is not None:
        base["previousHash"] = entry.previousHash
    if entry.taskId is not None:
        base["taskId"] = entry.taskId
    if entry.sessionId is not None:
        base["sessionId"] = entry.sessionId

    canonical = canonicalize(base)
    return sha256_hex(canonical)


def verify_audit_chain(
    entries: list[AuditEntry],
    resolve_key_func: Callable[[str], object],
) -> bool:
    """Verify an ordered list of audit entries.

    Checks:
    1. Each entry's entryHash is correct (recomputed from canonical form).
    2. Hash chain: entry[n].entryHash == entry[n+1].previousHash.
    3. Signatures are valid.
    4. Timestamps are monotonically increasing.

    Args:
        entries: Ordered list of :class:`AuditEntry` objects.
        resolve_key_func: Callable(did: str) -> Ed25519PublicKey

    Returns:
        True if valid.

    Raises:
        ValueError: On any validation failure.
    """
    if not entries:
        return True

    prev_timestamp: datetime | None = None

    for i, entry in enumerate(entries):
        # 1. Verify entryHash
        expected_hash = _recompute_entry_hash(entry)
        if entry.entryHash != expected_hash:
            raise ValueError(
                f"Entry {i} ({entry.entryId}): entryHash mismatch. "
                f"Expected {expected_hash!r}, got {entry.entryHash!r}"
            )

        # 2. Verify hash chain
        if i == 0:
            # First entry: previousHash should be None (or caller's responsibility)
            pass
        else:
            prev_entry = entries[i - 1]
            if entry.previousHash != prev_entry.entryHash:
                raise ValueError(
                    f"Entry {i} ({entry.entryId}): previousHash mismatch. "
                    f"Expected {prev_entry.entryHash!r}, got {entry.previousHash!r}"
                )

        # 3. Verify signature
        actor_key = resolve_key_func(entry.actorDID)

        to_sign: dict = {
            "entryId": entry.entryId,
            "timestamp": entry.timestamp,
            "actorDID": entry.actorDID,
            "eventType": entry.eventType,
            "eventData": entry.eventData,
            "keyId": entry.keyId,
        }
        if entry.previousHash is not None:
            to_sign["previousHash"] = entry.previousHash
        if entry.taskId is not None:
            to_sign["taskId"] = entry.taskId
        if entry.sessionId is not None:
            to_sign["sessionId"] = entry.sessionId
        to_sign["entryHash"] = entry.entryHash

        canonical_to_sign = canonicalize(to_sign)
        if not verify_detached(entry.signature, canonical_to_sign, actor_key):
            raise ValueError(
                f"Entry {i} ({entry.entryId}): signature verification failed"
            )

        # 4. Verify timestamp monotonicity
        try:
            ts = datetime.fromisoformat(entry.timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(
                f"Entry {i} ({entry.entryId}): invalid timestamp {entry.timestamp!r}"
            ) from exc

        if prev_timestamp is not None and ts < prev_timestamp:
            raise ValueError(
                f"Entry {i} ({entry.entryId}): timestamp {entry.timestamp!r} is not "
                f"after previous entry timestamp"
            )
        prev_timestamp = ts

    return True


def create_audit_commitment(
    latest_hash: str,
    entry_count: int,
    actor_did: str,
    private_key: Ed25519PrivateKey,
    key_id: str,
) -> dict:
    """Create a lightweight audit commitment proof.

    This is a signed summary anchoring the current state of the audit chain,
    useful for delegation chain proofs or external verification.

    Args:
        latest_hash: entryHash of the latest audit entry.
        entry_count: Total number of entries in the chain.
        actor_did: DID of the committing actor.
        private_key: Ed25519 private key for signing.
        key_id: Key identifier.

    Returns:
        A dict containing the commitment proof.
    """
    entry = create_audit_entry(
        actor_did=actor_did,
        event_type="audit-commitment",
        event_data={
            "latestHash": latest_hash,
            "entryCount": entry_count,
        },
        private_key=private_key,
        key_id=key_id,
        previous_hash=latest_hash,
    )
    return {
        "commitmentId": str(uuid.uuid4()),
        "latestHash": latest_hash,
        "entryCount": entry_count,
        "actorDID": actor_did,
        "timestamp": entry.timestamp,
        "entryHash": entry.entryHash,
        "signature": entry.signature,
        "keyId": key_id,
    }
