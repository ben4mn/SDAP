"""Audit entry creation and signing."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel

from sdap.crypto import canonicalize, sha256_hex, sign_detached


class AuditEntry(BaseModel):
    """A single signed audit log entry."""

    entryId: str
    timestamp: str
    actorDID: str
    eventType: str
    eventData: dict
    previousHash: Optional[str] = None
    taskId: Optional[str] = None
    sessionId: Optional[str] = None
    entryHash: str
    signature: str
    keyId: str

    model_config = {"extra": "allow"}


def create_audit_entry(
    actor_did: str,
    event_type: str,
    event_data: dict,
    private_key: Ed25519PrivateKey,
    key_id: str,
    previous_hash: Optional[str] = None,
    task_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> AuditEntry:
    """Create a signed audit entry.

    Steps:
    1. Generate entryId (UUID4).
    2. Set timestamp (now UTC ISO 8601).
    3. Build the base object (without entryHash and signature).
    4. Compute entryHash: JCS-canonicalize the base object, SHA-256.
    5. Sign: JCS-canonicalize object with entryHash but without signature field, Ed25519 detached.
    6. Return complete AuditEntry.

    Args:
        actor_did: DID of the entity creating this entry.
        event_type: Semantic event type string.
        event_data: Arbitrary event data dict.
        private_key: Ed25519 private key for signing.
        key_id: Key identifier included in the signature header.
        previous_hash: entryHash of the preceding entry (None for first entry).
        task_id: Optional task identifier.
        session_id: Optional session identifier.

    Returns:
        Signed :class:`AuditEntry`.
    """
    entry_id = str(uuid.uuid4())
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    # Build base object without entryHash and signature
    base: dict = {
        "entryId": entry_id,
        "timestamp": timestamp,
        "actorDID": actor_did,
        "eventType": event_type,
        "eventData": event_data,
        "keyId": key_id,
    }
    if previous_hash is not None:
        base["previousHash"] = previous_hash
    if task_id is not None:
        base["taskId"] = task_id
    if session_id is not None:
        base["sessionId"] = session_id

    # Compute entryHash over base object
    canonical_base = canonicalize(base)
    entry_hash = sha256_hex(canonical_base)

    # Build object with entryHash but without signature for signing
    to_sign = dict(base)
    to_sign["entryHash"] = entry_hash

    canonical_to_sign = canonicalize(to_sign)
    signature = sign_detached(canonical_to_sign, private_key, key_id)

    return AuditEntry(
        entryId=entry_id,
        timestamp=timestamp,
        actorDID=actor_did,
        eventType=event_type,
        eventData=event_data,
        previousHash=previous_hash,
        taskId=task_id,
        sessionId=session_id,
        entryHash=entry_hash,
        signature=signature,
        keyId=key_id,
    )
