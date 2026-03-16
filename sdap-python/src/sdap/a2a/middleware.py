"""A2A message wrapping and unwrapping with SDAP session security."""

from __future__ import annotations

import json
import time

from sdap.crypto import decrypt_payload, encrypt_payload, sha256_hex
from sdap.handshake.protocol import Session


def wrap_a2a_message(
    message: dict,
    session: Session,
    encrypt_key: bytes,
    sender_did: str,
) -> dict:
    """Wrap an A2A message with an SDAP security envelope.

    The message payload is encrypted with AES-256-GCM using the session encrypt key.
    The envelope includes session metadata and a hash of the plaintext for audit.

    Args:
        message: The A2A message dict to wrap.
        session: The active :class:`Session`.
        encrypt_key: 32-byte AES session key.
        sender_did: DID of the message sender.

    Returns:
        Wrapped message dict with SDAP envelope.
    """
    if session.is_expired():
        raise ValueError(f"Session {session.session_id} has expired")

    # Get and increment the outgoing (send) sequence number
    current_seq = session.send_counter.get(sender_did, 0)
    next_seq = current_seq + 1
    session.send_counter[sender_did] = next_seq

    plaintext = json.dumps(message, separators=(",", ":")).encode("utf-8")
    audit_hash = sha256_hex(plaintext)

    encrypted = encrypt_payload(
        plaintext=plaintext,
        key=encrypt_key,
        session_id=session.session_id,
        sequence_number=next_seq,
        sender_did=sender_did,
    )

    return {
        "sdap": {
            "sessionId": session.session_id,
            "senderDID": sender_did,
            "sequenceNumber": next_seq,
            "auditHash": audit_hash,
            "timestamp": int(time.time()),
        },
        "payload": encrypted,
    }


def unwrap_a2a_message(
    wrapped: dict,
    session: Session,
    encrypt_key: bytes,
) -> dict:
    """Decrypt and validate a wrapped A2A message.

    Args:
        wrapped: The wrapped message dict from :func:`wrap_a2a_message`.
        session: The active :class:`Session`.
        encrypt_key: 32-byte AES session key.

    Returns:
        The original A2A message dict.

    Raises:
        ValueError: On decryption failure, session mismatch, or sequence violation.
    """
    sdap_header = wrapped.get("sdap")
    if not sdap_header:
        raise ValueError("Missing 'sdap' header in wrapped message")

    wrapped_session_id = sdap_header.get("sessionId")
    if wrapped_session_id != session.session_id:
        raise ValueError(
            f"Session ID mismatch: expected {session.session_id!r}, "
            f"got {wrapped_session_id!r}"
        )

    if session.is_expired():
        raise ValueError(f"Session {session.session_id} has expired")

    sender_did = sdap_header.get("senderDID")
    sequence_number = sdap_header.get("sequenceNumber")

    if not sender_did:
        raise ValueError("Missing senderDID in SDAP header")
    if sequence_number is None:
        raise ValueError("Missing sequenceNumber in SDAP header")

    # Validate sequence number monotonicity against received-from-sender counter
    current_seq = session.sequence_counter.get(sender_did, 0)
    if sequence_number <= current_seq:
        raise ValueError(
            f"Sequence number {sequence_number} is not greater than current "
            f"counter {current_seq} for sender {sender_did!r}"
        )

    encrypted = wrapped.get("payload")
    if not encrypted:
        raise ValueError("Missing 'payload' in wrapped message")

    plaintext = decrypt_payload(
        jwe=encrypted,
        key=encrypt_key,
        session_id=session.session_id,
        sequence_number=sequence_number,
        sender_did=sender_did,
    )

    # Verify audit hash
    expected_hash = sha256_hex(plaintext)
    if sdap_header.get("auditHash") and sdap_header["auditHash"] != expected_hash:
        raise ValueError("Audit hash mismatch — message may have been tampered with")

    # Update sequence counter
    session.sequence_counter[sender_did] = sequence_number

    return json.loads(plaintext)
