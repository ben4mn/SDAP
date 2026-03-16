"""AES-256-GCM encryption/decryption for SDAP session payloads (JWE-like format)."""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _build_aad(session_id: str, sequence_number: int, sender_did: str) -> bytes:
    """Build Additional Authenticated Data bytes."""
    aad_obj = {
        "sessionId": session_id,
        "sequenceNumber": sequence_number,
        "senderDID": sender_did,
    }
    return json.dumps(aad_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def encrypt_payload(
    plaintext: bytes,
    key: bytes,
    session_id: str,
    sequence_number: int,
    sender_did: str,
) -> str:
    """Encrypt plaintext with AES-256-GCM and return a compact JWE-like string.

    Format: ``<protected>.<iv>.<ciphertext>.<tag>``

    The ``<protected>`` header contains algorithm metadata.
    AAD is derived from sessionId, sequenceNumber, and senderDID.
    """
    if len(key) != 32:
        raise ValueError("key must be 32 bytes for AES-256-GCM")

    iv = os.urandom(12)  # 96-bit nonce
    aad = _build_aad(session_id, sequence_number, sender_did)

    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext + 16-byte tag appended
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, aad)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    protected_header = {
        "alg": "dir",
        "enc": "A256GCM",
        "apu": _b64url_encode(aad),
    }
    protected_b64 = _b64url_encode(
        json.dumps(protected_header, separators=(",", ":")).encode()
    )
    iv_b64 = _b64url_encode(iv)
    ciphertext_b64 = _b64url_encode(ciphertext)
    tag_b64 = _b64url_encode(tag)

    return f"{protected_b64}.{iv_b64}.{ciphertext_b64}.{tag_b64}"


def decrypt_payload(
    jwe: str,
    key: bytes,
    session_id: str,
    sequence_number: int,
    sender_did: str,
) -> bytes:
    """Decrypt a compact JWE-like string produced by :func:`encrypt_payload`.

    Raises ``ValueError`` if the AAD doesn't match or decryption fails.
    """
    if len(key) != 32:
        raise ValueError("key must be 32 bytes for AES-256-GCM")

    parts = jwe.split(".")
    if len(parts) != 4:
        raise ValueError("Invalid JWE: expected 4 dot-separated parts")

    _, iv_b64, ciphertext_b64, tag_b64 = parts
    iv = _b64url_decode(iv_b64)
    ciphertext = _b64url_decode(ciphertext_b64)
    tag = _b64url_decode(tag_b64)

    aad = _build_aad(session_id, sequence_number, sender_did)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(iv, ciphertext + tag, aad)
    except Exception as exc:
        raise ValueError(f"Decryption failed: {exc}") from exc

    return plaintext
