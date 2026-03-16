"""Ed25519 JWS signing and verification."""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    # Re-pad
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def sign_jws(payload: bytes, private_key: Ed25519PrivateKey, key_id: str) -> str:
    """Create a compact JWS with EdDSA algorithm and kid header.

    Returns the compact serialization: ``<header>.<payload>.<signature>``.
    """
    header = {"alg": "EdDSA", "kid": key_id}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = private_key.sign(signing_input)
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_jws(jws: str, public_key: Ed25519PublicKey) -> bytes:
    """Verify a compact JWS and return the decoded payload bytes.

    Raises ``ValueError`` on invalid format or bad signature.
    """
    parts = jws.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWS: expected 3 dot-separated parts")
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _b64url_decode(sig_b64)
    try:
        public_key.verify(signature, signing_input)
    except Exception as exc:
        raise ValueError(f"JWS signature verification failed: {exc}") from exc
    return _b64url_decode(payload_b64)


def sign_detached(
    canonical_bytes: bytes, private_key: Ed25519PrivateKey, key_id: str
) -> str:
    """Create a detached-payload compact JWS.

    The payload section is empty: ``<header>..<signature>``.
    """
    header = {"alg": "EdDSA", "kid": key_id, "b64": False, "crit": ["b64"]}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    # For detached content JWS, signing input is header_b64 + "." + payload
    # Here payload is the raw canonical bytes (not base64-encoded per RFC 7797)
    signing_input = header_b64.encode("ascii") + b"." + canonical_bytes
    signature = private_key.sign(signing_input)
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}..{sig_b64}"


def verify_detached(
    jws: str, canonical_bytes: bytes, public_key: Ed25519PublicKey
) -> bool:
    """Verify a detached-payload JWS against the provided canonical bytes.

    Returns ``True`` if valid, ``False`` otherwise.
    """
    parts = jws.split(".")
    if len(parts) != 3 or parts[1] != "":
        return False
    header_b64, _, sig_b64 = parts
    signing_input = header_b64.encode("ascii") + b"." + canonical_bytes
    signature = _b64url_decode(sig_b64)
    try:
        public_key.verify(signature, signing_input)
        return True
    except Exception:
        return False
