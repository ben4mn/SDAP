"""X25519 ECDH key exchange and HKDF-based session key derivation."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def perform_ecdh(
    private_key: X25519PrivateKey, peer_public_key: X25519PublicKey
) -> bytes:
    """Perform X25519 ECDH and return the raw 32-byte shared secret."""
    return private_key.exchange(peer_public_key)


def derive_session_keys(
    shared_secret: bytes,
    nonce_a: bytes,
    nonce_b: bytes,
    session_id: str,
) -> tuple[bytes, bytes]:
    """Derive two 32-byte session keys from a shared secret using HKDF-SHA256.

    Args:
        shared_secret: Raw X25519 shared secret (32 bytes).
        nonce_a: Initiator nonce.
        nonce_b: Responder nonce.
        session_id: Unique session identifier string.

    Returns:
        ``(encrypt_key, mac_key)`` — each 32 bytes.
    """
    salt = hashlib.sha256(nonce_a + nonce_b).digest()
    info = b"sdap-session-v1" + session_id.encode("utf-8")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=info,
    )
    key_material = hkdf.derive(shared_secret)
    encrypt_key = key_material[:32]
    mac_key = key_material[32:]
    return encrypt_key, mac_key
