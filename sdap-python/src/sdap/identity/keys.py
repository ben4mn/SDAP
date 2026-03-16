"""Key generation and encoding utilities for SDAP identity."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# base58btc alphabet (Bitcoin variant)
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    """Encode bytes to base58btc string."""
    # Count leading zero bytes
    count = 0
    for b in data:
        if b == 0:
            count += 1
        else:
            break

    n = int.from_bytes(data, "big")
    result = []
    while n > 0:
        n, remainder = divmod(n, 58)
        result.append(_BASE58_ALPHABET[remainder])
    result.extend(_BASE58_ALPHABET[0] for _ in range(count))
    return "".join(reversed(result))


def _base58_decode(s: str) -> bytes:
    """Decode base58btc string to bytes."""
    n = 0
    for char in s:
        n = n * 58 + _BASE58_ALPHABET.index(char)
    # Count leading '1' chars (represent zero bytes)
    count = 0
    for char in s:
        if char == "1":
            count += 1
        else:
            break
    result = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    return b"\x00" * count + result


@dataclass
class KeyPair:
    """Holds a private key, corresponding public key, and a key identifier."""

    private_key: Ed25519PrivateKey | X25519PrivateKey
    public_key: Ed25519PublicKey | X25519PublicKey
    key_id: str


def generate_ed25519_keypair(key_id: str) -> KeyPair:
    """Generate a fresh Ed25519 key pair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return KeyPair(private_key=private_key, public_key=public_key, key_id=key_id)


def generate_x25519_keypair(key_id: str) -> KeyPair:
    """Generate a fresh X25519 key pair."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return KeyPair(private_key=private_key, public_key=public_key, key_id=key_id)


def public_key_to_multibase(
    key: Union[Ed25519PublicKey, X25519PublicKey],
) -> str:
    """Encode a public key as a multibase base58btc string (``z`` prefix)."""
    raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "z" + _base58_encode(raw)


def multibase_to_public_key(
    multibase: str,
    key_type: str,
) -> Union[Ed25519PublicKey, X25519PublicKey]:
    """Decode a multibase string back to an Ed25519 or X25519 public key.

    Args:
        multibase: Multibase string with ``z`` prefix (base58btc).
        key_type: ``"Ed25519"`` or ``"X25519"``.

    Raises:
        ValueError: If the prefix is unsupported or key_type is unrecognised.
    """
    if not multibase.startswith("z"):
        raise ValueError("Only base58btc multibase ('z' prefix) is supported")
    raw = _base58_decode(multibase[1:])
    if key_type == "Ed25519":
        return Ed25519PublicKey.from_public_bytes(raw)
    elif key_type == "X25519":
        return X25519PublicKey.from_public_bytes(raw)
    else:
        raise ValueError(f"Unsupported key_type: {key_type!r}")


def public_key_to_jwk(key: X25519PublicKey) -> dict:
    """Encode an X25519 public key as a JWK dict (OKP key type, X25519 curve)."""
    raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    x_b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return {
        "kty": "OKP",
        "crv": "X25519",
        "x": x_b64,
    }


def jwk_to_public_key(jwk: dict) -> X25519PublicKey:
    """Decode a JWK dict for an X25519 public key.

    Raises:
        ValueError: If the JWK is not a valid X25519 OKP key.
    """
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "X25519":
        raise ValueError("JWK must be an OKP key with crv=X25519")
    x_b64 = jwk["x"]
    padding = 4 - len(x_b64) % 4
    if padding != 4:
        x_b64 += "=" * padding
    raw = base64.urlsafe_b64decode(x_b64)
    return X25519PublicKey.from_public_bytes(raw)
