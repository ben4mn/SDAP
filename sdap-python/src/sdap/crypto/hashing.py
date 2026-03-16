"""SHA-256 hashing utilities."""

import hashlib


def sha256_hex(data: bytes) -> str:
    """Return lowercase hex-encoded SHA-256 digest of data."""
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """Return raw bytes SHA-256 digest of data."""
    return hashlib.sha256(data).digest()
