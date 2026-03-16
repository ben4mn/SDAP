"""Unit tests for sdap.crypto module."""

from __future__ import annotations

import json
import os

import pytest

from sdap.crypto.canonicalize import canonicalize
from sdap.crypto.encryption import decrypt_payload, encrypt_payload
from sdap.crypto.hashing import sha256_bytes, sha256_hex
from sdap.crypto.key_exchange import derive_session_keys, perform_ecdh
from sdap.crypto.signing import (
    sign_detached,
    sign_jws,
    verify_detached,
    verify_jws,
)
from sdap.identity.keys import generate_ed25519_keypair, generate_x25519_keypair


# ---------------------------------------------------------------------------
# Hashing tests
# ---------------------------------------------------------------------------


class TestHashing:
    def test_sha256_hex_known_value(self):
        # SHA256 of empty bytes
        result = sha256_hex(b"")
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_sha256_hex_is_lowercase(self):
        result = sha256_hex(b"hello")
        assert result == result.lower()

    def test_sha256_bytes_length(self):
        result = sha256_bytes(b"hello world")
        assert len(result) == 32

    def test_sha256_hex_and_bytes_consistent(self):
        data = b"test data"
        assert sha256_bytes(data).hex() == sha256_hex(data)


# ---------------------------------------------------------------------------
# Canonicalize tests
# ---------------------------------------------------------------------------


class TestCanonicalize:
    def test_empty_dict(self):
        assert canonicalize({}) == b"{}"

    def test_sorted_keys(self):
        result = canonicalize({"b": 2, "a": 1})
        assert result == b'{"a":1,"b":2}'

    def test_nested_sorted_keys(self):
        result = canonicalize({"z": {"b": 2, "a": 1}, "a": 0})
        assert result == b'{"a":0,"z":{"a":1,"b":2}}'

    def test_no_whitespace(self):
        result = canonicalize({"key": "value"})
        assert b" " not in result

    def test_null_value(self):
        result = canonicalize({"k": None})
        assert result == b'{"k":null}'

    def test_boolean_values(self):
        result = canonicalize({"t": True, "f": False})
        assert result == b'{"f":false,"t":true}'

    def test_array_values(self):
        result = canonicalize({"arr": [3, 1, 2]})
        assert result == b'{"arr":[3,1,2]}'

    def test_string_escaping(self):
        result = canonicalize({"s": 'hello "world"'})
        assert b'\\"world\\"' in result

    def test_integer(self):
        result = canonicalize({"n": 42})
        assert result == b'{"n":42}'

    def test_unicode_string(self):
        result = canonicalize({"emoji": "\u2764"})
        # Should not escape Unicode beyond JSON minimum
        decoded = result.decode("utf-8")
        assert "\u2764" in decoded

    def test_nan_raises(self):
        import math
        with pytest.raises(ValueError, match="NaN"):
            canonicalize({"n": math.nan})

    def test_inf_raises(self):
        import math
        with pytest.raises(ValueError, match="Infinity"):
            canonicalize({"n": math.inf})

    def test_is_bytes(self):
        result = canonicalize({"k": "v"})
        assert isinstance(result, bytes)


# ---------------------------------------------------------------------------
# Signing tests
# ---------------------------------------------------------------------------


class TestSigning:
    def setup_method(self):
        self.kp = generate_ed25519_keypair("test-key")

    def test_sign_jws_format(self):
        jws = sign_jws(b"hello", self.kp.private_key, "test-key")
        parts = jws.split(".")
        assert len(parts) == 3
        # All parts should be non-empty
        assert all(p for p in parts)

    def test_verify_jws_roundtrip(self):
        payload = b'{"message": "hello"}'
        jws = sign_jws(payload, self.kp.private_key, "test-key")
        recovered = verify_jws(jws, self.kp.public_key)
        assert recovered == payload

    def test_verify_jws_wrong_key(self):
        jws = sign_jws(b"data", self.kp.private_key, "test-key")
        wrong_kp = generate_ed25519_keypair("other")
        with pytest.raises(ValueError, match="signature"):
            verify_jws(jws, wrong_kp.public_key)

    def test_verify_jws_tampered_payload(self):
        jws = sign_jws(b"original", self.kp.private_key, "test-key")
        parts = jws.split(".")
        import base64
        tampered_payload = base64.urlsafe_b64encode(b"tampered").rstrip(b"=").decode()
        tampered_jws = f"{parts[0]}.{tampered_payload}.{parts[2]}"
        with pytest.raises(ValueError):
            verify_jws(tampered_jws, self.kp.public_key)

    def test_verify_jws_invalid_format(self):
        with pytest.raises(ValueError, match="3"):
            verify_jws("only.two", self.kp.public_key)

    def test_sign_detached_format(self):
        jws = sign_detached(b"canonical data", self.kp.private_key, "test-key")
        parts = jws.split(".")
        assert len(parts) == 3
        assert parts[1] == ""  # Empty payload section

    def test_verify_detached_valid(self):
        canonical = b'{"id":"did:sdap:example.com:agent"}'
        jws = sign_detached(canonical, self.kp.private_key, "test-key")
        assert verify_detached(jws, canonical, self.kp.public_key) is True

    def test_verify_detached_tampered(self):
        canonical = b"original"
        jws = sign_detached(canonical, self.kp.private_key, "test-key")
        assert verify_detached(jws, b"tampered", self.kp.public_key) is False

    def test_verify_detached_wrong_key(self):
        canonical = b"data"
        jws = sign_detached(canonical, self.kp.private_key, "test-key")
        wrong_kp = generate_ed25519_keypair("other")
        assert verify_detached(jws, canonical, wrong_kp.public_key) is False


# ---------------------------------------------------------------------------
# Key exchange tests
# ---------------------------------------------------------------------------


class TestKeyExchange:
    def setup_method(self):
        self.kp_a = generate_x25519_keypair("a")
        self.kp_b = generate_x25519_keypair("b")

    def test_ecdh_produces_shared_secret(self):
        secret_a = perform_ecdh(self.kp_a.private_key, self.kp_b.public_key)
        secret_b = perform_ecdh(self.kp_b.private_key, self.kp_a.public_key)
        assert secret_a == secret_b
        assert len(secret_a) == 32

    def test_different_keys_different_secrets(self):
        kp_c = generate_x25519_keypair("c")
        secret_a = perform_ecdh(self.kp_a.private_key, self.kp_b.public_key)
        secret_c = perform_ecdh(self.kp_a.private_key, kp_c.public_key)
        assert secret_a != secret_c

    def test_derive_session_keys_length(self):
        shared_secret = perform_ecdh(self.kp_a.private_key, self.kp_b.public_key)
        nonce_a = os.urandom(32)
        nonce_b = os.urandom(32)
        enc_key, mac_key = derive_session_keys(shared_secret, nonce_a, nonce_b, "session-1")
        assert len(enc_key) == 32
        assert len(mac_key) == 32

    def test_derive_session_keys_deterministic(self):
        shared_secret = perform_ecdh(self.kp_a.private_key, self.kp_b.public_key)
        nonce_a = os.urandom(32)
        nonce_b = os.urandom(32)
        k1 = derive_session_keys(shared_secret, nonce_a, nonce_b, "session-1")
        k2 = derive_session_keys(shared_secret, nonce_a, nonce_b, "session-1")
        assert k1 == k2

    def test_derive_session_keys_different_sessions(self):
        shared_secret = perform_ecdh(self.kp_a.private_key, self.kp_b.public_key)
        nonce_a = os.urandom(32)
        nonce_b = os.urandom(32)
        k1 = derive_session_keys(shared_secret, nonce_a, nonce_b, "session-1")
        k2 = derive_session_keys(shared_secret, nonce_a, nonce_b, "session-2")
        assert k1[0] != k2[0]

    def test_derive_keys_are_independent(self):
        shared_secret = perform_ecdh(self.kp_a.private_key, self.kp_b.public_key)
        nonce_a = os.urandom(32)
        nonce_b = os.urandom(32)
        enc_key, mac_key = derive_session_keys(shared_secret, nonce_a, nonce_b, "s")
        assert enc_key != mac_key


# ---------------------------------------------------------------------------
# Encryption tests
# ---------------------------------------------------------------------------


class TestEncryption:
    def setup_method(self):
        self.key = os.urandom(32)
        self.session_id = "test-session-abc"
        self.seq = 0
        self.sender = "did:sdap:example.com:agent"

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = b"hello, secure world!"
        jwe = encrypt_payload(plaintext, self.key, self.session_id, self.seq, self.sender)
        recovered = decrypt_payload(jwe, self.key, self.session_id, self.seq, self.sender)
        assert recovered == plaintext

    def test_jwe_format(self):
        jwe = encrypt_payload(b"data", self.key, self.session_id, self.seq, self.sender)
        parts = jwe.split(".")
        assert len(parts) == 4

    def test_wrong_key_fails(self):
        jwe = encrypt_payload(b"secret", self.key, self.session_id, self.seq, self.sender)
        wrong_key = os.urandom(32)
        with pytest.raises(ValueError, match="[Dd]ecrypt"):
            decrypt_payload(jwe, wrong_key, self.session_id, self.seq, self.sender)

    def test_wrong_session_id_fails(self):
        jwe = encrypt_payload(b"secret", self.key, self.session_id, self.seq, self.sender)
        with pytest.raises(ValueError):
            decrypt_payload(jwe, self.key, "wrong-session", self.seq, self.sender)

    def test_wrong_sequence_fails(self):
        jwe = encrypt_payload(b"secret", self.key, self.session_id, self.seq, self.sender)
        with pytest.raises(ValueError):
            decrypt_payload(jwe, self.key, self.session_id, self.seq + 1, self.sender)

    def test_wrong_sender_fails(self):
        jwe = encrypt_payload(b"secret", self.key, self.session_id, self.seq, self.sender)
        with pytest.raises(ValueError):
            decrypt_payload(jwe, self.key, self.session_id, self.seq, "did:sdap:other.com:agent")

    def test_ciphertext_is_random(self):
        plaintext = b"same plaintext"
        jwe1 = encrypt_payload(plaintext, self.key, self.session_id, self.seq, self.sender)
        jwe2 = encrypt_payload(plaintext, self.key, self.session_id, self.seq, self.sender)
        # Different IVs should produce different ciphertexts
        assert jwe1 != jwe2

    def test_invalid_key_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_payload(b"data", b"short", self.session_id, self.seq, self.sender)

    def test_empty_plaintext(self):
        jwe = encrypt_payload(b"", self.key, self.session_id, self.seq, self.sender)
        recovered = decrypt_payload(jwe, self.key, self.session_id, self.seq, self.sender)
        assert recovered == b""

    def test_large_payload(self):
        plaintext = os.urandom(64 * 1024)  # 64 KiB
        jwe = encrypt_payload(plaintext, self.key, self.session_id, self.seq, self.sender)
        recovered = decrypt_payload(jwe, self.key, self.session_id, self.seq, self.sender)
        assert recovered == plaintext
