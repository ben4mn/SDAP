"""Unit tests for sdap.handshake module."""

from __future__ import annotations

import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

import pytest

from sdap.handshake.protocol import (
    HandshakeState,
    Session,
    create_handshake_confirm,
    create_handshake_init,
    process_handshake_confirm,
    process_handshake_init,
)
from sdap.handshake.session_store import SessionStore
from sdap.identity.did import create_did, DIDDocument
from sdap.identity.keys import (
    generate_ed25519_keypair,
    generate_x25519_keypair,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agent(provider_domain: str, agent_id: str):
    """Create a full agent setup: auth keypair, ephemeral keypair, DID document."""
    auth_kp = generate_ed25519_keypair("auth-key-1")
    agree_kp = generate_x25519_keypair("agree-key-1")
    did = f"did:sdap:{provider_domain}:{agent_id}"
    doc = create_did(
        provider_domain=provider_domain,
        agent_id=agent_id,
        auth_key=auth_kp.public_key,
        agreement_key=agree_kp.public_key,
        a2a_endpoint=f"https://{provider_domain}/a2a",
        handshake_endpoint=f"https://{provider_domain}/sdap/handshake",
    )
    return auth_kp, agree_kp, did, doc


def _make_resolver(*docs: DIDDocument):
    """Return a resolve_did_func that serves the given DID documents."""
    mapping = {doc.id: doc for doc in docs}

    def resolve(did: str) -> DIDDocument:
        if did not in mapping:
            raise ValueError(f"DID not found: {did!r}")
        return mapping[did]

    return resolve


# ---------------------------------------------------------------------------
# Full handshake flow
# ---------------------------------------------------------------------------


class TestFullHandshake:
    def setup_method(self):
        self.alice_auth, self.alice_agree, self.alice_did, self.alice_doc = _make_agent(
            "alice.example.com", "alice-agent"
        )
        self.bob_auth, self.bob_agree, self.bob_did, self.bob_doc = _make_agent(
            "bob.example.com", "bob-agent"
        )
        self.resolver = _make_resolver(self.alice_doc, self.bob_doc)

    def test_full_three_message_handshake(self):
        # Step 1: Alice creates INIT
        alice_ephemeral = generate_x25519_keypair("alice-eph")
        init_msg, alice_eph_private = create_handshake_init(
            initiator_did=self.alice_did,
            target_did=self.bob_did,
            auth_private_key=self.alice_auth.private_key,
            auth_key_id=self.alice_auth.key_id,
            ephemeral_keypair=alice_ephemeral,
            requested_scopes=["records:read"],
            required_security_level="standard",
        )

        assert init_msg["type"] == "sdap-handshake-init"
        assert "jws" in init_msg

        # Decode the init payload to get nonce
        import base64, json
        parts = init_msg["jws"].split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        alice_nonce = payload["nonce"]
        session_id = payload["sessionId"]

        # Step 2: Bob processes INIT and creates ACCEPT
        bob_ephemeral = generate_x25519_keypair("bob-eph")
        accept_msg, bob_session = process_handshake_init(
            init_msg=init_msg,
            responder_did=self.bob_did,
            responder_auth_key=self.bob_auth.private_key,
            responder_auth_key_id=self.bob_auth.key_id,
            responder_ephemeral=bob_ephemeral,
            resolve_did_func=self.resolver,
            granted_scopes=["records:read"],
        )

        assert accept_msg["type"] == "sdap-handshake-accept"
        assert "jws" in accept_msg
        assert bob_session.session_id == session_id
        assert bob_session.initiator_did == self.alice_did
        assert bob_session.responder_did == self.bob_did
        assert bob_session.granted_scopes == ["records:read"]
        assert len(bob_session.encrypt_key) == 32
        assert len(bob_session.mac_key) == 32

        # Step 3: Alice processes ACCEPT and creates CONFIRM
        confirm_msg, alice_session = create_handshake_confirm(
            accept_msg=accept_msg,
            initiator_did=self.alice_did,
            initiator_nonce=alice_nonce,
            auth_private_key=self.alice_auth.private_key,
            auth_key_id=self.alice_auth.key_id,
            initiator_ephemeral_private=alice_eph_private,
        )

        assert confirm_msg["type"] == "sdap-handshake-confirm"
        assert "jws" in confirm_msg
        assert alice_session.session_id == session_id

        # Step 4: Bob processes CONFIRM
        confirmed_session = process_handshake_confirm(
            confirm_msg=confirm_msg,
            session=bob_session,
            resolve_did_func=self.resolver,
        )
        assert confirmed_session is bob_session

        # Both sessions should have the same keys
        assert alice_session.encrypt_key == bob_session.encrypt_key
        assert alice_session.mac_key == bob_session.mac_key

    def test_session_keys_match_both_sides(self):
        alice_ephemeral = generate_x25519_keypair("alice-eph")
        init_msg, alice_eph_private = create_handshake_init(
            initiator_did=self.alice_did,
            target_did=self.bob_did,
            auth_private_key=self.alice_auth.private_key,
            auth_key_id=self.alice_auth.key_id,
            ephemeral_keypair=alice_ephemeral,
            requested_scopes=["data:write"],
        )

        import base64, json
        parts = init_msg["jws"].split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        alice_nonce = payload["nonce"]

        bob_ephemeral = generate_x25519_keypair("bob-eph")
        accept_msg, bob_session = process_handshake_init(
            init_msg=init_msg,
            responder_did=self.bob_did,
            responder_auth_key=self.bob_auth.private_key,
            responder_auth_key_id=self.bob_auth.key_id,
            responder_ephemeral=bob_ephemeral,
            resolve_did_func=self.resolver,
        )

        _, alice_session = create_handshake_confirm(
            accept_msg=accept_msg,
            initiator_did=self.alice_did,
            initiator_nonce=alice_nonce,
            auth_private_key=self.alice_auth.private_key,
            auth_key_id=self.alice_auth.key_id,
            initiator_ephemeral_private=alice_eph_private,
        )

        assert alice_session.encrypt_key == bob_session.encrypt_key
        assert alice_session.mac_key == bob_session.mac_key
        assert alice_session.encrypt_key != alice_session.mac_key


# ---------------------------------------------------------------------------
# INIT validation
# ---------------------------------------------------------------------------


class TestHandshakeInitValidation:
    def setup_method(self):
        self.alice_auth, self.alice_agree, self.alice_did, self.alice_doc = _make_agent(
            "alice.example.com", "alice-agent"
        )
        self.bob_auth, self.bob_agree, self.bob_did, self.bob_doc = _make_agent(
            "bob.example.com", "bob-agent"
        )
        self.resolver = _make_resolver(self.alice_doc, self.bob_doc)

    def test_invalid_initiator_did_raises(self):
        ephemeral = generate_x25519_keypair("eph")
        with pytest.raises(ValueError, match="initiator"):
            create_handshake_init(
                initiator_did="not-a-did",
                target_did=self.bob_did,
                auth_private_key=self.alice_auth.private_key,
                auth_key_id=self.alice_auth.key_id,
                ephemeral_keypair=ephemeral,
                requested_scopes=[],
            )

    def test_invalid_target_did_raises(self):
        ephemeral = generate_x25519_keypair("eph")
        with pytest.raises(ValueError, match="target"):
            create_handshake_init(
                initiator_did=self.alice_did,
                target_did="not-a-did",
                auth_private_key=self.alice_auth.private_key,
                auth_key_id=self.alice_auth.key_id,
                ephemeral_keypair=ephemeral,
                requested_scopes=[],
            )

    def test_wrong_target_did_in_init_raises(self):
        """Bob rejects an INIT not addressed to him."""
        ephemeral = generate_x25519_keypair("eph")
        # Address init to alice but process with bob
        init_msg, _ = create_handshake_init(
            initiator_did=self.alice_did,
            target_did=self.alice_did,  # Wrong target!
            auth_private_key=self.alice_auth.private_key,
            auth_key_id=self.alice_auth.key_id,
            ephemeral_keypair=ephemeral,
            requested_scopes=[],
        )
        bob_eph = generate_x25519_keypair("bob-eph")
        with pytest.raises(ValueError, match="targetDID"):
            process_handshake_init(
                init_msg=init_msg,
                responder_did=self.bob_did,
                responder_auth_key=self.bob_auth.private_key,
                responder_auth_key_id=self.bob_auth.key_id,
                responder_ephemeral=bob_eph,
                resolve_did_func=self.resolver,
            )

    def test_missing_jws_raises(self):
        bob_eph = generate_x25519_keypair("bob-eph")
        with pytest.raises(ValueError, match="jws"):
            process_handshake_init(
                init_msg={"type": "sdap-handshake-init"},
                responder_did=self.bob_did,
                responder_auth_key=self.bob_auth.private_key,
                responder_auth_key_id=self.bob_auth.key_id,
                responder_ephemeral=bob_eph,
                resolve_did_func=self.resolver,
            )


# ---------------------------------------------------------------------------
# ACCEPT validation
# ---------------------------------------------------------------------------


class TestHandshakeAcceptValidation:
    def setup_method(self):
        self.alice_auth, _, self.alice_did, self.alice_doc = _make_agent(
            "alice.example.com", "alice-agent"
        )
        self.bob_auth, _, self.bob_did, self.bob_doc = _make_agent(
            "bob.example.com", "bob-agent"
        )
        self.resolver = _make_resolver(self.alice_doc, self.bob_doc)

    def _make_init(self):
        ephemeral = generate_x25519_keypair("eph")
        init_msg, eph_private = create_handshake_init(
            initiator_did=self.alice_did,
            target_did=self.bob_did,
            auth_private_key=self.alice_auth.private_key,
            auth_key_id=self.alice_auth.key_id,
            ephemeral_keypair=ephemeral,
            requested_scopes=["data:read"],
        )
        import base64, json
        parts = init_msg["jws"].split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        return init_msg, payload["nonce"], eph_private

    def test_nonce_mismatch_in_accept_raises(self):
        init_msg, alice_nonce, eph_private = self._make_init()
        bob_eph = generate_x25519_keypair("bob-eph")
        accept_msg, _ = process_handshake_init(
            init_msg=init_msg,
            responder_did=self.bob_did,
            responder_auth_key=self.bob_auth.private_key,
            responder_auth_key_id=self.bob_auth.key_id,
            responder_ephemeral=bob_eph,
            resolve_did_func=self.resolver,
        )

        with pytest.raises(ValueError, match="[Nn]once"):
            create_handshake_confirm(
                accept_msg=accept_msg,
                initiator_did=self.alice_did,
                initiator_nonce="wrong-nonce-value",
                auth_private_key=self.alice_auth.private_key,
                auth_key_id=self.alice_auth.key_id,
                initiator_ephemeral_private=eph_private,
            )

    def test_missing_jws_in_accept_raises(self):
        _, alice_nonce, eph_private = self._make_init()
        with pytest.raises(ValueError, match="jws"):
            create_handshake_confirm(
                accept_msg={"type": "sdap-handshake-accept"},
                initiator_did=self.alice_did,
                initiator_nonce=alice_nonce,
                auth_private_key=self.alice_auth.private_key,
                auth_key_id=self.alice_auth.key_id,
                initiator_ephemeral_private=eph_private,
            )


# ---------------------------------------------------------------------------
# CONFIRM validation
# ---------------------------------------------------------------------------


class TestHandshakeConfirmValidation:
    def setup_method(self):
        self.alice_auth, _, self.alice_did, self.alice_doc = _make_agent(
            "alice.example.com", "alice-agent"
        )
        self.bob_auth, _, self.bob_did, self.bob_doc = _make_agent(
            "bob.example.com", "bob-agent"
        )
        self.resolver = _make_resolver(self.alice_doc, self.bob_doc)

    def _full_init_accept(self):
        ephemeral = generate_x25519_keypair("eph")
        init_msg, eph_private = create_handshake_init(
            initiator_did=self.alice_did,
            target_did=self.bob_did,
            auth_private_key=self.alice_auth.private_key,
            auth_key_id=self.alice_auth.key_id,
            ephemeral_keypair=ephemeral,
            requested_scopes=[],
        )
        import base64, json
        parts = init_msg["jws"].split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        alice_nonce = payload["nonce"]

        bob_eph = generate_x25519_keypair("bob-eph")
        accept_msg, bob_session = process_handshake_init(
            init_msg=init_msg,
            responder_did=self.bob_did,
            responder_auth_key=self.bob_auth.private_key,
            responder_auth_key_id=self.bob_auth.key_id,
            responder_ephemeral=bob_eph,
            resolve_did_func=self.resolver,
        )
        confirm_msg, alice_session = create_handshake_confirm(
            accept_msg=accept_msg,
            initiator_did=self.alice_did,
            initiator_nonce=alice_nonce,
            auth_private_key=self.alice_auth.private_key,
            auth_key_id=self.alice_auth.key_id,
            initiator_ephemeral_private=eph_private,
        )
        return confirm_msg, bob_session, alice_session

    def test_wrong_session_id_in_confirm_raises(self):
        confirm_msg, bob_session, _ = self._full_init_accept()
        bob_session.session_id = "tampered-session-id"
        with pytest.raises(ValueError, match="[Ss]ession"):
            process_handshake_confirm(
                confirm_msg=confirm_msg,
                session=bob_session,
                resolve_did_func=self.resolver,
            )

    def test_expired_session_raises(self):
        confirm_msg, bob_session, _ = self._full_init_accept()
        # Set expiry to the past
        bob_session.expiry = datetime.fromtimestamp(
            time.time() - 100, tz=timezone.utc
        )
        with pytest.raises(ValueError, match="[Ee]xpired"):
            process_handshake_confirm(
                confirm_msg=confirm_msg,
                session=bob_session,
                resolve_did_func=self.resolver,
            )

    def test_missing_jws_in_confirm_raises(self):
        _, bob_session, _ = self._full_init_accept()
        with pytest.raises(ValueError, match="jws"):
            process_handshake_confirm(
                confirm_msg={"type": "sdap-handshake-confirm"},
                session=bob_session,
                resolve_did_func=self.resolver,
            )


# ---------------------------------------------------------------------------
# SessionStore tests
# ---------------------------------------------------------------------------


class TestSessionStore:
    def _make_session(self, session_id: str, expired: bool = False) -> Session:
        offset = -100 if expired else 3600
        return Session(
            session_id=session_id,
            initiator_did="did:sdap:alice.com:alice",
            responder_did="did:sdap:bob.com:bob",
            encrypt_key=b"a" * 32,
            mac_key=b"b" * 32,
            granted_scopes=["data:read"],
            security_level="standard",
            expiry=datetime.fromtimestamp(time.time() + offset, tz=timezone.utc),
            sequence_counter={"did:sdap:alice.com:alice": 0, "did:sdap:bob.com:bob": 0},
        )

    def test_store_and_get(self):
        store = SessionStore()
        session = self._make_session("sess-1")
        store.store(session)
        assert store.get("sess-1") is session

    def test_get_missing_returns_none(self):
        store = SessionStore()
        assert store.get("nonexistent") is None

    def test_remove(self):
        store = SessionStore()
        session = self._make_session("sess-1")
        store.store(session)
        store.remove("sess-1")
        assert store.get("sess-1") is None

    def test_remove_nonexistent_no_error(self):
        store = SessionStore()
        store.remove("nonexistent")  # Should not raise

    def test_cleanup_expired(self):
        store = SessionStore()
        active = self._make_session("active")
        expired = self._make_session("expired", expired=True)
        store.store(active)
        store.store(expired)

        store.cleanup_expired()

        assert store.get("active") is active
        assert store.get("expired") is None

    def test_next_sequence(self):
        store = SessionStore()
        session = self._make_session("sess-1")
        store.store(session)

        seq1 = store.next_sequence("sess-1", "did:sdap:alice.com:alice")
        seq2 = store.next_sequence("sess-1", "did:sdap:alice.com:alice")
        assert seq1 == 1
        assert seq2 == 2

    def test_next_sequence_different_dids(self):
        store = SessionStore()
        session = self._make_session("sess-1")
        store.store(session)

        seq_alice = store.next_sequence("sess-1", "did:sdap:alice.com:alice")
        seq_bob = store.next_sequence("sess-1", "did:sdap:bob.com:bob")
        assert seq_alice == 1
        assert seq_bob == 1

    def test_next_sequence_missing_session_raises(self):
        store = SessionStore()
        with pytest.raises(KeyError):
            store.next_sequence("nonexistent", "did:sdap:alice.com:alice")

    def test_validate_sequence_valid(self):
        store = SessionStore()
        session = self._make_session("sess-1")
        store.store(session)

        assert store.validate_sequence("sess-1", "did:sdap:alice.com:alice", 1) is True

    def test_validate_sequence_replay_fails(self):
        store = SessionStore()
        session = self._make_session("sess-1")
        store.store(session)

        store.next_sequence("sess-1", "did:sdap:alice.com:alice")  # counter = 1
        assert store.validate_sequence("sess-1", "did:sdap:alice.com:alice", 1) is False

    def test_validate_sequence_zero_fails(self):
        store = SessionStore()
        session = self._make_session("sess-1")
        store.store(session)
        assert store.validate_sequence("sess-1", "did:sdap:alice.com:alice", 0) is False


# ---------------------------------------------------------------------------
# HandshakeState enum
# ---------------------------------------------------------------------------


class TestHandshakeState:
    def test_enum_values_exist(self):
        assert HandshakeState.INIT_SENT == "INIT_SENT"
        assert HandshakeState.ACCEPT_RECEIVED == "ACCEPT_RECEIVED"
        assert HandshakeState.CONFIRMED == "CONFIRMED"
        assert HandshakeState.FAILED == "FAILED"
