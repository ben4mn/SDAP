"""Unit tests for sdap.a2a module."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from sdap.a2a.agent_card import build_sdap_extension
from sdap.a2a.middleware import unwrap_a2a_message, wrap_a2a_message
from sdap.a2a.client import SDAPClient
from sdap.handshake.protocol import Session
from sdap.handshake.session_store import SessionStore
from sdap.identity.did import create_did, DIDDocument
from sdap.identity.keys import generate_ed25519_keypair, generate_x25519_keypair


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session(
    session_id: str = "test-session",
    expired: bool = False,
    initiator_did: str = "did:sdap:alice.com:alice",
    responder_did: str = "did:sdap:bob.com:bob",
) -> Session:
    offset = -100 if expired else 3600
    return Session(
        session_id=session_id,
        initiator_did=initiator_did,
        responder_did=responder_did,
        encrypt_key=b"k" * 32,
        mac_key=b"m" * 32,
        granted_scopes=["data:read"],
        security_level="standard",
        expiry=datetime.fromtimestamp(time.time() + offset, tz=timezone.utc),
        sequence_counter={initiator_did: 0, responder_did: 0},
    )


# ---------------------------------------------------------------------------
# Agent Card extension
# ---------------------------------------------------------------------------


class TestBuildSdapExtension:
    def test_builds_valid_extension(self):
        ext = build_sdap_extension(
            did="did:sdap:example.com:agent",
            handshake_endpoint="https://example.com/sdap/handshake",
            supported_layers=[1, 2, 3],
            min_security_level="standard",
        )
        assert "sdap" in ext
        sdap = ext["sdap"]
        assert sdap["did"] == "did:sdap:example.com:agent"
        assert sdap["handshakeEndpoint"] == "https://example.com/sdap/handshake"
        assert sdap["supportedLayers"] == [1, 2, 3]
        assert sdap["minSecurityLevel"] == "standard"
        assert sdap["version"] == "1.0"

    def test_default_security_level_is_basic(self):
        ext = build_sdap_extension(
            did="did:sdap:example.com:agent",
            handshake_endpoint="https://example.com/sdap",
            supported_layers=[1],
        )
        assert ext["sdap"]["minSecurityLevel"] == "basic"

    def test_invalid_security_level_raises(self):
        with pytest.raises(ValueError, match="min_security_level"):
            build_sdap_extension(
                did="did:sdap:example.com:agent",
                handshake_endpoint="https://example.com/sdap",
                supported_layers=[1],
                min_security_level="ultra",
            )

    def test_all_security_levels_valid(self):
        for level in ("basic", "standard", "high", "critical"):
            ext = build_sdap_extension(
                did="did:sdap:example.com:agent",
                handshake_endpoint="https://example.com/sdap",
                supported_layers=[1],
                min_security_level=level,
            )
            assert ext["sdap"]["minSecurityLevel"] == level


# ---------------------------------------------------------------------------
# Middleware: wrap and unwrap
# ---------------------------------------------------------------------------


class TestWrapUnwrap:
    def setup_method(self):
        self.sender_did = "did:sdap:alice.com:alice"
        self.session = _make_session(initiator_did=self.sender_did)

    def test_wrap_produces_sdap_envelope(self):
        message = {"action": "get-record", "id": "123"}
        wrapped = wrap_a2a_message(
            message=message,
            session=self.session,
            encrypt_key=self.session.encrypt_key,
            sender_did=self.sender_did,
        )
        assert "sdap" in wrapped
        assert "payload" in wrapped
        sdap = wrapped["sdap"]
        assert sdap["sessionId"] == self.session.session_id
        assert sdap["senderDID"] == self.sender_did
        assert sdap["sequenceNumber"] == 1
        assert "auditHash" in sdap
        assert "timestamp" in sdap

    def test_wrap_unwrap_roundtrip(self):
        message = {"action": "get-record", "data": {"id": "abc"}}
        wrapped = wrap_a2a_message(
            message=message,
            session=self.session,
            encrypt_key=self.session.encrypt_key,
            sender_did=self.sender_did,
        )
        recovered = unwrap_a2a_message(
            wrapped=wrapped,
            session=self.session,
            encrypt_key=self.session.encrypt_key,
        )
        assert recovered == message

    def test_sequence_increments(self):
        msg = {"x": 1}
        w1 = wrap_a2a_message(msg, self.session, self.session.encrypt_key, self.sender_did)
        w2 = wrap_a2a_message(msg, self.session, self.session.encrypt_key, self.sender_did)
        assert w1["sdap"]["sequenceNumber"] == 1
        assert w2["sdap"]["sequenceNumber"] == 2

    def test_unwrap_updates_sequence_counter(self):
        msg = {"x": 1}
        wrapped = wrap_a2a_message(msg, self.session, self.session.encrypt_key, self.sender_did)

        # Create a fresh session for the receiver (same keys)
        recv_session = _make_session(
            session_id=self.session.session_id,
            initiator_did=self.sender_did,
        )
        recv_session.encrypt_key = self.session.encrypt_key

        unwrap_a2a_message(wrapped, recv_session, recv_session.encrypt_key)
        assert recv_session.sequence_counter.get(self.sender_did) == 1

    def test_replay_same_seq_raises(self):
        msg = {"x": 1}
        wrapped = wrap_a2a_message(msg, self.session, self.session.encrypt_key, self.sender_did)

        recv_session = _make_session(
            session_id=self.session.session_id,
            initiator_did=self.sender_did,
        )
        recv_session.encrypt_key = self.session.encrypt_key

        # First unwrap OK
        unwrap_a2a_message(wrapped, recv_session, recv_session.encrypt_key)
        # Second unwrap with same message should fail (sequence already consumed)
        with pytest.raises(ValueError, match="[Ss]equence"):
            unwrap_a2a_message(wrapped, recv_session, recv_session.encrypt_key)

    def test_wrap_expired_session_raises(self):
        expired = _make_session(expired=True)
        with pytest.raises(ValueError, match="[Ee]xpired"):
            wrap_a2a_message({"x": 1}, expired, expired.encrypt_key, self.sender_did)

    def test_unwrap_wrong_session_id_raises(self):
        msg = {"x": 1}
        wrapped = wrap_a2a_message(msg, self.session, self.session.encrypt_key, self.sender_did)
        # Modify session_id in envelope
        wrapped["sdap"]["sessionId"] = "wrong-session-id"

        other_session = _make_session(session_id="wrong-session-id-no-match")
        with pytest.raises(ValueError, match="[Ss]ession"):
            unwrap_a2a_message(wrapped, other_session, self.session.encrypt_key)

    def test_wrap_with_empty_message(self):
        wrapped = wrap_a2a_message({}, self.session, self.session.encrypt_key, self.sender_did)
        recovered = unwrap_a2a_message(wrapped, self.session, self.session.encrypt_key)
        assert recovered == {}

    def test_missing_sdap_header_raises(self):
        with pytest.raises(ValueError, match="sdap"):
            unwrap_a2a_message({"payload": "something"}, self.session, self.session.encrypt_key)

    def test_missing_payload_raises(self):
        with pytest.raises(ValueError, match="payload"):
            unwrap_a2a_message(
                {"sdap": {"sessionId": self.session.session_id, "senderDID": self.sender_did, "sequenceNumber": 1}},
                self.session,
                self.session.encrypt_key,
            )


# ---------------------------------------------------------------------------
# SDAPClient
# ---------------------------------------------------------------------------


class TestSDAPClient:
    def setup_method(self):
        self.alice_kp = generate_ed25519_keypair("alice-auth")
        self.alice_did = "did:sdap:alice.example.com:alice"
        self.session_store = SessionStore()
        self.client = SDAPClient(
            did=self.alice_did,
            auth_keypair=self.alice_kp,
            session_store=self.session_store,
        )

    def test_send_secure_creates_envelope(self):
        session = _make_session(initiator_did=self.alice_did)
        envelope = self.client.send_secure(session, {"action": "ping"})
        assert "sdap" in envelope
        assert "payload" in envelope

    def test_receive_secure_decrypts(self):
        session = _make_session(initiator_did=self.alice_did)
        # Simulate receiving a message sent by the other party
        other_did = "did:sdap:bob.com:bob"
        envelope = wrap_a2a_message(
            message={"data": "hello"},
            session=session,
            encrypt_key=session.encrypt_key,
            sender_did=other_did,
        )
        result = self.client.receive_secure(envelope, session)
        assert result == {"data": "hello"}

    async def test_establish_session_calls_http(self):
        """Test that establish_session makes the correct HTTP calls."""
        bob_auth = generate_ed25519_keypair("bob-auth")
        bob_agree = generate_x25519_keypair("bob-agree")
        bob_did = "did:sdap:bob.example.com:bob"
        bob_doc = create_did(
            provider_domain="bob.example.com",
            agent_id="bob",
            auth_key=bob_auth.public_key,
            agreement_key=bob_agree.public_key,
            a2a_endpoint="https://bob.example.com/a2a",
            handshake_endpoint="https://bob.example.com/sdap/handshake",
        )

        alice_auth = generate_ed25519_keypair("alice-auth-2")
        alice_agree = generate_x25519_keypair("alice-agree")
        alice_did = "did:sdap:alice.example.com:alice2"
        alice_doc = create_did(
            provider_domain="alice.example.com",
            agent_id="alice2",
            auth_key=alice_auth.public_key,
            agreement_key=alice_agree.public_key,
            a2a_endpoint="https://alice.example.com/a2a",
            handshake_endpoint="https://alice.example.com/sdap/handshake",
        )

        # Create a mock HTTP client that simulates Bob's server
        from sdap.handshake.protocol import process_handshake_init

        bob_ephemeral = generate_x25519_keypair("bob-eph")

        def resolve(did):
            if did == bob_did:
                return bob_doc
            if did == alice_did:
                return alice_doc
            raise ValueError(f"Unknown DID: {did}")

        async def mock_post(url, **kwargs):
            req_body = kwargs.get("json", {})
            if "confirm" not in url:
                # This is the INIT -> ACCEPT response
                accept_msg, _ = process_handshake_init(
                    init_msg=req_body,
                    responder_did=bob_did,
                    responder_auth_key=bob_auth.private_key,
                    responder_auth_key_id=bob_auth.key_id,
                    responder_ephemeral=bob_ephemeral,
                    resolve_did_func=resolve,
                    granted_scopes=["data:read"],
                )
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = accept_msg
                return mock_resp
            else:
                # CONFIRM endpoint
                mock_resp = MagicMock()
                mock_resp.status_code = 204
                return mock_resp

        mock_http = AsyncMock()
        mock_http.post = mock_post

        client = SDAPClient(
            did=alice_did,
            auth_keypair=alice_auth,
            session_store=self.session_store,
        )

        session = await client.establish_session(
            target_did=bob_did,
            requested_scopes=["data:read"],
            resolve_did_func=resolve,
            http_client=mock_http,
        )

        assert session.initiator_did == alice_did
        assert session.responder_did == bob_did
        assert "data:read" in session.granted_scopes
        # Session should be stored
        assert self.session_store.get(session.session_id) is session
