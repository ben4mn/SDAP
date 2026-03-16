"""Integration tests for the full SDAP protocol flow end-to-end.

Covers:
  1. Full end-to-end flow (handshake → encrypted messaging → delegation → audit)
  2. Three-agent delegation chain (A→B→C)
  3. Security negative tests (tampered messages, replay attacks, etc.)
"""

from __future__ import annotations

import base64
import json
import os
import time

import pytest

from sdap.identity import (
    generate_ed25519_keypair,
    generate_x25519_keypair,
    create_did,
    DIDDocument,
    create_attestation,
    verify_attestation,
)
from sdap.crypto import (
    encrypt_payload,
    decrypt_payload,
)
from sdap.handshake import (
    create_handshake_init,
    process_handshake_init,
    create_handshake_confirm,
    process_handshake_confirm,
    Session,
    SessionStore,
    HandshakeState,
)
from sdap.delegation import (
    create_delegation_token,
    decode_delegation_token,
    compute_chain_hash,
    validate_delegation_chain,
    is_scope_subset,
    DelegationConstraints,
    DelegationTokenPayload,
)
from sdap.audit import (
    create_audit_entry,
    verify_audit_chain,
    create_audit_commitment,
    AuditEntry,
)
from sdap.a2a import wrap_a2a_message, unwrap_a2a_message


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_agent(provider_domain: str, agent_id: str):
    """Create a full agent: auth keypair, agreement keypair, DID, DIDDocument."""
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


def _make_key_resolver(*pairs):
    """Return a resolve_key_func from (did, keypair) tuples."""
    mapping = {did: kp.public_key for did, kp in pairs}

    def resolve(did: str):
        if did not in mapping:
            raise ValueError(f"Unknown DID: {did!r}")
        return mapping[did]

    return resolve


def _decode_jws_payload(jws: str) -> dict:
    """Decode the middle (payload) part of a compact JWS."""
    parts = jws.split(".")
    payload_b64 = parts[1]
    # Add padding
    payload_b64 += "=" * (4 - len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


def _perform_full_handshake(initiator, responder, resolver, scopes=None):
    """Perform a complete 3-message handshake between two agents.

    Returns (alice_session, bob_session).
    """
    if scopes is None:
        scopes = ["data:read"]

    auth_a, _, did_a, _ = initiator
    auth_b, _, did_b, _ = responder

    eph_a = generate_x25519_keypair("eph-a")
    init_msg, eph_a_private = create_handshake_init(
        initiator_did=did_a,
        target_did=did_b,
        auth_private_key=auth_a.private_key,
        auth_key_id=auth_a.key_id,
        ephemeral_keypair=eph_a,
        requested_scopes=scopes,
    )

    init_payload = _decode_jws_payload(init_msg["jws"])
    alice_nonce = init_payload["nonce"]

    eph_b = generate_x25519_keypair("eph-b")
    accept_msg, bob_session = process_handshake_init(
        init_msg=init_msg,
        responder_did=did_b,
        responder_auth_key=auth_b.private_key,
        responder_auth_key_id=auth_b.key_id,
        responder_ephemeral=eph_b,
        resolve_did_func=resolver,
        granted_scopes=scopes,
    )

    confirm_msg, alice_session = create_handshake_confirm(
        accept_msg=accept_msg,
        initiator_did=did_a,
        initiator_nonce=alice_nonce,
        auth_private_key=auth_a.private_key,
        auth_key_id=auth_a.key_id,
        initiator_ephemeral_private=eph_a_private,
    )

    process_handshake_confirm(
        confirm_msg=confirm_msg,
        session=bob_session,
        resolve_did_func=resolver,
    )

    return alice_session, bob_session


# ---------------------------------------------------------------------------
# Test 1: Full end-to-end flow
# ---------------------------------------------------------------------------


class TestFullEndToEndFlow:
    """Exercise every major SDAP layer in sequence."""

    def setup_method(self):
        # Three agents: A (initiator), B (responder/delegatee), C (sub-delegatee)
        self.agent_a = _make_agent("alice.example.com", "agent-a")
        self.agent_b = _make_agent("bob.example.com", "agent-b")
        self.agent_c = _make_agent("carol.example.com", "agent-c")

        _, _, self.did_a, self.doc_a = self.agent_a
        _, _, self.did_b, self.doc_b = self.agent_b
        _, _, self.did_c, self.doc_c = self.agent_c

        self.auth_a, _, _, _ = self.agent_a
        self.auth_b, _, _, _ = self.agent_b
        self.auth_c, _, _, _ = self.agent_c

        self.resolver = _make_resolver(self.doc_a, self.doc_b, self.doc_c)

    # --- Step 1-2: Handshake ---

    def test_step1_handshake_produces_matching_sessions(self):
        scopes = ["medical-records:read:summary-only", "audit:read"]
        alice_session, bob_session = _perform_full_handshake(
            self.agent_a, self.agent_b, self.resolver, scopes=scopes
        )

        assert alice_session.session_id == bob_session.session_id
        assert alice_session.encrypt_key == bob_session.encrypt_key
        assert alice_session.mac_key == bob_session.mac_key
        assert alice_session.initiator_did == self.did_a
        assert alice_session.responder_did == self.did_b
        assert set(alice_session.granted_scopes) == set(scopes)

    def test_step2_encrypted_message_exchange_a_to_b(self):
        alice_session, bob_session = _perform_full_handshake(
            self.agent_a, self.agent_b, self.resolver
        )

        # A wraps a message → B unwraps
        message = {"action": "get-record", "patientId": "P-001"}
        wrapped = wrap_a2a_message(
            message=message,
            session=alice_session,
            encrypt_key=alice_session.encrypt_key,
            sender_did=self.did_a,
        )
        recovered = unwrap_a2a_message(
            wrapped=wrapped,
            session=bob_session,
            encrypt_key=bob_session.encrypt_key,
        )
        assert recovered == message

    def test_step2_encrypted_message_exchange_b_to_a(self):
        alice_session, bob_session = _perform_full_handshake(
            self.agent_a, self.agent_b, self.resolver
        )

        # First, consume seq 1 on A's side so B can reply on its counter
        wrap_a2a_message(
            message={"ping": True},
            session=alice_session,
            encrypt_key=alice_session.encrypt_key,
            sender_did=self.did_a,
        )

        # B wraps a response → A unwraps
        response = {"status": "ok", "record": {"summary": "Healthy"}}
        wrapped_response = wrap_a2a_message(
            message=response,
            session=bob_session,
            encrypt_key=bob_session.encrypt_key,
            sender_did=self.did_b,
        )
        recovered = unwrap_a2a_message(
            wrapped=wrapped_response,
            session=alice_session,
            encrypt_key=alice_session.encrypt_key,
        )
        assert recovered == response

    def test_step3_delegation_root_and_sub(self):
        """A creates root delegation for B; B sub-delegates to C."""
        root_scopes = ["medical-records:read:summary-only", "audit:read"]
        sub_scopes = ["medical-records:read:summary-only"]

        # A creates root token for B
        root_token = create_delegation_token(
            issuer_did=self.did_a,
            delegatee_did=self.did_b,
            audience_did=self.did_c,
            private_key=self.auth_a.private_key,
            scopes=root_scopes,
            constraints=DelegationConstraints(maxUses=10),
            delegation_depth=0,
        )
        root_payload = decode_delegation_token(root_token, self.auth_a.public_key)

        # B sub-delegates to C with narrower scopes
        sub_token = create_delegation_token(
            issuer_did=self.did_b,
            delegatee_did=self.did_c,
            audience_did=self.did_c,
            private_key=self.auth_b.private_key,
            scopes=sub_scopes,
            constraints=DelegationConstraints(maxUses=5),
            parent_token_id=root_payload.jti,
            delegation_depth=1,
            parent_chain_hash=None,
        )

        # Validate full chain
        resolve_keys = _make_key_resolver(
            (self.did_a, self.auth_a),
            (self.did_b, self.auth_b),
        )
        leaf = validate_delegation_chain([root_token, sub_token], resolve_keys)

        assert leaf.iss == self.did_b
        assert leaf.sub == self.did_c
        assert leaf.scopes == sub_scopes
        assert is_scope_subset(sub_scopes, root_scopes)

    def test_step4_audit_chain_of_5_entries(self):
        """Build a chain of 5 audit entries and verify integrity."""
        events = [
            ("session.initiated", {"sessionId": "sess-001"}),
            ("session.established", {"sessionId": "sess-001", "peerDID": self.did_b}),
            ("payload.encrypted", {"bytes": 128}),
            ("delegation.created", {"tokenId": "tok-abc"}),
            ("task.completed", {"taskId": "task-xyz", "result": "success"}),
        ]

        entries: list[AuditEntry] = []
        prev_hash = None
        for event_type, event_data in events:
            entry = create_audit_entry(
                actor_did=self.did_a,
                event_type=event_type,
                event_data=event_data,
                private_key=self.auth_a.private_key,
                key_id=self.auth_a.key_id,
                previous_hash=prev_hash,
                session_id="sess-001",
            )
            entries.append(entry)
            prev_hash = entry.entryHash

        assert len(entries) == 5
        resolve_keys = _make_key_resolver((self.did_a, self.auth_a))
        assert verify_audit_chain(entries, resolve_keys) is True

        # Verify chain linkage
        for i in range(1, len(entries)):
            assert entries[i].previousHash == entries[i - 1].entryHash


# ---------------------------------------------------------------------------
# Test 2: Three-agent delegation chain A→B→C
# ---------------------------------------------------------------------------


class TestDelegationChainThreeAgents:
    """Full delegation chain test: A→B→C with scope/constraint narrowing."""

    def setup_method(self):
        self.kp_a = generate_ed25519_keypair("key-a")
        self.kp_b = generate_ed25519_keypair("key-b")
        self.kp_c = generate_ed25519_keypair("key-c")

        self.did_a = "did:sdap:alpha.example.com:agent-a"
        self.did_b = "did:sdap:beta.example.com:agent-b"
        self.did_c = "did:sdap:gamma.example.com:agent-c"

        self.audience_did = self.did_c

        # A creates root token for B
        root_scopes = ["records:read", "records:write", "audit:read"]
        self.root_token = create_delegation_token(
            issuer_did=self.did_a,
            delegatee_did=self.did_b,
            audience_did=self.audience_did,
            private_key=self.kp_a.private_key,
            scopes=root_scopes,
            constraints=DelegationConstraints(maxUses=100, requireMFA=False),
            delegation_depth=0,
        )
        self.root_payload = decode_delegation_token(self.root_token, self.kp_a.public_key)

        # B sub-delegates to C with narrower scopes and tighter constraints
        sub_scopes = ["records:read"]
        self.sub_token = create_delegation_token(
            issuer_did=self.did_b,
            delegatee_did=self.did_c,
            audience_did=self.audience_did,
            private_key=self.kp_b.private_key,
            scopes=sub_scopes,
            constraints=DelegationConstraints(maxUses=10, requireMFA=True),
            parent_token_id=self.root_payload.jti,
            delegation_depth=1,
            parent_chain_hash=None,
        )

        self.resolve_keys = _make_key_resolver(
            (self.did_a, self.kp_a),
            (self.did_b, self.kp_b),
        )

    def test_chain_validates_successfully(self):
        leaf = validate_delegation_chain(
            [self.root_token, self.sub_token], self.resolve_keys
        )
        assert leaf.iss == self.did_b
        assert leaf.sub == self.did_c
        assert leaf.scopes == ["records:read"]

    def test_scope_narrowing_is_valid(self):
        """Sub-delegation's scopes must be a subset of root scopes."""
        root_payload = decode_delegation_token(self.root_token, self.kp_a.public_key)
        sub_payload = decode_delegation_token(self.sub_token, self.kp_b.public_key)
        assert is_scope_subset(sub_payload.scopes, root_payload.scopes)

    def test_scope_escalation_rejected(self):
        """B cannot grant C more scopes than B received from A."""
        escalated_scopes = ["records:read", "records:write", "admin:delete"]
        bad_sub_token = create_delegation_token(
            issuer_did=self.did_b,
            delegatee_did=self.did_c,
            audience_did=self.audience_did,
            private_key=self.kp_b.private_key,
            scopes=escalated_scopes,
            constraints=DelegationConstraints(),
            parent_token_id=self.root_payload.jti,
            delegation_depth=1,
        )
        with pytest.raises(ValueError, match="[Ss]cope"):
            validate_delegation_chain([self.root_token, bad_sub_token], self.resolve_keys)

    def test_constraint_tightening_preserved(self):
        """Sub-delegation maxUses is tighter (10 < 100)."""
        sub_payload = decode_delegation_token(self.sub_token, self.kp_b.public_key)
        root_payload = decode_delegation_token(self.root_token, self.kp_a.public_key)
        # Sub has tighter maxUses
        assert sub_payload.constraints.maxUses <= root_payload.constraints.maxUses
        # Sub added MFA requirement
        assert sub_payload.constraints.requireMFA is True

    def test_chain_depth_is_correct(self):
        root_payload = decode_delegation_token(self.root_token, self.kp_a.public_key)
        sub_payload = decode_delegation_token(self.sub_token, self.kp_b.public_key)
        assert root_payload.delegationDepth == 0
        assert sub_payload.delegationDepth == 1

    def test_chain_linkage(self):
        """Sub-token parentTokenId must match root token's jti."""
        root_payload = decode_delegation_token(self.root_token, self.kp_a.public_key)
        sub_payload = decode_delegation_token(self.sub_token, self.kp_b.public_key)
        assert sub_payload.parentTokenId == root_payload.jti

    def test_continuity_break_fails(self):
        """A chain where B's token is issued by a stranger fails validation."""
        kp_stranger = generate_ed25519_keypair("stranger")
        did_stranger = "did:sdap:nowhere.example.com:stranger"

        # Stranger (not B) creates a child token pretending B issued it
        bad_sub = create_delegation_token(
            issuer_did=did_stranger,  # breaks continuity
            delegatee_did=self.did_c,
            audience_did=self.audience_did,
            private_key=kp_stranger.private_key,
            scopes=["records:read"],
            constraints=DelegationConstraints(),
            parent_token_id=self.root_payload.jti,
            delegation_depth=1,
        )
        resolve_with_stranger = _make_key_resolver(
            (self.did_a, self.kp_a),
            (self.did_b, self.kp_b),
            (did_stranger, kp_stranger),
        )
        with pytest.raises(ValueError, match="[Cc]ontinuity|iss"):
            validate_delegation_chain([self.root_token, bad_sub], resolve_with_stranger)


# ---------------------------------------------------------------------------
# Test 3: Security negative tests
# ---------------------------------------------------------------------------


class TestSecurityNegative:
    """Security and negative path tests for the full SDAP stack."""

    def setup_method(self):
        self.agent_a = _make_agent("alice.example.com", "agent-a")
        self.agent_b = _make_agent("bob.example.com", "agent-b")

        _, _, self.did_a, self.doc_a = self.agent_a
        _, _, self.did_b, self.doc_b = self.agent_b
        self.auth_a, _, _, _ = self.agent_a
        self.auth_b, _, _, _ = self.agent_b

        self.resolver = _make_resolver(self.doc_a, self.doc_b)

    # --- Expired attestation rejected ---

    def test_expired_attestation_rejected(self):
        """An attestation with a past expiry must be rejected on verify."""
        token = create_attestation(
            issuer_did=self.did_a,
            subject_did=self.did_b,
            private_key=self.auth_a.private_key,
            agent_type="specialist",
            capabilities=["data:read"],
            security_level="standard",
            compliance_tags=[],
            max_delegation_depth=3,
            ttl_seconds=-1,  # Already expired
        )
        with pytest.raises((ValueError, Exception)):
            verify_attestation(token, self.auth_a.public_key)

    # --- Scope escalation rejected ---

    def test_scope_escalation_in_delegation_rejected(self):
        """Sub-delegation that adds scopes not in parent is rejected."""
        kp_a = generate_ed25519_keypair("a")
        kp_b = generate_ed25519_keypair("b")
        did_a = "did:sdap:alpha.example.com:a"
        did_b = "did:sdap:beta.example.com:b"
        did_c = "did:sdap:gamma.example.com:c"

        root = create_delegation_token(
            issuer_did=did_a,
            delegatee_did=did_b,
            audience_did=did_c,
            private_key=kp_a.private_key,
            scopes=["records:read"],  # Only read
            constraints=DelegationConstraints(),
            delegation_depth=0,
        )
        root_payload = decode_delegation_token(root, kp_a.public_key)

        # B tries to grant write (escalation!)
        bad_child = create_delegation_token(
            issuer_did=did_b,
            delegatee_did=did_c,
            audience_did=did_c,
            private_key=kp_b.private_key,
            scopes=["records:read", "records:write"],  # Escalated!
            constraints=DelegationConstraints(),
            parent_token_id=root_payload.jti,
            delegation_depth=1,
        )

        resolve = _make_key_resolver((did_a, kp_a), (did_b, kp_b))
        with pytest.raises(ValueError, match="[Ss]cope"):
            validate_delegation_chain([root, bad_child], resolve)

    # --- Replay detection ---

    def test_replay_detection_rejects_duplicate_sequence(self):
        """The same wrapped message cannot be delivered twice (sequence check)."""
        alice_session, bob_session = _perform_full_handshake(
            self.agent_a, self.agent_b, self.resolver
        )

        message = {"action": "sensitive-op"}
        wrapped = wrap_a2a_message(
            message=message,
            session=alice_session,
            encrypt_key=alice_session.encrypt_key,
            sender_did=self.did_a,
        )

        # First delivery: OK
        unwrap_a2a_message(
            wrapped=wrapped,
            session=bob_session,
            encrypt_key=bob_session.encrypt_key,
        )

        # Second delivery: must be rejected (sequence already consumed)
        with pytest.raises(ValueError, match="[Ss]equence"):
            unwrap_a2a_message(
                wrapped=wrapped,
                session=bob_session,
                encrypt_key=bob_session.encrypt_key,
            )

    # --- Broken audit chain ---

    def test_broken_audit_chain_fails_verification(self):
        """Modifying an audit entry's data must break chain verification."""
        kp = generate_ed25519_keypair("audit-key")
        did = "did:sdap:audit.example.com:actor"
        resolve = _make_key_resolver((did, kp))

        prev_hash = None
        entries: list[AuditEntry] = []
        for i in range(4):
            entry = create_audit_entry(
                actor_did=did,
                event_type=f"event-{i}",
                event_data={"index": i},
                private_key=kp.private_key,
                key_id=kp.key_id,
                previous_hash=prev_hash,
            )
            entries.append(entry)
            prev_hash = entry.entryHash

        # Tamper with entry[1]'s eventData
        tampered = entries[1].model_copy(update={"eventData": {"index": 999}})
        entries[1] = tampered

        with pytest.raises(ValueError, match="[Hh]ash"):
            verify_audit_chain(entries, resolve)

    # --- Tampered message ---

    def test_tampered_encrypted_payload_fails_decryption(self):
        """Flipping a byte in the encrypted payload must cause decryption failure."""
        alice_session, bob_session = _perform_full_handshake(
            self.agent_a, self.agent_b, self.resolver
        )

        message = {"secret": "top-secret-data"}
        wrapped = wrap_a2a_message(
            message=message,
            session=alice_session,
            encrypt_key=alice_session.encrypt_key,
            sender_did=self.did_a,
        )

        # Tamper: flip a byte in the payload string
        original_payload: str = wrapped["payload"]
        # Decode → flip → re-encode
        parts = original_payload.split(".")
        # Flip a character in the ciphertext segment (index 2)
        ct_b64 = parts[2]
        # Toggle the first character
        flipped_char = "A" if ct_b64[0] != "A" else "B"
        tampered_payload = ".".join([parts[0], parts[1], flipped_char + ct_b64[1:], parts[3]])
        wrapped["payload"] = tampered_payload

        with pytest.raises((ValueError, Exception)):
            unwrap_a2a_message(
                wrapped=wrapped,
                session=bob_session,
                encrypt_key=bob_session.encrypt_key,
            )

    # --- Wrong key decryption ---

    def test_wrong_session_key_fails_decryption(self):
        """Decrypting with a different session key must fail."""
        alice_session, _ = _perform_full_handshake(
            self.agent_a, self.agent_b, self.resolver
        )

        message = {"data": "confidential"}
        wrapped = wrap_a2a_message(
            message=message,
            session=alice_session,
            encrypt_key=alice_session.encrypt_key,
            sender_did=self.did_a,
        )

        # Create a fresh session for agent_b using wrong (random) keys
        from datetime import datetime, timezone
        wrong_session = Session(
            session_id=alice_session.session_id,
            initiator_did=self.did_a,
            responder_did=self.did_b,
            encrypt_key=os.urandom(32),  # Wrong key!
            mac_key=os.urandom(32),
            granted_scopes=["data:read"],
            security_level="standard",
            expiry=datetime.fromtimestamp(time.time() + 3600, tz=timezone.utc),
            sequence_counter={self.did_a: 0, self.did_b: 0},
        )

        with pytest.raises((ValueError, Exception)):
            unwrap_a2a_message(
                wrapped=wrapped,
                session=wrong_session,
                encrypt_key=wrong_session.encrypt_key,
            )

    # --- Invalid DID format ---

    def test_invalid_initiator_did_rejected(self):
        """Handshake init with a malformed DID must be rejected."""
        eph = generate_x25519_keypair("eph")
        with pytest.raises(ValueError, match="[Ii]nitiator|DID|did"):
            create_handshake_init(
                initiator_did="not-a-valid-did",
                target_did=self.did_b,
                auth_private_key=self.auth_a.private_key,
                auth_key_id=self.auth_a.key_id,
                ephemeral_keypair=eph,
                requested_scopes=[],
            )

    def test_invalid_target_did_rejected(self):
        """Handshake init with a malformed target DID must be rejected."""
        eph = generate_x25519_keypair("eph")
        with pytest.raises(ValueError, match="[Tt]arget|DID|did"):
            create_handshake_init(
                initiator_did=self.did_a,
                target_did="malformed::did",
                auth_private_key=self.auth_a.private_key,
                auth_key_id=self.auth_a.key_id,
                ephemeral_keypair=eph,
                requested_scopes=[],
            )

    # --- Nonce mismatch ---

    def test_nonce_mismatch_in_confirm_rejected(self):
        """Providing the wrong initiator nonce to create_handshake_confirm is rejected."""
        eph_a = generate_x25519_keypair("eph-a")
        init_msg, eph_a_private = create_handshake_init(
            initiator_did=self.did_a,
            target_did=self.did_b,
            auth_private_key=self.auth_a.private_key,
            auth_key_id=self.auth_a.key_id,
            ephemeral_keypair=eph_a,
            requested_scopes=["data:read"],
        )

        eph_b = generate_x25519_keypair("eph-b")
        accept_msg, _ = process_handshake_init(
            init_msg=init_msg,
            responder_did=self.did_b,
            responder_auth_key=self.auth_b.private_key,
            responder_auth_key_id=self.auth_b.key_id,
            responder_ephemeral=eph_b,
            resolve_did_func=self.resolver,
        )

        with pytest.raises(ValueError, match="[Nn]once"):
            create_handshake_confirm(
                accept_msg=accept_msg,
                initiator_did=self.did_a,
                initiator_nonce="completely-wrong-nonce",
                auth_private_key=self.auth_a.private_key,
                auth_key_id=self.auth_a.key_id,
                initiator_ephemeral_private=eph_a_private,
            )

    # --- Full handshake, then delegation chain, then audit in one test ---

    def test_combined_handshake_delegation_audit(self):
        """Smoke test: handshake → message exchange → delegation → audit chain."""
        scopes = ["medical-records:read:summary-only", "audit:read"]

        # 1. Handshake
        alice_session, bob_session = _perform_full_handshake(
            self.agent_a, self.agent_b, self.resolver, scopes=scopes
        )
        assert alice_session.encrypt_key == bob_session.encrypt_key

        # 2. Message exchange
        msg = {"task": "retrieve-summary", "patient": "P-002"}
        wrapped = wrap_a2a_message(
            message=msg,
            session=alice_session,
            encrypt_key=alice_session.encrypt_key,
            sender_did=self.did_a,
        )
        recovered = unwrap_a2a_message(
            wrapped=wrapped,
            session=bob_session,
            encrypt_key=bob_session.encrypt_key,
        )
        assert recovered == msg

        # 3. Delegation: A→B
        root_token = create_delegation_token(
            issuer_did=self.did_a,
            delegatee_did=self.did_b,
            audience_did=self.did_b,
            private_key=self.auth_a.private_key,
            scopes=scopes,
            constraints=DelegationConstraints(maxUses=20),
            delegation_depth=0,
        )
        resolve_keys = _make_key_resolver((self.did_a, self.auth_a))
        leaf = validate_delegation_chain([root_token], resolve_keys)
        assert leaf.sub == self.did_b

        # 4. Audit trail
        prev_hash = None
        audit_entries: list[AuditEntry] = []
        for event_type, event_data in [
            ("session.initiated", {"sessionId": alice_session.session_id}),
            ("payload.encrypted", {"messageCount": 1}),
            ("delegation.created", {"jti": leaf.jti}),
        ]:
            entry = create_audit_entry(
                actor_did=self.did_a,
                event_type=event_type,
                event_data=event_data,
                private_key=self.auth_a.private_key,
                key_id=self.auth_a.key_id,
                previous_hash=prev_hash,
                session_id=alice_session.session_id,
            )
            audit_entries.append(entry)
            prev_hash = entry.entryHash

        resolve_audit = _make_key_resolver((self.did_a, self.auth_a))
        assert verify_audit_chain(audit_entries, resolve_audit) is True
