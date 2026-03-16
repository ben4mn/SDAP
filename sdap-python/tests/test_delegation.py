"""Unit tests for sdap.delegation module."""

from __future__ import annotations

import time

import pytest

from sdap.delegation.chain import (
    is_scope_subset,
    parse_scope,
    validate_delegation_chain,
)
from sdap.delegation.tokens import (
    DelegationConstraints,
    DelegationTokenPayload,
    compute_chain_hash,
    create_delegation_token,
    decode_delegation_token,
)
from sdap.identity.keys import generate_ed25519_keypair


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


ISSUER_DID = "did:sdap:acme.example.com:issuer"
DELEGATEE_DID = "did:sdap:acme.example.com:delegatee"
AUDIENCE_DID = "did:sdap:acme.example.com:audience"
AGENT_A = "did:sdap:acme.example.com:agent-a"
AGENT_B = "did:sdap:acme.example.com:agent-b"
AGENT_C = "did:sdap:acme.example.com:agent-c"


def _key_store(*keypairs):
    """Build a resolve_key_func from a set of (did, keypair) pairs."""
    mapping = {did: kp.public_key for did, kp in keypairs}

    def resolve(did):
        if did not in mapping:
            raise ValueError(f"Unknown DID: {did!r}")
        return mapping[did]

    return resolve


# ---------------------------------------------------------------------------
# compute_chain_hash
# ---------------------------------------------------------------------------


class TestComputeChainHash:
    def test_root_token_hash(self):
        h = compute_chain_hash(None, "jti-1")
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex

    def test_child_token_hash(self):
        root_hash = compute_chain_hash(None, "jti-1")
        child_hash = compute_chain_hash(root_hash, "jti-2")
        assert child_hash != root_hash
        assert len(child_hash) == 64

    def test_deterministic(self):
        h1 = compute_chain_hash("parent_hash", "jti")
        h2 = compute_chain_hash("parent_hash", "jti")
        assert h1 == h2

    def test_different_parents_differ(self):
        h1 = compute_chain_hash("hash_a", "jti")
        h2 = compute_chain_hash("hash_b", "jti")
        assert h1 != h2


# ---------------------------------------------------------------------------
# Token creation and decoding
# ---------------------------------------------------------------------------


class TestDelegationTokens:
    def setup_method(self):
        self.kp = generate_ed25519_keypair("test-key")
        self.constraints = DelegationConstraints()

    def test_create_and_decode(self):
        token = create_delegation_token(
            issuer_did=ISSUER_DID,
            delegatee_did=DELEGATEE_DID,
            audience_did=AUDIENCE_DID,
            private_key=self.kp.private_key,
            scopes=["records:read"],
            constraints=self.constraints,
        )
        assert isinstance(token, str)
        assert token.count(".") == 2

        payload = decode_delegation_token(token, self.kp.public_key)
        assert payload.iss == ISSUER_DID
        assert payload.sub == DELEGATEE_DID
        assert payload.aud == AUDIENCE_DID
        assert payload.scopes == ["records:read"]
        assert payload.delegationDepth == 0
        assert payload.parentTokenId is None
        assert payload.parentChainHash is None

    def test_with_parent_chain(self):
        # Root token
        root_kp = generate_ed25519_keypair("root-key")
        root_token = create_delegation_token(
            issuer_did=AGENT_A,
            delegatee_did=AGENT_B,
            audience_did=AUDIENCE_DID,
            private_key=root_kp.private_key,
            scopes=["records:read", "records:write"],
            constraints=DelegationConstraints(),
            delegation_depth=0,
        )
        root_payload = decode_delegation_token(root_token, root_kp.public_key)

        # Child token
        child_kp = generate_ed25519_keypair("child-key")
        child_hash = compute_chain_hash(None, root_payload.jti)
        child_token = create_delegation_token(
            issuer_did=AGENT_B,
            delegatee_did=AGENT_C,
            audience_did=AUDIENCE_DID,
            private_key=child_kp.private_key,
            scopes=["records:read"],
            constraints=DelegationConstraints(),
            parent_token_id=root_payload.jti,
            delegation_depth=1,
            parent_chain_hash=None,
        )
        child_payload = decode_delegation_token(child_token, child_kp.public_key)
        assert child_payload.parentTokenId == root_payload.jti
        assert child_payload.delegationDepth == 1
        assert child_payload.parentChainHash is not None

    def test_invalid_issuer_did_raises(self):
        with pytest.raises(ValueError, match="[Ii]ssuer"):
            create_delegation_token(
                issuer_did="not-a-did",
                delegatee_did=DELEGATEE_DID,
                audience_did=AUDIENCE_DID,
                private_key=self.kp.private_key,
                scopes=[],
                constraints=self.constraints,
            )

    def test_invalid_delegatee_did_raises(self):
        with pytest.raises(ValueError, match="[Dd]elegatee"):
            create_delegation_token(
                issuer_did=ISSUER_DID,
                delegatee_did="not-a-did",
                audience_did=AUDIENCE_DID,
                private_key=self.kp.private_key,
                scopes=[],
                constraints=self.constraints,
            )

    def test_wrong_key_raises(self):
        token = create_delegation_token(
            issuer_did=ISSUER_DID,
            delegatee_did=DELEGATEE_DID,
            audience_did=AUDIENCE_DID,
            private_key=self.kp.private_key,
            scopes=[],
            constraints=self.constraints,
        )
        wrong_kp = generate_ed25519_keypair("wrong")
        with pytest.raises(ValueError):
            decode_delegation_token(token, wrong_kp.public_key)

    def test_ttl(self):
        token = create_delegation_token(
            issuer_did=ISSUER_DID,
            delegatee_did=DELEGATEE_DID,
            audience_did=AUDIENCE_DID,
            private_key=self.kp.private_key,
            scopes=[],
            constraints=self.constraints,
            ttl_seconds=7200,
        )
        payload = decode_delegation_token(token, self.kp.public_key)
        assert payload.exp - payload.iat == pytest.approx(7200, abs=2)

    def test_constraints_encoded(self):
        constraints = DelegationConstraints(
            maxUses=5,
            allowedResources=["resource-a"],
            requireMFA=True,
        )
        token = create_delegation_token(
            issuer_did=ISSUER_DID,
            delegatee_did=DELEGATEE_DID,
            audience_did=AUDIENCE_DID,
            private_key=self.kp.private_key,
            scopes=["data:read"],
            constraints=constraints,
        )
        payload = decode_delegation_token(token, self.kp.public_key)
        assert payload.constraints.maxUses == 5
        assert payload.constraints.allowedResources == ["resource-a"]
        assert payload.constraints.requireMFA is True


# ---------------------------------------------------------------------------
# Scope parsing and subset checks
# ---------------------------------------------------------------------------


class TestScopeSubset:
    def test_exact_match(self):
        assert is_scope_subset(["records:read"], ["records:read"]) is True

    def test_subset_is_valid(self):
        assert is_scope_subset(["records:read"], ["records:read", "records:write"]) is True

    def test_superset_is_invalid(self):
        assert is_scope_subset(["records:read", "records:write"], ["records:read"]) is False

    def test_wildcard_action_covers_any(self):
        assert is_scope_subset(["records:read"], ["records:*"]) is True

    def test_global_wildcard(self):
        assert is_scope_subset(["any:scope"], ["*"]) is True

    def test_qualifier_covered_by_base(self):
        assert is_scope_subset(["records:read:public"], ["records:read"]) is True

    def test_qualifier_covered_by_wildcard(self):
        assert is_scope_subset(["records:read:public"], ["records:*"]) is True

    def test_empty_child_is_subset_of_anything(self):
        assert is_scope_subset([], ["records:read"]) is True

    def test_child_with_uncovered_scope_fails(self):
        assert is_scope_subset(["admin:delete"], ["records:read"]) is False


class TestParseScope:
    def test_two_part_scope(self):
        resource, action, qualifier = parse_scope("records:read")
        assert resource == "records"
        assert action == "read"
        assert qualifier is None

    def test_three_part_scope(self):
        resource, action, qualifier = parse_scope("records:read:public")
        assert resource == "records"
        assert action == "read"
        assert qualifier == "public"

    def test_invalid_scope_raises(self):
        with pytest.raises(ValueError):
            parse_scope("nocolon")


# ---------------------------------------------------------------------------
# Chain validation
# ---------------------------------------------------------------------------


class TestValidateDelegationChain:
    def _make_chain(self, length: int = 2, scopes=None):
        """Create a valid delegation chain of given length."""
        if scopes is None:
            scopes = [["records:read", "records:write"]] + [["records:read"]] * (length - 1)

        keypairs = [generate_ed25519_keypair(f"key-{i}") for i in range(length + 1)]
        dids = [f"did:sdap:example{i}.com:agent" for i in range(length + 1)]

        tokens = []
        previous_jti = None
        previous_chain_hash = None

        for i in range(length):
            token = create_delegation_token(
                issuer_did=dids[i],
                delegatee_did=dids[i + 1],
                audience_did=dids[-1],
                private_key=keypairs[i].private_key,
                scopes=scopes[i] if i < len(scopes) else ["records:read"],
                constraints=DelegationConstraints(),
                parent_token_id=previous_jti,
                delegation_depth=i,
                parent_chain_hash=previous_chain_hash,
            )
            payload = decode_delegation_token(token, keypairs[i].public_key)
            previous_chain_hash = payload.parentChainHash
            # For next iteration, update chain hash
            if previous_jti is not None:
                # The chain hash stored in this token IS the new running hash
                pass
            previous_chain_hash = compute_chain_hash(
                previous_chain_hash if i > 0 else None,
                payload.jti,
            ) if i == 0 else payload.parentChainHash
            # Simpler: recompute to track
            if i == 0:
                previous_chain_hash = None  # root has no parent hash, next child uses compute_chain_hash(None, jti)
            else:
                previous_chain_hash = payload.parentChainHash

            previous_jti = payload.jti
            tokens.append(token)

        resolve_key_func = _key_store(*[(dids[i], keypairs[i]) for i in range(length)])
        return tokens, resolve_key_func

    def test_single_token_chain(self):
        kp = generate_ed25519_keypair("k")
        token = create_delegation_token(
            issuer_did=AGENT_A,
            delegatee_did=AGENT_B,
            audience_did=AUDIENCE_DID,
            private_key=kp.private_key,
            scopes=["records:read"],
            constraints=DelegationConstraints(),
        )
        resolve = _key_store((AGENT_A, kp))
        leaf = validate_delegation_chain([token], resolve)
        assert leaf.iss == AGENT_A
        assert leaf.sub == AGENT_B

    def test_two_token_chain_valid(self):
        kp_a = generate_ed25519_keypair("a")
        kp_b = generate_ed25519_keypair("b")

        root = create_delegation_token(
            issuer_did=AGENT_A,
            delegatee_did=AGENT_B,
            audience_did=AGENT_C,
            private_key=kp_a.private_key,
            scopes=["records:read", "records:write"],
            constraints=DelegationConstraints(),
            delegation_depth=0,
        )
        root_payload = decode_delegation_token(root, kp_a.public_key)

        child = create_delegation_token(
            issuer_did=AGENT_B,
            delegatee_did=AGENT_C,
            audience_did=AGENT_C,
            private_key=kp_b.private_key,
            scopes=["records:read"],
            constraints=DelegationConstraints(),
            parent_token_id=root_payload.jti,
            delegation_depth=1,
            parent_chain_hash=None,
        )

        resolve = _key_store((AGENT_A, kp_a), (AGENT_B, kp_b))
        leaf = validate_delegation_chain([root, child], resolve)
        assert leaf.sub == AGENT_C

    def test_scope_widening_fails(self):
        kp_a = generate_ed25519_keypair("a")
        kp_b = generate_ed25519_keypair("b")

        root = create_delegation_token(
            issuer_did=AGENT_A,
            delegatee_did=AGENT_B,
            audience_did=AGENT_C,
            private_key=kp_a.private_key,
            scopes=["records:read"],  # Only read
            constraints=DelegationConstraints(),
            delegation_depth=0,
        )
        root_payload = decode_delegation_token(root, kp_a.public_key)

        child = create_delegation_token(
            issuer_did=AGENT_B,
            delegatee_did=AGENT_C,
            audience_did=AGENT_C,
            private_key=kp_b.private_key,
            scopes=["records:read", "records:write"],  # Added write — invalid!
            constraints=DelegationConstraints(),
            parent_token_id=root_payload.jti,
            delegation_depth=1,
        )

        resolve = _key_store((AGENT_A, kp_a), (AGENT_B, kp_b))
        with pytest.raises(ValueError, match="[Ss]cope"):
            validate_delegation_chain([root, child], resolve)

    def test_continuity_break_fails(self):
        kp_a = generate_ed25519_keypair("a")
        kp_b = generate_ed25519_keypair("b")
        kp_c = generate_ed25519_keypair("c")

        root = create_delegation_token(
            issuer_did=AGENT_A,
            delegatee_did=AGENT_B,
            audience_did=AGENT_C,
            private_key=kp_a.private_key,
            scopes=["records:read"],
            constraints=DelegationConstraints(),
            delegation_depth=0,
        )
        root_payload = decode_delegation_token(root, kp_a.public_key)

        # child issued by AGENT_C instead of AGENT_B (breaks chain)
        child = create_delegation_token(
            issuer_did=AGENT_C,  # Wrong issuer!
            delegatee_did=AGENT_B,
            audience_did=AGENT_C,
            private_key=kp_c.private_key,
            scopes=["records:read"],
            constraints=DelegationConstraints(),
            parent_token_id=root_payload.jti,
            delegation_depth=1,
        )

        resolve = _key_store((AGENT_A, kp_a), (AGENT_B, kp_b), (AGENT_C, kp_c))
        with pytest.raises(ValueError, match="[Cc]ontinuity|iss"):
            validate_delegation_chain([root, child], resolve)

    def test_empty_chain_raises(self):
        with pytest.raises(ValueError, match="[Ee]mpty"):
            validate_delegation_chain([], lambda did: None)

    def test_wrong_depth_fails(self):
        kp_a = generate_ed25519_keypair("a")
        kp_b = generate_ed25519_keypair("b")

        root = create_delegation_token(
            issuer_did=AGENT_A,
            delegatee_did=AGENT_B,
            audience_did=AGENT_C,
            private_key=kp_a.private_key,
            scopes=["records:read"],
            constraints=DelegationConstraints(),
            delegation_depth=0,
        )
        root_payload = decode_delegation_token(root, kp_a.public_key)

        # Use wrong depth=5 instead of 1
        child = create_delegation_token(
            issuer_did=AGENT_B,
            delegatee_did=AGENT_C,
            audience_did=AGENT_C,
            private_key=kp_b.private_key,
            scopes=["records:read"],
            constraints=DelegationConstraints(),
            parent_token_id=root_payload.jti,
            delegation_depth=5,  # Wrong!
        )

        resolve = _key_store((AGENT_A, kp_a), (AGENT_B, kp_b))
        with pytest.raises(ValueError, match="[Dd]epth"):
            validate_delegation_chain([root, child], resolve)
