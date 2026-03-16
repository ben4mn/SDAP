"""Unit tests for sdap.identity module."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from sdap.identity.attestation import create_attestation, verify_attestation
from sdap.identity.did import (
    DIDDocument,
    create_did,
    parse_did,
    resolve_did,
    validate_did,
)
from sdap.identity.keys import (
    generate_ed25519_keypair,
    generate_x25519_keypair,
    jwk_to_public_key,
    multibase_to_public_key,
    public_key_to_jwk,
    public_key_to_multibase,
)


# ---------------------------------------------------------------------------
# Key tests
# ---------------------------------------------------------------------------


class TestKeyGeneration:
    def test_generate_ed25519_keypair_returns_keypair(self):
        kp = generate_ed25519_keypair("key-1")
        assert kp.key_id == "key-1"
        assert kp.private_key is not None
        assert kp.public_key is not None

    def test_generate_x25519_keypair_returns_keypair(self):
        kp = generate_x25519_keypair("key-1")
        assert kp.key_id == "key-1"
        assert kp.private_key is not None
        assert kp.public_key is not None

    def test_ed25519_keypairs_are_unique(self):
        kp1 = generate_ed25519_keypair("k1")
        kp2 = generate_ed25519_keypair("k2")
        m1 = public_key_to_multibase(kp1.public_key)
        m2 = public_key_to_multibase(kp2.public_key)
        assert m1 != m2

    def test_x25519_keypairs_are_unique(self):
        kp1 = generate_x25519_keypair("k1")
        kp2 = generate_x25519_keypair("k2")
        m1 = public_key_to_multibase(kp1.public_key)
        m2 = public_key_to_multibase(kp2.public_key)
        assert m1 != m2


class TestMultibaseEncoding:
    def test_ed25519_roundtrip(self):
        kp = generate_ed25519_keypair("k")
        encoded = public_key_to_multibase(kp.public_key)
        assert encoded.startswith("z")
        recovered = multibase_to_public_key(encoded, "Ed25519")
        # Verify raw bytes match
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        orig_bytes = kp.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        recv_bytes = recovered.public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert orig_bytes == recv_bytes

    def test_x25519_roundtrip(self):
        kp = generate_x25519_keypair("k")
        encoded = public_key_to_multibase(kp.public_key)
        assert encoded.startswith("z")
        recovered = multibase_to_public_key(encoded, "X25519")
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        orig_bytes = kp.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        recv_bytes = recovered.public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert orig_bytes == recv_bytes

    def test_invalid_prefix_raises(self):
        with pytest.raises(ValueError, match="base58btc"):
            multibase_to_public_key("mABC", "Ed25519")

    def test_unsupported_key_type_raises(self):
        kp = generate_ed25519_keypair("k")
        encoded = public_key_to_multibase(kp.public_key)
        with pytest.raises(ValueError, match="key_type"):
            multibase_to_public_key(encoded, "RSA")


class TestJWK:
    def test_x25519_jwk_roundtrip(self):
        kp = generate_x25519_keypair("k")
        jwk = public_key_to_jwk(kp.public_key)
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "X25519"
        assert "x" in jwk

        recovered = jwk_to_public_key(jwk)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        orig_bytes = kp.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        recv_bytes = recovered.public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert orig_bytes == recv_bytes

    def test_invalid_jwk_raises(self):
        with pytest.raises(ValueError, match="X25519"):
            jwk_to_public_key({"kty": "RSA"})


# ---------------------------------------------------------------------------
# DID tests
# ---------------------------------------------------------------------------


class TestValidateDID:
    @pytest.mark.parametrize("did", [
        "did:sdap:acme-health.com:records-agent-v2",
        "did:sdap:example.org:agent-1",
        "did:sdap:provider.io",
        "did:sdap:sub.domain.example.com:fleet.agent",
    ])
    def test_valid_dids(self, did):
        assert validate_did(did) is True

    @pytest.mark.parametrize("did", [
        "did:web:example.com",
        "sdap:example.com:agent",
        "did:sdap:",
        "did:sdap:UPPERCASE.COM:agent",
        "did:sdap:no-tld:agent",
        "",
    ])
    def test_invalid_dids(self, did):
        assert validate_did(did) is False


class TestParseDID:
    def test_parse_agent_did(self):
        domain, agent = parse_did("did:sdap:acme-health.com:records-agent-v2")
        assert domain == "acme-health.com"
        assert agent == "records-agent-v2"

    def test_parse_provider_did(self):
        domain, agent = parse_did("did:sdap:acme-health.com")
        assert domain == "acme-health.com"
        assert agent == ""

    def test_invalid_did_raises(self):
        with pytest.raises(ValueError):
            parse_did("not-a-did")


class TestCreateDID:
    def setup_method(self):
        self.auth_kp = generate_ed25519_keypair("auth-key-1")
        self.agree_kp = generate_x25519_keypair("agree-key-1")

    def test_creates_valid_document(self):
        doc = create_did(
            provider_domain="acme-health.com",
            agent_id="records-agent",
            auth_key=self.auth_kp.public_key,
            agreement_key=self.agree_kp.public_key,
            a2a_endpoint="https://acme-health.com/a2a",
            handshake_endpoint="https://acme-health.com/sdap/handshake",
        )
        assert doc.id == "did:sdap:acme-health.com:records-agent"
        assert doc.controller == "did:sdap:acme-health.com"
        assert len(doc.verificationMethod) == 2
        assert len(doc.authentication) == 1
        assert len(doc.keyAgreement) == 1
        assert len(doc.service) == 2

    def test_auth_key_is_ed25519(self):
        doc = create_did(
            "example.com", "agent", self.auth_kp.public_key, self.agree_kp.public_key
        )
        ed_vms = [v for v in doc.verificationMethod if v.type == "Ed25519VerificationKey2020"]
        assert len(ed_vms) == 1
        assert ed_vms[0].publicKeyMultibase.startswith("z")

    def test_agree_key_is_x25519(self):
        doc = create_did(
            "example.com", "agent", self.auth_kp.public_key, self.agree_kp.public_key
        )
        x_vms = [v for v in doc.verificationMethod if v.type == "X25519KeyAgreementKey2020"]
        assert len(x_vms) == 1
        assert x_vms[0].publicKeyMultibase.startswith("z")

    def test_with_attestation(self):
        doc = create_did(
            "example.com",
            "agent",
            self.auth_kp.public_key,
            self.agree_kp.public_key,
            provider_attestation="eyJ.eyJ.sig",
        )
        assert doc.providerAttestation == "eyJ.eyJ.sig"

    def test_json_ld_dump(self):
        doc = create_did(
            "example.com", "agent", self.auth_kp.public_key, self.agree_kp.public_key
        )
        data = doc.model_dump_json_ld()
        assert "@context" in data
        assert data["id"] == "did:sdap:example.com:agent"


class TestResolveDID:
    async def test_resolve_success(self):
        auth_kp = generate_ed25519_keypair("auth-key-1")
        agree_kp = generate_x25519_keypair("agree-key-1")
        doc = create_did(
            "example.com", "agent", auth_kp.public_key, agree_kp.public_key
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = doc.model_dump_json_ld()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        result = await resolve_did("did:sdap:example.com:agent", mock_client)
        assert result.id == "did:sdap:example.com:agent"

    async def test_resolve_http_error(self):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with pytest.raises(ValueError, match="HTTP 404"):
            await resolve_did("did:sdap:example.com:agent", mock_client)

    async def test_resolve_provider_only_did_raises(self):
        mock_client = AsyncMock()
        with pytest.raises(ValueError, match="provider-only"):
            await resolve_did("did:sdap:example.com", mock_client)


# ---------------------------------------------------------------------------
# Attestation tests
# ---------------------------------------------------------------------------


class TestAttestation:
    def setup_method(self):
        self.issuer_kp = generate_ed25519_keypair("issuer-key")
        self.issuer_did = "did:sdap:acme-health.com"
        self.subject_did = "did:sdap:acme-health.com:records-agent"

    def test_create_and_verify(self):
        token = create_attestation(
            issuer_did=self.issuer_did,
            subject_did=self.subject_did,
            private_key=self.issuer_kp.private_key,
            agent_type="specialist",
            capabilities=["medical-records:read"],
            security_level="high",
            compliance_tags=["HIPAA", "SOC2"],
            max_delegation_depth=3,
        )
        assert isinstance(token, str)
        assert token.count(".") == 2

        attestation = verify_attestation(token, self.issuer_kp.public_key)
        assert attestation.iss == self.issuer_did
        assert attestation.sub == self.subject_did
        assert attestation.sdap_attestation.agentType == "specialist"
        assert attestation.sdap_attestation.securityLevel == "high"
        assert "HIPAA" in attestation.sdap_attestation.complianceTags
        assert attestation.sdap_attestation.maxDelegationDepth == 3

    def test_wrong_key_raises(self):
        token = create_attestation(
            issuer_did=self.issuer_did,
            subject_did=self.subject_did,
            private_key=self.issuer_kp.private_key,
            agent_type="specialist",
            capabilities=[],
            security_level="standard",
            compliance_tags=[],
            max_delegation_depth=1,
        )
        wrong_kp = generate_ed25519_keypair("wrong")
        with pytest.raises(ValueError):
            verify_attestation(token, wrong_kp.public_key)

    def test_invalid_security_level_raises(self):
        with pytest.raises(ValueError, match="securityLevel"):
            create_attestation(
                issuer_did=self.issuer_did,
                subject_did=self.subject_did,
                private_key=self.issuer_kp.private_key,
                agent_type="specialist",
                capabilities=[],
                security_level="ultra",
                compliance_tags=[],
                max_delegation_depth=1,
            )

    def test_invalid_issuer_did_raises(self):
        with pytest.raises(ValueError, match="issuer"):
            create_attestation(
                issuer_did="not-a-did",
                subject_did=self.subject_did,
                private_key=self.issuer_kp.private_key,
                agent_type="specialist",
                capabilities=[],
                security_level="standard",
                compliance_tags=[],
                max_delegation_depth=1,
            )

    def test_ttl(self):
        token = create_attestation(
            issuer_did=self.issuer_did,
            subject_did=self.subject_did,
            private_key=self.issuer_kp.private_key,
            agent_type="tool",
            capabilities=[],
            security_level="basic",
            compliance_tags=[],
            max_delegation_depth=0,
            ttl_seconds=3600,
        )
        attestation = verify_attestation(token, self.issuer_kp.public_key)
        # exp should be approximately now + 3600
        assert attestation.exp - attestation.iat == pytest.approx(3600, abs=2)
