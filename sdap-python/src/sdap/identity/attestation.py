"""Provider attestation JWT creation and verification."""

from __future__ import annotations

import time
from typing import Optional

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, field_validator

from sdap.identity.did import validate_did

_VALID_SECURITY_LEVELS = {"basic", "standard", "high", "critical"}


class SDAPAttestationClaims(BaseModel):
    agentType: str
    capabilities: list[str]
    securityLevel: str
    complianceTags: list[str]
    maxDelegationDepth: int

    @field_validator("securityLevel")
    @classmethod
    def _check_security_level(cls, v: str) -> str:
        if v not in _VALID_SECURITY_LEVELS:
            raise ValueError(
                f"securityLevel must be one of {_VALID_SECURITY_LEVELS}, got {v!r}"
            )
        return v


class ProviderAttestation(BaseModel):
    """Decoded payload of a provider attestation JWT."""

    iss: str
    sub: str
    iat: int
    exp: int
    sdap_attestation: SDAPAttestationClaims

    @field_validator("iss", "sub")
    @classmethod
    def _check_did(cls, v: str) -> str:
        if not validate_did(v):
            raise ValueError(f"Expected a valid did:sdap DID, got {v!r}")
        return v


def create_attestation(
    issuer_did: str,
    subject_did: str,
    private_key: Ed25519PrivateKey,
    agent_type: str,
    capabilities: list[str],
    security_level: str,
    compliance_tags: list[str],
    max_delegation_depth: int,
    ttl_seconds: int = 86400,
) -> str:
    """Create a compact JWT attestation signed with an Ed25519 key.

    Args:
        issuer_did: Provider DID (``did:sdap:<provider>``).
        subject_did: Agent DID (``did:sdap:<provider>:<agent>``).
        private_key: Ed25519 private key owned by the provider.
        agent_type: Semantic agent type (e.g. ``"specialist"``).
        capabilities: List of capability strings.
        security_level: One of ``basic``, ``standard``, ``high``, ``critical``.
        compliance_tags: Compliance/regulatory tags (e.g. ``["HIPAA"]``).
        max_delegation_depth: Maximum allowed delegation chain depth.
        ttl_seconds: Token lifetime in seconds (default 86400 = 24 h).

    Returns:
        Compact JWT string.

    Raises:
        ValueError: If DIDs are invalid or security_level is unrecognised.
    """
    if not validate_did(issuer_did):
        raise ValueError(f"Invalid issuer DID: {issuer_did!r}")
    if not validate_did(subject_did):
        raise ValueError(f"Invalid subject DID: {subject_did!r}")
    if security_level not in _VALID_SECURITY_LEVELS:
        raise ValueError(
            f"securityLevel must be one of {_VALID_SECURITY_LEVELS}, got {security_level!r}"
        )

    now = int(time.time())
    payload = {
        "iss": issuer_did,
        "sub": subject_did,
        "iat": now,
        "exp": now + ttl_seconds,
        "sdap_attestation": {
            "agentType": agent_type,
            "capabilities": capabilities,
            "securityLevel": security_level,
            "complianceTags": compliance_tags,
            "maxDelegationDepth": max_delegation_depth,
        },
    }

    token: str = jwt.encode(payload, private_key, algorithm="EdDSA")
    return token


def verify_attestation(
    token: str,
    issuer_public_key: Ed25519PublicKey,
) -> ProviderAttestation:
    """Verify and decode a provider attestation JWT.

    Args:
        token: Compact JWT string.
        issuer_public_key: Ed25519 public key of the issuer.

    Returns:
        Decoded :class:`ProviderAttestation`.

    Raises:
        ValueError: If the token is expired, has invalid claims, or
                    the signature is invalid.
        jwt.PyJWTError: On low-level JWT decoding errors.
    """
    try:
        claims = jwt.decode(
            token,
            issuer_public_key,
            algorithms=["EdDSA"],
            options={"verify_exp": True},
        )
    except jwt.ExpiredSignatureError as exc:
        raise ValueError(f"Attestation token has expired: {exc}") from exc
    except jwt.PyJWTError as exc:
        raise ValueError(f"Invalid attestation token: {exc}") from exc

    # Validate structure via Pydantic
    attestation_data = claims.get("sdap_attestation", {})
    return ProviderAttestation(
        iss=claims["iss"],
        sub=claims["sub"],
        iat=claims["iat"],
        exp=claims["exp"],
        sdap_attestation=SDAPAttestationClaims(**attestation_data),
    )
