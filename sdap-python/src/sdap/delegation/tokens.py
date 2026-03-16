"""Delegation token creation and verification."""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Optional

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, Field

from sdap.identity.did import validate_did


class DelegationConstraints(BaseModel):
    """Constraints on a delegation token."""

    notBefore: Optional[int] = None
    notAfter: Optional[int] = None
    maxUses: Optional[int] = None
    allowedResources: Optional[list[str]] = None
    allowedActions: Optional[list[str]] = None
    ipRestrictions: Optional[list[str]] = None
    requireMFA: Optional[bool] = None
    dataClassification: Optional[str] = None

    model_config = {"extra": "allow"}


class DelegationTokenPayload(BaseModel):
    """Payload of a decoded delegation JWT."""

    iss: str
    sub: str
    aud: str
    iat: int
    exp: int
    jti: str
    scopes: list[str]
    constraints: DelegationConstraints
    delegationDepth: int = 0
    parentTokenId: Optional[str] = None
    parentChainHash: Optional[str] = None

    model_config = {"extra": "allow"}


def compute_chain_hash(parent_chain_hash: Optional[str], parent_jti: str) -> str:
    """Compute SHA-256(parent_chain_hash + parent_jti).

    If parent_chain_hash is None (root token), hash is SHA-256(parent_jti).
    """
    data = (parent_chain_hash or "") + parent_jti
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def create_delegation_token(
    issuer_did: str,
    delegatee_did: str,
    audience_did: str,
    private_key: Ed25519PrivateKey,
    scopes: list[str],
    constraints: DelegationConstraints,
    parent_token_id: Optional[str] = None,
    delegation_depth: int = 0,
    parent_chain_hash: Optional[str] = None,
    ttl_seconds: int = 3600,
) -> str:
    """Create a signed delegation token JWT.

    Args:
        issuer_did: DID of the token issuer (delegator).
        delegatee_did: DID of the token subject (delegatee / recipient).
        audience_did: DID of the intended audience (verifier).
        private_key: Ed25519 private key of the issuer.
        scopes: List of scope strings being delegated.
        constraints: :class:`DelegationConstraints` limiting the delegation.
        parent_token_id: JTI of the parent token (for chain).
        delegation_depth: Depth in the delegation chain (0 = root).
        parent_chain_hash: Chain hash from parent token.
        ttl_seconds: Token lifetime in seconds.

    Returns:
        Compact JWT string.
    """
    if not validate_did(issuer_did):
        raise ValueError(f"Invalid issuer DID: {issuer_did!r}")
    if not validate_did(delegatee_did):
        raise ValueError(f"Invalid delegatee DID: {delegatee_did!r}")
    if not validate_did(audience_did):
        raise ValueError(f"Invalid audience DID: {audience_did!r}")

    now = int(time.time())
    jti = str(uuid.uuid4())

    chain_hash: Optional[str] = None
    if parent_token_id is not None:
        chain_hash = compute_chain_hash(parent_chain_hash, parent_token_id)

    payload: dict = {
        "iss": issuer_did,
        "sub": delegatee_did,
        "aud": audience_did,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": jti,
        "scopes": scopes,
        "constraints": constraints.model_dump(exclude_none=True),
        "delegationDepth": delegation_depth,
    }
    if parent_token_id is not None:
        payload["parentTokenId"] = parent_token_id
    if chain_hash is not None:
        payload["parentChainHash"] = chain_hash

    token: str = jwt.encode(payload, private_key, algorithm="EdDSA")
    return token


def decode_delegation_token(
    token: str,
    issuer_public_key: Ed25519PublicKey,
) -> DelegationTokenPayload:
    """Verify and decode a delegation token.

    Args:
        token: Compact JWT string.
        issuer_public_key: Ed25519 public key of the token issuer.

    Returns:
        :class:`DelegationTokenPayload`.

    Raises:
        ValueError: On invalid signature, expiry, or malformed claims.
    """
    try:
        claims = jwt.decode(
            token,
            issuer_public_key,
            algorithms=["EdDSA"],
            options={"verify_exp": True, "verify_aud": False},
        )
    except jwt.ExpiredSignatureError as exc:
        raise ValueError(f"Delegation token has expired: {exc}") from exc
    except jwt.PyJWTError as exc:
        raise ValueError(f"Invalid delegation token: {exc}") from exc

    constraints_data = claims.get("constraints", {})
    return DelegationTokenPayload(
        iss=claims["iss"],
        sub=claims["sub"],
        aud=claims["aud"],
        iat=claims["iat"],
        exp=claims["exp"],
        jti=claims["jti"],
        scopes=claims.get("scopes", []),
        constraints=DelegationConstraints(**constraints_data),
        delegationDepth=claims.get("delegationDepth", 0),
        parentTokenId=claims.get("parentTokenId"),
        parentChainHash=claims.get("parentChainHash"),
    )
