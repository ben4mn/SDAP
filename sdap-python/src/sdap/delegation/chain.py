"""Delegation chain validation."""

from __future__ import annotations

import time
from typing import Callable

from sdap.delegation.tokens import (
    DelegationConstraints,
    DelegationTokenPayload,
    compute_chain_hash,
    decode_delegation_token,
)


def parse_scope(scope: str) -> tuple[str, str, str | None]:
    """Parse a scope string in "resource:action[:qualifier]" format.

    Returns:
        (resource, action, qualifier_or_None)
    """
    parts = scope.split(":", 2)
    if len(parts) < 2:
        raise ValueError(f"Invalid scope format: {scope!r} (expected resource:action[:qualifier])")
    resource = parts[0]
    action = parts[1]
    qualifier = parts[2] if len(parts) == 3 else None
    return resource, action, qualifier


def is_scope_subset(child_scopes: list[str], parent_scopes: list[str]) -> bool:
    """Return True if every scope in *child_scopes* is covered by *parent_scopes*.

    A child scope is covered if an identical scope or a wildcard exists in the parent.
    Wildcard rules:
    - "resource:*" covers "resource:action" and "resource:action:qualifier"
    - "resource:action" covers "resource:action:qualifier"
    - "*" or "*:*" covers everything
    """
    for child in child_scopes:
        if not _is_covered(child, parent_scopes):
            return False
    return True


def _is_covered(scope: str, parent_scopes: list[str]) -> bool:
    if scope in parent_scopes:
        return True
    if "*" in parent_scopes or "*:*" in parent_scopes:
        return True
    try:
        resource, action, qualifier = parse_scope(scope)
    except ValueError:
        return scope in parent_scopes

    # Check wildcard on action: "resource:*"
    if f"{resource}:*" in parent_scopes:
        return True
    # Check parent without qualifier: "resource:action" covers "resource:action:qualifier"
    if qualifier is not None and f"{resource}:{action}" in parent_scopes:
        return True
    return False


def _constraints_tightened_or_equal(
    child: DelegationConstraints,
    parent: DelegationConstraints,
) -> bool:
    """Return True if child constraints are at least as restrictive as parent constraints.

    Tightening rules:
    - Numeric limits (maxUses): child must be <= parent (or parent is None = no limit)
    - Time bounds (notBefore, notAfter): child must be within parent bounds
    - Lists (allowedResources, allowedActions, ipRestrictions): child must be a subset
    - Booleans (requireMFA): child must be >= parent (if parent requires, child must too)
    - dataClassification: not loosened (child same or higher classification)
    """
    # maxUses: can only tighten (reduce)
    if parent.maxUses is not None:
        if child.maxUses is None or child.maxUses > parent.maxUses:
            return False

    # notAfter: child's expiry must not exceed parent's
    if parent.notAfter is not None:
        if child.notAfter is None or child.notAfter > parent.notAfter:
            return False

    # notBefore: child's start must not be before parent's
    if parent.notBefore is not None:
        if child.notBefore is None or child.notBefore < parent.notBefore:
            return False

    # allowedResources: child must be subset of parent
    if parent.allowedResources is not None:
        if child.allowedResources is None:
            return False
        if not set(child.allowedResources).issubset(set(parent.allowedResources)):
            return False

    # allowedActions: child must be subset of parent
    if parent.allowedActions is not None:
        if child.allowedActions is None:
            return False
        if not set(child.allowedActions).issubset(set(parent.allowedActions)):
            return False

    # ipRestrictions: child must be subset of parent
    if parent.ipRestrictions is not None:
        if child.ipRestrictions is None:
            return False
        if not set(child.ipRestrictions).issubset(set(parent.ipRestrictions)):
            return False

    # requireMFA: if parent requires it, child must too
    if parent.requireMFA is True and child.requireMFA is not True:
        return False

    return True


def validate_delegation_chain(
    tokens: list[str],
    resolve_key_func: Callable[[str], object],
) -> DelegationTokenPayload:
    """Validate a chain of delegation JWT tokens and return the leaf payload.

    Args:
        tokens: Ordered list of compact JWT strings, root first, leaf last.
        resolve_key_func: Callable(did: str) -> Ed25519PublicKey

    Returns:
        The leaf token's :class:`DelegationTokenPayload`.

    Raises:
        ValueError: If any validation check fails.
    """
    if not tokens:
        raise ValueError("Empty delegation chain")

    decoded: list[DelegationTokenPayload] = []
    for i, token in enumerate(tokens):
        # Determine the issuer from raw JWT (without verification) to fetch key
        import base64 as _b64
        import json

        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError(f"Token {i} is not a valid JWT")
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        raw_payload = json.loads(_b64.urlsafe_b64decode(payload_b64))
        iss = raw_payload.get("iss")
        if not iss:
            raise ValueError(f"Token {i} missing 'iss' claim")

        issuer_key = resolve_key_func(iss)
        payload = decode_delegation_token(token, issuer_key)
        decoded.append(payload)

    # Check chain continuity: token[n].sub == token[n+1].iss
    for i in range(len(decoded) - 1):
        if decoded[i].sub != decoded[i + 1].iss:
            raise ValueError(
                f"Chain continuity broken at index {i}: "
                f"token[{i}].sub={decoded[i].sub!r} != token[{i+1}].iss={decoded[i+1].iss!r}"
            )

    # Check depth consistency
    for i, payload in enumerate(decoded):
        if payload.delegationDepth != i:
            raise ValueError(
                f"Token {i} has delegationDepth={payload.delegationDepth}, expected {i}"
            )

    # Check scope narrowing
    for i in range(len(decoded) - 1):
        parent = decoded[i]
        child = decoded[i + 1]
        if not is_scope_subset(child.scopes, parent.scopes):
            raise ValueError(
                f"Token {i+1} scopes {child.scopes!r} are not a subset of "
                f"parent token {i} scopes {parent.scopes!r}"
            )

    # Check constraint tightening
    for i in range(len(decoded) - 1):
        parent = decoded[i]
        child = decoded[i + 1]
        if not _constraints_tightened_or_equal(child.constraints, parent.constraints):
            raise ValueError(
                f"Token {i+1} constraints are looser than parent token {i} constraints"
            )

    # Check chain hash integrity
    running_hash = None
    for i, payload in enumerate(decoded):
        if i == 0:
            # Root token should have no parentTokenId or parentChainHash
            if payload.parentTokenId is not None:
                raise ValueError("Root token (index 0) should not have parentTokenId")
            running_hash = None
        else:
            parent = decoded[i - 1]
            expected_hash = compute_chain_hash(running_hash, parent.jti)
            if payload.parentChainHash != expected_hash:
                raise ValueError(
                    f"Token {i} chain hash mismatch: "
                    f"expected {expected_hash!r}, got {payload.parentChainHash!r}"
                )
            if payload.parentTokenId != parent.jti:
                raise ValueError(
                    f"Token {i} parentTokenId={payload.parentTokenId!r} "
                    f"does not match parent jti={parent.jti!r}"
                )
            running_hash = expected_hash

    # Check temporal bounds (all already verified by jwt.decode, but double-check nbf)
    now = int(time.time())
    for i, payload in enumerate(decoded):
        if payload.constraints.notBefore is not None and now < payload.constraints.notBefore:
            raise ValueError(f"Token {i} is not yet valid (notBefore constraint)")
        if payload.constraints.notAfter is not None and now > payload.constraints.notAfter:
            raise ValueError(f"Token {i} has expired (notAfter constraint)")

    return decoded[-1]
