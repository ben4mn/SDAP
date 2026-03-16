"""SDAP delegation module — delegation token creation and chain validation."""

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

__all__ = [
    # chain
    "is_scope_subset",
    "parse_scope",
    "validate_delegation_chain",
    # tokens
    "DelegationConstraints",
    "DelegationTokenPayload",
    "compute_chain_hash",
    "create_delegation_token",
    "decode_delegation_token",
]
