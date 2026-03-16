"""SDAP identity module — DID operations, attestation, and key management."""

from sdap.identity.attestation import (
    ProviderAttestation,
    SDAPAttestationClaims,
    create_attestation,
    verify_attestation,
)
from sdap.identity.did import (
    DIDDocument,
    ServiceEndpoint,
    VerificationMethod,
    create_did,
    parse_did,
    resolve_did,
    validate_did,
)
from sdap.identity.keys import (
    KeyPair,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    jwk_to_public_key,
    multibase_to_public_key,
    public_key_to_jwk,
    public_key_to_multibase,
)

__all__ = [
    # attestation
    "ProviderAttestation",
    "SDAPAttestationClaims",
    "create_attestation",
    "verify_attestation",
    # did
    "DIDDocument",
    "ServiceEndpoint",
    "VerificationMethod",
    "create_did",
    "parse_did",
    "resolve_did",
    "validate_did",
    # keys
    "KeyPair",
    "generate_ed25519_keypair",
    "generate_x25519_keypair",
    "jwk_to_public_key",
    "multibase_to_public_key",
    "public_key_to_jwk",
    "public_key_to_multibase",
]
