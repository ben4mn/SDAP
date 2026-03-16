"""
SDAP Example 2: Delegation Chain
=================================
Three agents — Orchestrator (A), Specialist (B), Sub-specialist (C) — demonstrate
SDAP's hierarchical delegation model.

  A (orchestrator.net) creates a root delegation token for B
  B (specialist.org)   sub-delegates to C with narrowed scope and tighter constraints
  Chain is validated end-to-end with cryptographic proof of every link

Run with:
    cd sdap-python && PYTHONPATH=src python ../examples/delegation-chain/example.py
"""

from __future__ import annotations

import time

from sdap.identity import generate_ed25519_keypair
from sdap.delegation import (
    DelegationConstraints,
    create_delegation_token,
    decode_delegation_token,
    validate_delegation_chain,
)

SEPARATOR = "-" * 60


def main() -> None:
    print(SEPARATOR)
    print("SDAP Example: Delegation Chain  (A → B → C)")
    print(SEPARATOR)

    # ------------------------------------------------------------------ #
    # Step 1: Set up three agents                                         #
    # ------------------------------------------------------------------ #
    print("\n[1] Setting up three agents")

    kp_a = generate_ed25519_keypair("auth-key-1")
    kp_b = generate_ed25519_keypair("auth-key-1")
    kp_c = generate_ed25519_keypair("auth-key-1")

    did_a = "did:sdap:orchestrator.net:agent-a"
    did_b = "did:sdap:specialist.org:agent-b"
    did_c = "did:sdap:subspec.io:agent-c"

    print(f"   A (Orchestrator) : {did_a}")
    print(f"   B (Specialist)   : {did_b}")
    print(f"   C (Sub-spec)     : {did_c}")

    # ------------------------------------------------------------------ #
    # Step 2: A creates root delegation token for B                      #
    # ------------------------------------------------------------------ #
    print("\n[2] A creates root delegation token for B")

    root_scopes = ["patient-data:read", "lab-results:read", "audit:read"]
    now = int(time.time())

    root_constraints = DelegationConstraints(
        maxUses=100,
        notAfter=now + 86400,          # expires in 24 h
        allowedResources=["patient/*", "lab/*", "audit/*"],
        requireMFA=False,
        dataClassification="PHI",
    )

    root_token = create_delegation_token(
        issuer_did=did_a,
        delegatee_did=did_b,
        audience_did=did_c,           # ultimate audience is C
        private_key=kp_a.private_key,
        scopes=root_scopes,
        constraints=root_constraints,
        delegation_depth=0,           # root token
    )

    root_payload = decode_delegation_token(root_token, kp_a.public_key)

    print(f"   Root token JTI   : {root_payload.jti}")
    print(f"   Issuer           : {root_payload.iss}")
    print(f"   Delegatee        : {root_payload.sub}")
    print(f"   Scopes           : {root_payload.scopes}")
    print(f"   Depth            : {root_payload.delegationDepth}")
    print(f"   maxUses          : {root_payload.constraints.maxUses}")
    print(f"   requireMFA       : {root_payload.constraints.requireMFA}")
    print(f"   dataClassif.     : {root_payload.constraints.dataClassification}")

    # ------------------------------------------------------------------ #
    # Step 3: B sub-delegates to C with narrowed scope + tighter bounds  #
    # ------------------------------------------------------------------ #
    print("\n[3] B sub-delegates to C (narrowed scope, tighter constraints)")

    # B can only grant a subset of what it received from A
    sub_scopes = ["lab-results:read"]      # narrower than root

    sub_constraints = DelegationConstraints(
        maxUses=10,                         # tighter: 10 < 100
        notAfter=now + 3600,               # tighter: 1 h < 24 h
        allowedResources=["lab/*"],        # tighter: only lab resources
        requireMFA=True,                   # tighter: now requires MFA
        dataClassification="PHI",          # same classification
    )

    sub_token = create_delegation_token(
        issuer_did=did_b,
        delegatee_did=did_c,
        audience_did=did_c,
        private_key=kp_b.private_key,
        scopes=sub_scopes,
        constraints=sub_constraints,
        parent_token_id=root_payload.jti,  # link to parent
        delegation_depth=1,
        parent_chain_hash=None,            # root has no prior hash
    )

    sub_payload = decode_delegation_token(sub_token, kp_b.public_key)

    print(f"   Sub token JTI    : {sub_payload.jti}")
    print(f"   Issuer           : {sub_payload.iss}")
    print(f"   Delegatee        : {sub_payload.sub}")
    print(f"   Scopes           : {sub_payload.scopes}")
    print(f"   Depth            : {sub_payload.delegationDepth}")
    print(f"   maxUses          : {sub_payload.constraints.maxUses}")
    print(f"   requireMFA       : {sub_payload.constraints.requireMFA}")
    print(f"   parentTokenId    : {sub_payload.parentTokenId}")
    print(f"   parentChainHash  : {sub_payload.parentChainHash[:16]}...")

    # ------------------------------------------------------------------ #
    # Step 4: Validate the full delegation chain                          #
    # ------------------------------------------------------------------ #
    print("\n[4] Validating the full delegation chain A → B → C")

    # Resolver maps each issuer DID to their Ed25519 public key
    key_store = {
        did_a: kp_a.public_key,
        did_b: kp_b.public_key,
        did_c: kp_c.public_key,
    }

    def resolve_key(did: str):
        if did not in key_store:
            raise ValueError(f"Key not found for DID: {did!r}")
        return key_store[did]

    leaf = validate_delegation_chain([root_token, sub_token], resolve_key)

    print(f"   Chain length     : 2 tokens (depth 0 and 1)")
    print(f"   Leaf issuer      : {leaf.iss}")
    print(f"   Leaf delegatee   : {leaf.sub}")
    print(f"   Effective scopes : {leaf.scopes}")
    print(f"   Chain valid      : True")

    # ------------------------------------------------------------------ #
    # Step 5: Print chain summary                                         #
    # ------------------------------------------------------------------ #
    print(f"\n[5] Delegation chain summary")
    print(f"   Token 0 (root):")
    print(f"     {root_payload.iss}  →  {root_payload.sub}")
    print(f"     scopes  : {root_payload.scopes}")
    print(f"     maxUses : {root_payload.constraints.maxUses}  |  requireMFA: {root_payload.constraints.requireMFA}")
    print(f"     jti     : {root_payload.jti}")
    print(f"   Token 1 (sub-delegation):")
    print(f"     {sub_payload.iss}  →  {sub_payload.sub}")
    print(f"     scopes  : {sub_payload.scopes}")
    print(f"     maxUses : {sub_payload.constraints.maxUses}  |  requireMFA: {sub_payload.constraints.requireMFA}")
    print(f"     jti     : {sub_payload.jti}")
    print(f"     parent  : {sub_payload.parentTokenId}")

    # ------------------------------------------------------------------ #
    # Summary                                                             #
    # ------------------------------------------------------------------ #
    print(f"\n{SEPARATOR}")
    print("Summary")
    print(SEPARATOR)
    print(f"  Chain      : A → B → C  (2-hop delegation)")
    print(f"  Root scope : {root_scopes}")
    print(f"  Leaf scope : {sub_scopes}  (narrowed)")
    print(f"  maxUses    : 100 → 10  (tightened)")
    print(f"  requireMFA : False → True  (added)")
    print(f"  Chain hash : cryptographically linked via SHA-256")
    print(f"  Status     : Delegation chain validated successfully")
    print(SEPARATOR)


if __name__ == "__main__":
    main()
