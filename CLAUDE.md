# CLAUDE.md — Secure Digital Agent Protocol (SDAP)

This file provides guidance to Claude Code when working with the SDAP project.

## Project Overview

SDAP (Secure Digital Agent Protocol) is an open protocol and dual-SDK reference
implementation for authenticated, encrypted, auditable agent-to-agent
communication. It sits above A2A/MCP at the security layer — providing identity,
key exchange, delegation, and audit capabilities that those protocols leave to
individual implementors.

The repo contains:
- Protocol specification and JSON schemas
- Python reference SDK (`sdap-python/`)
- TypeScript reference SDK (`sdap-typescript/`)
- Cross-language interop test vectors
- Runnable example scenarios

## Directory Structure

```
sdap/
├── spec/
│   ├── sdap-protocol-v1.md      # Protocol specification
│   ├── did-method-sdap.md       # DID method specification
│   ├── openapi.yaml             # OpenAPI 3.1 for handshake endpoints
│   └── schemas/                 # JSON Schema for every protocol message
├── whitepaper/
│   └── sdap-whitepaper.md
├── examples/
│   ├── cross-provider-handoff/  # Two agents, full handshake + encrypted exchange
│   ├── delegation-chain/        # Three-agent A→B→C delegation
│   └── medical-records/         # HIPAA + PHI + audit chain
├── sdap-python/
│   ├── src/sdap/
│   │   ├── identity/            # DID creation, key generation, attestation JWTs
│   │   ├── crypto/              # AES-256-GCM, X25519 ECDH, Ed25519, HKDF
│   │   ├── handshake/           # 3-message handshake protocol + session store
│   │   ├── delegation/          # Delegation tokens, chain validation
│   │   ├── audit/               # Audit entries, hash chain, commitment proofs
│   │   └── a2a/                 # A2A message wrapping, agent card builder
│   ├── tests/
│   └── pyproject.toml
├── sdap-typescript/
│   ├── src/
│   │   ├── identity/            # Mirrors Python identity module
│   │   ├── crypto/              # Mirrors Python crypto module
│   │   ├── handshake/           # Mirrors Python handshake module
│   │   ├── delegation/          # Mirrors Python delegation module
│   │   ├── audit/               # Mirrors Python audit module
│   │   └── a2a/                 # Mirrors Python a2a module
│   ├── tests/
│   └── package.json
└── tests/
    └── interop/                 # Cross-language test vectors + verification
```

## Quick Start

### Python SDK

```bash
cd sdap-python
pip install -e .                 # install with dependencies
pip install -e ".[dev]"          # include pytest

# Run tests
pytest tests/                    # all tests
pytest tests/ -v                 # verbose
pytest tests/ --cov=sdap         # with coverage

# Run examples
PYTHONPATH=src python3 ../examples/cross-provider-handoff/example.py
PYTHONPATH=src python3 ../examples/delegation-chain/example.py
PYTHONPATH=src python3 ../examples/medical-records/example.py
```

### TypeScript SDK

```bash
cd sdap-typescript
npm install
npm run build                    # compile TypeScript → dist/

# Run tests
npm test                         # vitest run (all tests)
npm run test:watch               # vitest watch mode
```

### Interop Tests

```bash
# Generate Python vectors
cd sdap-python
PYTHONPATH=src python3 ../tests/interop/generate_vectors_python.py

# Generate TypeScript vectors
cd sdap-typescript
npx ts-node --esm ../tests/interop/generate_vectors_typescript.ts

# Verify Python can read TypeScript vectors
cd sdap-python
PYTHONPATH=src pytest ../tests/interop/test_verify_ts_vectors.py -v

# Verify TypeScript can read Python vectors
cd sdap-typescript
npx vitest run ../tests/interop/verify_python_vectors.test.ts
```

## Python SDK — Key Module Descriptions

### `sdap.identity`

| Symbol | Purpose |
|---|---|
| `generate_ed25519_keypair(key_id)` | Generate Ed25519 keypair for authentication/signing |
| `generate_x25519_keypair(key_id)` | Generate X25519 keypair for key agreement |
| `create_did(provider_domain, agent_id, ...)` | Construct a `DIDDocument` |
| `create_attestation(issuer_did, subject_did, ...)` | Create a provider attestation JWT |
| `verify_attestation(token, issuer_public_key)` | Verify and decode attestation JWT |
| `validate_did(did)` | Syntax-check a `did:sdap` DID |

### `sdap.handshake`

| Symbol | Purpose |
|---|---|
| `create_handshake_init(...)` | Create INIT message + return ephemeral private key |
| `process_handshake_init(...)` | Process INIT, produce ACCEPT + Session |
| `create_handshake_confirm(...)` | Process ACCEPT, produce CONFIRM + Session |
| `process_handshake_confirm(...)` | Validate CONFIRM, return confirmed Session |
| `Session` | Dataclass: session_id, encrypt_key, mac_key, scopes, expiry |
| `SessionStore` | In-memory session store with TTL eviction |

### `sdap.delegation`

| Symbol | Purpose |
|---|---|
| `create_delegation_token(...)` | Create a signed delegation JWT |
| `decode_delegation_token(token, pubkey)` | Verify and decode a delegation JWT |
| `validate_delegation_chain(tokens, resolve_key_func)` | Full chain validation |
| `DelegationConstraints` | Pydantic model: maxUses, notAfter, requireMFA, dataClassification, ... |

### `sdap.audit`

| Symbol | Purpose |
|---|---|
| `create_audit_entry(actor_did, event_type, ...)` | Create a signed, hashed audit entry |
| `verify_audit_chain(entries, resolve_key_func)` | Verify hash chain + signatures |
| `create_audit_commitment(latest_hash, ...)` | Create a lightweight anchor proof |
| `AuditEntry` | Pydantic model for a single audit log entry |

### `sdap.a2a`

| Symbol | Purpose |
|---|---|
| `wrap_a2a_message(message, session, ...)` | Encrypt + wrap an A2A message in SDAP envelope |
| `unwrap_a2a_message(wrapped, session, ...)` | Decrypt + validate sequence number |
| `build_sdap_extension(did, ...)` | Build the `sdap` extension for an A2A Agent Card |
| `SDAPClient` | High-level client for session establishment and messaging |

### `sdap.crypto`

| Symbol | Purpose |
|---|---|
| `encrypt_payload(plaintext, key, ...)` | AES-256-GCM encrypt → compact JWE-like string |
| `decrypt_payload(jwe, key, ...)` | AES-256-GCM decrypt |
| `sign_jws(payload_bytes, private_key, ...)` | Ed25519 compact JWS |
| `verify_jws(jws, public_key)` | Verify Ed25519 JWS |
| `perform_ecdh(private_key, public_key)` | X25519 ECDH shared secret |
| `derive_session_keys(shared_secret, ...)` | HKDF → (encrypt_key, mac_key) |

## TypeScript SDK

Mirrors the Python SDK module-for-module. Each Python module has a TypeScript
counterpart in `sdap-typescript/src/<module>/`. The API surface is identical in
spirit; naming follows TypeScript conventions (camelCase, no underscores in
function params).

Cryptographic dependencies: `@noble/curves` (Ed25519, X25519), `@noble/hashes`
(SHA-256, HKDF), `jose` (JWT/JWS), `zod` (schema validation).

## Architecture Overview — 5-Layer Protocol Stack

```
Layer 5 — Application Tasks          (task lifecycle, results, streaming)
Layer 4 — A2A Integration            (agent card extension, message envelope)
Layer 3 — Delegation & Authorization (JWT token chains, scope narrowing)
Layer 2 — Session Management         (key derivation, sequence numbers, replay prevention)
Layer 1 — Handshake & Identity       (DID, attestation, 3-message key exchange)
```

Each layer builds on the one below. You can adopt individual layers
independently: e.g., use only Layer 1 for identity verification without
delegation, or only the audit module for tamper-evident logging.

## DID Method

`did:sdap:<provider_domain>[:<agent_id>]`

Examples:
- `did:sdap:acme-health.com` — provider DID (no agent_id)
- `did:sdap:acme-health.com:records-agent` — specific agent DID

Resolved via `https://<provider_domain>/.well-known/sdap/did/<agent_id>`.

## Cryptographic Choices

| Primitive | Algorithm | Purpose |
|---|---|---|
| Authentication / signing | Ed25519 | DID auth keys, JWS, attestations |
| Key agreement | X25519 ECDH | Ephemeral session key exchange |
| Key derivation | HKDF-SHA-256 | Session encrypt + MAC key derivation |
| Symmetric encryption | AES-256-GCM | Session payload encryption |
| Hashing | SHA-256 | Audit entry hashes, delegation chain hashes |

## Common Development Workflows

### Add a new Python test
Place it in `sdap-python/tests/test_<module>.py`. Run with:
```bash
cd sdap-python && pytest tests/test_<module>.py -v
```

### Add a new TypeScript test
Place it in `sdap-typescript/tests/<module>.test.ts`. Run with:
```bash
cd sdap-typescript && npm test
```

### Update interop vectors
After changing vector-generating code, regenerate both sets and commit:
```bash
cd sdap-python && PYTHONPATH=src python3 ../tests/interop/generate_vectors_python.py
cd sdap-typescript && npx tsx ../tests/interop/generate_vectors_typescript.ts
```

### Validate JSON schemas
```bash
cd sdap-python
PYTHONPATH=src python3 -c "
from sdap.identity import create_did, generate_ed25519_keypair, generate_x25519_keypair
import json
auth = generate_ed25519_keypair('k1')
agree = generate_x25519_keypair('k2')
doc = create_did('example.com', 'agent', auth.public_key, agree.public_key)
print(json.dumps(doc.model_dump_json_ld(), indent=2))
"
```

## Python Requirements

- Python >= 3.11
- `PyJWT >= 2.8`
- `cryptography >= 42.0`
- `httpx >= 0.27`
- `pydantic >= 2.5`

## TypeScript Requirements

- Node.js >= 18
- `@noble/curves`, `@noble/hashes`, `jose`, `zod`
