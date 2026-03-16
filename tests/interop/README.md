# SDAP Cross-Language Interop Tests

These tests verify that the Python and TypeScript SDAP SDKs are wire-compatible —
both produce identical outputs for the same deterministic inputs, and each can
verify cryptographic material created by the other.

## What is tested

| # | Primitive | Direction |
|---|-----------|-----------|
| 1 | JCS (RFC 8785) canonicalization | Python ↔ TypeScript produce identical bytes |
| 2 | SHA-256 | Python ↔ TypeScript produce identical hex digest |
| 3 | HKDF-SHA256 session key derivation | Python ↔ TypeScript produce identical `encrypt_key` / `mac_key` |
| 4 | Ed25519 JWS signing / verification | Python signs → TypeScript verifies; TypeScript signs → Python verifies |
| 5 | Detached JWS | Same as above |
| 6 | Attestation JWT (`sdap_attestation` claim) | Python signs → TypeScript verifies; TypeScript signs → Python verifies |
| 7 | Delegation token JWT | Same as above |
| 8 | Audit entry hash + detached signature | Python creates → TypeScript verifies; TypeScript creates → Python verifies |

## Directory layout

```
tests/interop/
  generate_vectors_python.py       — writes vectors_python.json
  generate_vectors_typescript.ts   — writes vectors_typescript.json
  verify_python_vectors.test.ts    — Vitest: TypeScript reads vectors_python.json
  test_verify_ts_vectors.py        — pytest: Python reads vectors_typescript.json
  vectors_python.json              — generated (checked in for CI convenience)
  vectors_typescript.json          — generated (checked in for CI convenience)
  README.md                        — this file
```

## Prerequisites

**Python SDK** – install once:
```bash
pip install -e sdap-python
# or, if multiple Python versions:
/opt/homebrew/bin/python3.11 -m pip install -e sdap-python
/opt/homebrew/bin/python3.11 -m pip install pytest
```

**TypeScript SDK** – install once:
```bash
cd sdap-typescript && npm install
```

## Step 1 — Generate vectors

Run both generators. Each generator uses the **same fixed inputs** (a deterministic
Ed25519 seed, fixed HKDF inputs, etc.) so the vectors can cross-verify.

```bash
# From the repository root:

# Python generator
/opt/homebrew/bin/python3.11 tests/interop/generate_vectors_python.py

# TypeScript generator (must run from sdap-typescript to access node_modules)
cd sdap-typescript
node_modules/.bin/vite-node ../tests/interop/generate_vectors_typescript.ts
cd ..
```

Both commands write their respective `vectors_*.json` files.

## Step 2 — Run verification tests

```bash
# TypeScript verifies Python vectors (Vitest)
cd sdap-typescript
node_modules/.bin/vitest run

# Python verifies TypeScript vectors (pytest)
cd ..   # back to repo root
/opt/homebrew/bin/python3.11 -m pytest tests/interop/test_verify_ts_vectors.py -v
```

Expected output for TypeScript:
```
✓ ../tests/interop/verify_python_vectors.test.ts  (10 tests)
```

Expected output for Python:
```
10 passed in 0.11s
```

## Fixed inputs used by both generators

```json
{
  "private_key_hex": "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b",
  "test_object": {"name": "Alice", "age": 30, "active": true, "scores": [100, 95, 88]},
  "test_payload": "Hello, SDAP!",
  "hkdf_inputs": {
    "shared_secret_hex": "0123456789abcdef...",
    "nonce_a_hex": "aaaa...",
    "nonce_b_hex": "bbbb...",
    "session_id": "test-session-001"
  }
}
```

The JWT tokens (attestation, delegation) and audit entry are non-deterministic
(timestamps, UUIDs) so the verification tests always load the freshly-generated
vectors — they do not compare tokens from different generators, only verify
that each generator's own tokens can be verified by the other language.
