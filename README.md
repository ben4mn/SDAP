# SDAP — Secure Digital Agent Protocol

**HTTPS for agent communication.**

![Status](https://img.shields.io/badge/status-alpha-orange)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![TypeScript](https://img.shields.io/badge/typescript-5.x-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)

---

## The Problem

Agents built on MCP, A2A, or custom HTTP APIs have no standard way to prove
their identity to each other, negotiate a shared security level, or cryptographically
bound their delegated authority. Every integration reinvents authentication,
encryption, and audit logging — inconsistently and often insecurely.

## The Solution

SDAP is a lightweight, layered security protocol that runs _above_ your existing
agent transport. It provides:

- **Decentralised identity** via `did:sdap` DIDs and provider-signed attestations
- **Authenticated key exchange** via a 3-message handshake (X25519 ECDH + HKDF)
- **Encrypted sessions** using AES-256-GCM with replay protection
- **Hierarchical delegation** with cryptographically linked JWT chains and
  scope/constraint narrowing
- **Tamper-evident audit trails** with SHA-256 hash chains and Ed25519 signatures

## Protocol Stack

```
┌─────────────────────────────────────────────────┐
│  Layer 5  Application Tasks                      │
│           task lifecycle, streaming results      │
├─────────────────────────────────────────────────┤
│  Layer 4  A2A Integration                        │
│           agent card extension, message envelope │
├─────────────────────────────────────────────────┤
│  Layer 3  Delegation & Authorization             │
│           JWT token chains, scope narrowing      │
├─────────────────────────────────────────────────┤
│  Layer 2  Session Management                     │
│           key derivation, sequence numbers       │
├─────────────────────────────────────────────────┤
│  Layer 1  Handshake & Identity                   │
│           did:sdap, attestations, key exchange   │
└─────────────────────────────────────────────────┘
```

You can adopt individual layers independently.

## MCP + A2A + SDAP

| Protocol | Layer | Responsibility |
|---|---|---|
| **MCP** | Tool / resource | Agent capability discovery and invocation |
| **A2A** | Agent communication | Task exchange format and lifecycle |
| **SDAP** | Security | Identity, encryption, delegation, audit |

SDAP adds a security envelope around any A2A message. It does not replace MCP
or A2A — it secures them.

---

## Quick Start

### Python

```bash
cd sdap-python
pip install -e .
```

```python
from sdap.identity import generate_ed25519_keypair, generate_x25519_keypair, create_did, create_attestation
from sdap.handshake import create_handshake_init, process_handshake_init, create_handshake_confirm, process_handshake_confirm
from sdap.a2a import wrap_a2a_message, unwrap_a2a_message

# 1. Create agent identity
auth_kp  = generate_ed25519_keypair("auth-key-1")
agree_kp = generate_x25519_keypair("agree-key-1")
did_doc  = create_did("acme-health.com", "records-agent",
                      auth_kp.public_key, agree_kp.public_key)

# 2. Perform handshake (simplified — see examples/ for the full flow)
eph = generate_x25519_keypair("eph")
init_msg, eph_private = create_handshake_init(
    initiator_did=did_doc.id,
    target_did="did:sdap:city-hospital.org:ehr-agent",
    auth_private_key=auth_kp.private_key,
    auth_key_id=auth_kp.key_id,
    ephemeral_keypair=eph,
    requested_scopes=["patient-data:read"],
)

# 3. Once session is established, send encrypted messages
# encrypted = wrap_a2a_message(message, session, encrypt_key=session.encrypt_key, sender_did=did_doc.id)
```

### TypeScript

```bash
cd sdap-typescript
npm install && npm run build
```

```typescript
import { generateEd25519Keypair, generateX25519Keypair, createDid } from "@sdap/sdk";
import { createHandshakeInit } from "@sdap/sdk";

const authKp  = generateEd25519Keypair("auth-key-1");
const agreeKp = generateX25519Keypair("agree-key-1");
const didDoc  = createDid("acme-health.com", "records-agent",
                           authKp.publicKey, agreeKp.publicKey);
```

---

## Examples

| Example | What it demonstrates |
|---|---|
| [`examples/cross-provider-handoff/`](examples/cross-provider-handoff/) | Full handshake + encrypted query/response between two providers |
| [`examples/delegation-chain/`](examples/delegation-chain/) | Three-agent A→B→C delegation with scope/constraint narrowing |
| [`examples/medical-records/`](examples/medical-records/) | HIPAA compliance tags, high-security sessions, PHI delegation, audit chain |

Run any example:
```bash
cd sdap-python
PYTHONPATH=src python3 ../examples/cross-provider-handoff/example.py
PYTHONPATH=src python3 ../examples/delegation-chain/example.py
PYTHONPATH=src python3 ../examples/medical-records/example.py
```

---

## Cryptographic Choices

| Primitive | Algorithm | Rationale |
|---|---|---|
| Signing / authentication | Ed25519 | Fast, compact, widely supported; NIST SP 800-186 |
| Key agreement | X25519 ECDH | No small-subgroup attacks; RFC 7748 |
| Key derivation | HKDF-SHA-256 | Standard key derivation; RFC 5869 |
| Symmetric encryption | AES-256-GCM | AEAD; authenticated encryption |
| Hashing | SHA-256 | Audit chain integrity, delegation chain hashes |

---

## References

- [Protocol Specification](spec/sdap-protocol-v1.md)
- [DID Method Specification](spec/did-method-sdap.md)
- [OpenAPI Spec](spec/openapi.yaml)
- [Whitepaper](whitepaper/sdap-whitepaper.md)
- [Interop Tests](tests/interop/)

---

## Repository Layout

```
spec/               Protocol + DID specs, JSON schemas, OpenAPI
whitepaper/         Concept whitepaper
examples/           Runnable Python examples
sdap-python/        Python reference SDK (src/sdap/)
sdap-typescript/    TypeScript reference SDK (src/)
tests/interop/      Cross-language test vectors
```

---

## Contributing

Contributions are welcome. Please open an issue before submitting a large pull
request. All cryptographic changes require corresponding test vector updates in
`tests/interop/`.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
