# SDAP — Secure Digital Agent Protocol

> **HTTPS for AI agent-to-agent communication.**
>
> A cryptographic trust layer for multi-provider AI agent ecosystems. Identity verification, mutual authentication, end-to-end encryption, scoped delegation, and tamper-evident audit trails — for agents built on [Google A2A](https://github.com/google/A2A), [Anthropic MCP](https://modelcontextprotocol.io/), or any agent-to-agent transport.

![Status](https://img.shields.io/badge/status-alpha-orange)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![TypeScript](https://img.shields.io/badge/typescript-5.x-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Tests Python](https://img.shields.io/badge/tests-186%20passing-brightgreen)
![Tests TypeScript](https://img.shields.io/badge/tests-107%20passing-brightgreen)

---

## Why SDAP?

AI agents are fragmenting across providers — Anthropic, Google, OpenAI, startups. Google's [A2A protocol](https://github.com/google/A2A) handles agent discovery and task delegation. Anthropic's [MCP](https://modelcontextprotocol.io/) handles tool and data access. But neither provides a standard for:

- **Verified agent identity** — How does one agent prove who it is to another agent from a different provider?
- **Mutual authentication** — How do two agents from different companies establish a trusted session?
- **End-to-end encryption** — How are sensitive payloads (medical records, financial data, PII) protected in transit between agents?
- **Scoped trust delegation** — How does Agent A grant Agent B limited permissions that Agent B can sub-delegate to Agent C — without privilege escalation?
- **Cryptographic audit trails** — How do you prove what happened in a multi-agent workflow after the fact?

SDAP fills this gap. It's a security and trust protocol that sits **on top of** A2A (or any agent transport), the same way HTTPS sits on top of HTTP.

**Positioning:** MCP (tools/data) + A2A (discovery/delegation) + **SDAP (trust/security)**

---

## Protocol Stack — 5 Independently Adoptable Layers

```
Layer 5: AUDIT TRAIL         Merkle-chained cryptographic event log
Layer 4: TRUST DELEGATION    Delegation tokens, scope constraints, chain validation
Layer 3: PAYLOAD SECURITY    AES-256-GCM encryption, forward secrecy, replay protection
Layer 2: SESSION (Handshake) Mutual authentication, X25519 key exchange, capability negotiation
Layer 1: IDENTITY            did:sdap DIDs, Ed25519 keys, provider attestations
         ─────────────────────────────────────────────────────────
         Transport: A2A JSON-RPC over HTTPS, or any agent protocol
```

Start with Layer 1 (identity) and add layers as needed. A low-sensitivity agent interaction might use Layers 1-2. Moving PHI across healthcare providers? All five layers.

---

## Key Features

### Decentralized Agent Identity (`did:sdap`)
Agents are identified by DIDs: `did:sdap:<provider-domain>:<agent-id>`. DID Documents are resolved via `https://<provider>/.well-known/sdap/did/<agent-id>` — no central registry, DNS-anchored trust. Supports Ed25519 authentication keys and X25519 key agreement keys.

### 3-Message Authenticated Handshake
Mutual authentication with ephemeral X25519 ECDH key exchange providing **forward secrecy**. Session keys derived via HKDF-SHA256. Nonce-based replay protection. 60-second clock skew tolerance.

### End-to-End Encrypted Sessions
AES-256-GCM encryption via JWE with authenticated additional data (AAD) binding ciphertext to session metadata. Monotonic sequence numbers prevent replay and reordering. Data classification tags (`public`, `internal`, `confidential`, `PHI`, `PII`, `restricted`).

### Hierarchical Trust Delegation
Signed JWT delegation tokens with **scope attenuation** — permissions can only narrow down the chain, never expand. Constraint inheritance enforces that child tokens can tighten but never loosen parent constraints. SHA-256 hash-linked chains detect tampering. Supports: `maxSubDelegations`, `allowedProviders`, `requiredSecurityLevel`, `requiredComplianceTags` (HIPAA, SOC2, etc.), `geofence`, `dataClassification`.

### Tamper-Evident Audit Trail
Every protocol event (session lifecycle, task operations, payload events, delegation usage, key rotation, policy violations) produces a signed audit entry. Entries form a Merkle-like hash chain — modifying any past entry invalidates all subsequent entries. Lightweight audit commitments propagate chain integrity proofs up the delegation hierarchy.

### A2A / MCP Integration
Backward-compatible Agent Card `sdap` extension. A2A message extension parameters (`sdap:sessionId`, `sdap:sequenceNumber`, `sdap:delegationChain`, `sdap:auditEntryHash`). Drop-in middleware for wrapping/unwrapping A2A messages with SDAP security envelopes.

---

## Quick Start

### Python SDK

```bash
cd sdap-python
pip install -e .
```

```python
from sdap.identity import generate_ed25519_keypair, generate_x25519_keypair, create_did
from sdap.handshake import create_handshake_init, process_handshake_init
from sdap.delegation import create_delegation_token, DelegationConstraints
from sdap.a2a import wrap_a2a_message, unwrap_a2a_message

# Create agent identity
auth_kp  = generate_ed25519_keypair("auth-key-1")
agree_kp = generate_x25519_keypair("agree-key-1")
did_doc  = create_did("acme-health.com", "records-agent",
                      auth_kp.public_key, agree_kp.public_key)

# Perform handshake → encrypted session → send secure messages
# See examples/ for complete flows
```

### TypeScript SDK

```bash
cd sdap-typescript
npm install && npm run build
```

```typescript
import { generateEd25519Keypair, generateX25519Keypair, createDid } from './src/identity/index.js';
import { createHandshakeInit } from './src/handshake/index.js';

const authKp  = generateEd25519Keypair("auth-key-1");
const agreeKp = generateX25519Keypair("agree-key-1");
const didDoc  = createDid({ providerDomain: "acme-health.com", agentId: "records-agent",
                             authPublicKey: authKp.publicKey, agreementPublicKey: agreeKp.publicKey });
```

### Run Tests

```bash
# Python (186 tests)
cd sdap-python && pip install -e ".[dev]" && pytest tests/ -v

# TypeScript (107 tests)
cd sdap-typescript && npm install && npm test

# Cross-language interop
cd sdap-python && PYTHONPATH=src python3 ../tests/interop/generate_vectors_python.py
cd sdap-typescript && npx vite-node ../tests/interop/generate_vectors_typescript.ts
cd sdap-typescript && npx vitest run ../tests/interop/verify_python_vectors.test.ts
cd sdap-python && PYTHONPATH=src pytest ../tests/interop/test_verify_ts_vectors.py
```

---

## Examples

| Example | Scenario | What It Demonstrates |
|---|---|---|
| [`cross-provider-handoff/`](examples/cross-provider-handoff/) | Two agents, two providers | Full handshake, encrypted query/response, provider attestations |
| [`delegation-chain/`](examples/delegation-chain/) | Three-agent A→B→C | Scoped delegation, constraint narrowing, chain validation |
| [`medical-records/`](examples/medical-records/) | Healthcare PHI transfer | HIPAA compliance tags, high-security sessions, PHI classification, audit trail verification, tamper detection |

```bash
cd sdap-python
PYTHONPATH=src python3 ../examples/cross-provider-handoff/example.py
PYTHONPATH=src python3 ../examples/delegation-chain/example.py
PYTHONPATH=src python3 ../examples/medical-records/example.py
```

---

## Cryptographic Primitives

| Purpose | Algorithm | Standard | Format |
|---|---|---|---|
| Agent authentication / signing | **Ed25519** | RFC 8032, NIST SP 800-186 | JWS compact (EdDSA) |
| Session key agreement | **X25519 ECDH** | RFC 7748 | JWK |
| Key derivation | **HKDF-SHA256** | RFC 5869 | — |
| Payload encryption | **AES-256-GCM** | NIST SP 800-38D | JWE compact |
| Hashing / integrity | **SHA-256** | FIPS 180-4 | Hex-encoded |
| Canonicalization | **JCS** | RFC 8785 | UTF-8 JSON |
| Identity tokens | **JWT** | RFC 7519 | JWS compact |
| Key encoding | **JWK** | RFC 7517 | JSON |

All algorithms are quantum-migration-ready — the protocol is algorithm-agnostic by design, with a documented migration path to ML-DSA / ML-KEM (NIST PQC standards).

---

## Use Cases

- **Healthcare / HIPAA** — Secure exchange of PHI between provider agents with compliance tag enforcement and full audit trails
- **Financial services** — Delegation chains for multi-agent transaction workflows with scope-limited authority
- **Enterprise AI orchestration** — Cross-vendor agent coordination with verified identity and encrypted channels
- **Government / FedRAMP** — High-security agent interactions with HSM-backed provider keys and geofence constraints
- **Insurance claims** — Multi-party agent workflows spanning policyholder, provider, and insurer systems
- **Legal / compliance** — Tamper-evident audit logs for agent actions involving regulated data

---

## Documentation

| Document | Description |
|---|---|
| [Whitepaper](whitepaper/sdap-whitepaper.md) | Non-technical concept document — the problem, the approach, real-world scenarios, open problems |
| [Protocol Specification](spec/sdap-protocol-v1.md) | RFC-style formal spec — all 5 layers, message formats, validation rules, crypto requirements |
| [DID Method Specification](spec/did-method-sdap.md) | `did:sdap` method — syntax, resolution, CRUD operations, security considerations |
| [OpenAPI Specification](spec/openapi.yaml) | REST API for DID resolution, handshake, revocation, audit retrieval |
| [JSON Schemas](spec/schemas/) | JSON Schema (draft 2020-12) for all 8 protocol message types |
| [Interop Test Vectors](tests/interop/) | Cross-language test vectors proving Python ↔ TypeScript compatibility |

---

## Repository Structure

```
sdap/
├── spec/                    Protocol specs, DID method, JSON schemas, OpenAPI
│   ├── sdap-protocol-v1.md  Full RFC-style protocol specification
│   ├── did-method-sdap.md   did:sdap DID method specification
│   ├── openapi.yaml         OpenAPI 3.1.0 REST API definition
│   └── schemas/             JSON Schema for all message types
├── whitepaper/              Concept whitepaper
├── sdap-python/             Python reference SDK
│   ├── src/sdap/            identity/ crypto/ handshake/ delegation/ audit/ a2a/
│   └── tests/               186 unit + integration tests
├── sdap-typescript/         TypeScript reference SDK
│   ├── src/                 identity/ crypto/ handshake/ delegation/ audit/ a2a/
│   └── tests/               107 unit + integration tests
├── tests/interop/           Cross-language interop test vectors
└── examples/                Three runnable scenario examples
```

---

## Open Problems

These are documented in the [whitepaper](whitepaper/sdap-whitepaper.md) — areas where the protocol acknowledges uncertainty and invites community input:

1. **Provider trust bootstrapping** — DNS-based for v1, curated registry for high-security
2. **Fleet vs. per-instance DIDs** — both patterns supported, trade-offs documented
3. **Scope vocabulary interoperability** — core scopes defined, namespaced custom scopes allowed
4. **Audit completeness guarantees** — social/contractual enforcement, not cryptographic proof
5. **Handshake latency optimization** — session caching, DID caching, lightweight mode
6. **Geofence enforcement** — contractual via attestations, not technically verifiable
7. **Post-quantum migration** — algorithm-agnostic key fields, documented path to ML-DSA/ML-KEM

---

## Related Projects & Standards

- [Google A2A](https://github.com/google/A2A) — Agent-to-Agent protocol (discovery, task delegation)
- [Anthropic MCP](https://modelcontextprotocol.io/) — Model Context Protocol (tool/data access)
- [W3C DID Core](https://www.w3.org/TR/did-core/) — Decentralized Identifier specification
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) — Verifiable credential data model
- [RFC 7516 (JWE)](https://datatracker.ietf.org/doc/html/rfc7516) — JSON Web Encryption
- [RFC 7515 (JWS)](https://datatracker.ietf.org/doc/html/rfc7515) — JSON Web Signatures
- [RFC 8785 (JCS)](https://datatracker.ietf.org/doc/html/rfc8785) — JSON Canonicalization Scheme

---

## Contributing

Contributions welcome. Please open an issue before submitting large pull requests. All cryptographic changes require corresponding test vector updates in `tests/interop/`.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
