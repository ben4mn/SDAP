# Secure Digital Agent Protocol (SDAP) v1.0

**Specification Version:** 1.0
**Date:** March 2026
**Status:** Draft
**Authors:** SDAP Working Group

---

## Abstract

The Secure Digital Agent Protocol (SDAP) defines a layered security and trust framework for AI agent-to-agent communication. SDAP operates as a security layer on top of the Agent-to-Agent (A2A) protocol, providing cryptographic identity verification, forward-secret session establishment, end-to-end payload encryption, scoped trust delegation, and tamper-evident audit trails.

This document is the normative specification for SDAP version 1.0. It covers all five protocol layers, their interactions, the message formats defined in the companion JSON schemas, integration with the A2A protocol, and the complete error taxonomy.

---

## Status of This Document

This document is a **Draft** specification of the SDAP Working Group. It is subject to change. Implementations based on this draft should be prepared to track updates.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119].

---

## Table of Contents

1. Introduction
2. Conventions and Definitions
3. Protocol Overview
4. Layer 1 — Identity
5. Layer 2 — Handshake and Session Establishment
6. Layer 3 — Payload Security
7. Layer 4 — Trust Delegation
8. Layer 5 — Audit Trail
9. A2A Integration
10. Error Codes
11. Security Considerations
12. Privacy Considerations
13. IANA Considerations
14. References

---

## 1. Introduction

### 1.1 Motivation

Autonomous AI agents increasingly collaborate across organizational boundaries to accomplish complex tasks. An orchestrating agent at one enterprise may delegate sub-tasks to specialist agents at other providers. This creates security challenges that existing protocols do not address:

- **Identity:** How does an agent know it is communicating with a genuine counterpart, not an impersonator?
- **Confidentiality:** How are sensitive payloads (medical records, financial data, PII) protected in transit between agents?
- **Authorization:** How does an agent verify that a peer has authority to request the operations it is requesting?
- **Accountability:** How can a multi-party pipeline produce a complete, non-repudiable audit trail spanning multiple providers?

SDAP addresses all four challenges through its five-layer architecture.

### 1.2 Design Principles

- **Layered:** Each layer adds security properties orthogonally. Implementations may adopt layers progressively based on their security requirements.
- **Decentralized:** No central authority controls identity or trust. Trust is anchored to DNS, which the internet already depends on.
- **Forward-secret:** Session keys are derived ephemerally and cannot be reconstructed after a session ends, protecting past communications even if long-term keys are compromised.
- **Composable:** SDAP extends the A2A protocol without breaking backward compatibility. Agents that do not implement SDAP can still interoperate with A2A-only agents.
- **Auditable:** Every significant protocol event generates a signed, chained audit entry enabling forensic reconstruction of multi-agent pipelines.

### 1.3 Relationship to A2A

SDAP is a security envelope around A2A, not a replacement. The A2A protocol defines the task and message semantics; SDAP provides the security context in which A2A tasks execute. An A2A session with SDAP active produces a `sessionId` that is threaded through all A2A messages, and A2A task completions trigger SDAP audit commitments.

### 1.4 Scope

This specification covers:

- The `did:sdap` identity method (referencing the companion DID method specification at `spec/did-method-sdap.md`)
- The SDAP 3-message handshake protocol
- Session envelope encryption with JWE
- Delegation token issuance, chain validation, and revocation
- Audit entry structure, hash chain, and commitment protocol
- REST API for DID resolution, revocation, handshake, and audit log retrieval

---

## 2. Conventions and Definitions

### 2.1 Cryptographic Algorithms

| Purpose | Algorithm | Format |
|---------|-----------|--------|
| Signing | Ed25519 ([RFC 8037]) | JWS compact serialization ([RFC 7515]) |
| Key agreement | X25519 ECDH ([RFC 8037]) | JWK ([RFC 7517]) |
| Key derivation | HKDF-SHA256 ([RFC 5869]) | — |
| Content encryption | AES-256-GCM | JWE compact serialization ([RFC 7516]) |
| Hashing | SHA-256 | Lowercase hex encoding |
| Canonicalization | JCS ([RFC 8785]) | — |

### 2.2 Definitions

| Term | Definition |
|------|-----------|
| **Agent** | An autonomous AI agent registered under an SDAP provider |
| **Provider** | An organization operating SDAP-compliant agent infrastructure at a DNS domain |
| **DID** | Decentralized Identifier — a globally unique, self-describing identifier per W3C DID Core 1.0 |
| **Attestation** | A signed JWT issued by a provider asserting facts about one of its agents |
| **Session** | A secured communication channel established by a successful SDAP handshake |
| **Session Key** | A 64-byte symmetric key (32-byte encryption key + 32-byte MAC key) derived during the handshake |
| **Delegation Token** | A signed JWT granting scoped permissions from a delegator to a delegatee |
| **Delegation Chain** | An ordered sequence of delegation tokens tracing authority from a root to a delegatee |
| **Audit Entry** | A signed, chained JSON record of a significant protocol event |
| **Audit Commitment** | A lightweight proof (latest hash + entry count) sent up the delegation chain |
| **JCS** | JSON Canonicalization Scheme per RFC 8785 |
| **JWE** | JSON Web Encryption per RFC 7516 |
| **JWS** | JSON Web Signature per RFC 7515 |

### 2.3 Security Levels

SDAP defines four security levels, each requiring a minimum set of active layers:

| Level | Required Layers | Key Storage | Notes |
|-------|----------------|-------------|-------|
| `basic` | 1–2 | Software | Identity + session establishment only |
| `standard` | 1–3 | Software | Adds payload encryption |
| `high` | 1–4 | Software (HSM recommended) | Adds trust delegation |
| `critical` | 1–5 | HSM required | Full stack; mandatory audit trail |

The security level is negotiated during the handshake (Section 5.3). A session's security level is the maximum supported by both parties that meets the initiator's required minimum.

---

## 3. Protocol Overview

### 3.1 Architecture

```
  Agent A (Initiator)                    Agent B (Responder)
  ┌─────────────────────┐                ┌─────────────────────┐
  │  Layer 5: Audit     │                │  Layer 5: Audit     │
  │  Layer 4: Deleg.    │                │  Layer 4: Deleg.    │
  │  Layer 3: Encrypt   │                │  Layer 3: Encrypt   │
  │  Layer 2: Handshake │◄──────────────►│  Layer 2: Handshake │
  │  Layer 1: Identity  │                │  Layer 1: Identity  │
  └─────────────────────┘                └─────────────────────┘
           │                                       │
           └──────────────┬────────────────────────┘
                          │
                   A2A Protocol
```

### 3.2 Session Lifecycle

```
  Agent A                              Agent B
     │                                    │
     │──── (1) Resolve B's DID ──────────►│ (DID resolution, Section 4.3)
     │                                    │
     │──── (2) HandshakeInit ────────────►│ (Section 5.2)
     │◄─── (3) HandshakeAccept ───────────│ (Section 5.3)
     │──── (4) HandshakeConfirm ─────────►│ (Section 5.4)
     │              [Session Established] │
     │                                    │
     │──── (5) SessionEnvelope(s) ───────►│ (Section 6.2, repeating)
     │◄─── (6) SessionEnvelope(s) ────────│
     │                                    │
     │  [A2A tasks execute within session]│
     │                                    │
     │──── (7) Audit Commitment ─────────►│ (Section 8.5, on task completion)
     │                                    │
     │          [Session Expires]         │
     │                                    │
```

### 3.3 Data Flow for A2A Task Execution

1. Before `tasks/send`: Initiate SDAP handshake to establish session.
2. Wrap A2A task payload in a `sdap/envelope` (Layer 3).
3. Present delegation tokens in `HandshakeConfirm` or in the A2A task extension parameters.
4. On `tasks/get`: Decrypt the session envelope to retrieve the response.
5. On task completion or cancellation: Send an audit commitment to all upstream delegators.

---

## 4. Layer 1 — Identity

### 4.1 Overview

Layer 1 establishes the identity of each communicating agent using the `did:sdap` DID method. The DID method specification is normatively defined in `spec/did-method-sdap.md`. This section summarizes the identity elements relevant to the protocol and defines the provider attestation format.

### 4.2 `did:sdap` Method

The full `did:sdap` method specification, including DID syntax, resolution procedure, DID Document structure, CRUD operations, and security considerations, is defined in the companion document `spec/did-method-sdap.md`.

DID syntax summary:

```
did:sdap:<provider-domain>:<agent-id>
```

Where `<provider-domain>` is the lowercased, fully-qualified DNS domain of the provider, and `<agent-id>` is a provider-unique identifier for the agent.

Resolution is performed via HTTPS GET to `https://<provider-domain>/.well-known/sdap/did/<agent-id>`. The response MUST be a DID Document conforming to the schema at `spec/schemas/did-document.json`.

### 4.3 DID Resolution Requirements

During protocol execution, implementations MUST:

1. Resolve peer DIDs before initiating or accepting a handshake.
2. Validate the resolved DID Document's `id` field matches the DID exactly.
3. Reject DID Documents with `deactivated: true` for new session establishment.
4. Cache DID Documents subject to the TTL rules in `spec/did-method-sdap.md` Section 3.3.
5. Re-resolve DID Documents at the start of each session for `high` and `critical` security levels (no cache reliance).

### 4.4 Provider Attestations

Provider attestations are short-lived JWTs embedded in DID Documents that allow a provider to assert security and compliance facts about its agents. Attestations supplement the cryptographic identity provided by the DID itself.

#### 4.4.1 Attestation Format

A provider attestation is a compact JWT (header.payload.signature) where:

- The **header** MUST include `"alg": "EdDSA"` and `"kid"` referencing the provider's Ed25519 authentication key DID URL.
- The **payload** MUST include the standard JWT claims and the `sdap_attestation` extension object.
- The **signature** MUST be an Ed25519 signature verifiable by the provider's public key.

**Standard JWT Claims:**

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | String | REQUIRED | Provider DID (e.g., `did:sdap:acme-health.com`) |
| `sub` | String | REQUIRED | Agent DID being attested |
| `iat` | Number | REQUIRED | Issued-at (Unix epoch seconds) |
| `exp` | Number | REQUIRED | Expiration (Unix epoch seconds); default 24 hours after `iat` |
| `jti` | String | REQUIRED | Unique JWT ID (UUID v4) |

**`sdap_attestation` Object Claims:**

| Claim | Type | Description |
|-------|------|-------------|
| `agentType` | String | `orchestrator`, `specialist`, `tool`, `gateway`, `compliance`, or `audit` |
| `capabilities` | Array | List of capability identifiers this agent exposes |
| `securityLevel` | String | `basic`, `standard`, `high`, or `critical` |
| `complianceTags` | Array | Compliance certifications (e.g., `HIPAA`, `SOC2`, `ISO27001`, `PCI-DSS`, `FedRAMP`) |
| `maxDelegationDepth` | Integer | Maximum delegation chain depth permitted for tokens issued by this agent |
| `auditPolicy` | String | `none`, `summary`, or `full` |
| `sbomHash` | String | SHA-256 hex hash of the agent's software bill of materials |
| `certifications` | Array | Structured certification objects with `name`, `issuedBy`, and `validUntil` |

**Example `sdap_attestation` payload:**

```json
{
  "iss": "did:sdap:acme-health.com",
  "sub": "did:sdap:acme-health.com:records-agent-v2",
  "iat": 1742032200,
  "exp": 1742118600,
  "jti": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "sdap_attestation": {
    "agentType": "specialist",
    "capabilities": ["medical-records:read", "medical-records:summarize"],
    "securityLevel": "high",
    "complianceTags": ["HIPAA", "SOC2"],
    "maxDelegationDepth": 2,
    "auditPolicy": "full"
  }
}
```

#### 4.4.2 Attestation Verification

Verifiers MUST perform the following checks when processing a `providerAttestation`:

1. Decode the JWT header; extract the `kid` parameter.
2. Resolve the provider DID (the `iss` claim) to obtain the provider's DID Document.
3. Locate the key identified by `kid` in the provider DID Document's `verificationMethod` array.
4. Verify the Ed25519 signature using that key.
5. Verify `iat` is in the past (within 60 seconds of clock skew tolerance).
6. Verify `exp` is in the future.
7. Verify `sub` matches the agent DID being verified.

An attestation that fails any of these checks MUST be treated as absent. Relying parties MAY require a valid attestation for sessions at `standard` level or above.

#### 4.4.3 Attestation Lifetime

Attestations have a default maximum lifetime of 24 hours (`exp - iat <= 86400`). For `critical` security level agents, implementations SHOULD issue attestations with a 4-hour lifetime or less. Expired attestations MUST be re-issued; providers SHOULD automate attestation renewal.

### 4.5 Key Hierarchy

SDAP defines a three-tier key hierarchy:

```
  Provider Root Key (HSM-backed)
  ├── Lifetime: 1–5 years
  ├── Purpose: Signs attestation JWTs; updates provider DID Document
  └── Algorithm: Ed25519

      Agent Identity Key (per-agent Ed25519)
      ├── Lifetime: 30–90 days (security-level dependent; see Section 4.5.1)
      ├── Purpose: Signs handshake messages, delegation tokens, audit entries
      └── Derived: Listed in agent's DID Document verificationMethod

          Ephemeral Session Key (X25519, per-handshake)
          ├── Lifetime: Single session (≤ 1 hour for standard; ≤ 15 minutes for high/critical)
          ├── Purpose: ECDH key agreement for session key derivation
          └── Discarded: After HKDF-SHA256 key derivation completes
```

#### 4.5.1 Key Rotation Schedule

| Security Level | Agent Identity Key Rotation | Notes |
|---------------|----------------------------|-------|
| `basic` | 365 days | Annual rotation |
| `standard` | 90 days | Quarterly rotation |
| `high` | 30 days | Monthly rotation |
| `critical` | 7 days or less | Weekly or more frequent |

Key rotation MUST be triggered immediately upon any suspected or confirmed key compromise.

#### 4.5.2 Key Rotation Protocol

1. Generate a new Ed25519 keypair (and optionally a new X25519 keypair) using a CSPRNG.
2. Add the new key(s) to the `verificationMethod` array in the agent's DID Document with a new `#key-fragment` identifier.
3. Update `authentication` (and/or `keyAgreement`) arrays to reference the new key(s).
4. Add a `revoked` timestamp to the old key entries; DO NOT remove them immediately.
5. Publish the updated DID Document to the resolution endpoint.
6. Retain the old key entries in the DID Document for a grace period of at least 24 hours.
7. After the grace period, remove the old key entries from the DID Document.
8. Emit a `key.rotated` audit entry (Section 8.2) recording both the retired and new key IDs.

Implementations MUST audit-log all key rotation events.

---

## 5. Layer 2 — Handshake and Session Establishment

### 5.1 Overview

Layer 2 provides mutual authentication and forward-secret session key establishment via a 3-message handshake. Both agents authenticate each other using Ed25519 signatures verified against their DID Documents. An ephemeral X25519 key exchange produces a session key that is derived only once and discarded afterward.

### 5.2 Handshake Message 1: HandshakeInit

The initiating agent sends `HandshakeInit` to the target agent's `SDAPHandshakeEndpoint` service URL (from the target's DID Document).

**Schema:** `spec/schemas/handshake-init.json`

**Required Fields:**

| Field | Description |
|-------|-------------|
| `type` | MUST be `"sdap/handshake/init"` |
| `version` | MUST be `"1.0"` |
| `initiatorDID` | The initiator's `did:sdap` DID |
| `targetDID` | The intended target's `did:sdap` DID |
| `nonce` | 32-byte CSPRNG nonce, base64url-encoded (no padding) |
| `timestamp` | ISO 8601 UTC timestamp |
| `ephemeralKey` | Fresh X25519 public key in JWK format (`kty: "OKP"`, `crv: "X25519"`) |
| `requestedScopes` | Array of scope strings the initiator requests |
| `requiredSecurityLevel` | Minimum acceptable security level |
| `signature` | JWS over JCS-canonicalized message (excluding `signature` field) |

**Signature construction:**

1. Construct the message object with all fields except `signature`.
2. Serialize using JCS (RFC 8785).
3. Sign the canonical bytes with the initiator's Ed25519 authentication key.
4. Produce a compact JWS with `alg: EdDSA` and `kid: <key-DID-URL>` in the header; detached payload format.

**Example:**

```json
{
  "type": "sdap/handshake/init",
  "version": "1.0",
  "initiatorDID": "did:sdap:orchestrator-corp.com:planning-agent-v1",
  "targetDID": "did:sdap:acme-health.com:records-agent-v2",
  "nonce": "dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBv",
  "timestamp": "2026-03-15T10:30:00.000Z",
  "ephemeralKey": {
    "kty": "OKP",
    "crv": "X25519",
    "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
  },
  "requestedScopes": ["medical-records:read:summary-only", "audit:read"],
  "requiredSecurityLevel": "standard",
  "signature": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpzZGFwOm9yY2hlc3RyYXRvci1jb3JwLmNvbTpwbGFubmluZy1hZ2VudC12MSNhdXRoLWtleS0xIn0..SIG"
}
```

### 5.3 Handshake Message 2: HandshakeAccept

Upon receiving a valid `HandshakeInit`, the target agent verifies it and responds with `HandshakeAccept`.

**Schema:** `spec/schemas/handshake-accept.json`

**Required Fields:**

| Field | Description |
|-------|-------------|
| `type` | MUST be `"sdap/handshake/accept"` |
| `sessionId` | UUID v4 assigned by the responder |
| `responderDID` | Responder's `did:sdap` DID (MUST match `targetDID` from init) |
| `initiatorDID` | Echoed from init message |
| `nonce` | Fresh 32-byte CSPRNG nonce, base64url-encoded (responder's nonce) |
| `initiatorNonce` | The nonce from init, echoed verbatim |
| `timestamp` | ISO 8601 UTC timestamp |
| `ephemeralKey` | Responder's fresh X25519 public key in JWK format |
| `grantedScopes` | Subset of `requestedScopes` that the responder grants |
| `sessionExpiry` | ISO 8601 UTC timestamp for session expiration |
| `signature` | JWS over JCS-canonicalized message |

**Optional Fields:**

| Field | Description |
|-------|-------------|
| `supportedLayers` | Array of integers (1–5) indicating which SDAP layers the responder supports |
| `negotiatedSecurityLevel` | The security level agreed for this session |

**Responder validation steps (MUST be performed before sending accept):**

1. Resolve the `initiatorDID` to obtain the initiator's DID Document.
2. Verify the `HandshakeInit` signature using the initiator's Ed25519 authentication key.
3. Verify that `targetDID` matches the responder's own DID.
4. Verify that `timestamp` is within 60 seconds of the current time.
5. Verify that `nonce` has not been seen within the last 60 seconds (replay protection).
6. Verify that `version` is supported.
7. Verify that `requiredSecurityLevel` can be met.
8. If a `providerAttestation` is present in the initiator's DID Document, verify it per Section 4.4.2.
9. Evaluate `requestedScopes` against local policy; determine `grantedScopes`.
10. Generate a fresh X25519 ephemeral keypair.
11. Assign a new UUID `sessionId`.
12. Sign and return `HandshakeAccept`.

**Session expiry defaults by security level:**

| Level | Default Session Duration |
|-------|------------------------|
| `basic` | 3600 seconds (1 hour) |
| `standard` | 3600 seconds (1 hour) |
| `high` | 900 seconds (15 minutes) |
| `critical` | 900 seconds (15 minutes) |

### 5.4 Handshake Message 3: HandshakeConfirm

The initiator verifies the `HandshakeAccept` and sends `HandshakeConfirm` to complete mutual authentication.

**Schema:** `spec/schemas/handshake-confirm.json`

**Required Fields:**

| Field | Description |
|-------|-------------|
| `type` | MUST be `"sdap/handshake/confirm"` |
| `sessionId` | Echoed from accept message |
| `initiatorDID` | Echoed from init/accept |
| `initiatorNonce` | The initiator's original nonce |
| `responderNonce` | The responder's nonce from the accept, echoed back |
| `timestamp` | ISO 8601 UTC timestamp |
| `sessionConfirmed` | MUST be `true` |
| `signature` | JWS over JCS-canonicalized message |

**Optional Fields:**

| Field | Description |
|-------|-------------|
| `delegationTokens` | Array of compact JWT delegation tokens presented at session start |

**Initiator validation steps (MUST be performed before sending confirm):**

1. Resolve the `responderDID` from the accept message to obtain their DID Document (or use cached document from step 1 of init flow).
2. Verify the `HandshakeAccept` signature using the responder's Ed25519 authentication key.
3. Verify `responderDID` matches the intended target.
4. Verify `initiatorNonce` echoed in the accept matches the nonce sent in init.
5. Verify `timestamp` is within 60 seconds of the current time.
6. Record `grantedScopes` and `sessionExpiry` for the established session.
7. Derive the session key (Section 5.5).
8. Sign and send `HandshakeConfirm`.

**Responder validation steps on confirm receipt:**

1. Locate the pending session by `sessionId`.
2. Verify the `HandshakeConfirm` signature using the initiator's Ed25519 authentication key.
3. Verify `initiatorNonce` matches the nonce from the init message.
4. Verify `responderNonce` matches the nonce from the accept message.
5. Verify `timestamp` is within 60 seconds of the current time.
6. Verify `sessionConfirmed` is `true`.
7. If `delegationTokens` are present, validate each per Section 7.3.
8. Mark the session as established.

### 5.5 Session Key Derivation

After the handshake completes, both agents independently derive the same session key using HKDF-SHA256.

**Key derivation:**

```
shared_secret = ECDH(initiator_ephemeral_private, responder_ephemeral_public)
              = ECDH(responder_ephemeral_private, initiator_ephemeral_public)

ikm = shared_secret                              (32 bytes, X25519 output)
salt = SHA-256(initiator_nonce_bytes || responder_nonce_bytes)   (32 bytes)
info = "sdap-session-v1" || session_id_bytes     (UTF-8 "sdap-session-v1" + 16-byte UUID)

session_key_material = HKDF-SHA256(ikm, salt, info, 64)   (64 bytes)

encrypt_key = session_key_material[0:32]          (AES-256-GCM key)
mac_key     = session_key_material[32:64]         (HMAC-SHA256 key for AAD integrity)
```

Where:
- `initiator_nonce_bytes` and `responder_nonce_bytes` are the raw (decoded from base64url) 32-byte nonces.
- `session_id_bytes` is the UUID parsed as 16 raw bytes.
- `||` denotes concatenation.

The ephemeral X25519 private keys MUST be zeroed from memory after this derivation.

### 5.6 Handshake Flow Diagram

```
Initiator                                      Responder
    │                                               │
    │─── HTTPS GET /.well-known/sdap/did/{id} ─────►│ (DID resolution)
    │◄── 200 OK (DID Document) ─────────────────────│
    │                                               │
    │  [Generate nonce_A, ephemeral keypair (eph_A)]│
    │                                               │
    │─── POST /sdap/handshake ──────────────────────►│
    │    {type: "sdap/handshake/init",              │
    │     initiatorDID, targetDID,                 │
    │     nonce: nonce_A, ephemeralKey: eph_A.pub, │
    │     requestedScopes, requiredSecurityLevel,  │
    │     signature: Sign(Ed25519_A, JCS(msg))}    │
    │                                               │
    │         [Responder: verify sig, check nonce,  │
    │          generate nonce_B, eph_B, sessionId]  │
    │                                               │
    │◄── 200 OK ─────────────────────────────────────│
    │    {type: "sdap/handshake/accept",            │
    │     sessionId, responderDID, initiatorDID,   │
    │     nonce: nonce_B, initiatorNonce: nonce_A, │
    │     ephemeralKey: eph_B.pub,                 │
    │     grantedScopes, sessionExpiry,            │
    │     signature: Sign(Ed25519_B, JCS(msg))}    │
    │                                               │
    │  [Initiator: verify sig, derive session key]  │
    │  encrypt_key, mac_key =                       │
    │    HKDF(ECDH(eph_A.priv, eph_B.pub),         │
    │         SHA256(nonce_A || nonce_B),           │
    │         "sdap-session-v1" || sessionId)       │
    │                                               │
    │─── POST /sdap/handshake ──────────────────────►│
    │    {type: "sdap/handshake/confirm",           │
    │     sessionId, initiatorDID,                 │
    │     initiatorNonce: nonce_A,                 │
    │     responderNonce: nonce_B,                 │
    │     sessionConfirmed: true,                  │
    │     delegationTokens: [...],   (optional)    │
    │     signature: Sign(Ed25519_A, JCS(msg))}    │
    │                                               │
    │         [Responder: verify sig, validate      │
    │          delegation tokens, derive session    │
    │          key identically]                     │
    │                                               │
    │         ╔══════════════════════════╗          │
    │         ║  SESSION ESTABLISHED     ║          │
    │         ╚══════════════════════════╝          │
    │                                               │
```

### 5.7 Nonce Replay Protection

Implementations MUST maintain a nonce cache per remote peer for a window of at least 60 seconds. Any nonce received in a `HandshakeInit` that was already seen from the same `initiatorDID` within this window MUST be rejected with `HANDSHAKE_REJECTED` error code and reason `nonce_invalid`.

### 5.8 Timestamp Skew Tolerance

All handshake messages include a `timestamp`. Receivers MUST reject messages where the timestamp deviates by more than 60 seconds from the receiver's local clock. Implementations SHOULD use NTP-synchronized clocks. If clock skew exceeds this threshold, the receiver MUST reject with `HANDSHAKE_REJECTED` and reason `timestamp_out_of_range`.

---

## 6. Layer 3 — Payload Security

### 6.1 Overview

Layer 3 encrypts all session payloads using AES-256-GCM wrapped in JWE compact serialization. It also defines data classification tags, selective field encryption, monotonic sequence numbers for replay and reorder protection, and chunked encryption for large payloads.

### 6.2 Session Envelopes

All messages transmitted within an established SDAP session MUST be wrapped in a `sdap/envelope`.

**Schema:** `spec/schemas/session-envelope.json`

**Required Fields:**

| Field | Description |
|-------|-------------|
| `type` | MUST be `"sdap/envelope"` |
| `version` | MUST be `"1.0"` |
| `sessionId` | UUID of the established session |
| `sequenceNumber` | Monotonically increasing integer starting at 1 |
| `timestamp` | ISO 8601 UTC timestamp |
| `senderDID` | DID of the message sender |
| `dataClassification` | Data classification tag (Section 6.4) |
| `payload` | JWE compact serialization of the encrypted content |
| `auditEntryHash` | Hash of the sender's latest audit entry at send time |

### 6.3 JWE Encryption

The `payload` field is a JWE compact serialization conforming to RFC 7516.

**Required JWE parameters:**

```
alg: ECDH-ES+A256KW
enc: A256GCM
```

**Additional Authenticated Data (AAD):**

The JWE AAD field MUST be the base64url-encoded UTF-8 encoding of the following JSON object serialized with JCS:

```json
{
  "sessionId": "<session UUID>",
  "sequenceNumber": <integer>,
  "senderDID": "<sender DID>"
}
```

This binds the ciphertext to its envelope metadata. Receivers MUST verify the AAD matches the envelope fields before accepting decrypted content.

**Encryption steps:**

1. Serialize the plaintext message using JCS (RFC 8785).
2. Construct the AAD from `sessionId`, `sequenceNumber`, and `senderDID`.
3. Encrypt using AES-256-GCM with `encrypt_key` from the session key material (Section 5.5).
4. Encode as JWE compact serialization.

**Decryption steps:**

1. Verify the `sessionId` and `sequenceNumber` in the AAD match the envelope header.
2. Verify the `senderDID` in the AAD matches the envelope `senderDID`.
3. Decrypt using `encrypt_key`.
4. Emit a `payload.decrypted` audit entry.

### 6.4 Data Classification

All session envelopes MUST declare a `dataClassification` tag. The tag appears in plaintext in the envelope header so that receivers can apply data handling policies before decryption.

| Tag | Description |
|-----|-------------|
| `public` | No access restrictions; freely shareable |
| `internal` | Internal to the provider organization |
| `confidential` | Sensitive business information; need-to-know basis |
| `PHI` | Protected Health Information under HIPAA |
| `PII` | Personally Identifiable Information |
| `restricted` | Highest sensitivity; additional controls required |

**Policy enforcement:**

- Receivers MUST verify that the session's `grantedScopes` and/or delegation tokens permit access to the declared `dataClassification` level.
- If the receiver's `sdap:minSecurityLevel` does not meet the requirements for the declared classification, the envelope MUST be rejected with `SCOPE_EXCEEDED`.
- `PHI` and `PII` data MUST NOT be transmitted in sessions below `standard` security level.
- `restricted` data REQUIRES `high` or `critical` security level.

### 6.5 Selective Field Encryption

For scenarios where routing metadata must remain visible to intermediaries while data content must be protected, SDAP supports selective field encryption. In this mode:

- Routing fields (`sessionId`, `senderDID`, `dataClassification`, `sequenceNumber`) remain in plaintext in the envelope.
- Only the `payload` field is encrypted.
- Additional fields that must be inspectable by routers (e.g., task type, priority) MAY be included in the envelope outside `payload` but MUST NOT contain sensitive data.

Implementations using selective encryption MUST document which fields are encrypted and which are plaintext. The `dataClassification` tag MUST always reflect the classification of the most sensitive field in the full message, including plaintext routing fields.

### 6.6 Sequence Numbers

Sequence numbers provide monotonic replay and reorder protection.

- The first message in a session from each sender MUST have `sequenceNumber: 1`.
- Each subsequent message from the same sender MUST increment by exactly 1.
- Sequence numbers are per-session, per-direction (initiator-to-responder has its own sequence; responder-to-initiator has a separate sequence).
- Receivers MUST reject envelopes with:
  - A `sequenceNumber` equal to or less than the last accepted number (duplicate or replay).
  - A `sequenceNumber` more than 1 greater than the last accepted number (gap, indicating dropped message).
  - An out-of-order `sequenceNumber`.
- Any sequence violation MUST trigger a `policy.violation` audit entry with `violationType: "sequence_violation"` and return `SEQUENCE_VIOLATION` error to the sender.

### 6.7 Chunked Encryption for Large Payloads

Payloads exceeding 1 MB (1,048,576 bytes) MUST be split into chunks and transmitted as multiple envelopes.

**Chunking rules:**

- Maximum chunk size: 64 KB (65,536 bytes) of plaintext.
- Each chunk is transmitted as a separate `sdap/envelope` with its own `sequenceNumber`.
- The JWE AAD for each chunk MUST include a `chunkIndex` and `totalChunks` field in addition to the standard AAD fields.
- The first chunk (`chunkIndex: 0`) MUST include a `chunkMetadata` field in its plaintext with `totalChunks` and `payloadHash` (SHA-256 of the complete reassembled plaintext).
- Receivers reassemble chunks in `sequenceNumber` order and verify the `payloadHash` after reassembly.

---

## 7. Layer 4 — Trust Delegation

### 7.1 Overview

Layer 4 enables an agent to delegate scoped authority to another agent using signed delegation tokens. Delegation tokens form chains where authority flows from a trust root downward, with scope that can only narrow (attenuate) at each step, never expand.

### 7.2 Delegation Token Format

A delegation token is a compact JWT (header.payload.signature).

**Header:**

```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "kid": "<delegator key DID URL>"
}
```

**Payload:**

**Schema:** `spec/schemas/delegation-token.json`

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | String | REQUIRED | Delegator DID |
| `sub` | String | REQUIRED | Delegatee DID |
| `aud` | String | REQUIRED | Target service DID or `"*"` |
| `iat` | Integer | REQUIRED | Issued-at (Unix epoch seconds) |
| `exp` | Integer | REQUIRED | Expiration (Unix epoch seconds) |
| `nbf` | Integer | OPTIONAL | Not-before (Unix epoch seconds) |
| `jti` | String | REQUIRED | Unique token ID (UUID v4) |
| `scopes` | Array | REQUIRED | Delegated scope strings |
| `constraints` | Object | REQUIRED | Operational constraints |
| `parentTokenId` | String/null | REQUIRED | Parent token `jti` (null for root tokens) |
| `delegationDepth` | Integer | REQUIRED | Chain depth (0 for root) |
| `delegationChainHash` | String/null | OPTIONAL | Running SHA-256 hash of ancestor chain |

**Default token lifetime:** 3600 seconds (1 hour) for `standard`; 900 seconds (15 minutes) for `high`/`critical`.

### 7.3 Constraint Object

The `constraints` object limits how delegated scopes may be used:

| Field | Type | Description |
|-------|------|-------------|
| `maxSubDelegations` | Integer | Max additional delegation depth from this token (0 = no sub-delegation) |
| `allowedProviders` | Array | Provider domains permitted to receive this delegation |
| `deniedProviders` | Array | Provider domains explicitly excluded (takes precedence over allowed) |
| `requiredSecurityLevel` | String | Minimum session security level for token use |
| `requiredComplianceTags` | Array | Compliance tags the recipient agent MUST hold |
| `geofence` | Object | Geographic constraint: `{ "allowedRegions": ["US", "EU"] }` (ISO 3166-1 alpha-2) |
| `dataClassification` | Array | Data classification levels this token permits access to |

Constraints MUST only narrow authority. A sub-delegation MUST NOT loosen any constraint present in the parent token.

### 7.4 Scope Language

Scopes follow the pattern:

```
<resource-type>:<action>[:<qualifier>]
```

Where:
- `<resource-type>` identifies the resource category (e.g., `medical-records`, `financial-data`, `audit`)
- `<action>` identifies the permitted operation (e.g., `read`, `write`, `transact`, `delegate`)
- `<qualifier>` (optional) further restricts the action (e.g., `summary-only`, `own-records`)

**Examples:**

| Scope | Meaning |
|-------|---------|
| `medical-records:read:summary-only` | Read medical records, summary view only |
| `medical-records:read` | Read medical records without restriction |
| `financial-data:transact` | Perform financial transactions |
| `audit:read` | Read audit log entries |
| `delegate:tasks` | Authority to create and delegate tasks |

Scope comparison is exact-string. `medical-records:read` does NOT imply `medical-records:read:summary-only`. Implementations SHOULD use the most specific scope that satisfies the use case.

### 7.5 Chain Validation

When validating a delegation chain, implementations MUST perform the following checks in order:

1. **Continuity check:** For each token in the chain (except the root), verify that `iss` of the current token equals `sub` of the parent token. A break in the `iss`→`sub` linkage is a chain integrity violation.

2. **Depth check:** Verify `delegationDepth` increments by exactly 1 at each step. Verify the total chain depth does not exceed the maximum allowed by the root token's `maxSubDelegations` or the overall system maximum of 5.

3. **Scope narrowing check:** For each non-root token, verify that its `scopes` is a subset of its parent token's `scopes`. Any scope present in a child that is absent from the parent is a scope attenuation violation.

4. **Constraint inheritance check:** For each non-root token, verify that its `constraints` are at least as restrictive as the parent's. Specifically:
   - `maxSubDelegations` MUST NOT exceed parent's `maxSubDelegations - 1`.
   - `requiredSecurityLevel` MUST NOT be lower than the parent's.
   - `allowedProviders` (if present in parent) MUST be a subset of the parent's.
   - `deniedProviders` MUST include all providers denied by the parent.
   - `requiredComplianceTags` MUST be a superset of the parent's.

5. **Temporal bounds check:** Verify that `iat < exp` for every token. Verify that no token's `exp` exceeds its parent token's `exp` (a child token MUST NOT outlive its parent).

6. **Signature verification:** Resolve the `iss` DID for each token and verify the JWT signature using the issuer's Ed25519 authentication key.

7. **Attestation freshness check:** If the operation's security level is `high` or `critical`, verify that a valid (non-expired) `providerAttestation` exists for each agent in the chain.

8. **Revocation check:** For each `jti`, check the revocation endpoint (Section 7.6) if available.

Any validation failure MUST result in rejection with `DELEGATION_INVALID` error.

### 7.6 Revocation

Delegation tokens rely on short lifetimes (1 hour default) as the primary revocation mechanism. For explicit pre-expiry revocation:

- Providers MAY expose a revocation endpoint at `/.well-known/sdap/revocations/{jti}`.
- The endpoint returns a 200 response with `{ "revoked": false }` for valid tokens and `{ "revoked": true, "revokedAt": "<ISO 8601>" }` for revoked tokens.
- Implementations at `high` or `critical` security level SHOULD check the revocation endpoint for every token in the delegation chain before accepting it.
- Upon revocation, agents MUST emit a `delegation.revoked` audit entry.

Revocation reasons: `security_incident`, `policy_change`, `explicit_revocation`, `provider_deactivated`.

### 7.7 Chain Hash

The `delegationChainHash` provides a running integrity check over the ancestry chain:

```
root token:      delegationChainHash = null
depth-1 token:   delegationChainHash = SHA-256(root.jti)
depth-2 token:   delegationChainHash = SHA-256(depth-1.delegationChainHash || depth-1.jti)
```

This allows partial chain verification without access to all ancestor tokens. Verifiers MUST recompute the hash from the presented chain and verify it matches the `delegationChainHash` of the deepest token.

---

## 8. Layer 5 — Audit Trail

### 8.1 Overview

Layer 5 creates a tamper-evident audit trail of every significant SDAP event. Audit entries are signed by the generating agent and chained via SHA-256 hashes. This makes it computationally infeasible to alter an entry without invalidating all subsequent entries.

### 8.2 Audit Entry Format

**Schema:** `spec/schemas/audit-entry.json`

**Required Fields:**

| Field | Description |
|-------|-------------|
| `entryId` | UUID v4 uniquely identifying this entry |
| `timestamp` | ISO 8601 UTC timestamp (MUST be monotonically non-decreasing within an agent's chain) |
| `actorDID` | DID of the agent generating this entry |
| `eventType` | Event type string (see Section 8.3) |
| `eventData` | Structured data per event type (see Section 8.3) |
| `previousHash` | SHA-256 of previous entry (null for genesis entry) |
| `entryHash` | SHA-256 of this entry's canonical form |
| `signature` | JWS over JCS-canonicalized entry |

**Optional Fields:**

| Field | Description |
|-------|-------------|
| `taskId` | A2A task ID this event is associated with |
| `sessionId` | SDAP session UUID |

**Hash computation:**

```
canonical = JCS({ <entry without "entryHash" and "signature" fields> })
entryHash = SHA-256(canonical)  (lowercase hex)
```

**Signature:**

Compute over the same canonical form used for `entryHash`:

```
signature = JWS(Ed25519_actor, canonical)  (compact, detached payload)
```

### 8.3 Event Types

| Event Type | Trigger | Required `eventData` Fields |
|------------|---------|----------------------------|
| `session.initiated` | Agent sends HandshakeInit | `initiatorDID`, `targetDID`, `requiredSecurityLevel` |
| `session.established` | HandshakeConfirm received and verified | `sessionId`, `initiatorDID`, `responderDID`, `negotiatedSecurityLevel` |
| `session.closed` | Session expires or terminates | `sessionId`, `reason` |
| `task.created` | A2A task created within session | `taskId` |
| `task.updated` | A2A task state changes | `taskId` |
| `task.completed` | A2A task completes successfully | `taskId` |
| `task.failed` | A2A task fails | `taskId`, `failureReason` |
| `payload.encrypted` | Plaintext encrypted into envelope | `sessionId`, `sequenceNumber`, `dataClassification` |
| `payload.decrypted` | Envelope decrypted | `sessionId`, `sequenceNumber`, `dataClassification` |
| `delegation.created` | Delegation token issued | `tokenId`, `delegateDID`, `scopes`, `delegationDepth` |
| `delegation.used` | Delegation token presented | `tokenId`, `operationScope`, `sessionId` |
| `delegation.revoked` | Token explicitly revoked | `tokenId`, `reason` |
| `key.rotated` | Agent key rotated | `retiredKeyId`, `newKeyId`, `keyType` |
| `policy.violation` | SDAP policy check fails | `violationType`, `description` |

Event data MUST NOT contain plaintext sensitive data (PII, PHI, financial data). Use identifiers and hashes only.

### 8.4 Audit Chain Integrity

The audit chain is a per-agent linked list:

```
Entry 1 (genesis):    previousHash = null
                      entryHash    = SHA-256(JCS(Entry1_no_hash_no_sig))

Entry 2:              previousHash = Entry1.entryHash
                      entryHash    = SHA-256(JCS(Entry2_no_hash_no_sig))

Entry N:              previousHash = Entry(N-1).entryHash
                      entryHash    = SHA-256(JCS(EntryN_no_hash_no_sig))
```

**Verification procedure:**

1. For each entry, recompute `entryHash` from the canonical form.
2. Verify the recomputed hash matches the stored `entryHash`.
3. Verify the stored `previousHash` equals the `entryHash` of the preceding entry.
4. Verify the `signature` using the `actorDID`'s Ed25519 authentication key.
5. Verify timestamps are monotonically non-decreasing.

Any discrepancy indicates tampering and MUST generate an `AUDIT_CHAIN_BROKEN` error.

### 8.5 Audit Commitments

An **audit commitment** is a lightweight proof sent from a delegatee to its delegator upon task completion, allowing the delegator to verify the delegatee's audit chain was intact at the time of the task.

**Commitment format:**

```json
{
  "taskId": "<A2A task ID>",
  "agentDID": "<delegatee DID>",
  "latestEntryHash": "<SHA-256 hex of most recent audit entry>",
  "entryCount": <integer>,
  "timestamp": "<ISO 8601>",
  "signature": "<JWS over JCS-canonicalized commitment>"
}
```

Commitments MUST be sent:
- Upon successful task completion (`task.completed`)
- Upon task failure (`task.failed`)
- Upon explicit session termination

The receiving agent MUST verify the commitment signature and record it in its own audit log as part of the `task.completed` or `task.failed` event data.

### 8.6 Optional Audit Anchor Service

For high-security deployments requiring non-repudiation guarantees beyond agent-local audit chains, SDAP supports an optional **Audit Anchor Service** analogous to Certificate Transparency.

- Agents MUST periodically submit their latest `entryHash` and entry count to the Anchor Service.
- The Anchor Service returns a signed timestamp proof.
- This proof can be used to establish that a given audit entry existed before a specific point in time, even if the agent later attempts to rewrite its history.

Implementation of the Audit Anchor Service is OPTIONAL and outside the scope of this specification.

---

## 9. A2A Integration

### 9.1 Agent Card Extension

SDAP agents SHOULD advertise their SDAP capabilities in their A2A Agent Card using the `sdap` extension field:

```json
{
  "name": "Medical Records Agent",
  "url": "https://acme-health.com/agents/records-v2/a2a",
  "sdap": {
    "did": "did:sdap:acme-health.com:records-agent-v2",
    "supportedLayers": [1, 2, 3, 4, 5],
    "minSecurityLevel": "standard",
    "handshakeEndpoint": "https://acme-health.com/agents/records-v2/sdap/handshake"
  }
}
```

The `sdap` extension field is backward-compatible; A2A agents that do not implement SDAP will ignore it.

### 9.2 A2A Message Extension Parameters

SDAP-enabled A2A messages SHOULD include the following extension parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `sdap:sessionId` | String (UUID) | The SDAP session ID under which this task is executing |
| `sdap:sequenceNumber` | Integer | The sequence number of the corresponding session envelope |
| `sdap:delegationChain` | Array | Array of compact JWT delegation tokens authorizing this task |
| `sdap:auditEntryHash` | String (hex) | Hash of the sender's latest audit entry at send time |

**Example A2A task with SDAP parameters:**

```json
{
  "id": "task-abc123",
  "message": {
    "role": "user",
    "parts": [{"type": "text", "text": "Summarize patient records for patient ID P-4821"}]
  },
  "sdap:sessionId": "550e8400-e29b-41d4-a716-446655440000",
  "sdap:sequenceNumber": 3,
  "sdap:delegationChain": ["eyJhbGciOiJFZERTQSJ9.PAYLOAD.SIG"],
  "sdap:auditEntryHash": "3f4e5d6c7b8a9f0e1d2c3b4a5e6f7d8c9b0a1e2d3c4b5a6f7e8d9c0b1a2f3e4"
}
```

### 9.3 Task Lifecycle Hooks

**Before `tasks/send`:**

1. If no SDAP session exists with the target agent, initiate the handshake (Section 5).
2. Wrap the task payload in a `sdap/envelope` per Section 6.2.
3. Include `sdap:sessionId` and `sdap:sequenceNumber` in the A2A task.
4. If delegation tokens are required, include them in `sdap:delegationChain`.

**On `tasks/get` response:**

1. Decrypt the `sdap/envelope` payload using the session `encrypt_key`.
2. Verify the `sequenceNumber` is as expected.
3. Emit a `payload.decrypted` audit entry.

**On task completion or cancellation:**

1. Emit a `task.completed` or `task.failed` audit entry.
2. If this agent is a delegatee in a delegation chain, send an audit commitment (Section 8.5) to the delegator.

---

## 10. Error Codes

All SDAP error responses MUST use the `sdap/error` message format defined in `spec/schemas/error.json`.

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `HANDSHAKE_REJECTED` | 401 | Target refused the handshake. Reasons: DID resolution failed, signature invalid, security level too low, attestation required, target DID mismatch, nonce invalid, timestamp out of range, unsupported version. |
| `ATTESTATION_INVALID` | 403 | A `providerAttestation` was malformed, expired, or had an invalid signature. Reasons: signature invalid, expired, issuer DID resolution failed, subject mismatch, missing required compliance tags. |
| `DELEGATION_INVALID` | 403 | A delegation token was malformed, expired, revoked, or failed chain validation. Reasons: signature invalid, expired, not yet valid, revoked, issuer DID resolution failed, scope attenuation violated, chain hash mismatch, depth limit exceeded, audience mismatch, geofence violated, compliance tag missing. |
| `SCOPE_EXCEEDED` | 403 | The requested operation is not covered by the session's granted scopes or delegation tokens. |
| `SEQUENCE_VIOLATION` | 400 | An envelope arrived with an unexpected sequence number (duplicate, gap, or out-of-order). |
| `SESSION_EXPIRED` | 401 | The session TTL has elapsed. A new handshake is required. |
| `ENCRYPTION_REQUIRED` | 400 | An unencrypted or improperly encrypted message was received where a JWE was expected. |
| `AUDIT_CHAIN_BROKEN` | 500 | The audit entry chain hash is inconsistent, indicating possible log tampering. |

**Error response example:**

```json
{
  "type": "sdap/error",
  "code": "HANDSHAKE_REJECTED",
  "message": "Handshake rejected: initiator DID could not be resolved",
  "sessionId": null,
  "details": {
    "reason": "did_resolution_failed",
    "initiatorDID": "did:sdap:unknown-provider.example:agent-1"
  },
  "timestamp": "2026-03-15T10:30:01.500Z"
}
```

---

## 11. Security Considerations

### 11.1 Key Compromise

If an agent's Ed25519 or X25519 private key is compromised:

1. The provider MUST immediately update the DID Document to revoke the compromised key (add `revoked` timestamp) and add a new key.
2. All active sessions signed with the compromised key MUST be terminated.
3. All delegation tokens signed with the compromised key MUST be revoked.
4. A `key.rotated` audit entry with `reason: "compromise_confirmed"` MUST be emitted.
5. Downstream delegators and delegatees MUST be notified out-of-band.

### 11.2 Replay Attacks

SDAP provides three complementary replay protections:

- **Handshake nonces:** Each handshake uses fresh nonces verified within a 60-second window.
- **Timestamps:** All messages include timestamps; receivers reject messages outside the 60-second skew window.
- **Sequence numbers:** Session envelopes use monotonic sequence numbers that reject duplicates and gaps.

### 11.3 Forward Secrecy

Ephemeral X25519 keys are generated fresh per handshake and MUST be zeroed from memory after session key derivation. This ensures that compromise of an agent's long-term keys does not expose past session contents.

### 11.4 Delegation Chain Forgery

Delegation chains are protected by:

- Ed25519 signatures at each step, requiring compromise of the signer's private key.
- The `delegationChainHash` running hash that detects chain tampering without full chain retrieval.
- Scope attenuation enforcement that prevents authority expansion.
- Short token lifetimes limiting the window of misuse.

### 11.5 Audit Log Tampering

The SHA-256 hash chain makes retroactive audit log modification computationally infeasible. An agent that alters a past entry must recompute all subsequent hashes and re-sign all subsequent entries with its Ed25519 key. The Audit Anchor Service (Section 8.6) provides an additional external reference point that makes tampering detectable even if an agent's key is later compromised.

### 11.6 DNS Trust Root

The `did:sdap` method anchors identity to DNS. Refer to `spec/did-method-sdap.md` Section 6 for a complete analysis of DNS trust root security, TLS requirements, and recommended mitigations.

### 11.7 Clock Skew and Time-Based Attacks

SDAP relies on timestamp validation at multiple points. Implementations MUST synchronize clocks via NTP. The 60-second skew window is intentionally tight; wider windows increase the replay attack surface. In adversarial environments, consider using network time security (RFC 8633).

---

## 12. Privacy Considerations

### 12.1 Audit Log Data Minimization

Audit entries MUST NOT contain plaintext sensitive data (PII, PHI, financial data, or private keys). Event data fields MUST record identifiers and hashes only. For example, a `payload.encrypted` entry records the `dataClassification` and optionally a `contentHash`, but not the plaintext content.

### 12.2 DID Document Exposure

DID Documents are publicly accessible. Refer to `spec/did-method-sdap.md` Section 7 for full privacy considerations regarding public key exposure, agent enumeration, and correlation via DID.

### 12.3 Delegation Chain Exposure

Delegation tokens include DIDs of all participants in the chain. When presenting delegation chains to third parties, consider the privacy implications of revealing all intermediate agents. In privacy-sensitive deployments, delegation chains MAY be presented only to the immediate target and withheld from other observers.

---

## 13. IANA Considerations

### 13.1 Media Types

SDAP messages use `application/json`. No new media types are registered by this specification.

### 13.2 URI Schemes

SDAP uses standard HTTPS for all endpoints. No new URI schemes are registered.

---

## 14. References

### 14.1 Normative References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", RFC 2119.
- [RFC 5869] Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869.
- [RFC 7515] Jones, M., Bradley, J., and N. Sakimura, "JSON Web Signature (JWS)", RFC 7515.
- [RFC 7516] Jones, M. and J. Hildebrand, "JSON Web Encryption (JWE)", RFC 7516.
- [RFC 7517] Jones, M., "JSON Web Key (JWK)", RFC 7517.
- [RFC 7519] Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token (JWT)", RFC 7519.
- [RFC 8037] Liusvaara, I., "CFRG Elliptic Curves for JOSE", RFC 8037.
- [RFC 8785] Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785.
- [W3C DID Core] Sporny, M. et al., "Decentralized Identifiers (DIDs) v1.0", W3C Recommendation.
- SDAP DID Method Specification — `spec/did-method-sdap.md`
- SDAP JSON Schemas — `spec/schemas/`

### 14.2 Informative References

- [RFC 3986] Berners-Lee, T., Fielding, R., and L. Masinter, "Uniform Resource Identifier (URI): Generic Syntax", RFC 3986.
- [RFC 8633] Malhotra, A. et al., "Network Time Security for the Network Time Protocol", RFC 8633.
- A2A Protocol Specification — https://google.github.io/A2A/specification/

---

## Appendix A. Security Level Compliance Matrix

| Requirement | `basic` | `standard` | `high` | `critical` |
|-------------|---------|------------|--------|------------|
| DID resolution (Layer 1) | REQUIRED | REQUIRED | REQUIRED | REQUIRED |
| Provider attestation | OPTIONAL | RECOMMENDED | REQUIRED | REQUIRED |
| Handshake (Layer 2) | REQUIRED | REQUIRED | REQUIRED | REQUIRED |
| Nonce replay protection | REQUIRED | REQUIRED | REQUIRED | REQUIRED |
| Payload encryption (Layer 3) | OPTIONAL | REQUIRED | REQUIRED | REQUIRED |
| Data classification tagging | OPTIONAL | REQUIRED | REQUIRED | REQUIRED |
| Sequence numbers | OPTIONAL | REQUIRED | REQUIRED | REQUIRED |
| Trust delegation (Layer 4) | NOT USED | NOT USED | REQUIRED | REQUIRED |
| Delegation chain depth limit (≤5) | — | — | REQUIRED | REQUIRED |
| Revocation endpoint check | — | — | REQUIRED | REQUIRED |
| Audit trail (Layer 5) | NOT USED | NOT USED | NOT USED | REQUIRED |
| Audit commitments | NOT USED | NOT USED | NOT USED | REQUIRED |
| HSM key storage | NOT REQUIRED | NOT REQUIRED | RECOMMENDED | REQUIRED |
| Re-resolve DID per session | NOT REQUIRED | NOT REQUIRED | REQUIRED | REQUIRED |
| Audit Anchor Service | NOT USED | NOT USED | OPTIONAL | RECOMMENDED |

---

## Appendix B. Key Derivation Test Vectors

The following test vectors are provided for implementation conformance testing.

**Input:**
```
initiator_ephemeral_private (hex): 77076d0a7318a57d3c16c17251b26645
                                   c6c2f6d2e8d8b6e3d7b53a5e2c7c8f9a
responder_ephemeral_public (hex):  de9edb7d7b7dc1b4d35b61c2ece43531
                                   3e4b5cfb4b25e1b5f2c1b5df8fa5e3d4
initiator_nonce (base64url):       dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBv
responder_nonce (base64url):       cmFuZG9tIG5vbmNlIGJ5dGVzIGhlcmUgeHh4
session_id (UUID):                 550e8400-e29b-41d4-a716-446655440000
```

**Intermediate values:**
```
shared_secret = X25519(initiator_ephemeral_private, responder_ephemeral_public)
salt = SHA-256(decode(initiator_nonce) || decode(responder_nonce))
info = UTF-8("sdap-session-v1") || UUID_bytes(session_id)
```

**Output:**
```
session_key_material = HKDF-SHA256(shared_secret, salt, info, 64)
encrypt_key = session_key_material[0:32]
mac_key     = session_key_material[32:64]
```

(Specific byte values omitted from this draft pending cryptographic review.)

---

## Appendix C. Scope Registry

The following scope strings are reserved by SDAP:

| Scope | Description |
|-------|-------------|
| `audit:read` | Read audit log entries |
| `audit:write` | Append audit log entries |
| `delegate:tasks` | Create and delegate tasks to sub-agents |
| `session:establish` | Establish SDAP sessions |
| `did:resolve` | Resolve DID Documents |

Provider-specific scopes SHOULD use the provider domain as a namespace prefix:
`<provider-domain>:<action>[:<qualifier>]` (e.g., `acme-health.com:medical-records:read`).
