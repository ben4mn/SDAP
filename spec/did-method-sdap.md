# DID Method Specification: `did:sdap`

**Specification Version:** 1.0
**Date:** March 2026
**Status:** Draft
**Authors:** SDAP Working Group

---

## Abstract

This document specifies the `did:sdap` DID method — the identity layer of the Secure Digital Agent Protocol (SDAP). The method defines a syntax for Decentralized Identifiers (DIDs) anchored to DNS provider domains, a resolution mechanism via HTTPS well-known endpoints, the structure of SDAP DID Documents, and the lifecycle operations (Create, Read, Update, Deactivate) for agent identities.

The `did:sdap` method is designed for AI agent ecosystems where agents must establish verifiable identity across organizational boundaries without relying on a central identity registry. Trust is rooted in DNS, which the internet already depends on, and amplified by provider attestations.

---

## 1. Introduction

### 1.1 Motivation

Multi-provider AI agent pipelines require a standardized way to answer: *Who is this agent, and can I trust what it claims?* Without a common identity standard, each provider implements ad-hoc authentication, creating a fragmented trust landscape where identity verification is either absent or dependent on bilateral agreements.

The `did:sdap` method provides:

- **Decentralized identity** — No single registry controls agent identities. Each provider manages their own agents under their DNS domain.
- **Cryptographic verifiability** — All identity claims are backed by public key cryptography (Ed25519 for signing, X25519 for key agreement).
- **Provider attestation** — Providers can attest to the security posture, compliance status, and capabilities of their agents.
- **Key rotation** — Keys can be rotated without changing the DID itself.
- **Fleet and per-instance identity** — Both patterns are supported depending on operational requirements.

### 1.2 Relationship to the W3C DID Core Specification

The `did:sdap` method conforms to the [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/) specification. DID Documents produced by this method are valid DID Core documents, extended with SDAP-specific properties in the `sdap` namespace.

### 1.3 Terminology

| Term | Definition |
|------|-----------|
| **Agent** | An AI agent instance registered under an SDAP provider |
| **Provider** | An organization operating an SDAP-compliant agent hosting infrastructure at a DNS domain |
| **Provider DID** | A `did:sdap` identifier for the provider itself (no agent-id segment) |
| **DID Document** | The JSON-LD document describing an agent's keys, services, and attestations |
| **Fleet DID** | A single DID shared by multiple instances of equivalent agents |
| **Per-instance DID** | A unique DID for each individual agent instance |
| **Provider Attestation** | A signed JWT in which a provider asserts facts about one of its agents |

---

## 2. DID Method Syntax

### 2.1 Method Name

The method name is `sdap`. All DIDs using this method begin with `did:sdap:`.

### 2.2 DID Syntax

```
did-sdap       = "did:sdap:" provider-domain ":" agent-id
provider-domain = *( unreserved / pct-encoded / sub-delims )
agent-id        = 1*( ALPHA / DIGIT / "-" / "_" / "." )
```

Where `provider-domain` is the fully-qualified DNS domain of the agent's provider, percent-encoded if necessary, and `agent-id` is an identifier for the agent that is unique within that provider's namespace.

#### 2.2.1 Provider DIDs

A provider itself may have a DID for signing attestations and provider-level operations. Provider DIDs omit the agent-id segment:

```
did-sdap-provider = "did:sdap:" provider-domain
```

**Note:** Provider DIDs without an agent-id are only valid as attestation issuers and cannot appear as `initiatorDID` or `targetDID` in session handshakes.

### 2.3 Examples

```
# Standard agent DID
did:sdap:acme-health.com:records-agent-v2

# Agent with numeric ID (e.g., auto-generated)
did:sdap:fintech-corp.io:agent-8f3a291b

# Fleet DID shared across instances
did:sdap:platform.example.com:research-fleet

# Per-instance DID with instance suffix
did:sdap:platform.example.com:research-agent-i-0a1b2c3d

# Provider DID (no agent-id)
did:sdap:acme-health.com

# Subdomain-hosted provider
did:sdap:agents.bigcloud.example:summarization-v3
```

### 2.4 Normalization

- The `provider-domain` MUST be lowercased before use in DID strings.
- The `agent-id` is case-sensitive and MUST be preserved exactly as registered.
- Percent-encoding in `provider-domain` follows RFC 3986. Dot (`.`) characters MUST NOT be encoded when they form part of the domain name structure.

---

## 3. DID Resolution

### 3.1 Resolution Endpoint

An SDAP DID is resolved via an HTTPS GET request to the well-known endpoint of the provider domain:

```
https://<provider-domain>/.well-known/sdap/did/<agent-id>
```

For provider DIDs (no agent-id):

```
https://<provider-domain>/.well-known/sdap/did
```

**Examples:**

| DID | Resolution URL |
|-----|---------------|
| `did:sdap:acme-health.com:records-agent-v2` | `https://acme-health.com/.well-known/sdap/did/records-agent-v2` |
| `did:sdap:acme-health.com` | `https://acme-health.com/.well-known/sdap/did` |
| `did:sdap:agents.bigcloud.example:summarization-v3` | `https://agents.bigcloud.example/.well-known/sdap/did/summarization-v3` |

### 3.2 Resolution Process

A resolver MUST perform the following steps:

1. **Parse** the DID to extract `provider-domain` and `agent-id` (if present).
2. **Validate** that the DID syntax is well-formed per Section 2.2.
3. **Construct** the resolution URL as specified in Section 3.1.
4. **Issue an HTTPS GET** request to the resolution URL.
   - The request MUST use TLS 1.2 or higher. TLS 1.3 is RECOMMENDED.
   - Certificate validation MUST be performed. Self-signed certificates MUST NOT be accepted.
   - The request MAY include `Accept: application/did+ld+json` and `Accept: application/json`.
5. **Handle the HTTP response:**
   - `200 OK` — Parse the response body as a DID Document (Section 4).
   - `404 Not Found` — The DID does not exist; return a `notFound` resolution error.
   - `410 Gone` — The DID has been deactivated; return the deactivated DID Document if included, otherwise a `deactivated` error.
   - `301/302/307/308` — Follow redirects up to a maximum of 3 hops, only to HTTPS URLs.
   - Other 4xx/5xx — Return a `notFound` or `internalError` resolution error as appropriate.
6. **Validate the DID Document:**
   - Confirm that the `id` field matches the resolved DID exactly.
   - Confirm that the document is not deactivated (unless resolution was for a deactivated DID).
   - Verify structural conformance with Section 4.

### 3.3 Caching

Resolvers MAY cache DID Documents subject to the following constraints:

- Use the `Cache-Control` header from the HTTP response to determine the cache TTL. If absent, default to 300 seconds (5 minutes).
- The maximum permissible cache TTL is 86400 seconds (24 hours).
- Revoked or deactivated DIDs MUST NOT be served from cache after the provider has indicated deactivation (via `410` response or `deactivated: true` in the document).
- High-security deployments (security level `high` or `critical`) SHOULD use a reduced cache TTL of 60 seconds or less.

### 3.4 Resolution Metadata

Resolvers SHOULD return resolution metadata alongside the DID Document including:

```json
{
  "contentType": "application/did+ld+json",
  "retrieved": "<ISO 8601 timestamp of resolution>",
  "cached": false,
  "error": null
}
```

---

## 4. DID Document Structure

### 4.1 Required Properties

A `did:sdap` DID Document MUST contain the following properties:

| Property | Type | Description |
|----------|------|-------------|
| `@context` | Array | JSON-LD contexts including W3C DID Core and SDAP context |
| `id` | String | The DID that this document describes |
| `controller` | String | DID of the controlling entity (typically the provider DID) |
| `verificationMethod` | Array | One or more verification methods (public keys) |
| `authentication` | Array | References to verification methods used for authentication |
| `keyAgreement` | Array | References to verification methods used for key exchange |
| `service` | Array | Service endpoints for the agent |
| `created` | String | ISO 8601 timestamp of DID Document creation |
| `updated` | String | ISO 8601 timestamp of last update |

### 4.2 Verification Methods

Each entry in `verificationMethod` MUST include:

| Property | Value |
|----------|-------|
| `id` | `<did>#<key-fragment>` (e.g., `did:sdap:example.com:agent-1#auth-key-1`) |
| `type` | `Ed25519VerificationKey2020` (auth) or `X25519KeyAgreementKey2020` (key agreement) |
| `controller` | The DID this key belongs to |
| `publicKeyMultibase` | Multibase-encoded public key |

**Authentication keys** use the `Ed25519VerificationKey2020` type and are referenced in the `authentication` array.

**Key agreement keys** use the `X25519KeyAgreementKey2020` type and are referenced in the `keyAgreement` array.

A DID Document MUST have at least one authentication key and at least one key agreement key. Key agreement keys are used for ECDH during the SDAP handshake session establishment.

### 4.3 Services

The `service` array MUST include at minimum:

#### 4.3.1 A2A Endpoint

```json
{
  "id": "<did>#a2a",
  "type": "A2AAgentEndpoint",
  "serviceEndpoint": "https://<provider>/<path>/a2a"
}
```

This is the endpoint for receiving A2A protocol tasks and messages.

#### 4.3.2 SDAP Handshake Endpoint

```json
{
  "id": "<did>#sdap-handshake",
  "type": "SDAPHandshakeEndpoint",
  "serviceEndpoint": "https://<provider>/<path>/sdap/handshake"
}
```

This is the endpoint for the SDAP mutual authentication handshake.

Additional service entries (e.g., SDAP audit log endpoint, capability advertisement endpoint) MAY be included.

### 4.4 Provider Attestation

The `providerAttestation` property is OPTIONAL but RECOMMENDED. When present, it MUST be a compact JWS string (JWT) with the following claims in the payload:

| Claim | Type | Description |
|-------|------|-------------|
| `iss` | String | Provider DID (signer of this attestation) |
| `sub` | String | Agent DID being attested |
| `iat` | Number | Issued-at time (Unix epoch) |
| `exp` | Number | Expiration time (Unix epoch) |
| `jti` | String | Unique JWT ID (UUID) |
| `sdap_attestation` | Object | SDAP-specific attestation claims (see below) |

The `sdap_attestation` object MAY include:

```json
{
  "complianceTags": ["HIPAA", "SOC2", "ISO27001"],
  "securityLevel": "high",
  "auditPolicy": "full",
  "sbomHash": "<SHA-256 hex of agent software bill of materials>",
  "certifications": [
    {
      "name": "HIPAA Business Associate",
      "issuedBy": "did:sdap:certifier.example.com",
      "validUntil": "2027-01-01T00:00:00Z"
    }
  ]
}
```

The attestation JWT MUST be signed with the provider's Ed25519 authentication key. Verifiers confirm the signature by resolving the provider DID and locating the corresponding key.

### 4.5 SDAP-Specific Extension Properties

The following SDAP extension properties MAY appear in a DID Document:

| Property | Type | Description |
|----------|------|-------------|
| `deactivated` | Boolean | `true` if this DID has been deactivated |
| `sdap:agentType` | String | Semantic type of agent (e.g., `orchestrator`, `specialist`, `tool`) |
| `sdap:fleetId` | String | Fleet identifier for fleet-DID deployments |
| `sdap:instanceId` | String | Instance identifier within a fleet |
| `sdap:supportedLayers` | Array of integers | Which SDAP layers (1–5) this agent supports |
| `sdap:minSecurityLevel` | String | Minimum required security level for sessions with this agent |

### 4.6 Complete DID Document Example

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/x25519-2020/v1",
    "https://sdap.dev/contexts/v1"
  ],
  "id": "did:sdap:acme-health.com:records-agent-v2",
  "controller": "did:sdap:acme-health.com",
  "verificationMethod": [
    {
      "id": "did:sdap:acme-health.com:records-agent-v2#auth-key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:sdap:acme-health.com:records-agent-v2",
      "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    },
    {
      "id": "did:sdap:acme-health.com:records-agent-v2#key-agreement-1",
      "type": "X25519KeyAgreementKey2020",
      "controller": "did:sdap:acme-health.com:records-agent-v2",
      "publicKeyMultibase": "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
    }
  ],
  "authentication": [
    "did:sdap:acme-health.com:records-agent-v2#auth-key-1"
  ],
  "keyAgreement": [
    "did:sdap:acme-health.com:records-agent-v2#key-agreement-1"
  ],
  "service": [
    {
      "id": "did:sdap:acme-health.com:records-agent-v2#a2a",
      "type": "A2AAgentEndpoint",
      "serviceEndpoint": "https://acme-health.com/agents/records-v2/a2a"
    },
    {
      "id": "did:sdap:acme-health.com:records-agent-v2#sdap-handshake",
      "type": "SDAPHandshakeEndpoint",
      "serviceEndpoint": "https://acme-health.com/agents/records-v2/sdap/handshake"
    }
  ],
  "providerAttestation": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "sdap:agentType": "specialist",
  "sdap:supportedLayers": [1, 2, 3, 4, 5],
  "sdap:minSecurityLevel": "standard",
  "created": "2026-01-15T09:00:00Z",
  "updated": "2026-02-20T14:30:00Z"
}
```

---

## 5. CRUD Operations

### 5.1 Create

To register a new agent DID, the provider MUST:

1. Generate an Ed25519 keypair for authentication signing.
2. Generate an X25519 keypair for key agreement.
3. Construct a DID Document conforming to Section 4, using the chosen `agent-id`.
4. Publish the DID Document at the resolution URL (Section 3.1) via HTTPS.
5. Optionally generate and embed a `providerAttestation` JWT signed by the provider's own Ed25519 key.

**Agent-ID uniqueness** is the responsibility of the provider. The provider MUST ensure that no two distinct agents share the same `agent-id` within their domain at any point in time (including deactivated agents within a recency window of 90 days).

**Key material** MUST be generated using a cryptographically secure random number generator. Private keys MUST be stored securely; for high-security deployments, HSM storage is RECOMMENDED.

There is no on-chain or registry transaction required for creation. The act of publishing the document at the well-known URL is the creation event.

### 5.2 Read

Reading (resolving) a DID is performed by any party following the resolution process in Section 3. The provider is responsible for serving accurate, current DID Documents at the resolution endpoint.

### 5.3 Update

To update a DID Document (e.g., to rotate keys, add services, update attestations):

1. Modify the DID Document contents as needed.
2. Update the `updated` timestamp to the current time.
3. Publish the updated document at the same resolution URL.
4. The `id` field MUST NOT change.

**Key rotation procedure:**
1. Generate new Ed25519 and/or X25519 keypairs.
2. Add the new key(s) to the `verificationMethod` array with a new key fragment ID.
3. Update the `authentication` and/or `keyAgreement` arrays to reference the new key(s).
4. The old key(s) SHOULD remain in `verificationMethod` with a `revoked` timestamp property for a grace period of at least 24 hours to allow in-flight sessions to complete.
5. Publish the updated document.

Parties with cached DID Documents SHOULD re-resolve after their cache TTL expires. High-security sessions SHOULD re-resolve the DID Document at the start of each new session rather than relying on cache.

### 5.4 Deactivate

To deactivate a DID (agent retirement, security incident):

1. Set `deactivated: true` in the DID Document.
2. Remove or retain (at provider's discretion) the `verificationMethod` entries.
3. Publish the updated document; alternatively, return HTTP `410 Gone`.
4. The `updated` timestamp MUST be set to the deactivation time.

**Deactivated DIDs** MUST NOT be used to initiate new sessions. Resolvers receiving a DID Document with `deactivated: true` MUST surface this to the caller.

**Hard deletion** (permanently removing the document from the well-known endpoint) is discouraged. Deactivated documents should remain available (returning `410 Gone` or the document with `deactivated: true`) so that archived audit trails referencing the DID can still be verified.

---

## 6. Security Considerations

### 6.1 DNS Trust Root

The `did:sdap` method anchors identity to DNS. This means:

- An entity that controls a DNS domain controls all `did:sdap` identities under that domain.
- DNS hijacking or domain takeover attacks can result in fraudulent DID Documents being served.

**Mitigations:**
- HTTPS with certificate validation ensures that a DNS response is backed by a valid TLS certificate issued for that domain (providing a second layer of verification beyond DNS alone).
- DNSSEC provides cryptographic protection for DNS responses. SDAP resolvers SHOULD prefer DNSSEC-validated responses and MAY require it for `high` and `critical` security levels.
- Domain-validated DID Documents should be treated as having trust level equivalent to a domain-validated TLS certificate. High-security contexts may require additional out-of-band verification.

### 6.2 TLS Requirements

All DID resolution MUST occur over HTTPS. Resolvers MUST:

- Validate the full TLS certificate chain against a trusted CA store.
- Reject self-signed certificates.
- Enforce TLS 1.2 as a minimum; TLS 1.3 is RECOMMENDED.
- Reject certificates with expired validity periods.
- Check certificate revocation via OCSP or CRL where feasible.

Failure to validate TLS certificates allows a network-level adversary to serve fraudulent DID Documents, defeating the entire identity layer.

### 6.3 Private Key Protection

- Agent private keys (Ed25519 and X25519) MUST be stored with appropriate access controls.
- For `high` and `critical` security level agents, HSM storage is STRONGLY RECOMMENDED.
- Private keys MUST NOT appear in DID Documents or be transmitted in any protocol message.
- If a private key is compromised, the provider MUST immediately deactivate the affected keys via DID Document update (Section 5.3) and notify relying parties.

### 6.4 Key Rotation

Keys SHOULD be rotated proactively on a schedule appropriate to the security level:

| Security Level | Recommended Rotation Period |
|---------------|----------------------------|
| basic | 365 days |
| standard | 90 days |
| high | 30 days |
| critical | 7 days or less |

Key rotation MUST be performed immediately upon any suspected or confirmed compromise.

### 6.5 Provider Attestation Verification

When verifying a `providerAttestation`:

1. Decode the JWT header to identify the signing key ID.
2. Resolve the provider DID (the `iss` claim) to obtain the provider's DID Document.
3. Locate the referenced key in the provider DID Document.
4. Verify the JWT signature using that key.
5. Verify that `iat` is in the past and `exp` is in the future.
6. Verify that the `sub` claim matches the agent DID being resolved.

An attestation with an expired `exp` MUST be treated as if no attestation were present. Relying parties MAY require a valid attestation for certain security levels.

### 6.6 Replay Attack Prevention

DID Documents are not themselves vulnerable to replay attacks, but the operations that use them are. Callers using DID Documents for signature verification MUST ensure that:

- Signed messages include a nonce or timestamp.
- The signed timestamp is within an acceptable skew window (SDAP default: 300 seconds).
- Nonces are not reused within a session.

### 6.7 Denial of Service via Resolution

A provider's well-known endpoint could become a target for DDoS aimed at preventing DID resolution. Providers SHOULD:

- Serve DID Documents from a CDN with appropriate cache headers.
- Implement rate limiting on the well-known endpoint.
- Use HTTP/2 or HTTP/3 to reduce connection overhead.

Resolvers SHOULD implement exponential backoff on resolution failures rather than hammering a failing endpoint.

### 6.8 Cross-Provider Identity Confusion

Agents from different providers that happen to share a similar name (e.g., `acme.com:billing-agent` and `acme.io:billing-agent`) are entirely distinct identities. Implementations MUST compare the full DID string — including the `provider-domain` segment — when performing identity checks. Partial matches MUST be treated as non-matches.

### 6.9 Agent-ID Reassignment Risk

Providers MUST NOT reuse agent-IDs for different agents within a 90-day window of deactivation. Reassigning an agent-ID could cause a resolving party to mistake a new agent's DID Document for the old agent's, potentially accepting stale cached audit trail entries or delegation tokens as applying to the new agent.

---

## 7. Privacy Considerations

### 7.1 Public Key Exposure

DID Documents are publicly accessible. The public keys, service endpoints, and attestation metadata they contain are intentionally public information. Providers SHOULD NOT include information in DID Documents that could be used to identify individual users or expose internal infrastructure details beyond what is necessary.

### 7.2 Agent Enumeration

The well-known endpoint structure (`/.well-known/sdap/did/<agent-id>`) means that an adversary can probe for agent IDs. Providers SHOULD NOT return verbose error messages distinguishing between "not found" and "forbidden" responses, to prevent enumeration.

### 7.3 Correlation via DID

A DID is a stable, globally resolvable identifier. While this is intentional for agents, providers SHOULD be aware that the use of a single DID across many interactions enables correlation of agent activity. For privacy-sensitive deployments, providers MAY issue short-lived ephemeral DIDs for specific tasks, though this adds operational complexity.

---

## 8. Conformance

An SDAP-compliant implementation MUST:

1. Support creating DID Documents that conform to the structure in Section 4.
2. Support resolution of `did:sdap` DIDs via the HTTPS well-known endpoint (Section 3).
3. Validate TLS certificates during resolution (Section 6.2).
4. Reject DID Documents where `deactivated: true` for new session initiation.
5. Support Ed25519VerificationKey2020 authentication keys.
6. Support X25519KeyAgreementKey2020 key agreement keys.
7. Implement the key rotation procedure in Section 5.3 within the recommended timelines for the deployed security level.

An SDAP-compliant implementation SHOULD:

1. Support DNSSEC-validated resolution for `high` and `critical` security levels.
2. Embed a valid `providerAttestation` in DID Documents for agents operating in regulated verticals.
3. Implement DID Document caching with appropriate TTLs per Section 3.3.
4. Use HSM-backed key storage for `high` and `critical` security level agents.

---

## 9. References

- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/) — Decentralized Identifiers specification
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) — URI Generic Syntax
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) — JSON Web Key (JWK)
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) — JSON Web Token (JWT)
- [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) — CFRG Elliptic Curves for JOSE (Ed25519, X25519)
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) — JSON Canonicalization Scheme (JCS)
- [Multibase](https://datatracker.ietf.org/doc/html/draft-multiformats-multibase) — Multibase encoding
- [Ed25519VerificationKey2020](https://w3c.github.io/vc-di-eddsa/) — Verification key type
- [X25519KeyAgreementKey2020](https://w3id.org/security/suites/x25519-2020/v1) — Key agreement key type
- SDAP Protocol Specification v1 — `spec/sdap-protocol-v1.md`
- SDAP OpenAPI Specification — `spec/openapi.yaml`
