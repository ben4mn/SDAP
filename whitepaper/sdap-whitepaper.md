# Secure Digital Agent Protocol (SDAP)
## A Trust and Security Layer for Multi-Provider AI Agent Ecosystems

**Version:** 0.1
**Date:** March 2026
**Status:** Draft for Community Review

---

## Abstract

AI agents are no longer isolated tools. They orchestrate other agents, delegate subtasks across organizational boundaries, and handle sensitive data on behalf of users who expect the same trust guarantees from an AI pipeline that they expect from a secure website. Today's agent ecosystem lacks a standard way to answer three fundamental questions: *Who is this agent? What is it allowed to do? And can we prove what happened after the fact?*

The Secure Digital Agent Protocol (SDAP) is a layered trust and security protocol designed to sit on top of existing agent communication protocols — most immediately Google's Agent-to-Agent (A2A) protocol — and provide verifiable identity, authenticated handoffs, scoped delegation, end-to-end encrypted payloads, and a tamper-evident audit trail. It is to agent communication what HTTPS is to web communication: not a replacement for the transport, but a security layer that makes the transport trustworthy enough to use in high-stakes environments.

This document describes the problem SDAP addresses, why existing protocols leave a gap, the design of the protocol itself, concrete real-world scenarios, and the open problems that the ecosystem must solve together.

---

## 1. The Problem: Fragmented Trust in Multi-Provider Agent Pipelines

### 1.1 The World We're Building Toward

The promise of agentic AI is compelling: an orchestrating agent receives a high-level goal from a user, decomposes it into subtasks, and delegates those subtasks to specialized sub-agents — some running on the same platform, many running on different platforms, built by different companies, operating under different regulatory regimes. A healthcare assistant might delegate records retrieval to a hospital EMR agent, lab interpretation to a diagnostics agent, and prescription routing to a pharmacy agent. A financial planning assistant might hand off tax strategy to a CPA-grade model, portfolio rebalancing to a brokerage agent, and compliance review to a regulated fintech service.

This is not speculative. Agent marketplaces are emerging. Delegation chains are forming. The infrastructure is being built right now.

### 1.2 The Trust Gap

The problem is that none of these cross-provider interactions have a standardized trust model. When Agent A running on Provider X delegates a task to Agent B running on Provider Y, several things are assumed but not verified:

- **Identity** — Is Agent B actually the agent it claims to be? Or is this a compromised instance, a misconfigured deployment, or a malicious impersonator?
- **Authority** — Did Agent A actually have the right to delegate this task? Who authorized the original delegation chain?
- **Scope** — Is Agent B being asked to do only what it's supposed to do, or can it escalate its own privileges mid-task?
- **Confidentiality** — Is the payload encrypted in transit, and only to the intended recipient?
- **Accountability** — If something goes wrong, can anyone reconstruct what happened, who authorized it, and what data was accessed?

Today's answer to all five questions is: *it depends on the platform, and there's no standard*. That is the trust gap SDAP is designed to close.

### 1.3 Why This Matters Now

The cost of deferring this problem grows with adoption. Every agent-to-agent integration built without a common trust layer is technical debt. Every sensitive operation performed by an unverified agent is a liability. And when the first high-profile breach of an agentic pipeline occurs — a medical agent leaking records, a financial agent executing unauthorized transactions — the damage will not just be to the affected organization. It will set back ecosystem trust broadly.

The window to establish a common standard before fragmentation calcifies is now.

---

## 2. Why Existing Protocols Don't Solve It

Before describing what SDAP does, it's important to be precise about what the existing protocols do and do not do. SDAP is not a competitor to A2A or MCP — it is a complement.

### 2.1 MCP (Model Context Protocol)

Anthropic's Model Context Protocol is a standard for connecting AI models to tools, data sources, and external services. It answers the question: *How does a model reach out to access a resource?* MCP is primarily a client-server protocol between a model and a tool provider. It handles tool discovery, invocation, and structured result return.

MCP does not address agent-to-agent delegation, inter-agent identity verification, or the trust relationships that arise when an agent operates on behalf of another agent on behalf of a user. It is a powerful protocol for its intended purpose; that purpose simply doesn't include the trust layer SDAP provides.

### 2.2 A2A (Agent-to-Agent Protocol)

Google's A2A protocol handles agent discovery and task delegation. An orchestrating agent can discover a sub-agent's capabilities via its Agent Card, send it tasks, and receive results. A2A is the most direct foundation for multi-provider agent pipelines and is the primary transport SDAP is designed to sit on top of.

What A2A does not specify: how to verify that the agent presenting an Agent Card is actually who it claims to be, how to ensure the delegating agent had the authority to delegate, how to encrypt the payload so that only the intended recipient can read it, or how to create a tamper-evident log of what happened. A2A gives agents a way to talk to each other. SDAP gives them a reason to trust what they hear.

### 2.3 The Stack

The right mental model is layered responsibility:

```
MCP   — Tools and data access
A2A   — Agent discovery and task delegation
SDAP  — Trust, security, and accountability
```

SDAP does not replace either protocol. It extends the A2A transport with a security envelope, and its identity model is compatible with MCP server discovery patterns. The three protocols together form a complete foundation for production-grade multi-provider agent systems.

---

## 3. SDAP's Approach: Layered Trust

SDAP is designed as a five-layer stack, where each layer builds on the one below it and can be adopted independently. An organization that needs only verified identity but is not yet ready to adopt the full audit trail can implement Layers 1 and 2 without the rest. A high-security healthcare deployment might require all five.

```
┌─────────────────────────────────────────────────────────┐
│  Layer 5: AUDIT TRAIL                                   │
│  Merkle-chained cryptographic event log                 │
├─────────────────────────────────────────────────────────┤
│  Layer 4: TRUST DELEGATION                              │
│  Delegation tokens, scope constraints, chain validation │
├─────────────────────────────────────────────────────────┤
│  Layer 3: PAYLOAD SECURITY                              │
│  JWE encryption, forward secrecy, key exchange         │
├─────────────────────────────────────────────────────────┤
│  Layer 2: SESSION (Handshake)                           │
│  Mutual authentication, capability negotiation          │
├─────────────────────────────────────────────────────────┤
│  Layer 1: IDENTITY                                      │
│  DIDs, provider attestations, key management           │
├─────────────────────────────────────────────────────────┤
│  Transport: A2A JSON-RPC over HTTPS                     │
└─────────────────────────────────────────────────────────┘
```

This layered design is intentional. Trust adoption in distributed systems is never all-or-nothing. Requiring full compliance on day one would prevent adoption. Progressive adoption, with each layer providing independent value, is how standards actually spread.

---

## 4. Core Concepts

### 4.1 Verified Agent Identity (Layer 1)

Every agent in an SDAP-compliant system has a Decentralized Identifier (DID) in the form:

```
did:sdap:<provider-domain>:<agent-id>
```

For example: `did:sdap:acme-health.com:records-agent-v2`

This DID is resolvable. When an agent presents this identifier, any party can fetch its DID document from a well-known HTTPS endpoint at the provider domain:

```
https://acme-health.com/.well-known/sdap/did/<agent-id>
```

The DID document contains the agent's public keys, its declared capabilities, any provider attestations, and the agent's software bill of materials (SBOM) hash. Provider attestations are signed statements from the provider asserting that a given agent instance has been audited, certified, or granted specific trust levels.

**Why DIDs, not centralized identity?** A central identity registry creates a single point of failure and a governance bottleneck. DNS-rooted DIDs allow each provider to manage their own agent identities while enabling any other party to resolve and verify them without depending on a third party. This is the same reason the web doesn't have a central certificate authority for domain names — DNS itself serves as the trust root.

**Key management** uses Ed25519 for signing (fast, compact, well-analyzed) and X25519 for key agreement. Keys can be rotated; the DID document includes version history. For high-security deployments, Hardware Security Module (HSM) backing is supported.

**Fleet vs. per-instance identities** are both supported. A provider running 1,000 instances of the same agent may give them all the same fleet DID (simpler key management) or unique per-instance DIDs (stronger non-repudiation). The protocol accommodates both patterns.

### 4.2 Secure Handshake and Session Establishment (Layer 2)

Before any sensitive data is exchanged, two SDAP agents perform a mutual authentication handshake:

1. **Hello**: The initiating agent presents its DID and a signed nonce.
2. **Resolution**: The receiving agent resolves the DID, verifies the signature, and presents its own DID and signed nonce.
3. **Verification**: Both agents verify each other. Neither proceeds without confirming the other's identity.
4. **Capability Negotiation**: Agents declare which SDAP features they support (which layers, which cipher suites, whether they require delegation tokens).
5. **Session Establishment**: A shared session key is derived using X25519 key agreement and HKDF-SHA256. This session key is used only for this session and is never transmitted.

This handshake provides mutual authentication — both parties verify each other, not just one way — and establishes forward secrecy. Compromise of a long-term key does not compromise past sessions.

Session state can be cached to amortize handshake cost. For low-sensitivity interactions, a "lightweight mode" allows agents with prior established trust to skip re-verification within a configurable TTL.

### 4.3 Payload Security (Layer 3)

All SDAP message payloads are encrypted using JSON Web Encryption (JWE) with AES-256-GCM. The session key established in Layer 2 is used as the encryption key.

Beyond confidentiality, payloads include:
- A content hash for integrity verification
- The sender's DID and a signature over the payload using Ed25519
- Timestamps and sequence numbers to prevent replay attacks

Canonicalization uses JCS (JSON Canonicalization Scheme, RFC 8785) before signing, ensuring that signature verification is deterministic regardless of JSON serialization differences between implementations.

### 4.4 Trust Delegation (Layer 4)

Delegation is where SDAP's design becomes most distinctive. When an orchestrating agent delegates a task to a sub-agent, it issues a delegation token — a signed, scoped, time-bounded credential that:

- Identifies the delegating agent (issuer)
- Identifies the receiving agent (subject)
- Specifies exactly which scopes (permissions) are delegated
- Specifies a maximum delegation depth (preventing unbounded chains)
- Includes an expiration time
- Is signed by the delegating agent's private key

**Scopes** are the vocabulary of permission. SDAP defines approximately 25 core scopes covering common agent operations:

| Category | Example Scopes |
|----------|---------------|
| Data access | `read:medical_records`, `read:financial_data`, `read:pii` |
| Data modification | `write:calendar`, `write:email` |
| Financial | `transact:payment`, `transact:trade` |
| Communication | `send:sms`, `send:email` |
| System | `execute:code`, `access:filesystem` |
| Meta | `delegate:tasks`, `audit:read` |

Providers can define namespaced custom scopes (e.g., `acme-health:read:imaging_data`) for domain-specific operations not covered by core scopes.

**Delegation chains** are explicitly validated. When Agent C receives a delegation from Agent B, which received authority from Agent A, the chain is: `User → A → B → C`. SDAP verifies that every link in this chain is valid — every token is properly signed, no token delegates more scope than its issuer held, and no token has expired. A token that tries to delegate a scope its issuer doesn't hold is cryptographically invalid.

**Scope attenuation** is enforced: scope can only be narrowed as it travels down a delegation chain, never expanded. An agent that received `read:medical_records` cannot delegate `write:medical_records`.

### 4.5 Audit Trail (Layer 5)

Every significant SDAP event — agent authentication, task delegation, payload exchange, scope usage, session termination — is recorded in an append-only, Merkle-chained log. Each event entry:

- Contains a timestamp, event type, involved DIDs, and a summary of the operation
- Is signed by the agent that generated it
- Includes the cryptographic hash of the previous entry (forming the chain)

This structure means that any tampering with a past entry invalidates all subsequent entries, providing tamper evidence. A verifier can confirm the integrity of an audit trail by checking chain continuity and signatures without having to trust the party that stored the log.

**What the audit trail doesn't do** is provide cryptographic proof that it is *complete*. An agent could, in principle, simply not generate audit entries for some operations. SDAP addresses this through two mechanisms: provider attestations that commit to audit policy compliance, and contractual enforcement through ecosystem participation agreements. Full cryptographic audit completeness is noted as an open problem (see Section 7).

---

## 5. Real-World Scenarios

### 5.1 Medical Records Handoff

**Context:** A patient's primary care AI assistant needs to retrieve imaging records from a hospital's radiology system and forward them to a specialist AI for interpretation.

**The flow without SDAP:**
The orchestrating agent sends a request to the radiology agent. The radiology agent has no way to verify who is asking or whether they're authorized. It might check an API key, but API keys don't encode *why* the request is being made or *on whose behalf*. The data is returned, potentially in plaintext, and there's no record of what was delegated or to whom.

**The flow with SDAP:**
1. The primary care agent resolves the radiology agent's DID, verifies its attestations (including HIPAA compliance certification from the hospital), and performs a mutual handshake.
2. The primary care agent presents a delegation token from the patient's consent management system, scoped to `read:imaging_data` and `read:radiology_reports`, valid for 30 minutes, with a delegation depth of 1.
3. The radiology agent verifies the delegation chain, confirms scope coverage, and returns the records in a JWE-encrypted payload.
4. The primary care agent issues a new, more narrowly scoped delegation token (`read:radiology_reports`, depth 0) to the specialist agent.
5. Every step is logged to each agent's audit trail with signed entries.

The patient, the hospital's compliance team, and the regulatory auditor can all independently verify exactly what data was accessed, when, by whom, and under what authority — from a tamper-evident log.

### 5.2 Financial Task Delegation

**Context:** A financial planning AI assistant is helping a user rebalance their portfolio. The orchestrating agent needs to delegate a specific trade execution to a brokerage agent, while a separate compliance agent reviews the trade before it goes through.

**The challenge:** The user authorized the financial assistant to *plan* the portfolio, not to execute trades unilaterally. The brokerage has strict requirements about authorization chains before accepting trade instructions from any AI agent.

**The flow with SDAP:**
1. The orchestrating agent holds a delegation token from the user's financial management app with scopes `read:portfolio`, `plan:rebalancing`, and `propose:trade`. Critically, it does not hold `transact:trade`.
2. When the agent proposes a trade to the user, the user approves. The approval generates a time-limited, amount-limited delegation token adding `transact:trade` (bounded to a specific ticker, quantity, and price range) to the agent's authority.
3. The orchestrating agent creates a sub-delegation to the brokerage agent, including all relevant tokens in the chain. The brokerage agent validates the full chain before accepting the instruction.
4. The compliance agent is sent a read-only copy of the delegation chain (`audit:read` scope) and signs off.
5. The trade executes. The audit trail records the user approval token, the delegation chain, the compliance sign-off, and the execution event.

If the brokerage is ever audited, it can produce a cryptographically verifiable record of the exact authorization chain for every AI-executed trade.

---

## 6. Protocol Design Principles

Several principles guided SDAP's design decisions and are worth making explicit.

**Cryptographic agility, opinionated defaults.** SDAP specifies default algorithms (Ed25519, X25519, AES-256-GCM) but structures key fields to support algorithm migration. This matters for quantum readiness — see Section 7. The protocol is not locked to today's cryptography.

**Independent layer adoption.** A protocol that requires full adoption before providing any value will not be adopted. Each SDAP layer provides independent value. An organization can implement just Layer 1 (verified identity) and be better off than before, without committing to the full stack.

**No new trust roots.** SDAP does not require a new global certificate authority or a new blockchain. Trust is bootstrapped from DNS, which the internet already depends on. This dramatically reduces the coordination burden for adoption.

**Privacy by design.** DID documents are public, but the data exchanged between agents is encrypted and scoped. The protocol is designed so that audit trails can record *what type* of operation occurred and *which agents* were involved without recording the sensitive *content* of the operation, subject to the parties' policies.

**Fail closed.** When verification fails at any layer, the protocol requires that the operation not proceed. A sub-agent that cannot verify a delegation chain must reject the request, not fall back to unverified operation.

---

## 7. Open Problems

SDAP v0.1 does not claim to solve every trust problem in multi-provider agent systems. The following are known open problems that the protocol acknowledges, with the current approach and the path to better solutions.

### 7.1 Provider Trust Bootstrapping

**The problem:** SDAP's identity layer is rooted in DNS. An agent at `acme-health.com` is trusted because DNS says that domain resolves to Acme Health. But DNS can be hijacked, and a domain registration doesn't verify that a company is legitimate, compliant, or has good security practices.

**Current approach (v1):** DNS-based trust, with provider attestations signed by the provider itself. This is equivalent to a self-signed certificate — it proves consistency, not legitimacy.

**Path forward:** An optional curated registry for high-security verticals (healthcare, finance, critical infrastructure) where providers undergo vetting before listing. This registry is not required for SDAP to function — it's an optional trust amplifier for contexts that need it. The model is similar to Extended Validation certificates for the web: the base protocol doesn't require it, but regulated industries can mandate it.

### 7.2 Fleet vs. Per-Instance Identity

**The problem:** Providers running large fleets of agent instances face a tension: per-instance DIDs provide the strongest non-repudiation (you can identify exactly which instance did what) but create key management complexity at scale. Fleet DIDs are operationally simpler but reduce traceability.

**Current approach:** Both patterns are supported. The DID document can include a fleet identifier alongside an instance identifier. The protocol does not mandate which pattern to use.

**Open question:** Should certain regulated operations require per-instance DIDs? This is a policy question, not a protocol question, but the protocol should make the policy expressible.

### 7.3 Scope Vocabulary Interoperability

**The problem:** If one provider's `read:medical_records` scope means something different from another provider's `read:medical_records` scope, the delegation system breaks down. Scope tokens are only meaningful if their semantics are shared.

**Current approach:** SDAP defines a core vocabulary of approximately 25 well-specified scopes. Custom scopes must be namespaced to prevent collisions. An agent receiving a scope it doesn't recognize must not grant it implicit permissions.

**Path forward:** Domain-specific scope registries, maintained by industry bodies (healthcare, finance, legal), that define authoritative scope semantics for their verticals. This is the same pattern that solved namespace conflicts in XML — the base standard defines the mechanism; industry bodies define the vocabulary.

### 7.4 Audit Completeness

**The problem:** An audit trail is only useful if it's complete. SDAP can verify that an audit trail hasn't been tampered with, but it cannot cryptographically prove that every operation generated an audit entry.

**Current approach:** Provider attestations include audit policy commitments. Ecosystem participation agreements create contractual obligations to maintain complete audit logs. Compliance auditors can spot-check log completeness against other observable signals.

**Path forward:** Trusted Execution Environment (TEE) integration, where agent operations are executed inside hardware enclaves that can produce cryptographically attested logs. This is technically achievable today on platforms supporting Intel TDX or AMD SEV-SNP, but mandating it would exclude a large portion of the ecosystem. It remains an opt-in security upgrade.

### 7.5 Handshake Latency

**The problem:** A full SDAP handshake involves DID resolution (an HTTPS round-trip), signature verification (fast, but not free), and key agreement. For high-frequency, low-sensitivity agent interactions, this overhead may be unacceptable.

**Current approach:** Session caching allows a completed handshake to be reused within a configurable TTL. DID document caching (with appropriate TTL from the DID endpoint) reduces resolution overhead. A "lightweight mode" allows agents with prior established trust to fast-path repeated interactions.

**Open question:** What is the right TTL for DID caching? Short TTLs reduce the window for using a revoked DID but increase resolution load. The protocol does not currently mandate a specific value.

### 7.6 Geofence Enforcement

**The problem:** Data residency requirements (GDPR, HIPAA, CCPA) often require that certain data not leave specific geographic jurisdictions. An SDAP delegation token can *assert* a geofence constraint, but the protocol has no way to technically enforce where a receiving agent is physically located.

**Current approach:** Geofence constraints are expressed in delegation tokens as attestation requirements. A delegating agent can require that the receiving agent hold a current attestation asserting that it operates within a specified region. This is a contractual and reputational enforcement mechanism, not a technical one.

**Path forward:** This is fundamentally a hard problem. Physical location cannot be cryptographically proven from within a networked system. The realistic path is cloud provider attestations (similar to how cloud providers today attest to data residency for regulated workloads) combined with contractual SLAs. SDAP provides the mechanism to express these constraints; enforcement depends on the ecosystem of attestation providers.

### 7.7 Quantum Readiness

**The problem:** Ed25519 and X25519 are vulnerable to Cryptographically Relevant Quantum Computers (CRQCs). While CRQCs capable of breaking these algorithms are not imminent, long-lived audit trails created today may need to remain verifiable past the point at which quantum attacks become feasible.

**Current approach:** SDAP key fields are structured with an explicit algorithm identifier alongside the key material. This enables algorithm migration without protocol version changes.

**Migration path:** NIST has standardized post-quantum algorithms: ML-DSA (CRYSTALS-Dilithium) for signatures, ML-KEM (CRYSTALS-Kyber) for key encapsulation. SDAP will specify these as supported alternatives in v0.2. Hybrid schemes (classical + post-quantum) allow gradual migration. The "harvest now, decrypt later" threat is most acute for encrypted payloads; the protocol prioritizes forward secrecy (Layer 3) to minimize this exposure.

---

## 8. Getting Started: Progressive Adoption

SDAP is designed to be adopted incrementally. The following adoption path allows organizations to begin capturing value immediately while building toward full compliance.

**Phase 1 — Identity and Verification (Layers 1–2)**
Publish DID documents for your agents. Implement DID resolution and signature verification in your agent runtime. Begin verifying the identity of agents you interact with before accepting their requests. This phase requires no changes to your business logic — only your agent communication layer.

**Phase 2 — Encrypted Payloads (Layer 3)**
Add JWE encryption to outbound payloads and decryption to inbound handlers. This is often the highest-priority step for regulated industries handling sensitive data.

**Phase 3 — Scoped Delegation (Layer 4)**
Implement delegation token issuance and validation. Begin expressing explicit scope constraints on cross-agent task delegation. This phase requires coordination with downstream agents — they must be capable of validating the tokens you issue.

**Phase 4 — Audit Trail (Layer 5)**
Enable audit logging for SDAP events. Commit to an audit retention policy and include it in your provider attestations. Begin consuming audit trails for compliance reporting.

Reference implementations are available in Python (`sdap-python`) and TypeScript (`sdap-typescript`). Both implement the full five-layer stack and are designed to work with A2A-compatible agent runtimes.

---

## 9. Call to Action

The infrastructure for a multi-provider AI agent ecosystem is being built right now. The choices made in the next 12 to 24 months will determine whether that ecosystem has a coherent trust model or a patchwork of incompatible, provider-specific security schemes.

SDAP is a proposal, not a mandate. We are actively seeking:

**Implementers** — Developers and platform teams who want to implement SDAP in their agent runtimes. The reference implementations are open source. Feedback from implementation experience will shape the v0.2 specification.

**Domain experts** — Healthcare, financial services, legal, and other regulated-industry practitioners who can drive the development of domain-specific scope vocabularies and attestation standards that the base protocol cannot fully specify.

**Protocol designers** — Researchers and protocol designers who can pressure-test the cryptographic design, identify edge cases in the delegation model, and contribute to the open problems outlined in Section 7.

**Platform integrators** — Teams building on top of A2A, MCP, or other agent protocols who can contribute interoperability experience and help ensure SDAP works in real-world multi-platform deployments.

The specification, reference implementations, and discussion forums are available in the SDAP repository. The v0.1 specification is open for community review. We welcome pull requests, issues, and design discussions.

Trust is not a feature you add to a protocol after the fact. It has to be designed in. SDAP is an invitation to do that design together, before the ecosystem fragments too far to course-correct.

---

## Appendix A: Cryptographic Primitives Summary

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Digital signatures | Ed25519 | Compact, fast, well-analyzed |
| Key agreement | X25519 | Elliptic-curve Diffie-Hellman |
| Key derivation | HKDF-SHA256 | From shared secret to session keys |
| Symmetric encryption | AES-256-GCM | Authenticated encryption |
| Hashing | SHA-256 | Audit chain, integrity checks |
| JSON canonicalization | JCS / RFC 8785 | Deterministic signing |
| Post-quantum (roadmap) | ML-DSA, ML-KEM | NIST standards, v0.2 target |

---

## Appendix B: DID Document Structure (Illustrative)

```json
{
  "id": "did:sdap:acme-health.com:records-agent-v2",
  "version": "1",
  "created": "2026-01-15T00:00:00Z",
  "updated": "2026-03-01T00:00:00Z",
  "verificationMethod": [{
    "id": "did:sdap:acme-health.com:records-agent-v2#key-1",
    "type": "Ed25519VerificationKey2020",
    "algorithm": "Ed25519",
    "publicKeyMultibase": "z6Mk..."
  }],
  "keyAgreement": [{
    "id": "did:sdap:acme-health.com:records-agent-v2#key-agreement-1",
    "type": "X25519KeyAgreementKey2020",
    "algorithm": "X25519",
    "publicKeyMultibase": "z6LS..."
  }],
  "capabilities": ["sdap/layer1", "sdap/layer2", "sdap/layer3", "sdap/layer4", "sdap/layer5"],
  "sdapVersion": "0.1",
  "attestations": [{
    "type": "HIPAACompliance",
    "issuer": "did:sdap:acme-health.com:compliance-authority",
    "issued": "2026-01-15T00:00:00Z",
    "expires": "2027-01-15T00:00:00Z",
    "signature": "eyJ..."
  }],
  "sbomHash": "sha256:a3f..."
}
```

---

## Appendix C: Delegation Token Structure (Illustrative)

```json
{
  "id": "urn:sdap:delegation:7f3a9c12-4b8e-4d2f-a1b3-9e8c7d6f5e4d",
  "version": "0.1",
  "issuer": "did:sdap:orchestrator.ai:planning-agent",
  "subject": "did:sdap:acme-health.com:records-agent-v2",
  "issuedAt": "2026-03-15T14:30:00Z",
  "expiresAt": "2026-03-15T15:00:00Z",
  "scopes": ["read:medical_records", "read:radiology_reports"],
  "maxDelegationDepth": 1,
  "parentDelegation": "urn:sdap:delegation:2a1b3c4d-...",
  "constraints": {
    "patientId": "sha256:b4f...",
    "geofence": "US"
  },
  "signature": {
    "algorithm": "Ed25519",
    "keyId": "did:sdap:orchestrator.ai:planning-agent#key-1",
    "value": "eyJ..."
  }
}
```

---

*SDAP v0.1 — March 2026. This document is released for community review. All cryptographic designs should be reviewed by qualified security engineers before production deployment.*
