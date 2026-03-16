/**
 * Generate cross-language interop test vectors using the TypeScript SDAP SDK.
 *
 * Run from the sdap-typescript directory:
 *   npx tsx ../tests/interop/generate_vectors_typescript.ts
 *
 * Or from the repository root:
 *   cd sdap-typescript && npx tsx ../tests/interop/generate_vectors_typescript.ts
 *
 * Writes tests/interop/vectors_typescript.json.
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519";

// Resolve paths relative to this script file
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Import SDK modules using relative paths from sdap-typescript/src
import { canonicalize } from "../../sdap-typescript/src/crypto/canonicalize.js";
import { sha256Hex } from "../../sdap-typescript/src/crypto/hashing.js";
import { signJws, signDetached } from "../../sdap-typescript/src/crypto/signing.js";
import { deriveSessionKeys } from "../../sdap-typescript/src/crypto/keyExchange.js";
import { createAttestation } from "../../sdap-typescript/src/identity/attestation.js";
import { createDelegationToken } from "../../sdap-typescript/src/delegation/tokens.js";
import { createAuditEntry } from "../../sdap-typescript/src/audit/entries.js";

// ---------------------------------------------------------------------------
// Fixed test inputs (shared with Python generator)
// ---------------------------------------------------------------------------

const FIXED_PRIVATE_KEY_HEX =
  "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b";

const TEST_OBJECT = { name: "Alice", age: 30, active: true, scores: [100, 95, 88] };
const TEST_PAYLOAD = "Hello, SDAP!";

const HKDF_INPUTS = {
  shared_secret_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  nonce_a_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  nonce_b_hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  session_id: "test-session-001",
};

const ATTESTATION_INPUTS = {
  issuer_did: "did:sdap:example.com",
  subject_did: "did:sdap:example.com:test-agent",
  agent_type: "specialist",
  capabilities: ["read:data"],
  security_level: "standard",
  compliance_tags: ["SOC2"],
  max_delegation_depth: 3,
};

const DELEGATION_INPUTS = {
  issuer_did: "did:sdap:example.com:agent-a",
  delegatee_did: "did:sdap:example.com:agent-b",
  audience_did: "did:sdap:example.com:agent-c",
  scopes: ["data:read", "audit:read"],
};

async function main(): Promise<void> {
  // ------------------------------------------------------------------
  // 1. Ed25519 keypair from fixed seed
  // ------------------------------------------------------------------
  const privateKeyBytes = Buffer.from(FIXED_PRIVATE_KEY_HEX, "hex");
  const privateKey = new Uint8Array(privateKeyBytes);
  const publicKey = ed25519.getPublicKey(privateKey);

  const privateKeyHex = Buffer.from(privateKey).toString("hex");
  const publicKeyHex = Buffer.from(publicKey).toString("hex");

  const KEY_ID = "interop-test-key-1";

  // ------------------------------------------------------------------
  // 2. JCS canonicalization
  // ------------------------------------------------------------------
  const canonicalBytes = canonicalize(TEST_OBJECT as Record<string, unknown>);
  const canonicalHex = Buffer.from(canonicalBytes).toString("hex");
  const canonicalUtf8 = new TextDecoder().decode(canonicalBytes);

  // ------------------------------------------------------------------
  // 3. SHA-256 of canonical bytes
  // ------------------------------------------------------------------
  const sha256OfCanonical = sha256Hex(canonicalBytes);

  // ------------------------------------------------------------------
  // 4. JWS signing
  // ------------------------------------------------------------------
  const jwsToken = await signJws(
    new TextEncoder().encode(TEST_PAYLOAD),
    privateKey,
    KEY_ID
  );

  // ------------------------------------------------------------------
  // 5. Detached JWS
  // ------------------------------------------------------------------
  const detachedJws = await signDetached(canonicalBytes, privateKey, KEY_ID);

  // ------------------------------------------------------------------
  // 6. HKDF key derivation
  // ------------------------------------------------------------------
  const sharedSecret = new Uint8Array(Buffer.from(HKDF_INPUTS.shared_secret_hex, "hex"));
  const nonceA = new Uint8Array(Buffer.from(HKDF_INPUTS.nonce_a_hex, "hex"));
  const nonceB = new Uint8Array(Buffer.from(HKDF_INPUTS.nonce_b_hex, "hex"));

  const { encryptKey, macKey } = deriveSessionKeys(
    sharedSecret,
    nonceA,
    nonceB,
    HKDF_INPUTS.session_id
  );
  const encryptKeyHex = Buffer.from(encryptKey).toString("hex");
  const macKeyHex = Buffer.from(macKey).toString("hex");

  // ------------------------------------------------------------------
  // 7. Attestation JWT (10 year TTL so it never expires in tests)
  // ------------------------------------------------------------------
  const attestationJwt = await createAttestation({
    issuerDid: ATTESTATION_INPUTS.issuer_did,
    subjectDid: ATTESTATION_INPUTS.subject_did,
    privateKey,
    agentType: ATTESTATION_INPUTS.agent_type,
    capabilities: ATTESTATION_INPUTS.capabilities,
    securityLevel: ATTESTATION_INPUTS.security_level,
    complianceTags: ATTESTATION_INPUTS.compliance_tags,
    maxDelegationDepth: ATTESTATION_INPUTS.max_delegation_depth,
    ttlSeconds: 86400 * 365 * 10,
  });

  // ------------------------------------------------------------------
  // 8. Delegation token JWT
  // ------------------------------------------------------------------
  const delegationJwt = await createDelegationToken({
    issuerDid: DELEGATION_INPUTS.issuer_did,
    delegateeDid: DELEGATION_INPUTS.delegatee_did,
    audienceDid: DELEGATION_INPUTS.audience_did,
    privateKey,
    scopes: DELEGATION_INPUTS.scopes,
    constraints: {},
    ttlSeconds: 86400 * 365 * 10,
  });

  // ------------------------------------------------------------------
  // 9. Audit entry
  // ------------------------------------------------------------------
  const auditEntry = await createAuditEntry({
    actorDid: "did:sdap:example.com:auditor",
    eventType: "interop.test",
    eventData: { message: "cross-language test" },
    privateKey,
    keyId: KEY_ID,
  });

  // ------------------------------------------------------------------
  // Assemble vectors
  // ------------------------------------------------------------------
  const vectors = {
    generator: "typescript",
    key: {
      private_key_hex: privateKeyHex,
      public_key_hex: publicKeyHex,
      key_id: KEY_ID,
    },
    canonicalization: {
      input: TEST_OBJECT,
      canonical_hex: canonicalHex,
      canonical_utf8: canonicalUtf8,
    },
    sha256: {
      input_hex: canonicalHex,
      hash_hex: sha256OfCanonical,
    },
    jws: {
      payload_utf8: TEST_PAYLOAD,
      token: jwsToken,
    },
    detached_jws: {
      payload_hex: canonicalHex,
      token: detachedJws,
    },
    hkdf: {
      inputs: HKDF_INPUTS,
      encrypt_key_hex: encryptKeyHex,
      mac_key_hex: macKeyHex,
    },
    attestation: {
      inputs: ATTESTATION_INPUTS,
      jwt: attestationJwt,
    },
    delegation: {
      inputs: DELEGATION_INPUTS,
      jwt: delegationJwt,
    },
    audit_entry: auditEntry,
  };

  const outPath = join(__dirname, "vectors_typescript.json");
  writeFileSync(outPath, JSON.stringify(vectors, null, 2));
  console.log(`Wrote ${outPath}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
