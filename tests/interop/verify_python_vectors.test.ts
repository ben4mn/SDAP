/**
 * Vitest test: verify Python-generated interop vectors using the TypeScript SDK.
 *
 * Run from sdap-typescript:
 *   npx vitest run ../tests/interop/verify_python_vectors.test.ts
 */

import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyJws, verifyDetached } from "../../sdap-typescript/src/crypto/signing.js";
import { canonicalize } from "../../sdap-typescript/src/crypto/canonicalize.js";
import { sha256Hex } from "../../sdap-typescript/src/crypto/hashing.js";
import { deriveSessionKeys } from "../../sdap-typescript/src/crypto/keyExchange.js";
import { verifyAttestation } from "../../sdap-typescript/src/identity/attestation.js";
import { decodeDelegationToken } from "../../sdap-typescript/src/delegation/tokens.js";
import { verifyDetached as verifyDetachedSigning } from "../../sdap-typescript/src/crypto/signing.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// Load vectors
// ---------------------------------------------------------------------------

interface Vectors {
  key: { public_key_hex: string; private_key_hex: string; key_id: string };
  canonicalization: { input: Record<string, unknown>; canonical_hex: string; canonical_utf8: string };
  sha256: { input_hex: string; hash_hex: string };
  jws: { payload_utf8: string; token: string };
  detached_jws: { payload_hex: string; token: string };
  hkdf: {
    inputs: {
      shared_secret_hex: string;
      nonce_a_hex: string;
      nonce_b_hex: string;
      session_id: string;
    };
    encrypt_key_hex: string;
    mac_key_hex: string;
  };
  attestation: {
    inputs: {
      issuer_did: string;
      subject_did: string;
      agent_type: string;
      capabilities: string[];
      security_level: string;
      compliance_tags: string[];
      max_delegation_depth: number;
    };
    jwt: string;
  };
  delegation: {
    inputs: {
      issuer_did: string;
      delegatee_did: string;
      audience_did: string;
      scopes: string[];
    };
    jwt: string;
  };
  audit_entry: {
    entryId: string;
    timestamp: string;
    actorDID: string;
    eventType: string;
    eventData: Record<string, unknown>;
    entryHash: string;
    signature: string;
    keyId: string;
    previousHash?: string;
    taskId?: string;
    sessionId?: string;
  };
}

let vectors: Vectors;

beforeAll(() => {
  const vectorsPath = join(__dirname, "vectors_python.json");
  vectors = JSON.parse(readFileSync(vectorsPath, "utf-8")) as Vectors;
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Python → TypeScript interop: JCS canonicalization", () => {
  it("produces identical canonical bytes for test object", () => {
    const ourCanonical = canonicalize(vectors.canonicalization.input);
    const ourHex = Buffer.from(ourCanonical).toString("hex");
    expect(ourHex).toBe(vectors.canonicalization.canonical_hex);
  });

  it("canonical UTF-8 string matches", () => {
    const ourCanonical = canonicalize(vectors.canonicalization.input);
    const ourUtf8 = new TextDecoder().decode(ourCanonical);
    expect(ourUtf8).toBe(vectors.canonicalization.canonical_utf8);
  });
});

describe("Python → TypeScript interop: SHA-256", () => {
  it("SHA-256 of canonical bytes matches", () => {
    const inputBytes = new Uint8Array(Buffer.from(vectors.sha256.input_hex, "hex"));
    const ourHash = sha256Hex(inputBytes);
    expect(ourHash).toBe(vectors.sha256.hash_hex);
  });
});

describe("Python → TypeScript interop: HKDF key derivation", () => {
  it("produces identical encrypt_key and mac_key", () => {
    const { inputs, encrypt_key_hex, mac_key_hex } = vectors.hkdf;
    const sharedSecret = new Uint8Array(Buffer.from(inputs.shared_secret_hex, "hex"));
    const nonceA = new Uint8Array(Buffer.from(inputs.nonce_a_hex, "hex"));
    const nonceB = new Uint8Array(Buffer.from(inputs.nonce_b_hex, "hex"));

    const { encryptKey, macKey } = deriveSessionKeys(
      sharedSecret,
      nonceA,
      nonceB,
      inputs.session_id
    );

    expect(Buffer.from(encryptKey).toString("hex")).toBe(encrypt_key_hex);
    expect(Buffer.from(macKey).toString("hex")).toBe(mac_key_hex);
  });
});

describe("Python → TypeScript interop: Ed25519 / JWS", () => {
  it("verifies Python-signed JWS token", async () => {
    const publicKey = new Uint8Array(Buffer.from(vectors.key.public_key_hex, "hex"));
    const payload = await verifyJws(vectors.jws.token, publicKey);
    const payloadUtf8 = new TextDecoder().decode(payload);
    expect(payloadUtf8).toBe(vectors.jws.payload_utf8);
  });

  it("verifies Python-signed detached JWS token", async () => {
    const publicKey = new Uint8Array(Buffer.from(vectors.key.public_key_hex, "hex"));
    const canonicalBytes = new Uint8Array(
      Buffer.from(vectors.detached_jws.payload_hex, "hex")
    );
    const valid = await verifyDetached(
      vectors.detached_jws.token,
      canonicalBytes,
      publicKey
    );
    expect(valid).toBe(true);
  });
});

describe("Python → TypeScript interop: attestation JWT", () => {
  it("verifies Python-signed attestation JWT", async () => {
    const publicKey = new Uint8Array(Buffer.from(vectors.key.public_key_hex, "hex"));
    const attestation = await verifyAttestation(vectors.attestation.jwt, publicKey);

    const inp = vectors.attestation.inputs;
    expect(attestation.iss).toBe(inp.issuer_did);
    expect(attestation.sub).toBe(inp.subject_did);
    expect(attestation.sdap_attestation.agentType).toBe(inp.agent_type);
    expect(attestation.sdap_attestation.capabilities).toEqual(inp.capabilities);
    expect(attestation.sdap_attestation.securityLevel).toBe(inp.security_level);
    expect(attestation.sdap_attestation.complianceTags).toEqual(inp.compliance_tags);
    expect(attestation.sdap_attestation.maxDelegationDepth).toBe(inp.max_delegation_depth);
  });
});

describe("Python → TypeScript interop: delegation JWT", () => {
  it("verifies Python-signed delegation JWT", async () => {
    const publicKey = new Uint8Array(Buffer.from(vectors.key.public_key_hex, "hex"));
    const delegation = await decodeDelegationToken(vectors.delegation.jwt, publicKey);

    const inp = vectors.delegation.inputs;
    expect(delegation.iss).toBe(inp.issuer_did);
    expect(delegation.sub).toBe(inp.delegatee_did);
    expect(delegation.aud).toBe(inp.audience_did);
    expect(delegation.scopes).toEqual(inp.scopes);
  });
});

describe("Python → TypeScript interop: audit entry", () => {
  it("verifies audit entry hash", () => {
    const entry = vectors.audit_entry;

    // Reconstruct base object (same logic as entries.ts / entries.py)
    const base: Record<string, unknown> = {
      actorDID: entry.actorDID,
      entryId: entry.entryId,
      eventData: entry.eventData,
      eventType: entry.eventType,
      keyId: entry.keyId,
      timestamp: entry.timestamp,
    };
    if (entry.previousHash !== undefined) base["previousHash"] = entry.previousHash;
    if (entry.taskId !== undefined) base["taskId"] = entry.taskId;
    if (entry.sessionId !== undefined) base["sessionId"] = entry.sessionId;

    const canonicalBase = canonicalize(base);
    const expectedHash = sha256Hex(canonicalBase);
    expect(entry.entryHash).toBe(expectedHash);
  });

  it("verifies audit entry detached signature", async () => {
    const entry = vectors.audit_entry;
    const publicKey = new Uint8Array(Buffer.from(vectors.key.public_key_hex, "hex"));

    // Reconstruct base object
    const base: Record<string, unknown> = {
      actorDID: entry.actorDID,
      entryId: entry.entryId,
      eventData: entry.eventData,
      eventType: entry.eventType,
      keyId: entry.keyId,
      timestamp: entry.timestamp,
    };
    if (entry.previousHash !== undefined) base["previousHash"] = entry.previousHash;
    if (entry.taskId !== undefined) base["taskId"] = entry.taskId;
    if (entry.sessionId !== undefined) base["sessionId"] = entry.sessionId;

    const canonicalBase = canonicalize(base);
    const entryHash = sha256Hex(canonicalBase);

    // Reconstruct toSign
    const toSign: Record<string, unknown> = { ...base, entryHash };
    const canonicalToSign = canonicalize(toSign);

    const valid = await verifyDetachedSigning(
      entry.signature,
      canonicalToSign,
      publicKey
    );
    expect(valid).toBe(true);
  });
});
