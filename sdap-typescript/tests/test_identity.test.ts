import { describe, it, expect } from "vitest";
import {
  generateEd25519KeyPair,
  generateX25519KeyPair,
  publicKeyToMultibase,
  multibaseToPublicKey,
  publicKeyToJwk,
  jwkToPublicKey,
  validateDid,
  parseDid,
  createDid,
  createAttestation,
  verifyAttestation,
} from "../src/index.js";

describe("Key generation", () => {
  it("generates Ed25519 key pair with correct sizes", () => {
    const kp = generateEd25519KeyPair("test-key");
    expect(kp.privateKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey.length).toBe(32);
    expect(kp.keyId).toBe("test-key");
  });

  it("generates X25519 key pair with correct sizes", () => {
    const kp = generateX25519KeyPair("test-key");
    expect(kp.privateKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey.length).toBe(32);
    expect(kp.keyId).toBe("test-key");
  });

  it("generates different key pairs each time", () => {
    const kp1 = generateEd25519KeyPair("k1");
    const kp2 = generateEd25519KeyPair("k2");
    expect(Buffer.from(kp1.publicKey).toString("hex")).not.toBe(
      Buffer.from(kp2.publicKey).toString("hex")
    );
  });
});

describe("Multibase encoding/decoding", () => {
  it("encodes and decodes a public key via multibase", () => {
    const kp = generateEd25519KeyPair("k");
    const multibase = publicKeyToMultibase(kp.publicKey);
    expect(multibase).toMatch(/^z/);
    const decoded = multibaseToPublicKey(multibase);
    expect(Buffer.from(decoded).toString("hex")).toBe(
      Buffer.from(kp.publicKey).toString("hex")
    );
  });

  it("throws on non-base58btc multibase prefix", () => {
    expect(() => multibaseToPublicKey("Mabc123")).toThrow();
  });
});

describe("JWK encoding/decoding", () => {
  it("encodes and decodes X25519 public key as JWK", () => {
    const kp = generateX25519KeyPair("k");
    const jwk = publicKeyToJwk(kp.publicKey);
    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("X25519");
    expect(jwk.x).toBeDefined();
    const recovered = jwkToPublicKey(jwk);
    expect(Buffer.from(recovered).toString("hex")).toBe(
      Buffer.from(kp.publicKey).toString("hex")
    );
  });

  it("throws on invalid JWK type", () => {
    expect(() => jwkToPublicKey({ kty: "RSA", crv: "X25519" })).toThrow();
  });

  it("throws on wrong curve", () => {
    expect(() => jwkToPublicKey({ kty: "OKP", crv: "Ed25519" })).toThrow();
  });
});

describe("DID validation", () => {
  it("validates correct DIDs", () => {
    expect(validateDid("did:sdap:example.com:agent-1")).toBe(true);
    expect(validateDid("did:sdap:sub.example.com:agent-123")).toBe(true);
    expect(validateDid("did:sdap:example.com")).toBe(true);
  });

  it("rejects invalid DIDs", () => {
    expect(validateDid("did:web:example.com")).toBe(false);
    expect(validateDid("not-a-did")).toBe(false);
    expect(validateDid("did:sdap:")).toBe(false);
    expect(validateDid("")).toBe(false);
  });
});

describe("DID parsing", () => {
  it("parses DID with agent ID", () => {
    const { providerDomain, agentId } = parseDid(
      "did:sdap:example.com:my-agent"
    );
    expect(providerDomain).toBe("example.com");
    expect(agentId).toBe("my-agent");
  });

  it("parses provider-only DID", () => {
    const { providerDomain, agentId } = parseDid("did:sdap:example.com");
    expect(providerDomain).toBe("example.com");
    expect(agentId).toBe("");
  });

  it("throws on invalid DID", () => {
    expect(() => parseDid("not-a-did")).toThrow();
  });
});

describe("createDid", () => {
  it("creates a valid DID document", () => {
    const authKp = generateEd25519KeyPair("auth-key-1");
    const agreeKp = generateX25519KeyPair("agree-key-1");

    const doc = createDid({
      providerDomain: "example.com",
      agentId: "my-agent",
      authPublicKey: authKp.publicKey,
      agreementPublicKey: agreeKp.publicKey,
      a2aEndpoint: "https://example.com/a2a",
      handshakeEndpoint: "https://example.com/handshake",
    });

    expect(doc.id).toBe("did:sdap:example.com:my-agent");
    expect(doc.controller).toBe("did:sdap:example.com");
    expect(doc.verificationMethod).toHaveLength(2);
    expect(doc.authentication).toHaveLength(1);
    expect(doc.keyAgreement).toHaveLength(1);
    expect(doc.service.length).toBeGreaterThanOrEqual(2);
  });

  it("creates placeholder services when endpoints missing", () => {
    const authKp = generateEd25519KeyPair("a");
    const agreeKp = generateX25519KeyPair("b");
    const doc = createDid({
      providerDomain: "test.io",
      agentId: "agent",
      authPublicKey: authKp.publicKey,
      agreementPublicKey: agreeKp.publicKey,
    });
    expect(doc.service.length).toBeGreaterThanOrEqual(2);
  });
});

describe("Attestation", () => {
  it("creates and verifies a valid attestation", async () => {
    const kp = generateEd25519KeyPair("provider-key");
    const issuerDid = "did:sdap:provider.example.com";
    const subjectDid = "did:sdap:provider.example.com:agent-1";

    const token = await createAttestation({
      issuerDid,
      subjectDid,
      privateKey: kp.privateKey,
      agentType: "specialist",
      capabilities: ["data:read"],
      securityLevel: "standard",
      complianceTags: ["HIPAA"],
      maxDelegationDepth: 3,
    });

    expect(typeof token).toBe("string");
    expect(token.split(".")).toHaveLength(3);

    const payload = await verifyAttestation(token, kp.publicKey);
    expect(payload.iss).toBe(issuerDid);
    expect(payload.sub).toBe(subjectDid);
    expect(payload.sdap_attestation.agentType).toBe("specialist");
    expect(payload.sdap_attestation.securityLevel).toBe("standard");
    expect(payload.sdap_attestation.complianceTags).toEqual(["HIPAA"]);
    expect(payload.sdap_attestation.maxDelegationDepth).toBe(3);
  });

  it("rejects expired attestation", async () => {
    const kp = generateEd25519KeyPair("k");
    const token = await createAttestation({
      issuerDid: "did:sdap:example.com",
      subjectDid: "did:sdap:example.com:agent",
      privateKey: kp.privateKey,
      agentType: "basic",
      capabilities: [],
      securityLevel: "basic",
      complianceTags: [],
      maxDelegationDepth: 1,
      ttlSeconds: -1, // already expired
    });

    await expect(verifyAttestation(token, kp.publicKey)).rejects.toThrow();
  });

  it("throws on invalid issuer DID", async () => {
    const kp = generateEd25519KeyPair("k");
    await expect(
      createAttestation({
        issuerDid: "not-a-did",
        subjectDid: "did:sdap:example.com:agent",
        privateKey: kp.privateKey,
        agentType: "basic",
        capabilities: [],
        securityLevel: "basic",
        complianceTags: [],
        maxDelegationDepth: 1,
      })
    ).rejects.toThrow(/issuer/i);
  });

  it("throws on invalid security level", async () => {
    const kp = generateEd25519KeyPair("k");
    await expect(
      createAttestation({
        issuerDid: "did:sdap:example.com",
        subjectDid: "did:sdap:example.com:agent",
        privateKey: kp.privateKey,
        agentType: "basic",
        capabilities: [],
        securityLevel: "superduper",
        complianceTags: [],
        maxDelegationDepth: 1,
      })
    ).rejects.toThrow();
  });
});
