import { describe, it, expect } from "vitest";
import {
  generateEd25519KeyPair,
} from "../src/identity/index.js";
import {
  createDelegationToken,
  decodeDelegationToken,
  computeChainHash,
  validateDelegationChain,
  isScopeSubset,
  parseScope,
  DelegationConstraints,
} from "../src/delegation/index.js";

const DID_A = "did:sdap:alpha.example.com:agent-a";
const DID_B = "did:sdap:beta.example.com:agent-b";
const DID_C = "did:sdap:gamma.example.com:agent-c";

describe("computeChainHash", () => {
  it("hashes parent_jti when no parent hash", () => {
    const h = computeChainHash(null, "jti-123");
    expect(typeof h).toBe("string");
    expect(h.length).toBe(64); // SHA-256 hex
  });

  it("hashes parent_hash + parent_jti", () => {
    const h1 = computeChainHash(null, "jti-A");
    const h2 = computeChainHash(h1, "jti-B");
    expect(h2).not.toBe(h1);
  });

  it("is deterministic", () => {
    const h1 = computeChainHash("abc", "def");
    const h2 = computeChainHash("abc", "def");
    expect(h1).toBe(h2);
  });
});

describe("parseScope", () => {
  it("parses resource:action", () => {
    const { resource, action, qualifier } = parseScope("records:read");
    expect(resource).toBe("records");
    expect(action).toBe("read");
    expect(qualifier).toBeUndefined();
  });

  it("parses resource:action:qualifier", () => {
    const { resource, action, qualifier } = parseScope(
      "medical:read:summary-only"
    );
    expect(resource).toBe("medical");
    expect(action).toBe("read");
    expect(qualifier).toBe("summary-only");
  });

  it("throws on invalid scope", () => {
    expect(() => parseScope("nocolon")).toThrow();
  });
});

describe("isScopeSubset", () => {
  it("returns true when scopes are identical", () => {
    expect(isScopeSubset(["a:b"], ["a:b"])).toBe(true);
  });

  it("returns true when parent has wildcard", () => {
    expect(isScopeSubset(["records:read"], ["records:*"])).toBe(true);
    expect(isScopeSubset(["records:write"], ["*:*"])).toBe(true);
    expect(isScopeSubset(["anything:here"], ["*"])).toBe(true);
  });

  it("returns true when parent covers qualifier with base scope", () => {
    expect(isScopeSubset(["a:b:c"], ["a:b"])).toBe(true);
  });

  it("returns false when child has extra scopes", () => {
    expect(isScopeSubset(["a:b", "c:d"], ["a:b"])).toBe(false);
  });

  it("returns false when scopes are disjoint", () => {
    expect(isScopeSubset(["c:d"], ["a:b"])).toBe(false);
  });
});

describe("Delegation token creation and verification", () => {
  it("creates and decodes a root delegation token", async () => {
    const kpA = generateEd25519KeyPair("key-a");

    const token = await createDelegationToken({
      issuerDid: DID_A,
      delegateeDid: DID_B,
      audienceDid: DID_C,
      privateKey: kpA.privateKey,
      scopes: ["records:read"],
      constraints: {},
      delegationDepth: 0,
    });

    expect(typeof token).toBe("string");
    expect(token.split(".")).toHaveLength(3);

    const payload = await decodeDelegationToken(token, kpA.publicKey);
    expect(payload.iss).toBe(DID_A);
    expect(payload.sub).toBe(DID_B);
    expect(payload.aud).toBe(DID_C);
    expect(payload.scopes).toEqual(["records:read"]);
    expect(payload.delegationDepth).toBe(0);
    expect(payload.parentTokenId).toBeUndefined();
  });

  it("creates a sub-delegation token with chain hash", async () => {
    const kpA = generateEd25519KeyPair("key-a");
    const kpB = generateEd25519KeyPair("key-b");

    const rootToken = await createDelegationToken({
      issuerDid: DID_A,
      delegateeDid: DID_B,
      audienceDid: DID_C,
      privateKey: kpA.privateKey,
      scopes: ["records:read", "audit:read"],
      constraints: { maxUses: 100 },
      delegationDepth: 0,
    });
    const rootPayload = await decodeDelegationToken(rootToken, kpA.publicKey);

    const subToken = await createDelegationToken({
      issuerDid: DID_B,
      delegateeDid: DID_C,
      audienceDid: DID_C,
      privateKey: kpB.privateKey,
      scopes: ["records:read"],
      constraints: { maxUses: 10 },
      parentTokenId: rootPayload.jti,
      delegationDepth: 1,
      parentChainHash: undefined,
    });

    const subPayload = await decodeDelegationToken(subToken, kpB.publicKey);
    expect(subPayload.parentTokenId).toBe(rootPayload.jti);
    expect(subPayload.parentChainHash).toBeDefined();
    expect(subPayload.delegationDepth).toBe(1);
  });

  it("throws on invalid issuer DID", async () => {
    const kp = generateEd25519KeyPair("k");
    await expect(
      createDelegationToken({
        issuerDid: "bad-did",
        delegateeDid: DID_B,
        audienceDid: DID_C,
        privateKey: kp.privateKey,
        scopes: [],
        constraints: {},
      })
    ).rejects.toThrow(/issuer/i);
  });

  it("throws on wrong public key for decoding", async () => {
    const kp1 = generateEd25519KeyPair("k1");
    const kp2 = generateEd25519KeyPair("k2");
    const token = await createDelegationToken({
      issuerDid: DID_A,
      delegateeDid: DID_B,
      audienceDid: DID_C,
      privateKey: kp1.privateKey,
      scopes: [],
      constraints: {},
    });
    await expect(decodeDelegationToken(token, kp2.publicKey)).rejects.toThrow();
  });
});

describe("validateDelegationChain", () => {
  it("validates a single-token chain", async () => {
    const kpA = generateEd25519KeyPair("a");
    const token = await createDelegationToken({
      issuerDid: DID_A,
      delegateeDid: DID_B,
      audienceDid: DID_C,
      privateKey: kpA.privateKey,
      scopes: ["records:read"],
      constraints: {},
      delegationDepth: 0,
    });

    const leaf = await validateDelegationChain(
      [token],
      (did) => {
        if (did === DID_A) return kpA.publicKey;
        throw new Error(`Unknown DID: ${did}`);
      }
    );
    expect(leaf.sub).toBe(DID_B);
  });

  it("validates a two-token chain", async () => {
    const kpA = generateEd25519KeyPair("a");
    const kpB = generateEd25519KeyPair("b");

    const root = await createDelegationToken({
      issuerDid: DID_A,
      delegateeDid: DID_B,
      audienceDid: DID_C,
      privateKey: kpA.privateKey,
      scopes: ["records:read", "audit:read"],
      constraints: { maxUses: 100 },
      delegationDepth: 0,
    });
    const rootPayload = await decodeDelegationToken(root, kpA.publicKey);

    const sub = await createDelegationToken({
      issuerDid: DID_B,
      delegateeDid: DID_C,
      audienceDid: DID_C,
      privateKey: kpB.privateKey,
      scopes: ["records:read"],
      constraints: { maxUses: 10 },
      parentTokenId: rootPayload.jti,
      delegationDepth: 1,
    });

    const keyMap = new Map([
      [DID_A, kpA.publicKey],
      [DID_B, kpB.publicKey],
    ]);
    const leaf = await validateDelegationChain(
      [root, sub],
      (did) => {
        const k = keyMap.get(did);
        if (!k) throw new Error(`Unknown DID: ${did}`);
        return k;
      }
    );
    expect(leaf.iss).toBe(DID_B);
    expect(leaf.sub).toBe(DID_C);
  });

  it("rejects scope escalation", async () => {
    const kpA = generateEd25519KeyPair("a");
    const kpB = generateEd25519KeyPair("b");

    const root = await createDelegationToken({
      issuerDid: DID_A,
      delegateeDid: DID_B,
      audienceDid: DID_C,
      privateKey: kpA.privateKey,
      scopes: ["records:read"],
      constraints: {},
      delegationDepth: 0,
    });
    const rootPayload = await decodeDelegationToken(root, kpA.publicKey);

    const bad = await createDelegationToken({
      issuerDid: DID_B,
      delegateeDid: DID_C,
      audienceDid: DID_C,
      privateKey: kpB.privateKey,
      scopes: ["records:read", "records:write"], // escalated!
      constraints: {},
      parentTokenId: rootPayload.jti,
      delegationDepth: 1,
    });

    const keyMap = new Map([
      [DID_A, kpA.publicKey],
      [DID_B, kpB.publicKey],
    ]);
    await expect(
      validateDelegationChain([root, bad], (did) => {
        const k = keyMap.get(did);
        if (!k) throw new Error(`Unknown DID: ${did}`);
        return k;
      })
    ).rejects.toThrow(/[Ss]cope/);
  });

  it("rejects broken chain continuity", async () => {
    const kpA = generateEd25519KeyPair("a");
    const kpStranger = generateEd25519KeyPair("stranger");
    const didStranger = "did:sdap:nowhere.example.com:stranger";

    const root = await createDelegationToken({
      issuerDid: DID_A,
      delegateeDid: DID_B,
      audienceDid: DID_C,
      privateKey: kpA.privateKey,
      scopes: ["records:read"],
      constraints: {},
      delegationDepth: 0,
    });
    const rootPayload = await decodeDelegationToken(root, kpA.publicKey);

    // Stranger (not B) creates a child
    const bad = await createDelegationToken({
      issuerDid: didStranger,
      delegateeDid: DID_C,
      audienceDid: DID_C,
      privateKey: kpStranger.privateKey,
      scopes: ["records:read"],
      constraints: {},
      parentTokenId: rootPayload.jti,
      delegationDepth: 1,
    });

    const keyMap = new Map([
      [DID_A, kpA.publicKey],
      [didStranger, kpStranger.publicKey],
    ]);
    await expect(
      validateDelegationChain([root, bad], (did) => {
        const k = keyMap.get(did);
        if (!k) throw new Error(`Unknown DID: ${did}`);
        return k;
      })
    ).rejects.toThrow(/[Cc]ontinuity|iss/);
  });

  it("throws on empty chain", async () => {
    await expect(
      validateDelegationChain([], () => new Uint8Array(32))
    ).rejects.toThrow(/[Ee]mpty/);
  });
});
