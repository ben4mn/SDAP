import { describe, it, expect } from "vitest";
import {
  generateEd25519KeyPair,
  generateX25519KeyPair,
  createDid,
  createAttestation,
  verifyAttestation,
  DIDDocument,
} from "../src/identity/index.js";
import {
  createHandshakeInit,
  processHandshakeInit,
  createHandshakeConfirm,
  processHandshakeConfirm,
  Session,
} from "../src/handshake/index.js";
import {
  createDelegationToken,
  decodeDelegationToken,
  validateDelegationChain,
  isScopeSubset,
  DelegationConstraints,
  DelegationTokenPayload,
} from "../src/delegation/index.js";
import {
  createAuditEntry,
  verifyAuditChain,
  AuditEntry,
} from "../src/audit/index.js";
import { wrapA2aMessage, unwrapA2aMessage } from "../src/a2a/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeAgent(providerDomain: string, agentId: string) {
  const authKp = generateEd25519KeyPair("auth-key-1");
  const agreeKp = generateX25519KeyPair("agree-key-1");
  const doc = createDid({
    providerDomain,
    agentId,
    authPublicKey: authKp.publicKey,
    agreementPublicKey: agreeKp.publicKey,
    a2aEndpoint: `https://${providerDomain}/a2a`,
    handshakeEndpoint: `https://${providerDomain}/handshake`,
  });
  return { authKp, agreeKp, doc, did: doc.id };
}

function makeResolver(...docs: DIDDocument[]) {
  const map = new Map(docs.map((d) => [d.id, d]));
  return (did: string): DIDDocument => {
    const doc = map.get(did);
    if (!doc) throw new Error(`DID not found: ${did}`);
    return doc;
  };
}

function makeKeyResolver(
  ...pairs: Array<{ did: string; publicKey: Uint8Array }>
) {
  const map = new Map(pairs.map((p) => [p.did, p.publicKey]));
  return (did: string): Uint8Array => {
    const k = map.get(did);
    if (!k) throw new Error(`Unknown DID: ${did}`);
    return k;
  };
}

function decodeJwsPayload(jws: string): Record<string, unknown> {
  const parts = jws.split(".");
  const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const padding = 4 - (b64.length % 4);
  const padded = padding !== 4 ? b64 + "=".repeat(padding) : b64;
  return JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
}

async function performFullHandshake(
  initiator: ReturnType<typeof makeAgent>,
  responder: ReturnType<typeof makeAgent>,
  resolver: (did: string) => DIDDocument,
  scopes = ["data:read"]
): Promise<{ initiatorSession: Session; responderSession: Session }> {
  const ephA = generateX25519KeyPair("eph-a");
  const { initMessage, ephemeralPrivateKey } = await createHandshakeInit({
    initiatorDid: initiator.did,
    targetDid: responder.did,
    authPrivateKey: initiator.authKp.privateKey,
    authKeyId: initiator.authKp.keyId,
    ephemeralKeypair: ephA,
    requestedScopes: scopes,
  });

  const initPayload = decodeJwsPayload(initMessage["jws"] as string);
  const initiatorNonce = initPayload["nonce"] as string;

  const ephB = generateX25519KeyPair("eph-b");
  const { acceptMessage, session: responderSession } =
    await processHandshakeInit({
      initMsg: initMessage,
      responderDid: responder.did,
      responderAuthKey: responder.authKp.privateKey,
      responderAuthKeyId: responder.authKp.keyId,
      responderEphemeral: ephB,
      resolveDidFn: resolver,
      grantedScopes: scopes,
    });

  const { confirmMessage, session: initiatorSession } =
    await createHandshakeConfirm({
      acceptMsg: acceptMessage,
      initiatorDid: initiator.did,
      initiatorNonce,
      authPrivateKey: initiator.authKp.privateKey,
      authKeyId: initiator.authKp.keyId,
      initiatorEphemeralPrivate: ephemeralPrivateKey,
    });

  await processHandshakeConfirm({
    confirmMsg: confirmMessage,
    session: responderSession,
    resolveDidFn: resolver,
  });

  return { initiatorSession, responderSession };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Full handshake flow", () => {
  it("produces matching session keys", async () => {
    const alice = makeAgent("alice.example.com", "agent-a");
    const bob = makeAgent("bob.example.com", "agent-b");
    const resolver = makeResolver(alice.doc, bob.doc);
    const scopes = ["medical-records:read:summary-only", "audit:read"];

    const { initiatorSession, responderSession } = await performFullHandshake(
      alice,
      bob,
      resolver,
      scopes
    );

    expect(initiatorSession.sessionId).toBe(responderSession.sessionId);
    expect(
      Buffer.from(initiatorSession.encryptKey).toString("hex")
    ).toBe(Buffer.from(responderSession.encryptKey).toString("hex"));
    expect(
      Buffer.from(initiatorSession.macKey).toString("hex")
    ).toBe(Buffer.from(responderSession.macKey).toString("hex"));
    expect(initiatorSession.initiatorDid).toBe(alice.did);
    expect(initiatorSession.responderDid).toBe(bob.did);
    expect(new Set(initiatorSession.grantedScopes)).toEqual(new Set(scopes));
  });
});

describe("Encrypted message exchange", () => {
  it("Alice wraps, Bob unwraps", async () => {
    const alice = makeAgent("alice.example.com", "a");
    const bob = makeAgent("bob.example.com", "b");
    const resolver = makeResolver(alice.doc, bob.doc);

    const { initiatorSession, responderSession } = await performFullHandshake(
      alice,
      bob,
      resolver
    );

    const message = { action: "get-record", patientId: "P-001" };
    const wrapped = await wrapA2aMessage(
      message,
      initiatorSession,
      initiatorSession.encryptKey,
      alice.did
    );
    const recovered = await unwrapA2aMessage(
      wrapped,
      responderSession,
      responderSession.encryptKey
    );
    expect(recovered).toEqual(message);
  });

  it("Bob wraps, Alice unwraps", async () => {
    const alice = makeAgent("alice.example.com", "a");
    const bob = makeAgent("bob.example.com", "b");
    const resolver = makeResolver(alice.doc, bob.doc);

    const { initiatorSession, responderSession } = await performFullHandshake(
      alice,
      bob,
      resolver
    );

    // Consume seq 1 on Alice's side
    await wrapA2aMessage(
      { ping: true },
      initiatorSession,
      initiatorSession.encryptKey,
      alice.did
    );

    const response = { status: "ok", record: { summary: "Healthy" } };
    const wrapped = await wrapA2aMessage(
      response,
      responderSession,
      responderSession.encryptKey,
      bob.did
    );
    const recovered = await unwrapA2aMessage(
      wrapped,
      initiatorSession,
      initiatorSession.encryptKey
    );
    expect(recovered).toEqual(response);
  });
});

describe("Delegation chain", () => {
  it("validates a two-token chain", async () => {
    const kpA = generateEd25519KeyPair("a");
    const kpB = generateEd25519KeyPair("b");
    const didA = "did:sdap:alice.example.com:a";
    const didB = "did:sdap:bob.example.com:b";
    const didC = "did:sdap:carol.example.com:c";

    const rootScopes = ["medical-records:read:summary-only", "audit:read"];
    const subScopes = ["medical-records:read:summary-only"];

    const rootToken = await createDelegationToken({
      issuerDid: didA,
      delegateeDid: didB,
      audienceDid: didC,
      privateKey: kpA.privateKey,
      scopes: rootScopes,
      constraints: { maxUses: 10 },
      delegationDepth: 0,
    });
    const rootPayload = await decodeDelegationToken(rootToken, kpA.publicKey);

    const subToken = await createDelegationToken({
      issuerDid: didB,
      delegateeDid: didC,
      audienceDid: didC,
      privateKey: kpB.privateKey,
      scopes: subScopes,
      constraints: { maxUses: 5 },
      parentTokenId: rootPayload.jti,
      delegationDepth: 1,
    });

    const resolver = makeKeyResolver(
      { did: didA, publicKey: kpA.publicKey },
      { did: didB, publicKey: kpB.publicKey }
    );
    const leaf = await validateDelegationChain([rootToken, subToken], resolver);

    expect(leaf.iss).toBe(didB);
    expect(leaf.sub).toBe(didC);
    expect(leaf.scopes).toEqual(subScopes);
    expect(isScopeSubset(subScopes, rootScopes)).toBe(true);
  });
});

describe("Audit chain", () => {
  it("builds and verifies a chain of 5 entries", async () => {
    const kp = generateEd25519KeyPair("audit-key");
    const actorDid = "did:sdap:actor.example.com:actor";
    const resolver = makeKeyResolver({ did: actorDid, publicKey: kp.publicKey });

    const events = [
      ["session.initiated", { sessionId: "sess-001" }],
      ["session.established", { sessionId: "sess-001", peerDID: "did:sdap:b.com:b" }],
      ["payload.encrypted", { bytes: 128 }],
      ["delegation.created", { tokenId: "tok-abc" }],
      ["task.completed", { taskId: "task-xyz", result: "success" }],
    ] as Array<[string, Record<string, unknown>]>;

    const entries: AuditEntry[] = [];
    let prevHash: string | undefined;
    for (const [eventType, eventData] of events) {
      const entry = await createAuditEntry({
        actorDid,
        eventType,
        eventData,
        privateKey: kp.privateKey,
        keyId: kp.keyId,
        previousHash: prevHash,
        sessionId: "sess-001",
      });
      entries.push(entry);
      prevHash = entry.entryHash;
    }

    expect(entries.length).toBe(5);
    const valid = await verifyAuditChain(entries, resolver);
    expect(valid).toBe(true);

    // Verify chain linkage
    for (let i = 1; i < entries.length; i++) {
      expect(entries[i].previousHash).toBe(entries[i - 1].entryHash);
    }
  });
});

describe("Security negative tests", () => {
  it("rejects expired attestation", async () => {
    const kp = generateEd25519KeyPair("k");
    const token = await createAttestation({
      issuerDid: "did:sdap:a.example.com",
      subjectDid: "did:sdap:a.example.com:agent",
      privateKey: kp.privateKey,
      agentType: "specialist",
      capabilities: [],
      securityLevel: "standard",
      complianceTags: [],
      maxDelegationDepth: 1,
      ttlSeconds: -1, // already expired
    });
    await expect(verifyAttestation(token, kp.publicKey)).rejects.toThrow();
  });

  it("rejects scope escalation in delegation", async () => {
    const kpA = generateEd25519KeyPair("a");
    const kpB = generateEd25519KeyPair("b");
    const didA = "did:sdap:alpha.example.com:a";
    const didB = "did:sdap:beta.example.com:b";
    const didC = "did:sdap:gamma.example.com:c";

    const root = await createDelegationToken({
      issuerDid: didA,
      delegateeDid: didB,
      audienceDid: didC,
      privateKey: kpA.privateKey,
      scopes: ["records:read"],
      constraints: {},
      delegationDepth: 0,
    });
    const rootPayload = await decodeDelegationToken(root, kpA.publicKey);

    const bad = await createDelegationToken({
      issuerDid: didB,
      delegateeDid: didC,
      audienceDid: didC,
      privateKey: kpB.privateKey,
      scopes: ["records:read", "records:write"], // escalated!
      constraints: {},
      parentTokenId: rootPayload.jti,
      delegationDepth: 1,
    });

    const keyMap = makeKeyResolver(
      { did: didA, publicKey: kpA.publicKey },
      { did: didB, publicKey: kpB.publicKey }
    );
    await expect(
      validateDelegationChain([root, bad], keyMap)
    ).rejects.toThrow(/[Ss]cope/);
  });

  it("rejects replay of same wrapped message", async () => {
    const alice = makeAgent("alice.example.com", "a");
    const bob = makeAgent("bob.example.com", "b");
    const resolver = makeResolver(alice.doc, bob.doc);

    const { initiatorSession, responderSession } = await performFullHandshake(
      alice,
      bob,
      resolver
    );

    const message = { action: "sensitive-op" };
    const wrapped = await wrapA2aMessage(
      message,
      initiatorSession,
      initiatorSession.encryptKey,
      alice.did
    );

    // First delivery OK
    await unwrapA2aMessage(
      wrapped,
      responderSession,
      responderSession.encryptKey
    );

    // Second delivery must fail (sequence already consumed)
    await expect(
      unwrapA2aMessage(wrapped, responderSession, responderSession.encryptKey)
    ).rejects.toThrow(/[Ss]equence/);
  });

  it("rejects tampered encrypted payload", async () => {
    const alice = makeAgent("alice.example.com", "a");
    const bob = makeAgent("bob.example.com", "b");
    const resolver = makeResolver(alice.doc, bob.doc);

    const { initiatorSession, responderSession } = await performFullHandshake(
      alice,
      bob,
      resolver
    );

    const message = { secret: "top-secret" };
    const wrapped = await wrapA2aMessage(
      message,
      initiatorSession,
      initiatorSession.encryptKey,
      alice.did
    );

    // Tamper: flip first char in ciphertext segment
    const parts = wrapped.payload.split(".");
    const ct = parts[2];
    const flipped = ct[0] !== "A" ? "A" + ct.slice(1) : "B" + ct.slice(1);
    const tamperedWrapped = {
      ...wrapped,
      payload: [parts[0], parts[1], flipped, parts[3]].join("."),
    };

    await expect(
      unwrapA2aMessage(tamperedWrapped, responderSession, responderSession.encryptKey)
    ).rejects.toThrow();
  });

  it("rejects wrong session key", async () => {
    const alice = makeAgent("alice.example.com", "a");
    const bob = makeAgent("bob.example.com", "b");
    const resolver = makeResolver(alice.doc, bob.doc);

    const { initiatorSession } = await performFullHandshake(alice, bob, resolver);

    const message = { data: "confidential" };
    const wrapped = await wrapA2aMessage(
      message,
      initiatorSession,
      initiatorSession.encryptKey,
      alice.did
    );

    // Create a session with wrong key
    const wrongSession: Session = {
      ...initiatorSession,
      encryptKey: new Uint8Array(32).fill(0xff),
      sequenceCounter: { [alice.did]: 0, [bob.did]: 0 },
      sendCounter: {},
    };

    await expect(
      unwrapA2aMessage(wrapped, wrongSession, wrongSession.encryptKey)
    ).rejects.toThrow();
  });

  it("rejects broken audit chain", async () => {
    const kp = generateEd25519KeyPair("k");
    const did = "did:sdap:audit.example.com:actor";
    const resolver = makeKeyResolver({ did, publicKey: kp.publicKey });

    const entries: AuditEntry[] = [];
    let prevHash: string | undefined;
    for (let i = 0; i < 4; i++) {
      const entry = await createAuditEntry({
        actorDid: did,
        eventType: `event-${i}`,
        eventData: { index: i },
        privateKey: kp.privateKey,
        keyId: kp.keyId,
        previousHash: prevHash,
      });
      entries.push(entry);
      prevHash = entry.entryHash;
    }

    // Tamper with entry[1]'s eventData
    entries[1] = { ...entries[1], eventData: { index: 999 } };

    await expect(verifyAuditChain(entries, resolver)).rejects.toThrow(
      /[Hh]ash/
    );
  });

  it("rejects handshake with invalid initiator DID", async () => {
    const eph = generateX25519KeyPair("eph");
    const kp = generateEd25519KeyPair("k");
    await expect(
      createHandshakeInit({
        initiatorDid: "not-a-valid-did",
        targetDid: "did:sdap:example.com:agent",
        authPrivateKey: kp.privateKey,
        authKeyId: kp.keyId,
        ephemeralKeypair: eph,
        requestedScopes: [],
      })
    ).rejects.toThrow(/[Ii]nitiator|DID/i);
  });

  it("combined handshake + delegation + audit smoke test", async () => {
    const alice = makeAgent("alice.example.com", "a");
    const bob = makeAgent("bob.example.com", "b");
    const resolver = makeResolver(alice.doc, bob.doc);
    const scopes = ["medical-records:read:summary-only", "audit:read"];

    // 1. Handshake
    const { initiatorSession, responderSession } = await performFullHandshake(
      alice,
      bob,
      resolver,
      scopes
    );
    expect(
      Buffer.from(initiatorSession.encryptKey).toString("hex")
    ).toBe(Buffer.from(responderSession.encryptKey).toString("hex"));

    // 2. Message exchange
    const msg = { task: "retrieve-summary", patient: "P-002" };
    const wrapped = await wrapA2aMessage(
      msg,
      initiatorSession,
      initiatorSession.encryptKey,
      alice.did
    );
    const recovered = await unwrapA2aMessage(
      wrapped,
      responderSession,
      responderSession.encryptKey
    );
    expect(recovered).toEqual(msg);

    // 3. Delegation A→B
    const rootToken = await createDelegationToken({
      issuerDid: alice.did,
      delegateeDid: bob.did,
      audienceDid: bob.did,
      privateKey: alice.authKp.privateKey,
      scopes,
      constraints: { maxUses: 20 },
      delegationDepth: 0,
    });
    const keyResolver = makeKeyResolver({
      did: alice.did,
      publicKey: alice.authKp.publicKey,
    });
    const leaf = await validateDelegationChain([rootToken], keyResolver);
    expect(leaf.sub).toBe(bob.did);

    // 4. Audit trail
    const auditDid = alice.did;
    const auditResolver = makeKeyResolver({
      did: auditDid,
      publicKey: alice.authKp.publicKey,
    });
    const auditEntries: AuditEntry[] = [];
    let prevHash: string | undefined;
    for (const [eventType, eventData] of [
      ["session.initiated", { sessionId: initiatorSession.sessionId }],
      ["payload.encrypted", { messageCount: 1 }],
      ["delegation.created", { jti: leaf.jti }],
    ] as Array<[string, Record<string, unknown>]>) {
      const entry = await createAuditEntry({
        actorDid: auditDid,
        eventType,
        eventData,
        privateKey: alice.authKp.privateKey,
        keyId: alice.authKp.keyId,
        previousHash: prevHash,
        sessionId: initiatorSession.sessionId,
      });
      auditEntries.push(entry);
      prevHash = entry.entryHash;
    }
    const valid = await verifyAuditChain(auditEntries, auditResolver);
    expect(valid).toBe(true);
  });
});
