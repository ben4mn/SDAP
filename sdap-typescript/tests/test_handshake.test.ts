import { describe, it, expect } from "vitest";
import {
  generateEd25519KeyPair,
  generateX25519KeyPair,
  createDid,
  DIDDocument,
} from "../src/identity/index.js";
import {
  createHandshakeInit,
  processHandshakeInit,
  createHandshakeConfirm,
  processHandshakeConfirm,
  Session,
  SessionStore,
  isSessionExpired,
} from "../src/handshake/index.js";

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
) {
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

describe("Handshake protocol", () => {
  it("produces matching session keys after full handshake", async () => {
    const alice = makeAgent("alice.example.com", "agent-a");
    const bob = makeAgent("bob.example.com", "agent-b");
    const resolver = makeResolver(alice.doc, bob.doc);

    const { initiatorSession, responderSession } = await performFullHandshake(
      alice,
      bob,
      resolver
    );

    expect(initiatorSession.sessionId).toBe(responderSession.sessionId);
    expect(
      Buffer.from(initiatorSession.encryptKey).toString("hex")
    ).toBe(Buffer.from(responderSession.encryptKey).toString("hex"));
    expect(
      Buffer.from(initiatorSession.macKey).toString("hex")
    ).toBe(Buffer.from(responderSession.macKey).toString("hex"));
  });

  it("sessions have correct initiator and responder DIDs", async () => {
    const alice = makeAgent("alice.example.com", "agent-a");
    const bob = makeAgent("bob.example.com", "agent-b");
    const resolver = makeResolver(alice.doc, bob.doc);

    const { initiatorSession } = await performFullHandshake(alice, bob, resolver);

    expect(initiatorSession.initiatorDid).toBe(alice.did);
    expect(initiatorSession.responderDid).toBe(bob.did);
  });

  it("granted scopes are set correctly", async () => {
    const alice = makeAgent("alice.example.com", "a");
    const bob = makeAgent("bob.example.com", "b");
    const resolver = makeResolver(alice.doc, bob.doc);
    const scopes = ["records:read", "audit:read"];

    const { initiatorSession } = await performFullHandshake(
      alice,
      bob,
      resolver,
      scopes
    );
    expect(new Set(initiatorSession.grantedScopes)).toEqual(new Set(scopes));
  });

  it("rejects invalid initiator DID", async () => {
    const eph = generateX25519KeyPair("eph");
    const kp = generateEd25519KeyPair("k");
    await expect(
      createHandshakeInit({
        initiatorDid: "not-a-did",
        targetDid: "did:sdap:example.com:agent",
        authPrivateKey: kp.privateKey,
        authKeyId: kp.keyId,
        ephemeralKeypair: eph,
        requestedScopes: [],
      })
    ).rejects.toThrow(/initiator/i);
  });

  it("rejects invalid target DID", async () => {
    const eph = generateX25519KeyPair("eph");
    const kp = generateEd25519KeyPair("k");
    await expect(
      createHandshakeInit({
        initiatorDid: "did:sdap:example.com:agent",
        targetDid: "malformed::did",
        authPrivateKey: kp.privateKey,
        authKeyId: kp.keyId,
        ephemeralKeypair: eph,
        requestedScopes: [],
      })
    ).rejects.toThrow(/target/i);
  });

  it("rejects nonce mismatch in confirm", async () => {
    const alice = makeAgent("alice.example.com", "a");
    const bob = makeAgent("bob.example.com", "b");
    const resolver = makeResolver(alice.doc, bob.doc);

    const ephA = generateX25519KeyPair("eph-a");
    const { initMessage, ephemeralPrivateKey } = await createHandshakeInit({
      initiatorDid: alice.did,
      targetDid: bob.did,
      authPrivateKey: alice.authKp.privateKey,
      authKeyId: alice.authKp.keyId,
      ephemeralKeypair: ephA,
      requestedScopes: ["data:read"],
    });

    const ephB = generateX25519KeyPair("eph-b");
    const { acceptMessage } = await processHandshakeInit({
      initMsg: initMessage,
      responderDid: bob.did,
      responderAuthKey: bob.authKp.privateKey,
      responderAuthKeyId: bob.authKp.keyId,
      responderEphemeral: ephB,
      resolveDidFn: resolver,
    });

    await expect(
      createHandshakeConfirm({
        acceptMsg: acceptMessage,
        initiatorDid: alice.did,
        initiatorNonce: "completely-wrong-nonce",
        authPrivateKey: alice.authKp.privateKey,
        authKeyId: alice.authKp.keyId,
        initiatorEphemeralPrivate: ephemeralPrivateKey,
      })
    ).rejects.toThrow(/[Nn]once/);
  });
});

describe("SessionStore", () => {
  it("stores and retrieves a session", () => {
    const store = new SessionStore();
    const session: Session = {
      sessionId: "sess-1",
      initiatorDid: "did:sdap:a.com:a",
      responderDid: "did:sdap:b.com:b",
      encryptKey: new Uint8Array(32),
      macKey: new Uint8Array(32),
      grantedScopes: ["data:read"],
      securityLevel: "standard",
      expiry: new Date(Date.now() + 3600000),
      sequenceCounter: {},
      sendCounter: {},
    };

    store.store(session);
    const retrieved = store.get("sess-1");
    expect(retrieved).toBeDefined();
    expect(retrieved?.sessionId).toBe("sess-1");
  });

  it("returns undefined for missing session", () => {
    const store = new SessionStore();
    expect(store.get("nonexistent")).toBeUndefined();
  });

  it("removes a session", () => {
    const store = new SessionStore();
    const session: Session = {
      sessionId: "sess-2",
      initiatorDid: "did:sdap:a.com:a",
      responderDid: "did:sdap:b.com:b",
      encryptKey: new Uint8Array(32),
      macKey: new Uint8Array(32),
      grantedScopes: [],
      securityLevel: "basic",
      expiry: new Date(Date.now() + 3600000),
      sequenceCounter: {},
      sendCounter: {},
    };
    store.store(session);
    store.remove("sess-2");
    expect(store.get("sess-2")).toBeUndefined();
  });

  it("tracks sequence numbers", () => {
    const store = new SessionStore();
    const session: Session = {
      sessionId: "seq-sess",
      initiatorDid: "did:sdap:a.com:a",
      responderDid: "did:sdap:b.com:b",
      encryptKey: new Uint8Array(32),
      macKey: new Uint8Array(32),
      grantedScopes: [],
      securityLevel: "basic",
      expiry: new Date(Date.now() + 3600000),
      sequenceCounter: { "did:sdap:a.com:a": 0 },
      sendCounter: {},
    };
    store.store(session);

    expect(store.nextSequence("seq-sess", "did:sdap:a.com:a")).toBe(1);
    expect(store.nextSequence("seq-sess", "did:sdap:a.com:a")).toBe(2);
  });

  it("validateSequence returns true for larger seq", () => {
    const store = new SessionStore();
    const session: Session = {
      sessionId: "val-sess",
      initiatorDid: "did:sdap:a.com:a",
      responderDid: "did:sdap:b.com:b",
      encryptKey: new Uint8Array(32),
      macKey: new Uint8Array(32),
      grantedScopes: [],
      securityLevel: "basic",
      expiry: new Date(Date.now() + 3600000),
      sequenceCounter: { "did:sdap:a.com:a": 5 },
      sendCounter: {},
    };
    store.store(session);
    expect(store.validateSequence("val-sess", "did:sdap:a.com:a", 6)).toBe(true);
    expect(store.validateSequence("val-sess", "did:sdap:a.com:a", 5)).toBe(false);
    expect(store.validateSequence("val-sess", "did:sdap:a.com:a", 4)).toBe(false);
  });

  it("cleanupExpired removes expired sessions", () => {
    const store = new SessionStore();
    const expired: Session = {
      sessionId: "old",
      initiatorDid: "did:sdap:a.com:a",
      responderDid: "did:sdap:b.com:b",
      encryptKey: new Uint8Array(32),
      macKey: new Uint8Array(32),
      grantedScopes: [],
      securityLevel: "basic",
      expiry: new Date(Date.now() - 1000), // past
      sequenceCounter: {},
      sendCounter: {},
    };
    const fresh: Session = {
      ...expired,
      sessionId: "new",
      expiry: new Date(Date.now() + 3600000),
    };
    store.store(expired);
    store.store(fresh);
    store.cleanupExpired();
    expect(store.get("old")).toBeUndefined();
    expect(store.get("new")).toBeDefined();
  });
});
