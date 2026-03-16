import { describe, it, expect } from "vitest";
import {
  generateEd25519KeyPair,
} from "../src/identity/index.js";
import {
  createAuditEntry,
  verifyAuditChain,
  createAuditCommitment,
  AuditEntry,
} from "../src/audit/index.js";

const ACTOR_DID = "did:sdap:audit.example.com:actor";

function makeKeyResolver(kp: { publicKey: Uint8Array }, did: string) {
  return (d: string): Uint8Array => {
    if (d === did) return kp.publicKey;
    throw new Error(`Unknown DID: ${d}`);
  };
}

describe("createAuditEntry", () => {
  it("creates a valid audit entry", async () => {
    const kp = generateEd25519KeyPair("key-1");
    const entry = await createAuditEntry({
      actorDid: ACTOR_DID,
      eventType: "session.started",
      eventData: { sessionId: "s-001" },
      privateKey: kp.privateKey,
      keyId: kp.keyId,
    });

    expect(entry.entryId).toBeDefined();
    expect(entry.actorDID).toBe(ACTOR_DID);
    expect(entry.eventType).toBe("session.started");
    expect(entry.entryHash).toBeDefined();
    expect(entry.signature).toBeDefined();
    expect(entry.keyId).toBe(kp.keyId);
    expect(entry.previousHash).toBeUndefined();
  });

  it("includes previousHash when provided", async () => {
    const kp = generateEd25519KeyPair("k");
    const entry1 = await createAuditEntry({
      actorDid: ACTOR_DID,
      eventType: "event-1",
      eventData: {},
      privateKey: kp.privateKey,
      keyId: kp.keyId,
    });
    const entry2 = await createAuditEntry({
      actorDid: ACTOR_DID,
      eventType: "event-2",
      eventData: {},
      privateKey: kp.privateKey,
      keyId: kp.keyId,
      previousHash: entry1.entryHash,
    });
    expect(entry2.previousHash).toBe(entry1.entryHash);
  });
});

describe("verifyAuditChain", () => {
  it("verifies a chain of entries", async () => {
    const kp = generateEd25519KeyPair("k");
    const resolver = makeKeyResolver(kp, ACTOR_DID);

    const entries: AuditEntry[] = [];
    let prevHash: string | undefined;
    for (let i = 0; i < 4; i++) {
      const entry = await createAuditEntry({
        actorDid: ACTOR_DID,
        eventType: `event-${i}`,
        eventData: { index: i },
        privateKey: kp.privateKey,
        keyId: kp.keyId,
        previousHash: prevHash,
      });
      entries.push(entry);
      prevHash = entry.entryHash;
    }

    const result = await verifyAuditChain(entries, resolver);
    expect(result).toBe(true);
  });

  it("returns true for empty chain", async () => {
    const result = await verifyAuditChain([], () => new Uint8Array(32));
    expect(result).toBe(true);
  });

  it("detects tampered entryHash", async () => {
    const kp = generateEd25519KeyPair("k");
    const resolver = makeKeyResolver(kp, ACTOR_DID);

    const entry = await createAuditEntry({
      actorDid: ACTOR_DID,
      eventType: "event",
      eventData: { x: 1 },
      privateKey: kp.privateKey,
      keyId: kp.keyId,
    });

    // Tamper with eventData
    const tampered: AuditEntry = { ...entry, eventData: { x: 999 } };
    await expect(verifyAuditChain([tampered], resolver)).rejects.toThrow(
      /[Hh]ash/
    );
  });

  it("detects broken hash chain", async () => {
    const kp = generateEd25519KeyPair("k");
    const resolver = makeKeyResolver(kp, ACTOR_DID);

    const entry1 = await createAuditEntry({
      actorDid: ACTOR_DID,
      eventType: "e1",
      eventData: {},
      privateKey: kp.privateKey,
      keyId: kp.keyId,
    });
    const entry2 = await createAuditEntry({
      actorDid: ACTOR_DID,
      eventType: "e2",
      eventData: {},
      privateKey: kp.privateKey,
      keyId: kp.keyId,
      previousHash: "wrong-hash", // should be entry1.entryHash
    });

    // entry2.previousHash != entry1.entryHash
    await expect(
      verifyAuditChain([entry1, entry2], resolver)
    ).rejects.toThrow(/[Hh]ash/);
  });

  it("verifies chain with session and task IDs", async () => {
    const kp = generateEd25519KeyPair("k");
    const resolver = makeKeyResolver(kp, ACTOR_DID);

    const entry = await createAuditEntry({
      actorDid: ACTOR_DID,
      eventType: "task.completed",
      eventData: { result: "ok" },
      privateKey: kp.privateKey,
      keyId: kp.keyId,
      sessionId: "session-123",
      taskId: "task-456",
    });

    expect(entry.sessionId).toBe("session-123");
    expect(entry.taskId).toBe("task-456");
    const result = await verifyAuditChain([entry], resolver);
    expect(result).toBe(true);
  });
});

describe("createAuditCommitment", () => {
  it("creates a commitment object", async () => {
    const kp = generateEd25519KeyPair("k");
    const latestHash = "a".repeat(64);

    const commitment = await createAuditCommitment({
      latestHash,
      entryCount: 5,
      actorDid: ACTOR_DID,
      privateKey: kp.privateKey,
      keyId: kp.keyId,
    });

    expect(commitment.commitmentId).toBeDefined();
    expect(commitment.latestHash).toBe(latestHash);
    expect(commitment.entryCount).toBe(5);
    expect(commitment.actorDID).toBe(ACTOR_DID);
    expect(commitment.signature).toBeDefined();
    expect(commitment.entryHash).toBeDefined();
  });
});
