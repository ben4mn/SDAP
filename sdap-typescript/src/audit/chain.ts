/**
 * Audit chain verification and commitment creation.
 */

import { randomUUID } from "node:crypto";
import { AuditEntry, createAuditEntry } from "./entries.js";
import { canonicalize } from "../crypto/canonicalize.js";
import { sha256Hex } from "../crypto/hashing.js";
import { verifyDetached } from "../crypto/signing.js";

function recomputeEntryHash(entry: AuditEntry): string {
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

  const canonical = canonicalize(base);
  return sha256Hex(canonical);
}

export interface AuditCommitment {
  commitmentId: string;
  latestHash: string;
  entryCount: number;
  actorDID: string;
  timestamp: string;
  entryHash: string;
  signature: string;
  keyId: string;
}

/**
 * Verify an ordered list of audit entries.
 *
 * Checks:
 * 1. Each entry's entryHash is correct (recomputed from canonical form).
 * 2. Hash chain: entry[n].entryHash == entry[n+1].previousHash.
 * 3. Signatures are valid.
 * 4. Timestamps are monotonically increasing.
 */
export async function verifyAuditChain(
  entries: AuditEntry[],
  resolveKeyFn: (did: string) => Uint8Array
): Promise<boolean> {
  if (entries.length === 0) return true;

  let prevTimestamp: Date | null = null;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    // 1. Verify entryHash
    const expectedHash = recomputeEntryHash(entry);
    if (entry.entryHash !== expectedHash) {
      throw new Error(
        `Entry ${i} (${entry.entryId}): entryHash mismatch. ` +
          `Expected ${JSON.stringify(expectedHash)}, got ${JSON.stringify(entry.entryHash)}`
      );
    }

    // 2. Verify hash chain
    if (i > 0) {
      const prevEntry = entries[i - 1];
      if (entry.previousHash !== prevEntry.entryHash) {
        throw new Error(
          `Entry ${i} (${entry.entryId}): previousHash mismatch. ` +
            `Expected ${JSON.stringify(prevEntry.entryHash)}, got ${JSON.stringify(entry.previousHash)}`
        );
      }
    }

    // 3. Verify signature
    const actorKey = resolveKeyFn(entry.actorDID);

    const toSign: Record<string, unknown> = {
      actorDID: entry.actorDID,
      entryId: entry.entryId,
      entryHash: entry.entryHash,
      eventData: entry.eventData,
      eventType: entry.eventType,
      keyId: entry.keyId,
      timestamp: entry.timestamp,
    };
    if (entry.previousHash !== undefined) toSign["previousHash"] = entry.previousHash;
    if (entry.taskId !== undefined) toSign["taskId"] = entry.taskId;
    if (entry.sessionId !== undefined) toSign["sessionId"] = entry.sessionId;

    const canonicalToSign = canonicalize(toSign);
    const valid = await verifyDetached(entry.signature, canonicalToSign, actorKey);
    if (!valid) {
      throw new Error(
        `Entry ${i} (${entry.entryId}): signature verification failed`
      );
    }

    // 4. Verify timestamp monotonicity
    let ts: Date;
    try {
      ts = new Date(entry.timestamp);
      if (isNaN(ts.getTime())) {
        throw new Error("Invalid date");
      }
    } catch {
      throw new Error(
        `Entry ${i} (${entry.entryId}): invalid timestamp ${JSON.stringify(entry.timestamp)}`
      );
    }

    if (prevTimestamp !== null && ts < prevTimestamp) {
      throw new Error(
        `Entry ${i} (${entry.entryId}): timestamp ${JSON.stringify(entry.timestamp)} is not ` +
          `after previous entry timestamp`
      );
    }
    prevTimestamp = ts;
  }

  return true;
}

/**
 * Create a lightweight audit commitment proof.
 */
export async function createAuditCommitment(params: {
  latestHash: string;
  entryCount: number;
  actorDid: string;
  privateKey: Uint8Array;
  keyId: string;
}): Promise<AuditCommitment> {
  const { latestHash, entryCount, actorDid, privateKey, keyId } = params;

  const entry = await createAuditEntry({
    actorDid,
    eventType: "audit-commitment",
    eventData: {
      entryCount,
      latestHash,
    },
    privateKey,
    keyId,
    previousHash: latestHash,
  });

  return {
    commitmentId: randomUUID(),
    latestHash,
    entryCount,
    actorDID: actorDid,
    timestamp: entry.timestamp,
    entryHash: entry.entryHash,
    signature: entry.signature,
    keyId,
  };
}
