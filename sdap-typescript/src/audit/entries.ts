/**
 * Audit entry creation and signing.
 */

import { randomUUID } from "node:crypto";
import { z } from "zod";
import { canonicalize } from "../crypto/canonicalize.js";
import { sha256Hex } from "../crypto/hashing.js";
import { signDetached } from "../crypto/signing.js";

export const AuditEntrySchema = z
  .object({
    entryId: z.string(),
    timestamp: z.string(),
    actorDID: z.string(),
    eventType: z.string(),
    eventData: z.record(z.unknown()),
    previousHash: z.string().optional(),
    taskId: z.string().optional(),
    sessionId: z.string().optional(),
    entryHash: z.string(),
    signature: z.string(),
    keyId: z.string(),
  })
  .passthrough();

export type AuditEntry = z.infer<typeof AuditEntrySchema>;

/**
 * Create a signed audit entry.
 *
 * Steps:
 * 1. Generate entryId (UUID4).
 * 2. Set timestamp (now UTC ISO 8601 with milliseconds).
 * 3. Build the base object (without entryHash and signature).
 * 4. Compute entryHash: JCS-canonicalize the base object, SHA-256.
 * 5. Sign: JCS-canonicalize object with entryHash but without signature field, Ed25519 detached.
 * 6. Return complete AuditEntry.
 */
export async function createAuditEntry(params: {
  actorDid: string;
  eventType: string;
  eventData: Record<string, unknown>;
  privateKey: Uint8Array;
  keyId: string;
  previousHash?: string;
  taskId?: string;
  sessionId?: string;
}): Promise<AuditEntry> {
  const {
    actorDid,
    eventType,
    eventData,
    privateKey,
    keyId,
    previousHash,
    taskId,
    sessionId,
  } = params;

  const entryId = randomUUID();
  const now = new Date();
  // Format: YYYY-MM-DDTHH:MM:SS.mmmZ
  const timestamp =
    now.toISOString().replace(/(\.\d{3})Z$/, "$1") + "Z";

  // Build base object without entryHash and signature
  const base: Record<string, unknown> = {
    actorDID: actorDid,
    entryId,
    eventData,
    eventType,
    keyId,
    timestamp,
  };
  if (previousHash !== undefined) base["previousHash"] = previousHash;
  if (taskId !== undefined) base["taskId"] = taskId;
  if (sessionId !== undefined) base["sessionId"] = sessionId;

  // Compute entryHash over base object
  const canonicalBase = canonicalize(base);
  const entryHash = sha256Hex(canonicalBase);

  // Build object with entryHash but without signature for signing
  const toSign: Record<string, unknown> = { ...base, entryHash };
  const canonicalToSign = canonicalize(toSign);
  const signature = await signDetached(canonicalToSign, privateKey, keyId);

  return AuditEntrySchema.parse({
    entryId,
    timestamp,
    actorDID: actorDid,
    eventType,
    eventData,
    previousHash,
    taskId,
    sessionId,
    entryHash,
    signature,
    keyId,
  });
}
