/**
 * A2A message wrapping and unwrapping with SDAP session security.
 */

import { encryptPayload, decryptPayload, sha256Hex } from "../crypto/index.js";
import { Session, isSessionExpired } from "../handshake/protocol.js";

export interface WrappedMessage {
  sdap: {
    sessionId: string;
    senderDID: string;
    sequenceNumber: number;
    auditHash: string;
    timestamp: number;
  };
  payload: string;
}

/**
 * Wrap an A2A message with an SDAP security envelope.
 */
export async function wrapA2aMessage(
  message: Record<string, unknown>,
  session: Session,
  encryptKey: Uint8Array,
  senderDid: string
): Promise<WrappedMessage> {
  if (isSessionExpired(session)) {
    throw new Error(`Session ${session.sessionId} has expired`);
  }

  // Get and increment the outgoing (send) sequence number
  const currentSeq = session.sendCounter[senderDid] ?? 0;
  const nextSeq = currentSeq + 1;
  session.sendCounter[senderDid] = nextSeq;

  const plaintext = new TextEncoder().encode(JSON.stringify(message));
  const auditHash = sha256Hex(plaintext);

  const encrypted = await encryptPayload(
    plaintext,
    encryptKey,
    session.sessionId,
    nextSeq,
    senderDid
  );

  return {
    sdap: {
      sessionId: session.sessionId,
      senderDID: senderDid,
      sequenceNumber: nextSeq,
      auditHash,
      timestamp: Math.floor(Date.now() / 1000),
    },
    payload: encrypted,
  };
}

/**
 * Decrypt and validate a wrapped A2A message.
 */
export async function unwrapA2aMessage(
  wrapped: WrappedMessage,
  session: Session,
  encryptKey: Uint8Array
): Promise<Record<string, unknown>> {
  const sdapHeader = wrapped.sdap;
  if (!sdapHeader) {
    throw new Error("Missing 'sdap' header in wrapped message");
  }

  if (sdapHeader.sessionId !== session.sessionId) {
    throw new Error(
      `Session ID mismatch: expected ${JSON.stringify(session.sessionId)}, ` +
        `got ${JSON.stringify(sdapHeader.sessionId)}`
    );
  }

  if (isSessionExpired(session)) {
    throw new Error(`Session ${session.sessionId} has expired`);
  }

  const senderDid = sdapHeader.senderDID;
  const sequenceNumber = sdapHeader.sequenceNumber;

  if (!senderDid) {
    throw new Error("Missing senderDID in SDAP header");
  }
  if (sequenceNumber === undefined || sequenceNumber === null) {
    throw new Error("Missing sequenceNumber in SDAP header");
  }

  // Validate sequence number monotonicity against received-from-sender counter
  const currentSeq = session.sequenceCounter[senderDid] ?? 0;
  if (sequenceNumber <= currentSeq) {
    throw new Error(
      `Sequence number ${sequenceNumber} is not greater than current ` +
        `counter ${currentSeq} for sender ${JSON.stringify(senderDid)}`
    );
  }

  const encryptedPayload = wrapped.payload;
  if (!encryptedPayload) {
    throw new Error("Missing 'payload' in wrapped message");
  }

  const plaintext = await decryptPayload(
    encryptedPayload,
    encryptKey,
    session.sessionId,
    sequenceNumber,
    senderDid
  );

  // Verify audit hash
  const expectedHash = sha256Hex(plaintext);
  if (sdapHeader.auditHash && sdapHeader.auditHash !== expectedHash) {
    throw new Error(
      "Audit hash mismatch — message may have been tampered with"
    );
  }

  // Update sequence counter
  session.sequenceCounter[senderDid] = sequenceNumber;

  return JSON.parse(new TextDecoder().decode(plaintext));
}
