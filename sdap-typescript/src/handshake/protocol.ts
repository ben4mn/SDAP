/**
 * SDAP 3-message handshake protocol.
 */

import { randomBytes } from "node:crypto";
import { randomUUID } from "node:crypto";
import {
  signJws,
  verifyJws,
  performEcdh,
  deriveSessionKeys,
} from "../crypto/index.js";
import { validateDid, DIDDocument } from "../identity/did.js";
import {
  KeyPair,
  publicKeyToJwk,
  jwkToPublicKey,
  multibaseToPublicKey,
} from "../identity/keys.js";

const MAX_CLOCK_SKEW_SECONDS = 60;

export interface Session {
  sessionId: string;
  initiatorDid: string;
  responderDid: string;
  encryptKey: Uint8Array;
  macKey: Uint8Array;
  grantedScopes: string[];
  securityLevel: string;
  expiry: Date;
  /** Maps DID → last received sequence number (for replay detection) */
  sequenceCounter: Record<string, number>;
  /** Maps DID → last sent sequence number (for outgoing ordering) */
  sendCounter: Record<string, number>;
}

export function isSessionExpired(session: Session): boolean {
  return new Date() >= session.expiry;
}

function nowTs(): number {
  return Math.floor(Date.now() / 1000);
}

function checkTimestamp(ts: number): void {
  const now = nowTs();
  if (Math.abs(now - ts) > MAX_CLOCK_SKEW_SECONDS) {
    throw new Error(
      `Timestamp ${ts} is outside allowed clock skew (${MAX_CLOCK_SKEW_SECONDS}s)`
    );
  }
}

function getAuthPublicKey(didDoc: DIDDocument): Uint8Array {
  if (!didDoc.authentication || didDoc.authentication.length === 0) {
    throw new Error(`DID document ${didDoc.id} has no authentication keys`);
  }
  const authKeyId = didDoc.authentication[0];
  for (const vm of didDoc.verificationMethod) {
    if (vm.id === authKeyId) {
      return multibaseToPublicKey(vm.publicKeyMultibase);
    }
  }
  throw new Error(
    `Auth key ${authKeyId} not found in verification methods`
  );
}

function getAgreementPublicKey(didDoc: DIDDocument): Uint8Array {
  if (!didDoc.keyAgreement || didDoc.keyAgreement.length === 0) {
    throw new Error(`DID document ${didDoc.id} has no key agreement keys`);
  }
  const agreeKeyId = didDoc.keyAgreement[0];
  for (const vm of didDoc.verificationMethod) {
    if (vm.id === agreeKeyId) {
      return multibaseToPublicKey(vm.publicKeyMultibase);
    }
  }
  throw new Error(
    `Agreement key ${agreeKeyId} not found in verification methods`
  );
}

function decodeJwsPayload(jws: string): Record<string, unknown> {
  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWS format");
  }
  const payloadB64 = parts[1];
  const padding = 4 - (payloadB64.length % 4);
  const padded = padding !== 4 ? payloadB64 + "=".repeat(padding) : payloadB64;
  const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
}

/**
 * Create a handshake INIT message.
 *
 * Returns { initMessage, ephemeralPrivateKey }
 */
export async function createHandshakeInit(params: {
  initiatorDid: string;
  targetDid: string;
  authPrivateKey: Uint8Array;
  authKeyId: string;
  ephemeralKeypair: KeyPair;
  requestedScopes: string[];
  requiredSecurityLevel?: string;
}): Promise<{ initMessage: Record<string, unknown>; ephemeralPrivateKey: Uint8Array }> {
  const {
    initiatorDid,
    targetDid,
    authPrivateKey,
    authKeyId,
    ephemeralKeypair,
    requestedScopes,
    requiredSecurityLevel = "standard",
  } = params;

  if (!validateDid(initiatorDid)) {
    throw new Error(`Invalid initiator DID: ${JSON.stringify(initiatorDid)}`);
  }
  if (!validateDid(targetDid)) {
    throw new Error(`Invalid target DID: ${JSON.stringify(targetDid)}`);
  }

  const nonce = randomBytes(32).toString("hex");
  const sessionId = randomUUID();

  const payload = {
    type: "sdap-handshake-init",
    version: "1.0",
    sessionId,
    initiatorDID: initiatorDid,
    targetDID: targetDid,
    nonce,
    timestamp: nowTs(),
    ephemeralKey: publicKeyToJwk(ephemeralKeypair.publicKey),
    requestedScopes,
    requiredSecurityLevel,
  };

  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  const jws = await signJws(payloadBytes, authPrivateKey, authKeyId);

  const initMessage = {
    type: "sdap-handshake-init",
    jws,
  };

  return { initMessage, ephemeralPrivateKey: ephemeralKeypair.privateKey };
}

/**
 * Validate an INIT message, produce an ACCEPT message, and derive session keys.
 *
 * Returns { acceptMessage, session }
 */
export async function processHandshakeInit(params: {
  initMsg: Record<string, unknown>;
  responderDid: string;
  responderAuthKey: Uint8Array;
  responderAuthKeyId: string;
  responderEphemeral: KeyPair;
  resolveDidFn: (did: string) => DIDDocument;
  grantedScopes?: string[];
  sessionTtl?: number;
}): Promise<{ acceptMessage: Record<string, unknown>; session: Session }> {
  const {
    initMsg,
    responderDid,
    responderAuthKey,
    responderAuthKeyId,
    responderEphemeral,
    resolveDidFn,
    grantedScopes: grantedScopesOverride,
    sessionTtl = 3600,
  } = params;

  const jws = initMsg["jws"] as string | undefined;
  if (!jws) {
    throw new Error("Missing 'jws' in init message");
  }

  // Decode without verification first to extract initiator DID
  const payload = decodeJwsPayload(jws);

  const initiatorDid = payload["initiatorDID"] as string | undefined;
  if (!initiatorDid || !validateDid(initiatorDid)) {
    throw new Error(`Invalid initiatorDID in INIT payload: ${JSON.stringify(initiatorDid)}`);
  }

  // Resolve initiator DID to get auth public key
  const initiatorDoc = resolveDidFn(initiatorDid);
  const initiatorAuthKey = getAuthPublicKey(initiatorDoc);

  // Verify signature
  try {
    await verifyJws(jws, initiatorAuthKey);
  } catch (err) {
    throw new Error(`INIT message signature verification failed: ${err}`);
  }

  if (payload["type"] !== "sdap-handshake-init") {
    throw new Error("Invalid message type in INIT payload");
  }
  if (payload["targetDID"] !== responderDid) {
    throw new Error(
      `targetDID mismatch: expected ${JSON.stringify(responderDid)}, got ${JSON.stringify(payload["targetDID"])}`
    );
  }
  checkTimestamp(payload["timestamp"] as number);

  const sessionId = payload["sessionId"] as string;
  const initiatorNonce = payload["nonce"] as string;
  const initiatorEphemeralKey = jwkToPublicKey(
    payload["ephemeralKey"] as JsonWebKey
  );
  const requestedScopes = (payload["requestedScopes"] as string[]) ?? [];

  const grantedScopes = grantedScopesOverride ?? requestedScopes;

  // ECDH with initiator's ephemeral key
  const sharedSecret = performEcdh(
    responderEphemeral.privateKey,
    initiatorEphemeralKey
  );

  const responderNonce = randomBytes(32).toString("hex");

  // nonce_a: initiator nonce (hex string → bytes if 64 hex chars, else UTF-8)
  const nonceABytes =
    initiatorNonce.length === 64
      ? Buffer.from(initiatorNonce, "hex")
      : Buffer.from(initiatorNonce, "utf8");
  const nonceBBytes = Buffer.from(responderNonce, "utf8");

  const { encryptKey, macKey } = deriveSessionKeys(
    sharedSecret,
    nonceABytes,
    nonceBBytes,
    sessionId
  );

  const expiryTs = nowTs() + sessionTtl;
  const expiry = new Date(expiryTs * 1000);

  const securityLevel =
    (payload["requiredSecurityLevel"] as string) ?? "standard";

  const session: Session = {
    sessionId,
    initiatorDid,
    responderDid,
    encryptKey,
    macKey,
    grantedScopes,
    securityLevel,
    expiry,
    sequenceCounter: { [initiatorDid]: 0, [responderDid]: 0 },
    sendCounter: {},
  };

  // Build accept payload
  const acceptPayload = {
    type: "sdap-handshake-accept",
    version: "1.0",
    sessionId,
    initiatorDID: initiatorDid,
    responderDID: responderDid,
    initiatorNonce,
    responderNonce,
    timestamp: nowTs(),
    ephemeralKey: publicKeyToJwk(responderEphemeral.publicKey),
    grantedScopes,
    securityLevel,
    sessionExpiry: expiryTs,
  };

  const acceptPayloadBytes = new TextEncoder().encode(
    JSON.stringify(acceptPayload)
  );
  const acceptJws = await signJws(
    acceptPayloadBytes,
    responderAuthKey,
    responderAuthKeyId
  );

  const acceptMessage = {
    type: "sdap-handshake-accept",
    jws: acceptJws,
  };

  return { acceptMessage, session };
}

/**
 * Process an ACCEPT message and produce a CONFIRM message.
 *
 * Returns { confirmMessage, session }
 */
export async function createHandshakeConfirm(params: {
  acceptMsg: Record<string, unknown>;
  initiatorDid: string;
  initiatorNonce: string;
  authPrivateKey: Uint8Array;
  authKeyId: string;
  initiatorEphemeralPrivate: Uint8Array;
}): Promise<{ confirmMessage: Record<string, unknown>; session: Session }> {
  const {
    acceptMsg,
    initiatorDid,
    initiatorNonce,
    authPrivateKey,
    authKeyId,
    initiatorEphemeralPrivate,
  } = params;

  const jws = acceptMsg["jws"] as string | undefined;
  if (!jws) {
    throw new Error("Missing 'jws' in accept message");
  }

  const payload = decodeJwsPayload(jws);

  if (payload["type"] !== "sdap-handshake-accept") {
    throw new Error("Invalid message type in ACCEPT payload");
  }

  const responderDid = payload["responderDID"] as string | undefined;
  if (!responderDid || !validateDid(responderDid)) {
    throw new Error(
      `Invalid responderDID in ACCEPT payload: ${JSON.stringify(responderDid)}`
    );
  }

  if (payload["initiatorDID"] !== initiatorDid) {
    throw new Error("initiatorDID mismatch in ACCEPT message");
  }
  if (payload["initiatorNonce"] !== initiatorNonce) {
    throw new Error(
      "Nonce mismatch in ACCEPT message: initiator nonce not echoed correctly"
    );
  }

  checkTimestamp(payload["timestamp"] as number);

  const sessionId = payload["sessionId"] as string;
  const responderNonce = payload["responderNonce"] as string;
  const responderEphemeralKey = jwkToPublicKey(
    payload["ephemeralKey"] as JsonWebKey
  );
  const grantedScopes = (payload["grantedScopes"] as string[]) ?? [];
  const securityLevel = (payload["securityLevel"] as string) ?? "standard";
  const sessionExpiryTs = payload["sessionExpiry"] as number | undefined;

  const expiry = sessionExpiryTs
    ? new Date(sessionExpiryTs * 1000)
    : new Date((nowTs() + 3600) * 1000);

  // ECDH and key derivation
  const sharedSecret = performEcdh(
    initiatorEphemeralPrivate,
    responderEphemeralKey
  );

  const nonceABytes =
    initiatorNonce.length === 64
      ? Buffer.from(initiatorNonce, "hex")
      : Buffer.from(initiatorNonce, "utf8");
  const nonceBBytes = Buffer.from(responderNonce, "utf8");

  const { encryptKey, macKey } = deriveSessionKeys(
    sharedSecret,
    nonceABytes,
    nonceBBytes,
    sessionId
  );

  const session: Session = {
    sessionId,
    initiatorDid,
    responderDid,
    encryptKey,
    macKey,
    grantedScopes,
    securityLevel,
    expiry,
    sequenceCounter: { [initiatorDid]: 0, [responderDid]: 0 },
    sendCounter: {},
  };

  // Build confirm payload
  const confirmPayload = {
    type: "sdap-handshake-confirm",
    version: "1.0",
    sessionId,
    initiatorDID: initiatorDid,
    responderDID: responderDid,
    responderNonce,
    timestamp: nowTs(),
  };

  const confirmPayloadBytes = new TextEncoder().encode(
    JSON.stringify(confirmPayload)
  );
  const confirmJws = await signJws(
    confirmPayloadBytes,
    authPrivateKey,
    authKeyId
  );

  const confirmMessage = {
    type: "sdap-handshake-confirm",
    jws: confirmJws,
  };

  return { confirmMessage, session };
}

/**
 * Validate a CONFIRM message and return the confirmed session.
 */
export async function processHandshakeConfirm(params: {
  confirmMsg: Record<string, unknown>;
  session: Session;
  resolveDidFn: (did: string) => DIDDocument;
}): Promise<Session> {
  const { confirmMsg, session, resolveDidFn } = params;

  const jws = confirmMsg["jws"] as string | undefined;
  if (!jws) {
    throw new Error("Missing 'jws' in confirm message");
  }

  const payload = decodeJwsPayload(jws);

  if (payload["type"] !== "sdap-handshake-confirm") {
    throw new Error("Invalid message type in CONFIRM payload");
  }

  if (payload["sessionId"] !== session.sessionId) {
    throw new Error("Session ID mismatch in CONFIRM message");
  }
  if (payload["initiatorDID"] !== session.initiatorDid) {
    throw new Error("initiatorDID mismatch in CONFIRM message");
  }
  if (payload["responderDID"] !== session.responderDid) {
    throw new Error("responderDID mismatch in CONFIRM message");
  }

  checkTimestamp(payload["timestamp"] as number);

  if (isSessionExpired(session)) {
    throw new Error("Session has expired before confirmation");
  }

  // Verify signature using initiator's auth key
  const initiatorDoc = resolveDidFn(session.initiatorDid);
  const initiatorAuthKey = getAuthPublicKey(initiatorDoc);

  try {
    await verifyJws(jws, initiatorAuthKey);
  } catch (err) {
    throw new Error(`CONFIRM message signature verification failed: ${err}`);
  }

  return session;
}
