/**
 * AES-256-GCM encryption/decryption for SDAP session payloads.
 */

import { webcrypto } from "node:crypto";

function b64urlEncode(data: Uint8Array): string {
  return Buffer.from(data)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function b64urlDecode(s: string): Uint8Array {
  const padding = 4 - (s.length % 4);
  const padded = padding !== 4 ? s + "=".repeat(padding) : s;
  const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(b64, "base64"));
}

function buildAad(
  sessionId: string,
  sequenceNumber: number,
  senderDid: string
): Uint8Array {
  const aadObj = {
    senderDID: senderDid,
    sequenceNumber,
    sessionId,
  };
  // Sort keys for determinism (same as Python sort_keys=True)
  const sortedKeys = Object.keys(aadObj).sort() as Array<keyof typeof aadObj>;
  const sorted: Record<string, unknown> = {};
  for (const k of sortedKeys) {
    sorted[k] = aadObj[k];
  }
  return new TextEncoder().encode(JSON.stringify(sorted));
}

/**
 * Encrypt plaintext with AES-256-GCM and return a compact JWE-like string.
 *
 * Format: <protected>.<iv>.<ciphertext>.<tag>
 */
export async function encryptPayload(
  plaintext: Uint8Array,
  key: Uint8Array,
  sessionId: string,
  sequenceNumber: number,
  senderDid: string
): Promise<string> {
  if (key.length !== 32) {
    throw new Error("key must be 32 bytes for AES-256-GCM");
  }

  const iv = webcrypto.getRandomValues(new Uint8Array(12)); // 96-bit nonce
  const aad = buildAad(sessionId, sequenceNumber, senderDid);

  const cryptoKey = await webcrypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const ciphertextWithTag = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    cryptoKey,
    plaintext
  );

  const ctBytes = new Uint8Array(ciphertextWithTag);
  const ciphertext = ctBytes.slice(0, ctBytes.length - 16);
  const tag = ctBytes.slice(ctBytes.length - 16);

  const protectedHeader = {
    alg: "dir",
    apu: b64urlEncode(aad),
    enc: "A256GCM",
  };
  const protectedB64 = b64urlEncode(
    new TextEncoder().encode(JSON.stringify(protectedHeader))
  );
  const ivB64 = b64urlEncode(iv);
  const ciphertextB64 = b64urlEncode(ciphertext);
  const tagB64 = b64urlEncode(tag);

  return `${protectedB64}.${ivB64}.${ciphertextB64}.${tagB64}`;
}

/**
 * Decrypt a compact JWE-like string produced by encryptPayload.
 */
export async function decryptPayload(
  jwe: string,
  key: Uint8Array,
  sessionId: string,
  sequenceNumber: number,
  senderDid: string
): Promise<Uint8Array> {
  if (key.length !== 32) {
    throw new Error("key must be 32 bytes for AES-256-GCM");
  }

  const parts = jwe.split(".");
  if (parts.length !== 4) {
    throw new Error("Invalid JWE: expected 4 dot-separated parts");
  }

  const [, ivB64, ciphertextB64, tagB64] = parts;
  const iv = b64urlDecode(ivB64);
  const ciphertext = b64urlDecode(ciphertextB64);
  const tag = b64urlDecode(tagB64);

  const aad = buildAad(sessionId, sequenceNumber, senderDid);

  const cryptoKey = await webcrypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  // Concatenate ciphertext + tag for AES-GCM decrypt
  const ctWithTag = new Uint8Array(ciphertext.length + tag.length);
  ctWithTag.set(ciphertext, 0);
  ctWithTag.set(tag, ciphertext.length);

  try {
    const plaintext = await webcrypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
      cryptoKey,
      ctWithTag
    );
    return new Uint8Array(plaintext);
  } catch (err) {
    throw new Error(`Decryption failed: ${err}`);
  }
}
