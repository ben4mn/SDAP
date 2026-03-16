/**
 * Ed25519 JWS signing and verification.
 */

import { ed25519 } from "@noble/curves/ed25519";

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

/**
 * Create a compact JWS with EdDSA algorithm and kid header.
 *
 * Returns the compact serialization: <header>.<payload>.<signature>
 */
export async function signJws(
  payload: Uint8Array,
  privateKey: Uint8Array,
  keyId: string
): Promise<string> {
  const header = { alg: "EdDSA", kid: keyId };
  const headerB64 = b64urlEncode(
    new TextEncoder().encode(JSON.stringify(header))
  );
  const payloadB64 = b64urlEncode(payload);
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = ed25519.sign(signingInput, privateKey);
  const sigB64 = b64urlEncode(signature);
  return `${headerB64}.${payloadB64}.${sigB64}`;
}

/**
 * Verify a compact JWS and return the decoded payload bytes.
 *
 * Raises Error on invalid format or bad signature.
 */
export async function verifyJws(
  jws: string,
  publicKey: Uint8Array
): Promise<Uint8Array> {
  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWS: expected 3 dot-separated parts");
  }
  const [headerB64, payloadB64, sigB64] = parts;
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = b64urlDecode(sigB64);
  const valid = ed25519.verify(signature, signingInput, publicKey);
  if (!valid) {
    throw new Error("JWS signature verification failed");
  }
  return b64urlDecode(payloadB64);
}

/**
 * Create a detached-payload compact JWS.
 *
 * The payload section is empty: <header>..<signature>
 */
export async function signDetached(
  canonicalBytes: Uint8Array,
  privateKey: Uint8Array,
  keyId: string
): Promise<string> {
  const header = { alg: "EdDSA", kid: keyId, b64: false, crit: ["b64"] };
  const headerB64 = b64urlEncode(
    new TextEncoder().encode(JSON.stringify(header))
  );
  // For detached content JWS, signing input is header_b64 + "." + raw payload bytes
  const headerBytes = new TextEncoder().encode(headerB64 + ".");
  const signingInput = new Uint8Array(
    headerBytes.length + canonicalBytes.length
  );
  signingInput.set(headerBytes, 0);
  signingInput.set(canonicalBytes, headerBytes.length);

  const signature = ed25519.sign(signingInput, privateKey);
  const sigB64 = b64urlEncode(signature);
  return `${headerB64}..${sigB64}`;
}

/**
 * Verify a detached-payload JWS against the provided canonical bytes.
 *
 * Returns true if valid, false otherwise.
 */
export async function verifyDetached(
  jws: string,
  canonicalBytes: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  const parts = jws.split(".");
  if (parts.length !== 3 || parts[1] !== "") {
    return false;
  }
  const [headerB64, , sigB64] = parts;

  const headerBytes = new TextEncoder().encode(headerB64 + ".");
  const signingInput = new Uint8Array(
    headerBytes.length + canonicalBytes.length
  );
  signingInput.set(headerBytes, 0);
  signingInput.set(canonicalBytes, headerBytes.length);

  const signature = b64urlDecode(sigB64);
  try {
    return ed25519.verify(signature, signingInput, publicKey);
  } catch {
    return false;
  }
}
