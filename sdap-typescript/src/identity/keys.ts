/**
 * Key generation and encoding utilities for SDAP identity.
 */

import { ed25519, x25519 } from "@noble/curves/ed25519";

// base58btc alphabet (Bitcoin variant)
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  keyId: string;
}

function base58Encode(data: Uint8Array): string {
  // Count leading zero bytes
  let count = 0;
  for (const b of data) {
    if (b === 0) count++;
    else break;
  }

  let n = BigInt("0x" + Buffer.from(data).toString("hex"));
  const result: string[] = [];
  while (n > 0n) {
    const remainder = Number(n % 58n);
    n = n / 58n;
    result.push(BASE58_ALPHABET[remainder]);
  }
  for (let i = 0; i < count; i++) {
    result.push(BASE58_ALPHABET[0]);
  }
  return result.reverse().join("");
}

function base58Decode(s: string): Uint8Array {
  let n = 0n;
  for (const char of s) {
    const idx = BASE58_ALPHABET.indexOf(char);
    if (idx < 0) throw new Error(`Invalid base58 character: ${char}`);
    n = n * 58n + BigInt(idx);
  }
  // Count leading '1' chars (represent zero bytes)
  let count = 0;
  for (const char of s) {
    if (char === "1") count++;
    else break;
  }
  const hex = n.toString(16).padStart(2, "0");
  const padded = hex.length % 2 === 0 ? hex : "0" + hex;
  const bytes = n > 0n ? Buffer.from(padded, "hex") : Buffer.alloc(0);
  const result = new Uint8Array(count + bytes.length);
  result.set(bytes, count);
  return result;
}

/**
 * Generate a fresh Ed25519 key pair.
 */
export function generateEd25519KeyPair(keyId: string): KeyPair {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey, keyId };
}

/**
 * Generate a fresh X25519 key pair.
 */
export function generateX25519KeyPair(keyId: string): KeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey, keyId };
}

/**
 * Encode a public key as a multibase base58btc string ('z' prefix).
 */
export function publicKeyToMultibase(key: Uint8Array): string {
  return "z" + base58Encode(key);
}

/**
 * Decode a multibase string back to raw public key bytes.
 */
export function multibaseToPublicKey(multibase: string): Uint8Array {
  if (!multibase.startsWith("z")) {
    throw new Error("Only base58btc multibase ('z' prefix) is supported");
  }
  return base58Decode(multibase.slice(1));
}

/**
 * Encode an X25519 public key as a JWK (OKP key type, X25519 curve).
 */
export function publicKeyToJwk(key: Uint8Array): JsonWebKey {
  const xB64 = Buffer.from(key)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  return {
    kty: "OKP",
    crv: "X25519",
    x: xB64,
  };
}

/**
 * Decode a JWK dict for an X25519 public key to raw bytes.
 */
export function jwkToPublicKey(jwk: JsonWebKey): Uint8Array {
  if (jwk.kty !== "OKP" || jwk.crv !== "X25519") {
    throw new Error("JWK must be an OKP key with crv=X25519");
  }
  if (!jwk.x) throw new Error("JWK missing x parameter");
  const xB64 = jwk.x.replace(/-/g, "+").replace(/_/g, "/");
  const padding = 4 - (xB64.length % 4);
  const padded = padding !== 4 ? xB64 + "=".repeat(padding) : xB64;
  return new Uint8Array(Buffer.from(padded, "base64"));
}
