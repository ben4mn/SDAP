/**
 * X25519 ECDH key exchange and HKDF-based session key derivation.
 */

import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

/**
 * Perform X25519 ECDH and return the raw 32-byte shared secret.
 */
export function performEcdh(
  privateKey: Uint8Array,
  peerPublicKey: Uint8Array
): Uint8Array {
  return x25519.getSharedSecret(privateKey, peerPublicKey);
}

/**
 * Derive two 32-byte session keys from a shared secret using HKDF-SHA256.
 *
 * Returns { encryptKey, macKey } — each 32 bytes.
 */
export function deriveSessionKeys(
  sharedSecret: Uint8Array,
  nonceA: Uint8Array,
  nonceB: Uint8Array,
  sessionId: string
): { encryptKey: Uint8Array; macKey: Uint8Array } {
  // salt = SHA256(nonce_a + nonce_b)
  const combined = new Uint8Array(nonceA.length + nonceB.length);
  combined.set(nonceA, 0);
  combined.set(nonceB, nonceA.length);
  const salt = sha256(combined);

  const infoStr = "sdap-session-v1" + sessionId;
  const info = new TextEncoder().encode(infoStr);

  const keyMaterial = hkdf(sha256, sharedSecret, salt, info, 64);
  const encryptKey = keyMaterial.slice(0, 32);
  const macKey = keyMaterial.slice(32, 64);
  return { encryptKey, macKey };
}
