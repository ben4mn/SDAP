/**
 * SHA-256 hashing utilities.
 */

import { sha256 } from "@noble/hashes/sha256";

/**
 * Return lowercase hex-encoded SHA-256 digest of data.
 */
export function sha256Hex(data: Uint8Array): string {
  return Buffer.from(sha256(data)).toString("hex");
}

/**
 * Return raw bytes SHA-256 digest of data.
 */
export function sha256Bytes(data: Uint8Array): Uint8Array {
  return sha256(data);
}
