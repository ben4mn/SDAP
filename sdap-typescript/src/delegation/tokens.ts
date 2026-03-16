/**
 * Delegation token creation and verification.
 */

import { SignJWT, jwtVerify, importJWK } from "jose";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import { sha256 } from "@noble/hashes/sha256";
import { validateDid } from "../identity/did.js";
import { ed25519 } from "@noble/curves/ed25519";

export const DelegationConstraintsSchema = z
  .object({
    notBefore: z.number().int().optional(),
    notAfter: z.number().int().optional(),
    maxUses: z.number().int().optional(),
    allowedResources: z.array(z.string()).optional(),
    allowedActions: z.array(z.string()).optional(),
    ipRestrictions: z.array(z.string()).optional(),
    requireMFA: z.boolean().optional(),
    dataClassification: z.string().optional(),
  })
  .passthrough();

export const DelegationTokenPayloadSchema = z
  .object({
    iss: z.string(),
    sub: z.string(),
    aud: z.string(),
    iat: z.number(),
    exp: z.number(),
    jti: z.string(),
    scopes: z.array(z.string()),
    constraints: DelegationConstraintsSchema,
    delegationDepth: z.number().int().default(0),
    parentTokenId: z.string().optional(),
    parentChainHash: z.string().optional(),
  })
  .passthrough();

export type DelegationConstraints = z.infer<typeof DelegationConstraintsSchema>;
export type DelegationTokenPayload = z.infer<typeof DelegationTokenPayloadSchema>;

/**
 * Compute SHA-256(parent_chain_hash + parent_jti).
 *
 * If parent_chain_hash is null (root token), hash is SHA-256(parent_jti).
 */
export function computeChainHash(
  parentChainHash: string | null,
  parentJti: string
): string {
  const data = (parentChainHash ?? "") + parentJti;
  return Buffer.from(sha256(new TextEncoder().encode(data))).toString("hex");
}

/**
 * Create a signed delegation token JWT.
 */
export async function createDelegationToken(params: {
  issuerDid: string;
  delegateeDid: string;
  audienceDid: string;
  privateKey: Uint8Array;
  scopes: string[];
  constraints: DelegationConstraints;
  parentTokenId?: string;
  delegationDepth?: number;
  parentChainHash?: string;
  ttlSeconds?: number;
}): Promise<string> {
  const {
    issuerDid,
    delegateeDid,
    audienceDid,
    privateKey,
    scopes,
    constraints,
    parentTokenId,
    delegationDepth = 0,
    parentChainHash,
    ttlSeconds = 3600,
  } = params;

  if (!validateDid(issuerDid)) {
    throw new Error(`Invalid issuer DID: ${JSON.stringify(issuerDid)}`);
  }
  if (!validateDid(delegateeDid)) {
    throw new Error(`Invalid delegatee DID: ${JSON.stringify(delegateeDid)}`);
  }
  if (!validateDid(audienceDid)) {
    throw new Error(`Invalid audience DID: ${JSON.stringify(audienceDid)}`);
  }

  const now = Math.floor(Date.now() / 1000);
  const jti = randomUUID();

  let chainHash: string | undefined;
  if (parentTokenId !== undefined) {
    chainHash = computeChainHash(parentChainHash ?? null, parentTokenId);
  }

  // Build payload
  const payloadObj: Record<string, unknown> = {
    scopes,
    constraints: removeUndefined(constraints),
    delegationDepth,
  };
  if (parentTokenId !== undefined) {
    payloadObj["parentTokenId"] = parentTokenId;
  }
  if (chainHash !== undefined) {
    payloadObj["parentChainHash"] = chainHash;
  }

  // Import the Ed25519 private key
  const publicKey = ed25519.getPublicKey(privateKey);
  const xPubB64 = Buffer.from(publicKey)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  const dB64 = Buffer.from(privateKey)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  const jwk = { kty: "OKP", crv: "Ed25519", x: xPubB64, d: dB64 };
  const key = await importJWK(jwk, "EdDSA");

  const token = await new SignJWT(payloadObj)
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(issuerDid)
    .setSubject(delegateeDid)
    .setAudience(audienceDid)
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .setJti(jti)
    .sign(key);

  return token;
}

/**
 * Verify and decode a delegation token.
 */
export async function decodeDelegationToken(
  token: string,
  issuerPublicKey: Uint8Array
): Promise<DelegationTokenPayload> {
  const xB64 = Buffer.from(issuerPublicKey)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  const jwk = { kty: "OKP", crv: "Ed25519", x: xB64 };
  const key = await importJWK(jwk, "EdDSA");

  let payload: Record<string, unknown>;
  try {
    const result = await jwtVerify(token, key, {
      algorithms: ["EdDSA"],
    });
    payload = result.payload as Record<string, unknown>;
  } catch (err) {
    throw new Error(`Invalid delegation token: ${err}`);
  }

  const constraints = (payload["constraints"] as DelegationConstraints) ?? {};

  return DelegationTokenPayloadSchema.parse({
    ...payload,
    constraints,
  });
}

function removeUndefined(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) result[k] = v;
  }
  return result;
}
