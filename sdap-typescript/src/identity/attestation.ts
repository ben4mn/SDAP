/**
 * Provider attestation JWT creation and verification.
 */

import { SignJWT, jwtVerify, importJWK } from "jose";
import { z } from "zod";
import { validateDid } from "./did.js";

const VALID_SECURITY_LEVELS = new Set(["basic", "standard", "high", "critical"]);

export const SDAPAttestationClaimsSchema = z.object({
  agentType: z.string(),
  capabilities: z.array(z.string()),
  securityLevel: z.string().refine((v) => VALID_SECURITY_LEVELS.has(v), {
    message: "securityLevel must be one of basic, standard, high, critical",
  }),
  complianceTags: z.array(z.string()),
  maxDelegationDepth: z.number().int(),
});

export const AttestationPayloadSchema = z.object({
  iss: z.string(),
  sub: z.string(),
  iat: z.number(),
  exp: z.number(),
  sdap_attestation: SDAPAttestationClaimsSchema,
});

export type SDAPAttestationClaims = z.infer<typeof SDAPAttestationClaimsSchema>;
export type AttestationPayload = z.infer<typeof AttestationPayloadSchema>;

/**
 * Create a compact JWT attestation signed with an Ed25519 key.
 */
export async function createAttestation(params: {
  issuerDid: string;
  subjectDid: string;
  privateKey: Uint8Array;
  agentType: string;
  capabilities: string[];
  securityLevel: string;
  complianceTags: string[];
  maxDelegationDepth: number;
  ttlSeconds?: number;
}): Promise<string> {
  const {
    issuerDid,
    subjectDid,
    privateKey,
    agentType,
    capabilities,
    securityLevel,
    complianceTags,
    maxDelegationDepth,
    ttlSeconds = 86400,
  } = params;

  if (!validateDid(issuerDid)) {
    throw new Error(`Invalid issuer DID: ${JSON.stringify(issuerDid)}`);
  }
  if (!validateDid(subjectDid)) {
    throw new Error(`Invalid subject DID: ${JSON.stringify(subjectDid)}`);
  }
  if (!VALID_SECURITY_LEVELS.has(securityLevel)) {
    throw new Error(
      `securityLevel must be one of ${[...VALID_SECURITY_LEVELS].join(", ")}, got ${JSON.stringify(securityLevel)}`
    );
  }

  const now = Math.floor(Date.now() / 1000);

  // Import the Ed25519 private key to jose format
  const xB64 = Buffer.from(privateKey.slice(0, 32))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  // For Ed25519, public key is derived from private key
  const { ed25519 } = await import("@noble/curves/ed25519");
  const publicKey = ed25519.getPublicKey(privateKey);
  const xPubB64 = Buffer.from(publicKey)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  const jwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: xPubB64,
    d: xB64,
  };

  const key = await importJWK(jwk, "EdDSA");

  const token = await new SignJWT({
    sdap_attestation: {
      agentType,
      capabilities,
      securityLevel,
      complianceTags,
      maxDelegationDepth,
    },
  })
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(issuerDid)
    .setSubject(subjectDid)
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .sign(key);

  return token;
}

/**
 * Verify and decode a provider attestation JWT.
 */
export async function verifyAttestation(
  token: string,
  issuerPublicKey: Uint8Array
): Promise<AttestationPayload> {
  const xB64 = Buffer.from(issuerPublicKey)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  const jwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: xB64,
  };

  const key = await importJWK(jwk, "EdDSA");

  let payload: Record<string, unknown>;
  try {
    const result = await jwtVerify(token, key, { algorithms: ["EdDSA"] });
    payload = result.payload as Record<string, unknown>;
  } catch (err) {
    throw new Error(`Invalid attestation token: ${err}`);
  }

  return AttestationPayloadSchema.parse(payload);
}
