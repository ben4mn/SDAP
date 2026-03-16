/**
 * SDAP DID document creation, parsing, validation, and resolution.
 */

import { z } from "zod";
import {
  publicKeyToMultibase,
  generateEd25519KeyPair,
  generateX25519KeyPair,
} from "./keys.js";

// Regex patterns derived from the JSON schema
const DID_PATTERN =
  /^did:sdap:([a-z0-9][a-z0-9\-\.]*\.[a-z]{2,})(?::([A-Za-z0-9\-_\.]+))?$/;

const DID_CONTEXTS = [
  "https://www.w3.org/ns/did/v1",
  "https://w3id.org/security/suites/ed25519-2020/v1",
  "https://w3id.org/security/suites/x25519-2020/v1",
  "https://sdap.dev/contexts/v1",
];

// Zod schemas
export const VerificationMethodSchema = z.object({
  id: z.string(),
  type: z.string(),
  controller: z.string(),
  publicKeyMultibase: z.string(),
  revoked: z.string().optional(),
});

export const ServiceEndpointSchema = z.object({
  id: z.string(),
  type: z.string(),
  serviceEndpoint: z.string(),
});

export const DIDDocumentSchema = z.object({
  "@context": z.array(z.string()),
  id: z.string(),
  controller: z.string(),
  verificationMethod: z.array(VerificationMethodSchema),
  authentication: z.array(z.string()),
  keyAgreement: z.array(z.string()),
  service: z.array(ServiceEndpointSchema),
  providerAttestation: z.string().optional(),
  created: z.string(),
  updated: z.string(),
  deactivated: z.boolean().optional(),
  "sdap:agentType": z.string().optional(),
  "sdap:fleetId": z.string().optional(),
  "sdap:instanceId": z.string().optional(),
  "sdap:supportedLayers": z.array(z.number()).optional(),
  "sdap:minSecurityLevel": z.string().optional(),
});

export type VerificationMethod = z.infer<typeof VerificationMethodSchema>;
export type ServiceEndpoint = z.infer<typeof ServiceEndpointSchema>;
export type DIDDocument = z.infer<typeof DIDDocumentSchema>;

/**
 * Return true if did is a syntactically valid did:sdap DID.
 */
export function validateDid(did: string): boolean {
  return DID_PATTERN.test(did);
}

/**
 * Extract { providerDomain, agentId } from a did:sdap DID.
 */
export function parseDid(did: string): {
  providerDomain: string;
  agentId: string;
} {
  const m = DID_PATTERN.exec(did);
  if (!m) {
    throw new Error(`Invalid did:sdap DID: ${JSON.stringify(did)}`);
  }
  return {
    providerDomain: m[1],
    agentId: m[2] ?? "",
  };
}

export interface CreateDidParams {
  providerDomain: string;
  agentId: string;
  authPublicKey: Uint8Array;
  agreementPublicKey: Uint8Array;
  authKeyId?: string;
  agreementKeyId?: string;
  a2aEndpoint?: string;
  handshakeEndpoint?: string;
  providerAttestation?: string;
  created?: string;
  updated?: string;
  extraFields?: Record<string, unknown>;
}

/**
 * Construct a DIDDocument for an SDAP agent.
 */
export function createDid(params: CreateDidParams): DIDDocument {
  const {
    providerDomain,
    agentId,
    authPublicKey,
    agreementPublicKey,
    authKeyId = "auth-key-1",
    agreementKeyId = "agree-key-1",
    a2aEndpoint,
    handshakeEndpoint,
    providerAttestation,
    created,
    updated,
    extraFields,
  } = params;

  const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const createdAt = created ?? now;
  const updatedAt = updated ?? now;

  const did = `did:sdap:${providerDomain}:${agentId}`;
  const controller = `did:sdap:${providerDomain}`;

  const authVmId = `${did}#${authKeyId}`;
  const agreeVmId = `${did}#${agreementKeyId}`;

  const verificationMethod: VerificationMethod[] = [
    {
      id: authVmId,
      type: "Ed25519VerificationKey2020",
      controller: did,
      publicKeyMultibase: publicKeyToMultibase(authPublicKey),
    },
    {
      id: agreeVmId,
      type: "X25519KeyAgreementKey2020",
      controller: did,
      publicKeyMultibase: publicKeyToMultibase(agreementPublicKey),
    },
  ];

  const services: ServiceEndpoint[] = [];
  if (a2aEndpoint) {
    services.push({
      id: `${did}#a2a`,
      type: "A2AAgentEndpoint",
      serviceEndpoint: a2aEndpoint,
    });
  }
  if (handshakeEndpoint) {
    services.push({
      id: `${did}#handshake`,
      type: "SDAPHandshakeEndpoint",
      serviceEndpoint: handshakeEndpoint,
    });
  }
  // Ensure at least 2 services per schema minItems=2
  while (services.length < 2) {
    const idx = services.length + 1;
    const svcType =
      idx === 1 ? "A2AAgentEndpoint" : "SDAPHandshakeEndpoint";
    services.push({
      id: `${did}#service-${idx}`,
      type: svcType,
      serviceEndpoint: `https://${providerDomain}/sdap/service-${idx}`,
    });
  }

  const docData: Record<string, unknown> = {
    "@context": DID_CONTEXTS,
    id: did,
    controller,
    verificationMethod,
    authentication: [authVmId],
    keyAgreement: [agreeVmId],
    service: services,
    created: createdAt,
    updated: updatedAt,
  };

  if (providerAttestation) {
    docData["providerAttestation"] = providerAttestation;
  }
  if (extraFields) {
    Object.assign(docData, extraFields);
  }

  return DIDDocumentSchema.parse(docData);
}

/**
 * Resolve a did:sdap DID via the HTTPS .well-known endpoint.
 */
export async function resolveDid(
  did: string,
  fetchFn: typeof fetch = fetch
): Promise<DIDDocument> {
  const { providerDomain, agentId } = parseDid(did);
  if (!agentId) {
    throw new Error("Cannot resolve a provider-only DID (no agentId)");
  }

  const url = `https://${providerDomain}/.well-known/sdap/did/${agentId}`;
  const response = await fetchFn(url);
  if (!response.ok) {
    throw new Error(
      `DID resolution failed for ${did}: HTTP ${response.status}`
    );
  }
  const data = await response.json();
  return DIDDocumentSchema.parse(data);
}
