/**
 * Delegation chain validation.
 */

import {
  DelegationConstraints,
  DelegationTokenPayload,
  computeChainHash,
  decodeDelegationToken,
} from "./tokens.js";

/**
 * Parse a scope string in "resource:action[:qualifier]" format.
 */
export function parseScope(scope: string): {
  resource: string;
  action: string;
  qualifier?: string;
} {
  const parts = scope.split(":");
  if (parts.length < 2) {
    throw new Error(
      `Invalid scope format: ${JSON.stringify(scope)} (expected resource:action[:qualifier])`
    );
  }
  return {
    resource: parts[0],
    action: parts[1],
    qualifier: parts[2],
  };
}

function isCovered(scope: string, parentScopes: string[]): boolean {
  if (parentScopes.includes(scope)) return true;
  if (parentScopes.includes("*") || parentScopes.includes("*:*")) return true;

  let resource: string, action: string, qualifier: string | undefined;
  try {
    ({ resource, action, qualifier } = parseScope(scope));
  } catch {
    return parentScopes.includes(scope);
  }

  if (parentScopes.includes(`${resource}:*`)) return true;
  if (qualifier !== undefined && parentScopes.includes(`${resource}:${action}`))
    return true;

  return false;
}

/**
 * Return true if every scope in childScopes is covered by parentScopes.
 */
export function isScopeSubset(
  childScopes: string[],
  parentScopes: string[]
): boolean {
  return childScopes.every((s) => isCovered(s, parentScopes));
}

function constraintsTightenedOrEqual(
  child: DelegationConstraints,
  parent: DelegationConstraints
): boolean {
  // maxUses: can only tighten (reduce)
  if (parent.maxUses !== undefined) {
    if (child.maxUses === undefined || child.maxUses > parent.maxUses)
      return false;
  }

  // notAfter: child's expiry must not exceed parent's
  if (parent.notAfter !== undefined) {
    if (child.notAfter === undefined || child.notAfter > parent.notAfter)
      return false;
  }

  // notBefore: child's start must not be before parent's
  if (parent.notBefore !== undefined) {
    if (child.notBefore === undefined || child.notBefore < parent.notBefore)
      return false;
  }

  // allowedResources: child must be subset of parent
  if (parent.allowedResources !== undefined) {
    if (child.allowedResources === undefined) return false;
    const parentSet = new Set(parent.allowedResources);
    if (!child.allowedResources.every((r) => parentSet.has(r))) return false;
  }

  // allowedActions: child must be subset of parent
  if (parent.allowedActions !== undefined) {
    if (child.allowedActions === undefined) return false;
    const parentSet = new Set(parent.allowedActions);
    if (!child.allowedActions.every((a) => parentSet.has(a))) return false;
  }

  // ipRestrictions: child must be subset of parent
  if (parent.ipRestrictions !== undefined) {
    if (child.ipRestrictions === undefined) return false;
    const parentSet = new Set(parent.ipRestrictions);
    if (!child.ipRestrictions.every((ip) => parentSet.has(ip))) return false;
  }

  // requireMFA: if parent requires it, child must too
  if (parent.requireMFA === true && child.requireMFA !== true) return false;

  return true;
}

function decodeJwtPayloadRaw(token: string): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Not a valid JWT");
  }
  const payloadB64 = parts[1];
  const padding = 4 - (payloadB64.length % 4);
  const padded =
    padding !== 4 ? payloadB64 + "=".repeat(padding) : payloadB64;
  const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
}

/**
 * Validate a chain of delegation JWT tokens and return the leaf payload.
 */
export async function validateDelegationChain(
  tokens: string[],
  resolveKeyFn: (did: string) => Uint8Array
): Promise<DelegationTokenPayload> {
  if (tokens.length === 0) {
    throw new Error("Empty delegation chain");
  }

  const decoded: DelegationTokenPayload[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    const rawPayload = decodeJwtPayloadRaw(token);
    const iss = rawPayload["iss"] as string | undefined;
    if (!iss) {
      throw new Error(`Token ${i} missing 'iss' claim`);
    }

    const issuerKey = resolveKeyFn(iss);
    const payload = await decodeDelegationToken(token, issuerKey);
    decoded.push(payload);
  }

  // Check chain continuity: token[n].sub == token[n+1].iss
  for (let i = 0; i < decoded.length - 1; i++) {
    if (decoded[i].sub !== decoded[i + 1].iss) {
      throw new Error(
        `Chain continuity broken at index ${i}: ` +
          `token[${i}].sub=${JSON.stringify(decoded[i].sub)} != token[${i + 1}].iss=${JSON.stringify(decoded[i + 1].iss)}`
      );
    }
  }

  // Check depth consistency
  for (let i = 0; i < decoded.length; i++) {
    if (decoded[i].delegationDepth !== i) {
      throw new Error(
        `Token ${i} has delegationDepth=${decoded[i].delegationDepth}, expected ${i}`
      );
    }
  }

  // Check scope narrowing
  for (let i = 0; i < decoded.length - 1; i++) {
    const parent = decoded[i];
    const child = decoded[i + 1];
    if (!isScopeSubset(child.scopes, parent.scopes)) {
      throw new Error(
        `Token ${i + 1} scopes ${JSON.stringify(child.scopes)} are not a subset of ` +
          `parent token ${i} scopes ${JSON.stringify(parent.scopes)}`
      );
    }
  }

  // Check constraint tightening
  for (let i = 0; i < decoded.length - 1; i++) {
    const parent = decoded[i];
    const child = decoded[i + 1];
    if (!constraintsTightenedOrEqual(child.constraints, parent.constraints)) {
      throw new Error(
        `Token ${i + 1} constraints are looser than parent token ${i} constraints`
      );
    }
  }

  // Check chain hash integrity
  let runningHash: string | null = null;
  for (let i = 0; i < decoded.length; i++) {
    const payload = decoded[i];
    if (i === 0) {
      // Root token should have no parentTokenId
      if (payload.parentTokenId !== undefined) {
        throw new Error("Root token (index 0) should not have parentTokenId");
      }
      runningHash = null;
    } else {
      const parent = decoded[i - 1];
      const expectedHash = computeChainHash(runningHash, parent.jti);
      if (payload.parentChainHash !== expectedHash) {
        throw new Error(
          `Token ${i} chain hash mismatch: ` +
            `expected ${JSON.stringify(expectedHash)}, got ${JSON.stringify(payload.parentChainHash)}`
        );
      }
      if (payload.parentTokenId !== parent.jti) {
        throw new Error(
          `Token ${i} parentTokenId=${JSON.stringify(payload.parentTokenId)} ` +
            `does not match parent jti=${JSON.stringify(parent.jti)}`
        );
      }
      runningHash = expectedHash;
    }
  }

  // Check temporal bounds
  const now = Math.floor(Date.now() / 1000);
  for (let i = 0; i < decoded.length; i++) {
    const payload = decoded[i];
    if (
      payload.constraints.notBefore !== undefined &&
      now < payload.constraints.notBefore
    ) {
      throw new Error(`Token ${i} is not yet valid (notBefore constraint)`);
    }
    if (
      payload.constraints.notAfter !== undefined &&
      now > payload.constraints.notAfter
    ) {
      throw new Error(`Token ${i} has expired (notAfter constraint)`);
    }
  }

  return decoded[decoded.length - 1];
}
