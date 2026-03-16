/**
 * A2A Agent Card SDAP extension builder.
 */

const VALID_SECURITY_LEVELS = new Set(["basic", "standard", "high", "critical"]);

export interface SdapExtension {
  sdap: {
    version: string;
    did: string;
    handshakeEndpoint: string;
    supportedLayers: number[];
    minSecurityLevel: string;
  };
}

/**
 * Build the sdap extension object for an A2A Agent Card.
 */
export function buildSdapExtension(params: {
  did: string;
  handshakeEndpoint: string;
  supportedLayers: number[];
  minSecurityLevel?: string;
}): SdapExtension {
  const {
    did,
    handshakeEndpoint,
    supportedLayers,
    minSecurityLevel = "basic",
  } = params;

  if (!VALID_SECURITY_LEVELS.has(minSecurityLevel)) {
    throw new Error(
      `minSecurityLevel must be one of ${[...VALID_SECURITY_LEVELS].join(", ")}, ` +
        `got ${JSON.stringify(minSecurityLevel)}`
    );
  }

  return {
    sdap: {
      version: "1.0",
      did,
      handshakeEndpoint,
      supportedLayers,
      minSecurityLevel,
    },
  };
}
