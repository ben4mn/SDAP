/**
 * JSON Canonical Serialization (JCS) — RFC 8785.
 */

/**
 * Return RFC 8785 canonical JSON bytes for obj.
 *
 * Rules:
 * - Keys sorted lexicographically (Unicode code-point order), recursively
 * - No insignificant whitespace
 * - Strings encoded as UTF-8 with standard JSON escaping
 * - Numbers: no trailing zeros in fractions; integers have no decimal point
 * - null → null, booleans → true / false
 */
export function canonicalize(obj: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(serialize(obj));
}

function serialize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!isFinite(value)) {
      throw new Error("JCS does not support NaN or Infinity");
    }
    return serializeNumber(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const items = value.map((v) => serialize(v)).join(",");
    return `[${items}]`;
  }
  if (typeof value === "object" && value !== null) {
    const obj = value as Record<string, unknown>;
    const pairs = Object.keys(obj)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${serialize(obj[k])}`)
      .join(",");
    return `{${pairs}}`;
  }
  throw new Error(`Unsupported type for JCS: ${typeof value}`);
}

function serializeNumber(value: number): string {
  // Integer check
  if (Number.isInteger(value)) {
    return value.toString();
  }
  // Use toPrecision for float representation following ES2019 / RFC 8785
  // JavaScript's default number serialization is consistent with ES2019
  const s = String(value);
  if (s.includes("e") || s.includes("E")) {
    return normalizeExp(s);
  }
  return s;
}

function normalizeExp(s: string): string {
  // Normalize scientific notation: e+06 -> e+6
  return s.toLowerCase().replace(/e([+-])0*(\d+)/, (_, sign: string, digits: string) => `e${sign}${digits}`);
}
