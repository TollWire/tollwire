// Hash-chain primitives: canonical JSON, SHA-256 and the chain hash.
// This file is kept byte-identical in every package that uses it; a test in each package checks the copy.
// Only node:crypto is used; no other imports, no dependencies.
import { createHash } from "node:crypto";

/** `prev_hash` of the first entry of a chain. */
export const GENESIS_HASH = "0".repeat(64);

/**
 * Deterministic JSON: object keys sorted by UTF-16 code unit, members with value `undefined` omitted, no whitespace,
 * scalars via JSON.stringify. For strings, safe integers, booleans, null, arrays and objects this equals RFC 8785.
 * Behaviour is identical to the implementation the evidence log used before this module existed.
 */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/** Lower-case hex SHA-256 of a string (UTF-8) or of bytes. */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** SHA-256 over the canonical JSON of `entry`. The caller omits the `hash` field. */
export function entryHash(entry: unknown): string {
  return sha256Hex(canonicalJson(entry));
}

/** Hash of a chain record: SHA-256 over the canonical JSON of all fields except `hash`. */
export function chainHash(record: Record<string, unknown>): string {
  const rest: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) if (key !== "hash") rest[key] = value;
  return entryHash(rest);
}
