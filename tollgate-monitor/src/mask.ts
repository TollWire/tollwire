// Output masking: control, format and separator characters in strings that come from event files are written as
// \u{XXXX}. Unlike the sanitizer of the writers, backslashes stay as they are (the writers already escaped them; a second
// pass would double them). Keys are masked too. Depth and breadth are bounded.
const UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/gu;

export function maskText(text: string): string {
  return text.replace(UNSAFE, (ch) => `\\u{${(ch.codePointAt(0) as number).toString(16).toUpperCase().padStart(4, "0")}}`);
}

const MAX_DEPTH = 8;
const MAX_ENTRIES = 256;

/** Copy of a JSON value with masked strings and keys. Objects get no prototype, so a key `__proto__` stays plain data. */
export function maskDeep(value: unknown, depth = 0): unknown {
  if (typeof value === "string") return maskText(value);
  if (value === null || typeof value === "number" || typeof value === "boolean") return value;
  if (depth >= MAX_DEPTH) return null;
  if (Array.isArray(value)) return value.slice(0, MAX_ENTRIES).map((v) => maskDeep(v, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const [k, v] of Object.entries(value as Record<string, unknown>).slice(0, MAX_ENTRIES)) out[maskText(k)] = maskDeep(v, depth + 1);
    return out;
  }
  return null;
}
