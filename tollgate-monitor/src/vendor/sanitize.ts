// Sanitizer for every string that enters a log event.
// Backslashes are doubled first and control/format characters are written as \u{XXXX}, so that log lines cannot be
// forged with control characters or bidirectional text and the mapping from text to log text stays injective.

// C0, DEL, C1 (Cc), format characters incl. bidirectional controls (Cf), line/paragraph separators, lone surrogates.
const UNSAFE = /\\|[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/gu;

export function sanitize(text: string): string {
  // One pass: the escapes written here are not scanned again, which equals "backslashes first".
  return text.replace(UNSAFE, (ch) => {
    if (ch === "\\") return "\\\\";
    const cp = ch.codePointAt(0) as number;
    return `\\u{${cp.toString(16).toUpperCase().padStart(4, "0")}}`;
  });
}

/** Sanitizes every string value (not the keys) of a JSON-like structure. */
export function sanitizeDeep<T>(value: T): T {
  if (typeof value === "string") return sanitize(value) as T;
  if (Array.isArray(value)) return value.map((v) => sanitizeDeep(v)) as T;
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = sanitizeDeep(v);
    return out as T;
  }
  return value;
}

// One logical character of sanitized text: a doubled backslash, an escape, or one code point.
const TOKEN = /\\\\|\\u\{[0-9A-F]{4,6}\}|[\s\S]/gu;

/** Cuts sanitized text to `max` logical characters without splitting an escape, a backslash pair or a surrogate pair. */
export function truncateText(text: string, max: number): { text: string; cut: boolean } {
  if (text.length <= max) return { text, cut: false };
  let count = 0;
  let end = 0;
  for (const match of text.matchAll(TOKEN)) {
    if (count === max) return { text: text.slice(0, end), cut: true };
    count += 1;
    end += match[0].length;
  }
  return { text, cut: false };
}
