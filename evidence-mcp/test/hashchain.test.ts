import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { canonicalJson as vendored, chainHash, entryHash as vendoredEntryHash, GENESIS_HASH as VENDORED_GENESIS, sha256Hex } from "../src/vendor/hashchain.js";
import { canonicalJson, entryHash, GENESIS_HASH } from "../src/log.js";

// Reference: the implementation as it was in src/log.ts before it moved to the shared hash-chain module.
function referenceCanonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(referenceCanonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${referenceCanonicalJson(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

const SAMPLES: unknown[] = [
  {},
  [],
  null,
  "text",
  42,
  true,
  { b: 1, a: [2, { d: 3, c: undefined }] },
  { é: "ü", a: '\u0001"\\' },
  { "～": 2, "\u{1F600}": 1 },
  [0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, true, false, null],
  { type: "change", summary: "s", actor: "a", details: { nested: [{ z: 1, y: [] }], n: null }, seq: 1, ts: "2026-01-01T00:00:00.000Z", prev_hash: "0".repeat(64) },
  { a: [undefined, 1] }, // quirk kept on purpose: an undefined array element serializes as an empty slot
  { f: 1.5, neg: -0, big: 1e21 },
];

describe("evidence log uses the shared hash module without behaviour change", () => {
  it.each(SAMPLES.map((s, i) => [i, s] as const))("sample %i: canonical JSON equals the earlier implementation", (_i, sample) => {
    expect(canonicalJson(sample)).toBe(referenceCanonicalJson(sample));
    expect(vendored(sample)).toBe(referenceCanonicalJson(sample));
  });

  it("entryHash equals SHA-256 over the reference canonical JSON", () => {
    for (const sample of SAMPLES) {
      const expected = createHash("sha256").update(referenceCanonicalJson(sample)).digest("hex");
      expect(vendoredEntryHash(sample)).toBe(expected);
    }
    const base = { type: "change", summary: "s", actor: "a", seq: 1, ts: "2026-01-01T00:00:00.000Z", prev_hash: "0".repeat(64) } as const;
    expect(entryHash(base)).toBe(createHash("sha256").update(referenceCanonicalJson(base)).digest("hex"));
  });

  it("sha256Hex, chainHash and the genesis hash agree with the evidence log", () => {
    expect(sha256Hex("abc")).toBe(createHash("sha256").update("abc").digest("hex"));
    expect(sha256Hex(new Uint8Array([97, 98, 99]))).toBe(sha256Hex("abc"));
    expect(VENDORED_GENESIS).toBe(GENESIS_HASH);
    const entry = { seq: 1, ts: "2026-01-01T00:00:00.000Z", prev_hash: GENESIS_HASH, type: "change" as const, summary: "s", actor: "a" };
    expect(chainHash({ ...entry, hash: "ignored" })).toBe(entryHash(entry));
    expect(chainHash(entry)).toBe(entryHash(entry));
  });

  const source = new URL("../../modules/hashchain/hashchain.ts", import.meta.url);
  // The shared module lives outside this package and is not part of a standalone checkout; the check runs in the monorepo.
  it.skipIf(!existsSync(source))("vendored copy is byte-identical to the shared hash-chain module", () => {
    expect(readFileSync(new URL("../src/vendor/hashchain.ts", import.meta.url)).equals(readFileSync(source))).toBe(true);
  });
});
