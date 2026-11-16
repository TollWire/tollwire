import { readFileSync, existsSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { canonicalJson, chainHash, entryHash, GENESIS_HASH, sha256Hex } from "../src/vendor/hashchain.js";

// Test vectors computed independently (Python hashlib over the literal canonical string, not with this code).
const VECTORS: { name: string; value: unknown; canonical: string; sha256: string }[] = [
  { name: "empty object", value: {}, canonical: "{}", sha256: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" },
  {
    name: "sorted keys, nested, null",
    value: { b: 1, a: [2, { d: 3, c: null }] },
    canonical: '{"a":[2,{"c":null,"d":3}],"b":1}',
    sha256: "05d056f52fa44429fb2c28612f0ecc637c2b5c9515c394aa667f7712c0bdcb42",
  },
  {
    name: "escapes and non-ASCII",
    value: { é: "ü", a: '\u0001"\\' },
    canonical: '{"a":"\\u0001\\"\\\\","é":"ü"}',
    sha256: "eaa03169c126ca8efddaee0b827b634d361a7ce5f6cfb17364ecde35822d7c16",
  },
  {
    name: "keys sorted by UTF-16 code unit (surrogate pair before U+FF5E)",
    value: { "～": 2, "\u{1F600}": 1 },
    canonical: '{"\u{1F600}":1,"～":2}',
    sha256: "5848fd4854a6ce2c6f23359368eef2f1a8d667176e91a9b74a92b7086fa7b207",
  },
  {
    name: "safe integers, booleans, null",
    value: [0, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, true, false, null],
    canonical: "[0,9007199254740991,-9007199254740991,true,false,null]",
    sha256: "1e31dee67ec3550cb95c19401382e729837f878a443bd0c5f98fa3bde9295f7d",
  },
];

describe("hashchain module (vendored copy)", () => {
  it.each(VECTORS)("canonical JSON and SHA-256 for $name", ({ value, canonical, sha256 }) => {
    expect(canonicalJson(value)).toBe(canonical);
    expect(entryHash(value)).toBe(sha256);
    expect(sha256Hex(canonical)).toBe(sha256);
  });

  it("omits undefined object members like JSON.stringify", () => {
    expect(canonicalJson({ b: 1, a: [2, { d: 3, c: undefined }] })).toBe('{"a":[2,{"d":3}],"b":1}');
  });

  it("hashes a record without its hash field (chain vector)", () => {
    const record = { seq: 1, ts: "2026-01-01T00:00:00.000Z", event: "x", prev_hash: GENESIS_HASH };
    const expected = "188406970afcf72f32e0e8bfdaf65b8b4d01e8f026aeeeaace849ca534466492";
    expect(chainHash(record)).toBe(expected);
    expect(chainHash({ ...record, hash: "ignored" })).toBe(expected);
    expect(GENESIS_HASH).toBe("0".repeat(64));
  });

  it("hashes binary input", () => {
    expect(sha256Hex(new Uint8Array([]))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  // Drift check: the shared module is the single source; each package carries a byte-identical copy. The module lives
  // outside this package and is not part of a standalone checkout, so the comparison only runs in the monorepo.
  const source = new URL("../../modules/hashchain/hashchain.ts", import.meta.url);
  it.skipIf(!existsSync(source))("is byte-identical to the shared hash-chain module", () => {
    const vendored = readFileSync(new URL("../src/vendor/hashchain.ts", import.meta.url));
    expect(vendored.equals(readFileSync(source))).toBe(true);
  });
});
