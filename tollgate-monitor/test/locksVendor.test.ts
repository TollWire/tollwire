import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// The vendored copy of the locks module must equal its single source. In a stand-alone checkout the source is missing.
const PAIRS: [string, string][] = [
  ["../../modules/locks/locks.ts", "../src/vendor/locks.ts"],
  ["../../modules/locks/protocol.ts", "../src/vendor/controlProtocol.ts"],
];

describe("vendored locks module", () => {
  for (const [from, to] of PAIRS) {
    const source = new URL(from, import.meta.url);
    it.skipIf(!existsSync(source))(`${to} is byte-identical to its source`, () => {
      expect(readFileSync(new URL(to, import.meta.url)).equals(readFileSync(source))).toBe(true);
    });
  }
  it("sits next to hashchain.ts, which it imports", () => {
    expect(existsSync(new URL("../src/vendor/hashchain.ts", import.meta.url))).toBe(true);
  });
});
