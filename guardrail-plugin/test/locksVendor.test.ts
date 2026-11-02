import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// The vendored copy of the locks module must equal its single source. In a stand-alone checkout the source is missing.
const SOURCE = new URL("../../modules/locks/locks.ts", import.meta.url);

describe("vendored locks module", () => {
  it.skipIf(!existsSync(SOURCE))("src/vendor/locks.ts is byte-identical to its single source (modules/locks/locks.ts)", () => {
    expect(readFileSync(new URL("../src/vendor/locks.ts", import.meta.url)).equals(readFileSync(SOURCE))).toBe(true);
  });
  it("sits next to hashchain.ts, which it imports", () => {
    expect(existsSync(new URL("../src/vendor/hashchain.ts", import.meta.url))).toBe(true);
  });
});
