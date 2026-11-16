import { describe, expect, it } from "vitest";
import { isEntryPoint } from "../src/entry.js";

describe("isEntryPoint", () => {
  const self = new URL(import.meta.url);
  it("matches only the module itself", () => {
    expect(isEntryPoint(self.href, self.pathname)).toBe(true);
    expect(isEntryPoint(self.href, undefined)).toBe(false);
    expect(isEntryPoint(self.href, "/does/not/exist.js")).toBe(false);
  });
});
