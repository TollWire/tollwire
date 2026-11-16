import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { isEntryPoint } from "../src/entry.js";

describe("isEntryPoint", () => {
  const self = new URL(import.meta.url);
  it("matches the module itself", () => {
    expect(isEntryPoint(self.href, self.pathname)).toBe(true);
  });
  it("rejects other or missing scripts", () => {
    expect(isEntryPoint(self.href, undefined)).toBe(false);
    expect(isEntryPoint(self.href, new URL("../package.json", import.meta.url).pathname)).toBe(false);
  });
  it("runs rather than silently skipping when realpath fails", () => {
    expect(isEntryPoint(self.href, "/does/not/exist.js")).toBe(true);
    expect(isEntryPoint(pathToFileURL("/does/not/exist.js").href, self.pathname)).toBe(true);
  });
});
