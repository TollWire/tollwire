import { Script } from "node:vm";
import { describe, expect, it } from "vitest";
import { ASSETS } from "../src/web/assets.js";

// A syntax error in the page script stops the whole GUI in the browser (found with a real browser, 2026-10-16:
// raw U+2028/U+2029 inside a regular expression literal). The script is compiled here, never run.
describe("page script /app.js", () => {
  const js = ASSETS["/app.js"]?.body ?? "";

  it("compiles as JavaScript", () => {
    expect(js.length).toBeGreaterThan(0);
    expect(() => new Script(js, { filename: "app.js" })).not.toThrow();
  });

  it("contains only ASCII, so no line separator or invisible character can end a literal early", () => {
    expect([...js].filter((c) => (c.codePointAt(0) ?? 0) > 0x7e && c !== "\n")).toEqual([]);
  });

  it("masks the invisible and bidirectional characters it is meant to mask", () => {
    const m = /var UNSAFE = (\/.*\/g);/.exec(js);
    expect(m).not.toBeNull();
    const re = new Script(`(${m?.[1] ?? "/x/g"})`).runInNewContext() as RegExp;
    for (const cp of [0x00, 0x1f, 0x7f, 0x9f, 0xad, 0x61c, 0x180e, 0x200b, 0x200f, 0x2028, 0x2029, 0x202e, 0x2060, 0xfeff, 0xfffb]) {
      expect(String.fromCodePoint(cp).replace(re, ""), cp.toString(16)).toBe("");
    }
    expect("abc äöü".replace(re, "")).toBe("abc äöü");
  });
});
