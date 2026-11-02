import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { codeLanguage, writeIndicator } from "../src/codeScan.js";

// Shared with the Python port: both implementations must classify identically.
const cases = JSON.parse(readFileSync(new URL("./fixtures/command-cases.json", import.meta.url), "utf8")) as {
  code: { lang: string; code: string; write: boolean }[];
};

describe("inline code heuristic (shared cases)", () => {
  it("has cases for every language", () => {
    expect(new Set(cases.code.map((c) => c.lang))).toEqual(new Set(["python", "js", "perl", "ruby", "php", "awk", "sed", "lua"]));
  });
  it.each(cases.code)("$lang: $code -> $write", ({ lang, code, write }) => expect(writeIndicator(code, lang)).toBe(write));
});

describe("codeLanguage", () => {
  it.each([
    ["python3.12", "python"], ["pypy3", "python"], ["node", "js"], ["bun", "js"], ["deno eval", "js"], ["perl5.36", "perl"],
    ["ruby", "ruby"], ["php8", "php"], ["gawk -i inplace", "awk"], ["sed", "sed"], ["lua", "unknown"],
  ])("%s -> %s", (via, lang) => expect(codeLanguage(via)).toBe(lang));
});

describe("linear run time on adversarial input", () => {
  it("handles long inputs quickly", () => {
    const inputs: [string, string][] = [
      ["awk", "print ".repeat(20000)],
      ["sed", `/${"e".repeat(40000)}`],
      ["js", `'${"+".repeat(40000)}`],
      ["python", `open(${"(".repeat(20000)}`],
      ["js", `a[${"[".repeat(20000)}`],
      ["perl", `open ${"'x',".repeat(10000)}`],
    ];
    for (const [lang, code] of inputs) {
      const start = Date.now();
      writeIndicator(code, lang);
      expect(Date.now() - start).toBeLessThan(2000);
    }
  });
});
