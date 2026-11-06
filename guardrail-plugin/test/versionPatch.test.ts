import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// Version 0.1.2: package.json, its lockfile and the plugin manifest (protected) must carry the same version, otherwise an
// update is not delivered. The bump is part of the patch release-0.1.2.patch (both products and the marketplace entries),
// which a human applies in one step at release time (the release check compares all three). This test applies only the
// guardrail-plugin part of the patch while it is pending and checks the real files once it is applied.
// Version 0.1.1 (guardrail-version-0.1.1.patch) is applied on main and was never published.
const pluginDir = new URL("../", import.meta.url);
const patchFile = new URL(["..", "..", "..", "org", "patches", "release-0.1.2.patch"].join("/"), import.meta.url);
const FILES = ["package.json", "package-lock.json", ".claude-plugin/plugin.json"];
type Versioned = { version: string; packages?: Record<string, { version?: string }> };

const read = (text: string): Versioned => JSON.parse(text) as Versioned;
const real = Object.fromEntries(FILES.map((f) => [f, readFileSync(new URL(f, pluginDir), "utf8")]));
const applied = read(real["package.json"] as string).version === "0.1.2";

function resulting(): Record<string, string> {
  if (applied) return real;
  const tmp = mkdtempSync(join(tmpdir(), "tg-version-"));
  for (const f of FILES) {
    const target = join(tmp, "product", "guardrail-plugin", f);
    mkdirSync(join(target, ".."), { recursive: true });
    writeFileSync(target, real[f] as string);
  }
  execFileSync("git", ["apply", "--include=product/guardrail-plugin/*", patchFile.pathname], { cwd: tmp });
  return Object.fromEntries(FILES.map((f) => [f, readFileSync(join(tmp, "product", "guardrail-plugin", f), "utf8")]));
}

describe("version 0.1.2 (release patch)", () => {
  const result = resulting();
  it("sets package.json, lockfile and plugin manifest to 0.1.2", () => {
    for (const f of FILES) expect(read(result[f] as string).version, f).toBe("0.1.2");
    expect(read(result["package-lock.json"] as string).packages?.[""]?.version).toBe("0.1.2");
  });
  it("changes nothing besides the version", () => {
    const strip = (text: string): unknown => JSON.parse(text.replaceAll('"version": "0.1.2"', '"version": "X"').replaceAll('"version": "0.1.1"', '"version": "X"'));
    for (const f of FILES) expect(strip(result[f] as string), f).toEqual(strip(real[f] as string));
  });
  it("keeps the three files in step in the current state", () => {
    const versions = FILES.map((f) => read(real[f] as string).version);
    expect(new Set(versions).size).toBe(1);
  });
});
