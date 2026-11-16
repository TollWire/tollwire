import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// package.json, its lockfile and the plugin manifest (protected) must carry the SAME version, otherwise Claude Code
// does not deliver an update. This invariant is checked on the live files at every release. The 0.1.2 and 0.1.3 bumps
// were delivered as `release-0.1.x.patch` (a human applied them at release time); from 0.1.4 the bump lands directly in
// the release PR, so the test asserts the live state instead of a pending patch. The plugin manifest keeps the reviewed
// description wording (since 0.1.3: "Blocks recognized writes …" instead of "Blocks writes …").
const pluginDir = new URL("../", import.meta.url);
const FILES = ["package.json", "package-lock.json", ".claude-plugin/plugin.json"];
const DESCRIPTION = "Blocks recognized writes to protected paths";
type Versioned = { version: string; description?: string; packages?: Record<string, { version?: string }> };
const read = (f: string): Versioned => JSON.parse(readFileSync(new URL(f, pluginDir), "utf8")) as Versioned;

describe("version (package.json, lockfile and plugin manifest in step)", () => {
  it("package.json, lockfile and plugin manifest carry the same version", () => {
    const versions = FILES.map((f) => read(f).version);
    expect(new Set(versions).size, versions.join(", ")).toBe(1);
  });
  it("the lockfile root package matches package.json", () => {
    expect(read("package-lock.json").packages?.[""]?.version).toBe(read("package.json").version);
  });
  it("the plugin manifest keeps the reviewed description", () => {
    expect((read(".claude-plugin/plugin.json").description ?? "").startsWith(DESCRIPTION)).toBe(true);
  });
});
