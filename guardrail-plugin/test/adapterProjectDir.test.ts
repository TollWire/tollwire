import { describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveProjectDir } from "../src/adapters/projectDir.js";

// The multi-agent adapters (Codex/Copilot) derive the project directory for the engine from the hook's cwd, because
// those agents do not set CLAUDE_PROJECT_DIR. Protected paths are relative to the repository root, so an agent
// started in a subfolder must not shift that root.
describe("resolveProjectDir (adapter helper)", () => {
  it("prefers an explicit CLAUDE_PROJECT_DIR", () => {
    expect(resolveProjectDir("/work/sub", { CLAUDE_PROJECT_DIR: "/explicit" })).toBe("/explicit");
  });

  it("walks up to the git root from a subfolder", () => {
    const root = mkdtempSync(join(tmpdir(), "tg-apd-"));
    mkdirSync(join(root, ".git"));
    const sub = join(root, "product", "pkg");
    mkdirSync(sub, { recursive: true });
    expect(resolveProjectDir(sub, {})).toBe(root);
  });

  it("falls back to cwd when there is no git root and no explicit variable", () => {
    const dir = mkdtempSync(join(tmpdir(), "tg-apd-nogit-"));
    expect(resolveProjectDir(dir, {})).toBe(dir);
  });
});
