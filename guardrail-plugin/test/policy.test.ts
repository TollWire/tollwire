import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { BUNDLED_POLICY_PATH, loadPolicy, parsePolicy, resolvePolicyPath } from "../src/policy.js";

const valid = { version: 1, protectedPaths: [], blockedCommands: [], allowedDependencies: { npm: [], pypi: [] } };

describe("policy", () => {
  it("loads the bundled default policy", () => {
    expect(loadPolicy(BUNDLED_POLICY_PATH).protectedPaths).toContain("AGENTS.md");
  });
  it("rejects invalid structure and invalid regex patterns", () => {
    expect(() => parsePolicy({ ...valid, version: 2 })).toThrow();
    expect(() => parsePolicy({ ...valid, blockedCommands: [{ pattern: "(", reason: "x" }] })).toThrow();
  });
  it("resolves project policy, then bundled default; TOLLGATE_POLICY does not replace the base", () => {
    const dir = mkdtempSync(join(tmpdir(), "tg-"));
    expect(resolvePolicyPath({}, dir)).toBe(BUNDLED_POLICY_PATH);
    mkdirSync(join(dir, ".tollgate"));
    writeFileSync(join(dir, ".tollgate", "policy.json"), JSON.stringify(valid));
    expect(resolvePolicyPath({}, dir)).toBe(join(dir, ".tollgate", "policy.json"));
    expect(resolvePolicyPath({ TOLLGATE_POLICY: "/x.json" }, dir)).toBe(join(dir, ".tollgate", "policy.json"));
  });
});
