import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkCommand } from "../src/evaluate.js";
import { parsePolicy, type Policy } from "../src/policy.js";

// Audit 2026-10-22, findings F-01 and F-02. The command rules live in policy/default.json (protected path); the fix is the patch
// guard-policy-f01-f02.patch, which a human applies. This test checks the result of the patch while it is pending and
// the real file once it is applied, so it works in both states and weakens no existing test. The same cases run against the
// Python repository hook of the development repository (test_guard_audit_f01_f02.py; both consumers must decide identically).
const policyFile = new URL("../policy/default.json", import.meta.url);
const patchFile = new URL(["..", "..", "..", "org", "patches", "guard-policy-f01-f02.patch"].join("/"), import.meta.url);
const MARK = "audit F-0";

function resultingPolicyText(): string {
  const real = readFileSync(policyFile, "utf8");
  if (real.includes(MARK)) return real;
  const tmp = mkdtempSync(join(tmpdir(), "tg-f01-"));
  mkdirSync(join(tmp, "product", "guardrail-plugin", "policy"), { recursive: true });
  writeFileSync(join(tmp, "product", "guardrail-plugin", "policy", "default.json"), real);
  execFileSync("git", ["apply", "--unsafe-paths", "--directory", ".", patchFile.pathname], { cwd: tmp });
  return readFileSync(join(tmp, "product", "guardrail-plugin", "policy", "default.json"), "utf8");
}

const text = resultingPolicyText();
const policy: Policy = parsePolicy(JSON.parse(text));
const cases = JSON.parse(readFileSync(new URL("./fixtures/audit-f01-f02-cases.json", import.meta.url), "utf8")) as { block: string[]; allow: string[] };
const shared = JSON.parse(readFileSync(new URL("./fixtures/command-cases.json", import.meta.url), "utf8")) as { block: string[]; allow: string[] };

describe("guard policy patch (audit F-01, F-02)", () => {
  it("adds rules at the end and leaves every existing rule unchanged", () => {
    const real = (JSON.parse(readFileSync(policyFile, "utf8")) as { blockedCommands: unknown[] }).blockedCommands;
    const after = (JSON.parse(text) as { blockedCommands: unknown[] }).blockedCommands;
    expect(after.slice(0, real.length)).toEqual(real);
    expect(after.length).toBeGreaterThanOrEqual(real.length);
  });
  it.each(cases.block)("blocks %j", (cmd) => expect(checkCommand(cmd, policy).allowed).toBe(false));
  it.each(cases.allow)("allows %j", (cmd) => expect(checkCommand(cmd, policy).allowed).toBe(true));
  it("keeps the decisions of the shared command cases", () => {
    for (const cmd of shared.block) expect(checkCommand(cmd, policy).allowed, cmd).toBe(false);
    for (const cmd of shared.allow) expect(checkCommand(cmd, policy).allowed, cmd).toBe(true);
  });
  it("names the audit in the reason of a blocked read", () => {
    expect(checkCommand("cat .env*", policy)).toEqual({ allowed: false, reason: expect.stringContaining("audit F-01") });
  });
  it("evaluates the new rules in linear time on pathological input", () => {
    const rules = policy.blockedCommands.filter((r) => r.reason.includes(MARK));
    expect(rules.length).toBeGreaterThanOrEqual(10);
    const inputs = [
      "gh api ".repeat(10000),
      "gh api graphql ".repeat(7000),
      "$(".repeat(30000),
      `${"cat ~/.".repeat(10000)}`,
      "/proc/".repeat(15000),
      " .e".repeat(25000),
      " s".repeat(35000),
      `gh api ${"/merge ".repeat(9000)}`,
      `npm ${"-x ".repeat(25000)}`,
      "$(echo ".repeat(10000),
      "cat x ".repeat(15000),
      "tar secrets ".repeat(8000),
      "npm --otp 1 -w p ".repeat(5000),
      "npm npm npm ".repeat(8000),
      "git commit -m x ".repeat(5000),
      "gh pr create -b ".repeat(5000),
      "gh api -X GET ".repeat(7000),
      "~/.ssh ".repeat(12000),
    ];
    for (const rule of rules) {
      const re = new RegExp(rule.pattern as string);
      for (const input of inputs) {
        const t = process.hrtime.bigint();
        re.test(input);
        const ms = Number(process.hrtime.bigint() - t) / 1e6;
        expect(ms, `${rule.reason} on ${input.slice(0, 12)}`).toBeLessThan(250); // backtracking would take seconds; headroom for a loaded runner
      }
    }
  });
});
