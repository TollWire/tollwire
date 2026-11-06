import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkCommand, evaluate } from "../src/evaluate.js";
import { parsePolicy, type Policy } from "../src/policy.js";

// Version 0.1.1: a command rule against running commands with elevated privileges (sudo, sudoedit, doas, pkexec; `su` stays a
// wrapper whose command string is checked). The policy file is protected; the change is the patch guardrail-policy-0.1.1.patch,
// which a human applies. This test checks the result of the patch while it is pending and the real
// files once it is applied, so it works in both states and weakens no existing test. The same cases run against the Python
// port of the repository hook (both consumers must decide identically).
const pluginDir = new URL("../", import.meta.url);
const patchFile = new URL(["..", "..", "..", "org", "patches", "guardrail-policy-0.1.1.patch"].join("/"), import.meta.url);
const MARK = "elevated privileges";
const FILES = ["policy/default.json"];

function resulting(): Record<string, string> {
  const real = Object.fromEntries(FILES.map((f) => [f, readFileSync(new URL(f, pluginDir), "utf8")]));
  if ((real["policy/default.json"] as string).includes(MARK)) return real;
  const tmp = mkdtempSync(join(tmpdir(), "tg-privilege-"));
  for (const f of FILES) {
    const target = join(tmp, "product", "guardrail-plugin", f);
    mkdirSync(join(target, ".."), { recursive: true });
    writeFileSync(target, real[f] as string);
  }
  execFileSync("git", ["apply", "--unsafe-paths", "--directory", ".", patchFile.pathname], { cwd: tmp });
  return Object.fromEntries(FILES.map((f) => [f, readFileSync(join(tmp, "product", "guardrail-plugin", f), "utf8")]));
}

const files = resulting();
const text = files["policy/default.json"] as string;
const policy: Policy = parsePolicy(JSON.parse(text));
const rules = policy.blockedCommands.filter((r) => r.reason.includes(MARK));
const cases = JSON.parse(readFileSync(new URL("./fixtures/privilege-cases.json", import.meta.url), "utf8")) as { block: string[]; allow: string[] };
const shared = JSON.parse(readFileSync(new URL("./fixtures/command-cases.json", import.meta.url), "utf8")) as { block: string[]; allow: string[] };

describe("privilege rule (policy patch 0.1.1)", () => {
  it("appends two rules and leaves every existing rule unchanged", () => {
    const real = (JSON.parse(readFileSync(new URL("policy/default.json", pluginDir), "utf8")) as { blockedCommands: { reason: string }[] }).blockedCommands;
    const before = real.filter((r) => !r.reason.includes(MARK));
    const after = (JSON.parse(text) as { blockedCommands: unknown[] }).blockedCommands;
    expect(after.slice(0, before.length)).toEqual(before);
    expect(after).toHaveLength(before.length + 2);
    expect(rules).toHaveLength(2);
    for (const r of rules) expect(r.pattern?.length).toBeLessThanOrEqual(500);
  });
  it.each(cases.block)("blocks %j", (cmd) => expect(checkCommand(cmd, policy)).toEqual({ allowed: false, reason: expect.stringContaining(MARK) }));
  it.each(cases.allow)("allows %j", (cmd) => expect(checkCommand(cmd, policy).allowed).toBe(true));
  it("keeps the decisions of the shared command cases", () => {
    for (const cmd of shared.block) expect(checkCommand(cmd, policy).allowed, cmd).toBe(false);
    for (const cmd of shared.allow) expect(checkCommand(cmd, policy).allowed, cmd).toBe(true);
  });
  it("blocks sudo also in a human session (command rules apply to everyone)", () => {
    expect(evaluate({ tool_name: "Bash", tool_input: { command: "sudo ls" } }, policy, { projectDir: "/repo", humanSession: true }).allowed).toBe(false);
  });
  it("evaluates the rules in linear time on pathological input", () => {
    const inputs = [
      ";".repeat(32000), "A=1;".repeat(8000), "env -a;".repeat(4500), "sh ".repeat(10000), "bash -c ".repeat(4000), "/a".repeat(16000),
      ";/aaaa".repeat(5000), `${"env -a ".repeat(4500)}x`, "timeout 1 ".repeat(3000), " -exec ".repeat(4500), "su x ".repeat(6000),
      "$(".repeat(16000), "a".repeat(32000), "x=".repeat(16000), "watch -n 1 ".repeat(3000), `${"nice ".repeat(6000)}x`,
      " env -u x".repeat(4000), " timeout -s x".repeat(3000), " xargs -I x".repeat(3000), " flock -w x".repeat(3000), " env".repeat(8000),
      `env ${"-a ".repeat(10000)}x`, `timeout ${"-s x ".repeat(5000)}`, `xargs ${"-0 ".repeat(10000)}`, `flock ${"-n ".repeat(10000)}f`,
      " exec -a".repeat(4000), "a=b ".repeat(8000), " env -S".repeat(5000), " xargs '".repeat(5000),
      "env -a|".repeat(4500), "env -a&".repeat(4500), "env -;".repeat(6000), "timeout -;".repeat(3500), "xargs -;".repeat(4000), "flock x;".repeat(4000),
      "exec -a;".repeat(4000), "env -u -;".repeat(3500), "timeout 5;".repeat(3000),
    ];
    for (const rule of rules) {
      const re = new RegExp(rule.pattern as string);
      for (const input of inputs) {
        const t = process.hrtime.bigint();
        re.test(input);
        const ms = Number(process.hrtime.bigint() - t) / 1e6;
        expect(ms, input.slice(0, 12)).toBeLessThan(250); // backtracking would take seconds; headroom for a loaded runner
      }
    }
  });
});
