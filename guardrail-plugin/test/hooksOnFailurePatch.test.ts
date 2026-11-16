import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// The hook manifests are protected files. The hardening "onFailure: block" for every PreToolUse hook (Claude Code >= 2.1.295:
// a hook that cannot start, times out, exits with an unexpected code or prints invalid JSON then blocks like exit code 2)
// is delivered as hooks-onfailure-block.patch, which a human applies. This test validates the result of the patch
// while it is pending, and the real files once it is applied. It works in both states and weakens no existing test.
const dir = new URL("../hooks/", import.meta.url);
const patchFile = new URL(["..", "..", "..", "org", "patches", "hooks-onfailure-block.patch"].join("/"), import.meta.url);
const FILES = ["hooks.json", "hooks.windows.json"];

interface Handler {
  type: string;
  command: string;
  timeout?: number;
  onFailure?: string;
}
interface Manifest {
  hooks: Record<string, { matcher?: string; hooks: Handler[] }[]>;
}

const parse = (text: string): Manifest => JSON.parse(text) as Manifest;
const allPre = (m: Manifest): Handler[] => (m.hooks.PreToolUse ?? []).flatMap((e) => e.hooks);

function load(name: string): { real: Manifest; result: Manifest } {
  const realText = readFileSync(new URL(name, dir), "utf8");
  const real = parse(realText);
  const applied = allPre(real).length > 0 && allPre(real).every((h) => h.onFailure === "block");
  if (applied) return { real, result: real };
  const tmp = mkdtempSync(join(tmpdir(), "tg-onfailure-"));
  mkdirSync(join(tmp, "product", "guardrail-plugin", "hooks"), { recursive: true });
  for (const f of FILES) writeFileSync(join(tmp, "product", "guardrail-plugin", "hooks", f), readFileSync(new URL(f, dir)));
  execFileSync("git", ["apply", "--unsafe-paths", "--directory", ".", patchFile.pathname], { cwd: tmp });
  return { real, result: parse(readFileSync(join(tmp, "product", "guardrail-plugin", "hooks", name), "utf8")) };
}

const strip = (m: Manifest): unknown => JSON.parse(JSON.stringify(m, (k, v: unknown) => (k === "onFailure" ? undefined : v)));

describe.each(FILES)("onFailure block for PreToolUse (%s)", (name) => {
  const { real, result } = load(name);

  it("is valid JSON with the two PreToolUse entries", () => {
    expect(result.hooks.PreToolUse).toHaveLength(2);
  });

  it("every PreToolUse handler (checked and unchecked tools) has onFailure block", () => {
    const handlers = allPre(result);
    expect(handlers).toHaveLength(2);
    for (const h of handlers) {
      expect(h.type).toBe("command");
      expect(h.onFailure).toBe("block");
    }
  });

  it("keeps the timeout and the wrapper command unchanged", () => {
    const before = allPre(real);
    const after = allPre(result);
    expect(after.map((h) => h.timeout)).toEqual(before.map((h) => h.timeout));
    expect(after.map((h) => h.timeout)).toEqual([30, 30]);
    expect(after.map((h) => h.command)).toEqual(before.map((h) => h.command));
  });

  it("changes nothing besides onFailure and sets it on no other event", () => {
    expect(strip(result)).toEqual(strip(real));
    for (const [event, entries] of Object.entries(result.hooks)) {
      if (event === "PreToolUse") continue;
      for (const h of entries.flatMap((e) => e.hooks)) expect(h.onFailure, event).toBeUndefined();
    }
  });
});
