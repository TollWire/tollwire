import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// hooks/hooks.json is a protected file: the PostToolUse entry for `tool_result` is delivered as a patch file that a human
// applies. This test checks the result of the patch while it is pending, and the real file once it is applied.
const hooksFile = new URL("../hooks/hooks.json", import.meta.url);
const patchFile = new URL(["..", "..", "..", "org", "patches", "monitor-hooks.patch"].join("/"), import.meta.url);

interface Manifest {
  hooks: Record<string, { matcher?: string; hooks: { type: string; command: string; timeout: number }[] }[]>;
}

function patched(): Manifest {
  const current = JSON.parse(readFileSync(hooksFile, "utf8")) as Manifest;
  if (current.hooks.PostToolUse !== undefined || !existsSync(patchFile)) return current;
  const dir = mkdtempSync(join(tmpdir(), "tg-mpatch-"));
  mkdirSync(join(dir, "product", "guardrail-plugin", "hooks"), { recursive: true });
  writeFileSync(join(dir, "product", "guardrail-plugin", "hooks", "hooks.json"), readFileSync(hooksFile));
  execFileSync("git", ["apply", "--unsafe-paths", "--directory", ".", patchFile.pathname], { cwd: dir });
  return JSON.parse(readFileSync(join(dir, "product", "guardrail-plugin", "hooks", "hooks.json"), "utf8")) as Manifest;
}

const manifest = patched();

function run(command: string, hookSource: string | null): { status: number | null; stderr: string } {
  const root = mkdtempSync(join(tmpdir(), "tg-mpatch-root-"));
  if (hookSource !== null) {
    mkdirSync(join(root, "dist"));
    writeFileSync(join(root, "dist", "hookCli.js"), hookSource);
  }
  const r = spawnSync("sh", ["-c", command], { input: "{}", env: { ...process.env, CLAUDE_PLUGIN_ROOT: root }, encoding: "utf8" });
  return { status: r.status, stderr: r.stderr };
}

describe("PostToolUse hook for tool_result (T21)", () => {
  it("registers one PostToolUse entry for all tools that calls the hook", () => {
    const entries = manifest.hooks.PostToolUse ?? [];
    expect(entries).toHaveLength(1);
    expect(entries[0]?.matcher).toBeUndefined();
    expect(entries[0]?.hooks[0]?.command).toContain("dist/hookCli.js");
  });

  it("is fail-open: a failing, missing or blocking hook ends with exit 0 and a notice", () => {
    const command = manifest.hooks.PostToolUse?.[0]?.hooks[0]?.command as string;
    expect(run(command, "process.exit(0);")).toEqual({ status: 0, stderr: "" });
    for (const source of [null, "process.exit(2);", "process.exit(3);", "throw new Error('boom');"]) {
      const r = run(command, source);
      expect(r.status, String(source)).toBe(0);
      expect(r.stderr).toContain("not blocking this event");
    }
  });

  it("binds every entry to its event with --event, in both branches of the command (the caller cannot change it)", () => {
    for (const [event, entries] of Object.entries(manifest.hooks)) {
      for (const entry of entries) {
        const command = entry.hooks[0]?.command as string;
        // Two calls (with and without timeout) in the plain form; one call in the hardened form (absolute timeout chosen beforehand).
        // macOS form: three calls, each bound to the event: hookCli once (with timeout), hookCliPosix twice (watchdog; enterprise `env -i`).
        if (command.includes("hookCliPosix.js")) {
          expect(command.split(`dist/hookCli.js\" --event ${event}`).length - 1, event).toBe(1);
          expect(command.split(`dist/hookCliPosix.js\" --event ${event}`).length - 1, event).toBe(2);
          expect(command.split("--event").length - 1, event).toBe(3);
          continue;
        }
        const calls = command.includes("NODE_OPTIONS") ? 1 : 2;
        expect(command.split(`dist/hookCli.js\" --event ${event}`).length - 1, event).toBe(calls);
        expect(command.split("--event").length - 1, event).toBe(calls);
      }
    }
  });

  it("leaves the fail-closed PreToolUse entry unchanged", () => {
    expect(manifest.hooks.PreToolUse?.[0]?.matcher).toBe("Bash|Edit|Write|MultiEdit|NotebookEdit");
    expect(run(manifest.hooks.PreToolUse?.[0]?.hooks[0]?.command as string, null).status).toBe(2);
    expect(Object.keys(manifest.hooks).sort()).toEqual(["PostToolUse", "PreToolUse", "SessionEnd", "SessionStart", "SubagentStart", "SubagentStop"]);
  });
});
