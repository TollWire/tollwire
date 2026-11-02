import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// hooks/hooks.json is a protected file: the extension for the decision log (second PreToolUse entry for observed tools,
// SessionStart/SessionEnd/SubagentStart/SubagentStop) is delivered as a patch file that a human applies. This test checks
// the result of that patch while it is pending, and the real file once it is applied.
const hooksFile = new URL("../hooks/hooks.json", import.meta.url);
const patchFile = new URL(["..", "..", "..", "org", "patches", "phase1-hooks.patch"].join("/"), import.meta.url);

interface Entry {
  matcher?: string;
  hooks: { type: string; command: string; timeout: number }[];
}
interface Manifest {
  hooks: Record<string, Entry[]>;
}

function patched(): Manifest {
  if (!existsSync(patchFile)) return JSON.parse(readFileSync(hooksFile, "utf8")) as Manifest;
  const dir = mkdtempSync(join(tmpdir(), "tg-patch-"));
  mkdirSync(join(dir, "product", "guardrail-plugin", "hooks"), { recursive: true });
  writeFileSync(join(dir, "product", "guardrail-plugin", "hooks", "hooks.json"), readFileSync(hooksFile));
  execFileSync("git", ["apply", "--unsafe-paths", "--directory", ".", patchFile.pathname], { cwd: dir });
  return JSON.parse(readFileSync(join(dir, "product", "guardrail-plugin", "hooks", "hooks.json"), "utf8")) as Manifest;
}

const manifest = patched();
const CHECKED = ["Bash", "Edit", "Write", "MultiEdit", "NotebookEdit"];

function run(command: string, hookSource: string | null): { status: number | null; stderr: string } {
  const root = mkdtempSync(join(tmpdir(), "tg-patch-root-"));
  if (hookSource !== null) {
    mkdirSync(join(root, "dist"));
    writeFileSync(join(root, "dist", "hookCli.js"), hookSource);
  }
  const r = spawnSync("sh", ["-c", command], { input: "{}", env: { ...process.env, CLAUDE_PLUGIN_ROOT: root }, encoding: "utf8" });
  return { status: r.status, stderr: r.stderr };
}

describe("hooks for the decision log", () => {
  it("keeps the fail-closed entry first and adds a disjoint entry for all other tools", () => {
    const entries = manifest.hooks.PreToolUse ?? [];
    expect(entries).toHaveLength(2);
    const closed = new RegExp(`^(?:${entries[0]?.matcher})$`);
    const open = new RegExp(entries[1]?.matcher as string);
    for (const name of CHECKED) {
      expect(closed.test(name), name).toBe(true);
      expect(open.test(name), name).toBe(false);
    }
    for (const name of ["Read", "Glob", "Grep", "LS", "WebFetch", "WebSearch", "Task", "mcp__server__tool", "NotebookRead"]) {
      expect(closed.test(name), name).toBe(false);
      expect(open.test(name), name).toBe(true);
    }
  });

  it("registers session and subagent events", () => {
    for (const event of ["SessionStart", "SessionEnd", "SubagentStart", "SubagentStop"]) {
      expect(manifest.hooks[event], event).toHaveLength(1);
      expect(manifest.hooks[event]?.[0]?.hooks[0]?.command).toContain('dist/hookCli.js');
    }
  });

  it("the fail-open entries never block: a failing, missing or blocking hook ends with exit 0", () => {
    const commands = [manifest.hooks.PreToolUse?.[1], manifest.hooks.SessionStart?.[0], manifest.hooks.SessionEnd?.[0], manifest.hooks.SubagentStart?.[0], manifest.hooks.SubagentStop?.[0]].map((e) => e?.hooks[0]?.command as string);
    for (const command of commands) {
      expect(run(command, "process.exit(0);")).toEqual({ status: 0, stderr: "" });
      for (const source of [null, "process.exit(2);", "process.exit(3);", "throw new Error('boom');", "import './missing.js';"]) {
        const r = run(command, source);
        expect(r.status, String(source)).toBe(0);
        expect(r.stderr).toContain("not blocking this event");
      }
    }
  });

  it("the fail-closed entry is unchanged", () => {
    const closed = manifest.hooks.PreToolUse?.[0];
    expect(closed?.matcher).toBe("Bash|Edit|Write|MultiEdit|NotebookEdit");
    expect(run(closed?.hooks[0]?.command as string, null).status).toBe(2);
  });
});
