import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// The hook command from the plugin manifest must block (exit 2) whenever the hook itself cannot run:
// Claude Code treats every exit code other than 2 as a non-blocking error (fail open).
const manifest = JSON.parse(readFileSync(new URL("../hooks/hooks.json", import.meta.url), "utf8")) as {
  hooks: { PreToolUse: { hooks: { command: string }[] }[] };
};
const command = manifest.hooks.PreToolUse[0]?.hooks[0]?.command ?? "";

function runWith(hookSource: string | null): { status: number | null; stderr: string } {
  const root = mkdtempSync(join(tmpdir(), "tg-manifest-"));
  if (hookSource !== null) {
    mkdirSync(join(root, "dist"));
    writeFileSync(join(root, "dist", "hookCli.js"), hookSource);
  }
  const r = spawnSync("sh", ["-c", command], {
    input: "{}",
    env: { ...process.env, CLAUDE_PLUGIN_ROOT: root },
    encoding: "utf8",
  });
  return { status: r.status, stderr: r.stderr };
}

describe("plugin hook command", () => {
  it("fails closed when node is not on PATH", () => {
    const r = spawnSync("/bin/sh", ["-c", command], { input: "{}", env: { PATH: "/nonexistent", CLAUDE_PLUGIN_ROOT: "/x" }, encoding: "utf8" });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("fail closed");
  });
  it("maps a timeout (exit 124 from timeout) to a block", () => {
    const bin = mkdtempSync(join(tmpdir(), "tg-timeout-"));
    writeFileSync(join(bin, "timeout"), "#!/bin/sh\nexit 124\n", { mode: 0o755 });
    const r = spawnSync("/bin/sh", ["-c", command], { input: "{}", env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, CLAUDE_PLUGIN_ROOT: "/x" }, encoding: "utf8" });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("timed out");
  });
  it("declares a Claude Code timeout above the inner timeout", () => {
    const hook = manifest.hooks.PreToolUse[0]?.hooks[0] as { timeout?: number; command: string };
    expect(hook.timeout).toBe(30);
    // The state of the file decides which form is required, and each form is checked strictly: before the integrity patch the plain
    // call, after it the hardened call (absolute env and timeout, cleaned environment, Node chosen by the wrapper, no PATH lookup).
    if (hook.command.includes('env -i "$@"')) {
      // After hooks-linux-env-i.patch: the Linux branches start the hook with an empty environment plus a positive list.
      expect(hook.command).toMatch(/\/usr\/bin\/env -i "\$@" \$T "\$N" "\$CLAUDE_PLUGIN_ROOT\/dist\/hookCli\.js"/);
      expect(hook.command).toContain('T="$t 25"');
      expect(hook.command).not.toContain("command -v");
      expect(hook.command).not.toContain("env -u");
    } else if (!hook.command.includes("NODE_OPTIONS")) {
      expect(hook.command).toContain('timeout 25 node "$CLAUDE_PLUGIN_ROOT/dist/hookCli.js"');
    } else {
      expect(hook.command).toMatch(/\$T \/usr\/bin\/env (?:-u [A-Z_0-9]+ )+"\$N" "\$CLAUDE_PLUGIN_ROOT\/dist\/hookCli\.js"/);
      expect(hook.command).toContain('T="$t 25"');
      expect(hook.command).not.toContain("command -v");
      expect(hook.command).toContain("-u NODE_OPTIONS");
    }
  });
  it("passes through allow (0) and block (2)", () => {
    expect(runWith("process.exit(0);").status).toBe(0);
    expect(runWith("process.stderr.write('blocked'); process.exit(2);")).toEqual({ status: 2, stderr: "blocked" });
  });
  it.each([
    ["missing dist", null],
    ["module load error", "import './missing.js';"],
    ["syntax error", "this is not javascript"],
    ["unexpected exit code", "process.exit(3);"],
    ["uncaught exception", "throw new Error('boom');"],
  ])("fails closed on %s", (_name, source) => {
    const r = runWith(source);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("fail closed");
  });
});
