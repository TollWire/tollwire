import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// Audit 2026-10-22, F-04. On Linux (stand-alone and enterprise mode) the hook wrapper removed only seven named variables, macOS used
// `env -i` with a positive list. hooks/hooks.json is a protected file; the change is delivered as hooks-linux-env-i.patch
// (apply AFTER hooks-onfailure-block.patch, with --unidiff-zero). This test checks the result of the patch while it is pending (with and
// without the onFailure patch before it) and the real file once it is applied.
const root = new URL("../../../", import.meta.url).pathname;
const REL = "product/guardrail-plugin/hooks/hooks.json";
const patches = join(root, "org", "patches");
const current = readFileSync(join(root, REL), "utf8");
const applied = current.includes('env -i \\"$@\\"');

interface Handler { type: string; command: string; timeout: number; onFailure?: string }
interface Manifest { hooks: Record<string, { matcher?: string; hooks: Handler[] }[]> }

function render(withOnFailure: boolean): Manifest {
  if (applied) return JSON.parse(current) as Manifest;
  const dir = mkdtempSync(join(tmpdir(), "tg-linuxenv-"));
  mkdirSync(join(dir, "product", "guardrail-plugin", "hooks"), { recursive: true });
  writeFileSync(join(dir, REL), current);
  writeFileSync(join(dir, REL.replace("hooks.json", "hooks.windows.json")), readFileSync(join(root, REL.replace("hooks.json", "hooks.windows.json"))));
  if (withOnFailure && !current.includes("onFailure")) execFileSync("git", ["apply", "-p1", join(patches, "hooks-onfailure-block.patch")], { cwd: dir });
  execFileSync("git", ["apply", "--unidiff-zero", "-p1", join(patches, "hooks-linux-env-i.patch")], { cwd: dir });
  return JSON.parse(readFileSync(join(dir, REL), "utf8")) as Manifest;
}

const plain = render(false);
const commands = (m: Manifest): string[] => Object.values(m.hooks).flatMap((es) => es.flatMap((e) => e.hooks.map((h) => h.command)));
const strip = (m: Manifest): unknown => JSON.parse(JSON.stringify(m, (k, v: unknown) => (k === "onFailure" || k === "command" ? undefined : v)));

describe("Linux hook wrapper with a positive environment list (hooks-linux-env-i.patch)", () => {
  it("replaces the named-variable form in all seven commands and keeps the macOS enterprise branch", () => {
    const all = commands(plain);
    expect(all).toHaveLength(7);
    for (const c of all) {
      expect(c).not.toContain("env -u");
      expect(c).not.toContain("NODE_OPTIONS");
      expect(c.split('/usr/bin/env -i "$@" ').length - 1).toBe(2);
      expect(c.split("set -- CLAUDE_PROJECT_DIR=").length - 1).toBe(1);
      // Order: `env -i` runs FIRST, `timeout` (if present) runs inside the cleaned environment, so LD_PRELOAD/LD_AUDIT/LD_DEBUG never reach it.
      expect(c).not.toContain("$T /usr/bin/env");
      expect(c.split('/usr/bin/env -i "$@" $T "$N" ').length - 1).toBe(1);
      expect(c.split('LANG="${LANG:-C}" $T "$N" ').length - 1).toBe(1);
      expect(c).toContain('/usr/bin/env -i CLAUDE_PROJECT_DIR="$CLAUDE_PROJECT_DIR" TOLLGATE_ENTERPRISE="$TOLLGATE_ENTERPRISE" TOLLGATE_HUMAN_SESSION="$TOLLGATE_HUMAN_SESSION" LANG="${LANG:-C}"');
    }
  });
  it("is the same result with and without the onFailure patch before it", () => {
    if (applied) return;
    const withOnFailure = render(true);
    expect(commands(withOnFailure)).toEqual(commands(plain));
    expect(strip(withOnFailure)).toEqual(strip(plain));
  });
  it("changes only the command texts", () => {
    const base = JSON.parse(current) as Manifest;
    if (applied) return;
    expect(strip(plain)).toEqual(strip(base));
  });
});

const LINUX = process.platform === "linux";
const SYSTEM_NODE = ["/opt/tollgate/node/bin/node", "/usr/bin/node"].some((p) => existsSync(p));
const PRINT_ENV = 'process.stdout.write(JSON.stringify(Object.keys(process.env).sort()));';
const HOSTILE = {
  NODE_OPTIONS: "--require /nonexistent/evil.js", NODE_PATH: "/nonexistent", NODE_V8_COVERAGE: "/nonexistent", LD_PRELOAD: "/nonexistent/e.so",
  LD_AUDIT: "/nonexistent/a.so", GLIBC_TUNABLES: "glibc.malloc.check=3", LD_DEBUG: "all", NODE_EXTRA_CA_CERTS: "/nonexistent/ca.pem",
  UV_THREADPOOL_SIZE: "1", SECRET_TOKEN: "synthetic",
};

function runLinux(command: string, env: NodeJS.ProcessEnv, noTimeout = false): { status: number | null; keys: string[]; stderr: string } {
  const pluginRoot = mkdtempSync(join(tmpdir(), "tg-linuxenv-root-"));
  mkdirSync(join(pluginRoot, "dist"));
  for (const f of ["hookCli.js", "hookCliPosix.js"]) writeFileSync(join(pluginRoot, "dist", f), PRINT_ENV);
  const c = noTimeout ? command.replace("/usr/bin/timeout /bin/timeout", "/nonexistent/timeout /nonexistent/timeout2") : command;
  const r = spawnSync("/bin/sh", ["-c", c], { input: "{}", env: { PATH: process.env.PATH ?? "", CLAUDE_PLUGIN_ROOT: pluginRoot, ...env }, encoding: "utf8", timeout: 30_000,
    // LD_DEBUG=all in HOSTILE makes the loader print every symbol binding of /bin/sh, uname, env, node ... (hundreds of KB, MiBs on newer glibc).
    // With the default 1 MiB maxBuffer spawnSync kills the child (status null). The generous buffer keeps the assertions meaningful.
    maxBuffer: 64 * 1024 * 1024 });
  let keys: string[] = [];
  try { keys = JSON.parse(r.stdout) as string[]; } catch { /* the stand-in did not run */ }
  return { status: r.status, keys, stderr: r.stderr };
}

describe.skipIf(!LINUX)("what the Node process of the hook sees on Linux", () => {
  const entries = commands(plain);
  const forbidden = ["NODE_OPTIONS", "NODE_PATH", "NODE_V8_COVERAGE", "LD_PRELOAD", "LD_AUDIT", "GLIBC_TUNABLES", "LD_DEBUG", "NODE_EXTRA_CA_CERTS", "UV_THREADPOOL_SIZE", "SECRET_TOKEN"];
  const user = { CLAUDE_PROJECT_DIR: "/p", HOME: "/h", TMPDIR: "/t", LANG: "de_DE.UTF-8", TOLLGATE_HUMAN_SESSION: "1", XDG_STATE_HOME: "/s" };

  it.each([["with timeout", false], ["without timeout (watchdog entry)", true]])("stand-alone mode, %s: only the positive list reaches Node", (_n, noTimeout) => {
    for (const c of entries) {
      const r = runLinux(c, { ...HOSTILE, ...user }, noTimeout);
      expect(r.status, r.stderr.slice(-2000)).toBe(0);
      for (const name of forbidden) expect(r.keys, name).not.toContain(name);
      expect(r.keys).toEqual(["CLAUDE_PROJECT_DIR", "HOME", "LANG", "PATH", "TMPDIR", "TOLLGATE_ENTERPRISE", "TOLLGATE_HUMAN_SESSION", "XDG_STATE_HOME"]);
    }
  });
  it("stand-alone mode forwards TOLLGATE_POLICY (documented feature) and leaves unset optional variables unset", () => {
    const r = runLinux(entries[0] as string, { TOLLGATE_POLICY: "/p.json" });
    expect(r.keys).toEqual(["LANG", "CLAUDE_PROJECT_DIR", "PATH", "TOLLGATE_ENTERPRISE", "TOLLGATE_HUMAN_SESSION", "TOLLGATE_POLICY"].sort());
  });
  it.skipIf(!SYSTEM_NODE)("enterprise mode: exactly the four variables, no PATH, HOME, TMPDIR or policy path", () => {
    for (const c of entries) {
      const r = runLinux(c, { ...HOSTILE, ...user, TOLLGATE_POLICY: "/evil.json", TOLLGATE_ENTERPRISE: "1" });
      expect(r.status, r.stderr.slice(-2000)).toBe(0);
      expect(r.keys).toEqual(["CLAUDE_PROJECT_DIR", "LANG", "TOLLGATE_ENTERPRISE", "TOLLGATE_HUMAN_SESSION"]);
    }
  });
});
