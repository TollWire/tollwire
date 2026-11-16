import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// hooks/hooks.json is a protected file. The macOS extension (root-owned Node and `env -i` in enterprise mode, the
// watchdog entry `hookCliPosix` instead of `timeout`) is delivered as macos-hooks.patch, to be applied AFTER
// hook-integrity.patch, or as macos-hooks-combined.patch instead of both (against the file of main). This test applies the pending
// patches to a copy, and checks the real file once they are applied. Darwin is simulated: `uname`, the node path and the timeout
// paths in the command text are replaced by temporary stand-ins (the real absolute paths exist only on a Mac, VM3/VM11).
// Nothing depends on the uid of the test process.
const root = new URL("../../../", import.meta.url).pathname;
const hooksFile = join(root, "product/guardrail-plugin/hooks/hooks.json");
const patches = join(root, "org", "patches");
const REL = "product/guardrail-plugin/hooks/hooks.json";

interface Entry { matcher?: string; hooks: { type: string; command: string; timeout: number }[] }
interface Manifest { hooks: Record<string, Entry[]> }

function copyWith(content: string): string {
  const dir = mkdtempSync(join(tmpdir(), "tg-macpatch-"));
  mkdirSync(join(dir, "product", "guardrail-plugin", "hooks"), { recursive: true });
  writeFileSync(join(dir, REL), content);
  return dir;
}
function apply(dir: string, patch: string): void {
  execFileSync("git", ["apply", "-p1", join(patches, patch)], { cwd: dir });
}
function fromFile(dir: string): Manifest {
  return JSON.parse(readFileSync(join(dir, REL), "utf8")) as Manifest;
}

const current = readFileSync(hooksFile, "utf8");
const alreadyMac = current.includes("hookCliPosix.js");
const alreadyHardened = current.includes("NODE_OPTIONS");

function build(order: "integrity+macos" | "combined"): Manifest {
  if (alreadyMac) return JSON.parse(current) as Manifest;
  const dir = copyWith(current);
  if (order === "combined") {
    if (alreadyHardened) return JSON.parse(current) as Manifest; // combined patch is for the file of main only
    apply(dir, "macos-hooks-combined.patch");
  } else {
    if (!alreadyHardened) apply(dir, "hook-integrity.patch");
    apply(dir, "macos-hooks.patch");
  }
  return fromFile(dir);
}

const manifest = build("integrity+macos");
const closed = manifest.hooks.PreToolUse?.[0]?.hooks[0]?.command as string;
const openTools = manifest.hooks.PreToolUse?.[1]?.hooks[0]?.command as string;
const lifecycle = ["SessionStart", "SessionEnd", "SubagentStart", "SubagentStop", "PostToolUse"].map((k) => manifest.hooks[k]?.[0]?.hooks[0]?.command as string);
const all = [closed, openTools, ...lifecycle];
const MAC_NODE = "/Library/Application Support/TollGate/node/bin/node";

interface Sim { dir: string; node: string; uname: string }

/** A stand-in tree: a "Library/Application Support" folder with a node, and a uname that prints `system`. */
function sim(system: string, withNode = true): Sim {
  const dir = mkdtempSync(join(tmpdir(), "tg-macsim-"));
  const nodeDir = join(dir, "Application Support", "node", "bin");
  mkdirSync(nodeDir, { recursive: true });
  const node = join(nodeDir, "node");
  if (withNode) symlinkSync(process.execPath, node);
  const uname = join(dir, "uname");
  writeFileSync(uname, `#!/bin/sh\necho ${system}\n`);
  chmodSync(uname, 0o755);
  return { dir, node, uname };
}

function run(command: string, s: Sim, files: Record<string, string>, env: NodeJS.ProcessEnv = {}, opts: { noTimeout?: boolean } = {}): { status: number | null; stdout: string; stderr: string } {
  const pluginRoot = mkdtempSync(join(tmpdir(), "tg-macplug-"));
  mkdirSync(join(pluginRoot, "dist"));
  for (const [name, text] of Object.entries(files)) writeFileSync(join(pluginRoot, "dist", name), text);
  let c = command.replaceAll("/usr/bin/uname", s.uname).replaceAll(MAC_NODE, s.node);
  if (opts.noTimeout === true) c = c.replace("/usr/bin/timeout /bin/timeout", "/nonexistent/timeout /nonexistent/timeout2");
  const r = spawnSync("/bin/sh", ["-c", c], { input: "{}", env: { PATH: process.env.PATH ?? "", CLAUDE_PLUGIN_ROOT: pluginRoot, ...env }, encoding: "utf8", timeout: 30_000 });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

const ECHO_ENV = 'process.stdout.write(JSON.stringify({ argv: process.argv.slice(2), env: Object.keys(process.env).sort(), opts: process.env.NODE_OPTIONS ?? null }));';
const KILL_SELF = 'process.kill(process.pid, "SIGKILL");';

describe("macOS hook manifest (after hook-integrity.patch and macos-hooks.patch)", () => {
  it("covers every event with the same darwin logic and keeps the order of the entries", () => {
    expect(all).toHaveLength(7);
    for (const c of all) {
      expect(c.startsWith('D=0; if [ "$(/usr/bin/uname -s 2>/dev/null)" = Darwin ]; then D=1; fi; TG=0;')).toBe(true);
      expect(c).toContain('/usr/bin/env -i CLAUDE_PROJECT_DIR="$CLAUDE_PROJECT_DIR" TOLLGATE_ENTERPRISE="$TOLLGATE_ENTERPRISE" TOLLGATE_HUMAN_SESSION="$TOLLGATE_HUMAN_SESSION" LANG="${LANG:-C}"');
      expect(c).toContain('"$CLAUDE_PLUGIN_ROOT/dist/hookCliPosix.js"');
      expect(c).toContain('"$CLAUDE_PLUGIN_ROOT/dist/hookCli.js"');
      expect(c).toContain('T="$t 25"'); // timeout is still used where it exists
      expect(c).not.toMatch(/env -i[^;]*-u /); // nothing is merely "unset" on the enterprise path
    }
    expect(manifest.hooks.PreToolUse?.[0]?.matcher).toBe("Bash|Edit|Write|MultiEdit|NotebookEdit");
    for (const e of Object.values(manifest.hooks).flat()) expect(e.hooks[0]?.timeout).toBe(30);
  });
  it("the macOS enterprise path names exactly one Node: the root-owned one of the package", () => {
    for (const c of all) {
      expect(c).toContain(`if [ -x "${MAC_NODE}" ]; then N="${MAC_NODE}"; fi;`);
      expect(c).not.toContain("/opt/homebrew");
      expect(c).not.toContain("/usr/local/bin/node");
    }
  });
  it("both orders give the same file (integrity then macos, or the combined patch on main)", () => {
    if (alreadyMac || alreadyHardened) return;
    expect(build("combined")).toEqual(manifest);
  });
});

describe("simulated macOS, enterprise signal (TOLLGATE_ENTERPRISE=1)", () => {
  const env = { TOLLGATE_ENTERPRISE: "1" };
  it("fails closed (2) for checked tools when the root-owned Node is missing, and for unchecked tools too", () => {
    const s = sim("Darwin", false);
    const files = { "hookCliPosix.js": "process.exit(0)", "hookCli.js": "process.exit(0)" };
    const a = run(closed, s, files, env);
    expect(a.status).toBe(2);
    expect(a.stderr).toContain("fail closed");
    // unchecked entry: no Node found -> the runner exits non-zero -> enterprise mode blocks
    expect(run(openTools, s, files, env).status).toBe(2);
  });
  it("runs the hook on that Node with an empty environment: NODE_OPTIONS, NODE_PATH, DYLD_*, PATH have no effect", () => {
    const s = sim("Darwin");
    const evil = join(s.dir, "evil.js");
    writeFileSync(evil, 'require("fs").writeFileSync(process.env.EVIL_MARK, "pwned");');
    const mark = join(s.dir, "mark");
    const r = run(closed, s, { "hookCliPosix.js": ECHO_ENV }, { ...env, NODE_OPTIONS: `--require ${evil}`, NODE_PATH: "/x", DYLD_INSERT_LIBRARIES: "/x.dylib", EVIL_MARK: mark, SECRET_TOKEN: "s", CLAUDE_PROJECT_DIR: "/p", TOLLGATE_HUMAN_SESSION: "1", LANG: "de_DE.UTF-8" });
    expect(r.status).toBe(0);
    expect(existsSync(mark)).toBe(false);
    const out = JSON.parse(r.stdout) as { argv: string[]; env: string[]; opts: string | null };
    expect(out.env).toEqual(["CLAUDE_PROJECT_DIR", "LANG", "TOLLGATE_ENTERPRISE", "TOLLGATE_HUMAN_SESSION"]);
    expect(out.opts).toBeNull();
    expect(out.argv).toEqual(["--event", "PreToolUse"]);
  });
  it("works for a Node path with a space", () => {
    const s = sim("Darwin");
    expect(s.node).toContain("Application Support");
    expect(run(lifecycle[0] as string, s, { "hookCliPosix.js": "process.exit(0)" }, env).status).toBe(0);
  });
  it("takes the hook's own exit code 0 and 2 through; a kill by the watchdog (137) becomes 2 for checked tools", () => {
    const s = sim("Darwin");
    expect(run(closed, s, { "hookCliPosix.js": "process.exit(2)" }, env).status).toBe(2);
    expect(run(closed, s, { "hookCliPosix.js": "process.exit(0)" }, env).status).toBe(0);
    const killed = run(closed, s, { "hookCliPosix.js": KILL_SELF }, env);
    expect(killed.status).toBe(2);
    expect(killed.stderr).toContain("fail closed");
    // the unchecked-tool code 42 stays a block, an unknown code is a block in enterprise mode
    expect(run(openTools, s, { "hookCliPosix.js": "process.exit(42)" }, env).status).toBe(2);
    expect(run(openTools, s, { "hookCliPosix.js": "process.exit(1)" }, env).status).toBe(2);
    expect(run(openTools, s, { "hookCliPosix.js": "process.exit(0)" }, env).status).toBe(0);
  });
});

describe("watchdog entry instead of timeout (M5)", () => {
  it("without a timeout program the POSIX entry (watchdog) is used, on macOS and elsewhere", () => {
    for (const system of ["Darwin", "Linux"]) {
      const s = sim(system);
      const r = run(lifecycle[0] as string, s, { "hookCliPosix.js": 'process.stdout.write("posix")', "hookCli.js": 'process.stdout.write("plain")' }, {}, { noTimeout: true });
      // outside enterprise mode `node` is looked up on PATH, which holds the test's node
      expect(r.stdout, system).toBe("posix");
    }
  });
  it("with a timeout program the plain entry is used, as before (Linux unchanged)", () => {
    const s = sim("Linux");
    const hasTimeout = ["/usr/bin/timeout", "/bin/timeout"].some((p) => existsSync(p));
    if (!hasTimeout) return;
    const r = run(lifecycle[0] as string, s, { "hookCliPosix.js": 'process.stdout.write("posix")', "hookCli.js": 'process.stdout.write("plain")' });
    expect(r.stdout).toBe("plain");
  });
  it("a hook that is killed without a timeout program blocks checked tools and never blocks others outside enterprise mode", () => {
    const s = sim("Darwin");
    expect(run(closed, s, { "hookCliPosix.js": KILL_SELF }, {}, { noTimeout: true }).status).toBe(2);
    expect(run(openTools, s, { "hookCliPosix.js": KILL_SELF }, {}, { noTimeout: true }).status).toBe(0);
  });
});
