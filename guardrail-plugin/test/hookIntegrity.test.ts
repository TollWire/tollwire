import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// hooks/hooks.json is a protected file. The hardening of the hook start (no NODE_OPTIONS and NODE_PATH from the user
// environment, a system Node in enterprise mode, exit code of the unchecked-tool rule mapped to a block) is delivered as
// hook-integrity.patch for a human to apply. This test checks the result of that patch while it is pending
// and the real file once it is applied. Nothing here depends on the uid of the test process.
const hooksFile = new URL("../hooks/hooks.json", import.meta.url);
const integrityPatch = new URL(["..", "..", "..", "org", "patches", "hook-integrity.patch"].join("/"), import.meta.url);

interface Entry {
  matcher?: string;
  hooks: { type: string; command: string; timeout: number }[];
}
interface Manifest {
  hooks: Record<string, Entry[]>;
}

/** The manifest as it will be once the pending patch is applied (or the real file if it already is). */
function hardened(): Manifest {
  const current = readFileSync(hooksFile, "utf8");
  // Hardened either by the named-variable form (-u NODE_OPTIONS ...) or by the positive-list form (env -i "$@", hooks-linux-env-i.patch).
  if (current.includes("NODE_OPTIONS") || current.includes('env -i \\"$@\\"')) return JSON.parse(current) as Manifest;
  const dir = mkdtempSync(join(tmpdir(), "tg-integrity-"));
  mkdirSync(join(dir, "product", "guardrail-plugin", "hooks"), { recursive: true });
  const target = join(dir, "product", "guardrail-plugin", "hooks", "hooks.json");
  writeFileSync(target, current);
  execFileSync("git", ["apply", "--unsafe-paths", "--directory", ".", integrityPatch.pathname], { cwd: dir });
  return JSON.parse(readFileSync(target, "utf8")) as Manifest;
}

const manifest = hardened();
const closed = manifest.hooks.PreToolUse?.[0]?.hooks[0]?.command as string;
const openTools = manifest.hooks.PreToolUse?.[1]?.hooks[0]?.command as string;
const lifecycle = ["SessionStart", "SessionEnd", "SubagentStart", "SubagentStop", "PostToolUse"].map((k) => manifest.hooks[k]?.[0]?.hooks[0]?.command as string);
const SYSTEM_NODE = ["/opt/tollgate/node/bin/node", "/usr/bin/node"].some((p) => existsSync(p));

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** Runs a manifest command with a plugin root whose hookCli.js is `script`; `fakeNode` is a program named node placed first on PATH. */
function run(command: string, script: string, env: NodeJS.ProcessEnv = {}, fakeNode = false, fakeTimeout = false): Run {
  const root = mkdtempSync(join(tmpdir(), "tg-integrity-root-"));
  mkdirSync(join(root, "dist"));
  writeFileSync(join(root, "dist", "hookCli.js"), script);
  const bin = join(root, "bin");
  mkdirSync(bin);
  if (fakeNode) {
    writeFileSync(join(bin, "node"), '#!/bin/sh\necho "FAKE-NODE-RAN"\nexit 0\n');
    chmodSync(join(bin, "node"), 0o755);
  }
  if (fakeTimeout) {
    // A program named timeout earlier on PATH that reports success without running anything.
    writeFileSync(join(bin, "timeout"), "#!/bin/sh\nexit 0\n");
    chmodSync(join(bin, "timeout"), 0o755);
  }
  const base: NodeJS.ProcessEnv = { PATH: fakeNode || fakeTimeout ? `${bin}:${process.env.PATH ?? ""}` : (process.env.PATH ?? ""), HOME: root };
  const r = spawnSync("sh", ["-c", command], { input: "{}", env: { ...base, CLAUDE_PLUGIN_ROOT: root, ...env }, encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

const PRINT_ENV = 'process.stdout.write(JSON.stringify({ options: process.env.NODE_OPTIONS ?? null, path: process.env.NODE_PATH ?? null, preload: process.env.LD_PRELOAD ?? null, argv: process.argv.slice(2) }));';
const HOSTILE = { NODE_OPTIONS: "--require /nonexistent/evil.js", NODE_PATH: "/nonexistent/modules", NODE_V8_COVERAGE: "/nonexistent/cov", LD_PRELOAD: "/nonexistent/evil.so" };

describe("hook start: environment of the Node process", () => {
  it("drops NODE_OPTIONS, NODE_PATH and LD_PRELOAD for every entry, in stand-alone and enterprise mode", () => {
    for (const command of [closed, openTools, ...lifecycle]) {
      for (const mode of [{}, { TOLLGATE_ENTERPRISE: "1" }]) {
        if ("TOLLGATE_ENTERPRISE" in mode && !SYSTEM_NODE) continue; // covered by the fail-closed test below
        const r = run(command, PRINT_ENV, { ...HOSTILE, ...mode });
        expect(r.status, `${JSON.stringify(mode)} ${r.stderr}`).toBe(0);
        expect(JSON.parse(r.stdout)).toMatchObject({ options: null, path: null, preload: null });
      }
    }
  });
  it("shows the damage the hardening prevents: without it NODE_OPTIONS reaches the process", () => {
    const r = spawnSync(process.execPath, ["-e", PRINT_ENV], { env: { ...process.env, ...HOSTILE, NODE_OPTIONS: "--no-warnings" }, encoding: "utf8" });
    expect(JSON.parse(r.stdout)).toMatchObject({ options: "--no-warnings" });
  });
  it("keeps the other variables and the stdin of the hook", () => {
    const r = run(closed, 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(s+process.env.CLAUDE_PROJECT_DIR));', { CLAUDE_PROJECT_DIR: "/x/project" });
    expect(r.stdout).toBe("{}/x/project");
  });
});

describe("hook start: Node binary in enterprise mode", () => {
  it("uses a system Node and never the first node on PATH when the enterprise signal is set", () => {
    const r = run(closed, 'process.stdout.write("REAL-NODE-RAN")', { TOLLGATE_ENTERPRISE: "1" }, true);
    if (SYSTEM_NODE) {
      expect(r.status).toBe(0);
      expect(r.stdout).toBe("REAL-NODE-RAN");
    } else {
      expect(r.status).toBe(2);
      expect(r.stderr).toContain("no system Node was found; fail closed");
    }
    expect(r.stdout).not.toContain("FAKE-NODE-RAN");
  });
  it("keeps using node from PATH without the enterprise signal", () => {
    const r = run(closed, 'process.stdout.write("REAL-NODE-RAN")', {}, true);
    // The test environment has neither /etc/tollgate nor the Mac admin directory; if one exists the signal is set and the other test applies.
    if (!existsSync("/etc/tollgate") && !existsSync("/Library/Application Support/TollGate")) expect(r.stdout).toContain("FAKE-NODE-RAN");
  });
  it("fails closed for checked tools and stays open for the other entries when no system Node exists", () => {
    // Without root the presence of the real system Node cannot be changed; both outcomes are the specified behaviour.
    expect(run(closed, "", { TOLLGATE_ENTERPRISE: "1" }).status).toBe(SYSTEM_NODE ? 0 : 2);
    // The entry for unchecked tools is fail closed in enterprise mode, too; the lifecycle entries stay open.
    expect(run(openTools, "", { TOLLGATE_ENTERPRISE: "1" }).status).toBe(SYSTEM_NODE ? 0 : 2);
    for (const command of lifecycle) expect(run(command, "", { TOLLGATE_ENTERPRISE: "1" }).status).toBe(0);
  });
  it("blocks unchecked tools on a crash, a timeout code or an odd exit code in enterprise mode, but not in stand-alone mode", () => {
    const dir = mkdtempSync(join(tmpdir(), "tg-integrity-ent-"));
    const sys = join(dir, "node");
    writeFileSync(sys, `#!/bin/sh\nexec "${process.execPath}" "$@"\n`);
    chmodSync(sys, 0o755);
    const enterpriseCommand = openTools.replace("/opt/tollgate/node/bin/node", sys);
    for (const script of ["throw new Error('boom');", "process.exit(3);", "process.exit(2);", "process.exit(124);", "import './missing.js';"]) {
      const r = run(enterpriseCommand, script, { TOLLGATE_ENTERPRISE: "1" });
      expect(r.status, script).toBe(2);
      expect(r.stderr).toContain("fail closed in enterprise mode");
      expect(run(openTools, script).status, `stand-alone ${script}`).toBe(0);
    }
    expect(run(enterpriseCommand, "process.exit(0);", { TOLLGATE_ENTERPRISE: "1" }).status).toBe(0);
  });
  it("never resolves timeout through PATH: a program named timeout that exits 0 cannot turn a block into an allow", () => {
    for (const env of [{}, { TOLLGATE_ENTERPRISE: "1" }]) {
      const r = run(closed, "process.exit(2);", env, false, true);
      expect(r.status, JSON.stringify(env)).toBe(2);
    }
    // Also with the hook failing: the fake timeout must not hide the failure either.
    expect(run(closed, "throw new Error('boom');", {}, false, true).status).toBe(2);
    expect(openTools).not.toContain("command -v");
    for (const command of [closed, openTools, ...lifecycle]) expect(command).not.toContain("command -v");
  });
  it("selects the system Node in the documented order (candidate paths redirected into a temporary directory)", () => {
    const dir = mkdtempSync(join(tmpdir(), "tg-integrity-sys-"));
    const first = join(dir, "opt-node");
    const second = join(dir, "usr-node");
    const make = (path: string, marker: string): void => {
      writeFileSync(path, `#!/bin/sh\necho ${marker}\nexec "${process.execPath}" "$@"\n`);
      chmodSync(path, 0o755);
    };
    const redirect = (command: string, a: string, b: string): string =>
      command.replace("/opt/tollgate/node/bin/node", a).replace("/usr/bin/node", b).replace('"/Library/Application Support/TollGate/node/bin/node"', '"/nonexistent/mac-node"');
    make(first, "OPT-NODE");
    make(second, "USR-NODE");
    const both = run(redirect(closed, first, second), PRINT_ENV, { TOLLGATE_ENTERPRISE: "1", ...HOSTILE }, true);
    expect(both.status).toBe(0);
    expect(both.stdout).toContain("OPT-NODE");
    expect(both.stdout).not.toContain("USR-NODE");
    expect(both.stdout).not.toContain("FAKE-NODE-RAN");
    expect(JSON.parse(both.stdout.slice(both.stdout.indexOf("{")))).toMatchObject({ options: null, path: null, preload: null });
    const onlySecond = run(redirect(closed, join(dir, "missing"), second), PRINT_ENV, { TOLLGATE_ENTERPRISE: "1" }, true);
    expect(onlySecond.stdout).toContain("USR-NODE");
    expect(onlySecond.stdout).not.toContain("FAKE-NODE-RAN");
    const none = run(redirect(closed, join(dir, "missing"), join(dir, "missing2")), PRINT_ENV, { TOLLGATE_ENTERPRISE: "1" }, true);
    expect(none.status).toBe(2);
    expect(none.stdout).not.toContain("FAKE-NODE-RAN");
  });
  it("treats the admin directory as the second enterprise signal", () => {
    expect(closed).toContain("[ -d /etc/tollgate ]");
    expect(closed).toContain('[ "$TOLLGATE_ENTERPRISE" = 1 ]');
  });
});

describe("hook start: exit codes", () => {
  const cases: [string, string][] = [
    ["allow", "process.exit(0);"],
    ["block", "process.exit(2);"],
    ["crash", "throw new Error('boom');"],
    ["other code", "process.exit(3);"],
  ];
  it("the fail-closed entry maps everything except 0 and 2 to 2", () => {
    const expected = [0, 2, 2, 2];
    cases.forEach(([name, script], i) => expect(run(closed, script).status, name).toBe(expected[i]));
    expect(run(closed, "process.exit(42);").status).toBe(2);
    expect(run(closed, "import './missing.js';").status).toBe(2);
  });
  it("the unchecked-tool entry blocks only on the exit code of the allowlist rule and stays open otherwise", () => {
    const expected = [0, 0, 0, 0];
    cases.forEach(([name, script], i) => expect(run(openTools, script).status, name).toBe(expected[i]));
    expect(run(openTools, "process.exit(42);").status).toBe(2);
    const crash = run(openTools, "throw new Error('boom');");
    expect(crash.stderr).toContain("not blocking this event");
  });
  it("the lifecycle entries never block", () => {
    for (const command of lifecycle) for (const [name, script] of cases) expect(run(command, script).status, name).toBe(0);
  });
  it("keeps the event binding of every entry (--event)", () => {
    for (const [event, entries] of Object.entries(manifest.hooks)) {
      for (const e of entries) expect(e.hooks[0]?.command, event).toContain(`dist/hookCli.js" --event ${event}`);
    }
  });
  it("keeps the matchers and the timeout", () => {
    expect(manifest.hooks.PreToolUse?.[0]?.matcher).toBe("Bash|Edit|Write|MultiEdit|NotebookEdit");
    expect(manifest.hooks.PreToolUse?.[1]?.matcher).toBe("^(?!(?:Bash|Edit|Write|MultiEdit|NotebookEdit)$).+");
    for (const entries of Object.values(manifest.hooks)) for (const e of entries) expect(e.hooks[0]?.timeout).toBe(30);
  });
});
