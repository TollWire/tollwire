import { chmodSync, linkSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkAdminLocks } from "../src/adminLocks.js";
import { parseEnterprisePolicy, parseLowerLayer, systemProtectedPaths, LOCKS_FILE } from "../src/enterprise.js";
import { enterpriseLayout } from "../src/events/layout.js";
import { BLOCK_EXIT_CODE, runHook, UNCHECKED_DENY_EXIT_CODE, type HookDeps, type HookResult } from "../src/hook.js";
import { RULE_KINDS } from "../src/events/types.js";
import { applyChange, emptyLocks, serializeLocks, type LockSpec, type LocksFile } from "../src/vendor/locks.js";
import { envFor, Fixture, readEvents, runtimeFor, tempDir } from "./events/helpers.js";
import { BUNDLED_WITHOUT_TAINT } from "./helpers.js";

// Admin locks: the hook evaluates the admin lock file before the split into checked and unchecked tools.
const owner = process.getuid?.() ?? 0; // owner of the fixture files (the test runs as this user, possibly root)
const uid = 4242; // the uid that the hook sees for the user (locks accept 1..4294967294)
const NOW = Date.parse("2026-10-18T09:12:03.120Z");
const NOW_ISO = new Date(NOW).toISOString();
const uuid = (n: number): string => `00000000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;

const BASE = { version: 2, revision: "acme-locks", protectedPaths: [], blockedCommands: [], allowedDependencies: { npm: [], pypi: [] } };
const ON = { ...BASE, control: { enabled: true }, tools: { unchecked: "deny", allow: ["WebFetch", "mcp__docs__*"] } };

function spec(n: number, kind: LockSpec["kind"], target: unknown, expires: string | null = null): LockSpec {
  return { id: uuid(n), kind, target, expires, by_uid: 1002, via: "monitor", event_id: uuid(1000 + n) };
}
function fileWith(...specs: LockSpec[]): LocksFile {
  return specs.reduce((f, s) => applyChange(f, serializeLocks(f), { op: "lock", spec: s }, NOW_ISO).next, emptyLocks("host-1", NOW_ISO));
}

interface Env {
  call: (tool: string, input?: Record<string, unknown>, extra?: Record<string, unknown>, env?: NodeJS.ProcessEnv) => HookResult;
  decisions: () => ReturnType<typeof readEvents>[number]["events"];
  write: (file: LocksFile | string, mode?: number) => string;
  locksPath: string;
  root: string;
  project: string;
}

function setup(policy: unknown = ON, now: () => number = () => NOW): Env {
  const root = tempDir("tg-locks-");
  const project = join(root, "project");
  mkdirSync(project);
  const rt = runtimeFor(root, new Fixture());
  const env: NodeJS.ProcessEnv = { ...envFor(root), CLAUDE_PROJECT_DIR: project, TOLLGATE_ENTERPRISE: "1" };
  const admin = join(root, "etc", "tollgate");
  mkdirSync(admin, { recursive: true });
  chmodSync(join(root, "etc"), 0o755);
  chmodSync(admin, 0o755);
  const policyFile = join(admin, "policy.json");
  writeFileSync(policyFile, JSON.stringify(policy), { mode: 0o644 });
  chmodSync(policyFile, 0o644);
  const control = join(root, "var", "lib", "tollgate", "control");
  mkdirSync(control, { recursive: true });
  for (const d of [join(root, "var"), join(root, "var", "lib"), join(root, "var", "lib", "tollgate"), control]) chmodSync(d, 0o755);
  const locksPath = join(control, "locks.json");
  const events = join(root, "events", String(owner));
  mkdirSync(events, { recursive: true, mode: 0o750 });
  const deps: HookDeps = {
    runtime: rt,
    // Pinned default policy without session taint (tool calls without a session start).
    resolve: { ownerUid: owner, stopAt: root, paths: { adminDir: admin, policyFile }, bundledPolicy: BUNDLED_WITHOUT_TAINT },
    enterpriseLayout: () => ({ ...enterpriseLayout("per_user", owner, rt.home), eventsDir: events, lockDir: events }),
    locks: { path: locksPath, now, uid },
  };
  const write = (file: LocksFile | string, mode = 0o644): string => {
    writeFileSync(locksPath, typeof file === "string" ? file : serializeLocks(file), { mode });
    chmodSync(locksPath, mode);
    return locksPath;
  };
  const call: Env["call"] = (tool, input = {}, extra = {}, extraEnv = {}) =>
    runHook(JSON.stringify({ session_id: "s-1", tool_use_id: "toolu_1", hook_event_name: "PreToolUse", tool_name: tool, tool_input: input, ...extra }), { ...env, ...extraEnv }, project, { ...deps, event: "PreToolUse" });
  const decisions = (): ReturnType<Env["decisions"]> => {
    try {
      return readEvents(events).flatMap((f) => f.events).filter((e) => e.type === "decision");
    } catch {
      return [];
    }
  };
  return { call, decisions, write, locksPath, root, project };
}

const READ = (e: Env): [string, Record<string, unknown>] => ["Read", { file_path: join(e.project, "a.ts") }];
const BASH: [string, Record<string, unknown>] = ["Bash", { command: "ls" }];

describe("lock kinds", () => {
  it("allows everything while the file is empty", () => {
    const e = setup();
    e.write(emptyLocks("host-1", NOW_ISO));
    expect(e.call(...BASH).code).toBe(0);
    expect(e.call(...READ(e)).code).toBe(0);
    expect(e.call("WebFetch", { url: "https://example.org/" }).code).toBe(0);
    const d = e.decisions().at(-1);
    expect(d?.policy?.layers.at(-1)).toMatchObject({ level: "locks", generation: 0 });
  });

  it("user lock: every tool of that uid, read-only ones too (Q3)", () => {
    const e = setup();
    e.write(fileWith(spec(1, "user", { uid })));
    const bash = e.call(...BASH);
    expect(bash.code).toBe(BLOCK_EXIT_CODE);
    expect(bash.message).toBe(
      [
        "TollGate guardrail: blocked.",
        `rule_id: ${uuid(1)}`,
        "rule_kind: admin_lock",
        "detail: blocked by an administrator lock (user).",
        "fix: locked by the administrator - contact your administrator.",
      ].join("\n"),
    );
    expect(e.call(...READ(e)).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(e.call("Edit", { file_path: join(e.project, "a.ts"), old_string: "a", new_string: "b" }).code).toBe(BLOCK_EXIT_CODE);
    expect(e.call("mcp__docs__search", {}).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });

  it("user lock for another uid does not apply", () => {
    const e = setup();
    e.write(fileWith(spec(1, "user", { uid: uid + 1 })));
    expect(e.call(...BASH).code).toBe(0);
  });

  it("session lock: that session only", () => {
    const e = setup();
    e.write(fileWith(spec(1, "session", { session_id: "s-1" })));
    expect(e.call(...BASH).code).toBe(BLOCK_EXIT_CODE);
    expect(e.call(...BASH, { session_id: "s-2" }).code).toBe(0);
    expect(e.call(...READ(e)).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });

  it("tool lock: exact name and MCP server wildcard, also a checked tool", () => {
    const e = setup();
    e.write(fileWith(spec(1, "tool", { tool: "mcp__docs__*" }), spec(2, "tool", { tool: "Bash" }), spec(3, "tool", { tool: "WebFetch" })));
    expect(e.call("mcp__docs__search", {}).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(e.call("mcp__docs2__search", {}).code).toBe(UNCHECKED_DENY_EXIT_CODE); // not on the tool allowlist anyway
    expect(e.call(...BASH).code).toBe(BLOCK_EXIT_CODE);
    expect(e.call("WebFetch", { url: "https://example.org/" }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(e.call(...READ(e)).code).toBe(0);
    expect(e.call("Edit", { file_path: join(e.project, "a.ts"), old_string: "a", new_string: "b" }).code).toBe(0);
  });

  it("emergency stop: every tool of every user; lifecycle and PostToolUse stay untouched", () => {
    const e = setup();
    e.write(fileWith(spec(1, "global", {})));
    expect(e.call(...BASH).code).toBe(BLOCK_EXIT_CODE);
    expect(e.call(...READ(e)).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(e.call("WebFetch", {}).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(e.call("mcp__docs__x", {}).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    for (const name of ["SessionStart", "SessionEnd", "SubagentStart", "SubagentStop"]) {
      const r = runHookWithEvent(e, name);
      expect(r.code, name).toBe(0);
    }
    const post = runHookWithEvent(e, "PostToolUse", { tool_name: "Bash", tool_input: { command: "ls" }, tool_response: "x" });
    expect(post.code).toBe(0);
  });

  it("an expired lock has no effect (system clock)", () => {
    let now = NOW;
    const e = setup(ON, () => now);
    e.write(fileWith(spec(1, "user", { uid }, new Date(NOW + 60_000).toISOString())));
    expect(e.call(...BASH).code).toBe(BLOCK_EXIT_CODE);
    now = NOW + 60_000;
    expect(e.call(...BASH).code).toBe(0);
  });

  it("TOLLGATE_HUMAN_SESSION does not lift a lock", () => {
    const e = setup({ ...ON, humanSession: { allowed: true } });
    e.write(fileWith(spec(1, "user", { uid })));
    expect(e.call(...BASH, {}, { TOLLGATE_HUMAN_SESSION: "1" }).code).toBe(BLOCK_EXIT_CODE);
    expect(e.decisions().at(-1)?.decision?.human_session).toBe(true);
  });
});

function runHookWithEvent(e: Env, name: string, extra: Record<string, unknown> = {}): HookResult {
  // Same wiring as the manifest: the hook is declared for this event.
  const input = JSON.stringify({ session_id: "s-1", hook_event_name: name, ...extra });
  const root = e.root;
  const rt = runtimeFor(root, new Fixture());
  return runHook(input, { ...envFor(root), CLAUDE_PROJECT_DIR: e.project, TOLLGATE_ENTERPRISE: "1" }, e.project, {
    runtime: rt,
    event: name,
    resolve: { ownerUid: owner, stopAt: root, paths: { adminDir: join(root, "etc", "tollgate"), policyFile: join(root, "etc", "tollgate", "policy.json") } },
    enterpriseLayout: () => ({ ...enterpriseLayout("per_user", owner, rt.home), eventsDir: join(root, "events", String(owner)), lockDir: join(root, "events", String(owner)) }),
    locks: { path: e.locksPath, now: () => NOW, uid },
  });
}

describe("a failure in the lock path never lets a call through (review)", () => {
  it("an exception while the decision is logged is a deny: exit 42 for an unchecked tool, exit 2 for a checked one", () => {
    const e = setup();
    e.write(fileWith(spec(1, "global", {})));
    const root = e.root;
    const rt = runtimeFor(root, new Fixture());
    const deps: HookDeps = {
      runtime: rt,
      event: "PreToolUse",
      resolve: { ownerUid: owner, stopAt: root, paths: { adminDir: join(root, "etc", "tollgate"), policyFile: join(root, "etc", "tollgate", "policy.json") } },
      enterpriseLayout: () => {
        throw new Error("layout failed");
      },
      locks: { path: e.locksPath, now: () => NOW, uid },
    };
    const call = (tool: string, input: Record<string, unknown>): HookResult =>
      runHook(JSON.stringify({ session_id: "s-1", hook_event_name: "PreToolUse", tool_name: tool, tool_input: input }), { ...envFor(root), CLAUDE_PROJECT_DIR: e.project, TOLLGATE_ENTERPRISE: "1" }, e.project, deps);
    expect(() => call("Read", { file_path: join(e.project, "a.ts") })).not.toThrow();
    expect(call("Read", { file_path: join(e.project, "a.ts") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(call("mcp__docs__search", {}).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(call("Bash", { command: "ls" }).code).toBe(BLOCK_EXIT_CODE);
  });
});

describe("decision event", () => {
  it("records admin_lock with the lock id and the locks layer; the policy hash does not change with the locks", () => {
    const e = setup();
    e.write(emptyLocks("host-1", NOW_ISO));
    e.call(...BASH);
    e.write(fileWith(spec(1, "tool", { tool: "Bash" })));
    const r = e.call(...BASH);
    expect(r.message).not.toMatch(/reason|incident/i);
    const [allowed, denied] = e.decisions();
    expect(allowed?.decision).toMatchObject({ outcome: "allow" });
    expect(denied?.decision).toMatchObject({ outcome: "deny", rule_kind: "admin_lock", rule_id: uuid(1) });
    expect(denied?.policy?.layers.at(-1)).toMatchObject({ level: "locks", generation: 1 });
    expect(denied?.policy?.layers.at(-1)?.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(denied?.policy?.sha256).toBe(allowed?.policy?.sha256);
    expect(denied?.policy?.layers.slice(0, -1)).toEqual(allowed?.policy?.layers.slice(0, -1));
    expect(RULE_KINDS).toContain("admin_lock");
    expect(RULE_KINDS).toContain("lock_error");
  });
});

describe("fail closed (control.enabled)", () => {
  const denies = (e: Env): void => {
    for (const [tool, input, code] of [[...BASH, BLOCK_EXIT_CODE], [...READ(e), UNCHECKED_DENY_EXIT_CODE], ["WebFetch", {}, UNCHECKED_DENY_EXIT_CODE]] as const) {
      const r = e.call(tool, input);
      expect(r.code, tool).toBe(code);
      expect(r.message).toContain("administrator lock state is unusable");
      expect(r.message).toContain("rule_id: -\nrule_kind: lock_error\n");
      expect(r.message).toContain("fix: the administrator lock state is unusable - contact your administrator.");
      // nothing of the cause reaches the agent
      expect(r.message).not.toContain(e.root);
    }
    expect(e.decisions().at(-1)?.decision).toMatchObject({ outcome: "deny", rule_kind: "lock_error", rule_id: null });
  };

  it("file missing", () => {
    denies(setup());
  });
  it("file invalid, unknown field, not canonical, empty", () => {
    for (const content of ["not json", "", "{}\n", `${serializeLocks(emptyLocks("h", NOW_ISO)).trimEnd()} \n`, serializeLocks(emptyLocks("h", NOW_ISO)).replace("}\n", ',"allow":["Bash"]}\n')]) {
      const e = setup();
      e.write(content);
      denies(e);
    }
  });
  it("file larger than 64 KiB", () => {
    const e = setup();
    e.write(`${" ".repeat(70_000)}\n`);
    denies(e);
  });
  it("file writable by group or others", () => {
    for (const mode of [0o664, 0o646, 0o666]) {
      const e = setup();
      e.write(emptyLocks("host-1", NOW_ISO), mode);
      denies(e);
    }
  });
  it("file is a symbolic link, or a path component is", () => {
    const e = setup();
    e.write(emptyLocks("host-1", NOW_ISO));
    const real = join(e.root, "real.json");
    writeFileSync(real, serializeLocks(emptyLocks("host-1", NOW_ISO)), { mode: 0o644 });
    chmodSync(real, 0o644);
    writeFileSync(join(e.root, "x"), "");
    const e2 = setup();
    symlinkSync(real, e2.locksPath);
    denies(e2);
    const e3 = setup();
    e3.write(emptyLocks("host-1", NOW_ISO));
    // replace the control directory by a link to another directory
    const dir = join(e3.root, "var", "lib", "tollgate", "control");
    const moved = join(e3.root, "elsewhere");
    mkdirSync(moved);
    chmodSync(moved, 0o755);
    writeFileSync(join(moved, "locks.json"), serializeLocks(emptyLocks("host-1", NOW_ISO)), { mode: 0o644 });
    chmodSync(join(moved, "locks.json"), 0o644);
    // rename keeps the test independent of rm
    mkdirSync(join(e3.root, "trash"));
    return import("node:fs").then(({ renameSync }) => {
      renameSync(dir, join(e3.root, "trash", "control"));
      symlinkSync(moved, dir);
      denies(e3);
    });
  });
  it("file with a second hard link", () => {
    const e = setup();
    e.write(emptyLocks("host-1", NOW_ISO));
    linkSync(e.locksPath, join(e.root, "alias.json"));
    denies(e);
  });
  it("a parent directory writable by group or others", () => {
    const e = setup();
    e.write(emptyLocks("host-1", NOW_ISO));
    chmodSync(join(e.root, "var", "lib", "tollgate"), 0o775);
    denies(e);
  });
  it("owner other than the administrator", () => {
    const e = setup();
    e.write(emptyLocks("host-1", NOW_ISO));
    const r = checkAdminLocks({ path: e.locksPath, ownerUid: owner + 1, stopAt: e.root, uid, sessionId: "s-1", toolName: "Bash", nowMs: NOW });
    expect(r.deny).toMatchObject({ kind: "lock_error" });
    expect(r.deny?.reason).toContain("not owned by the administrator");
    expect(r.deny?.message).not.toContain(e.root);
    expect(r.layer).toBeNull();
  });
  it("a valid file after the error is honoured again (nothing is remembered)", () => {
    const e = setup();
    denies(e);
    e.write(emptyLocks("host-1", NOW_ISO));
    expect(e.call(...BASH).code).toBe(0);
  });
});

describe("no effect without control.enabled", () => {
  it.each([
    ["no control section", BASE],
    ["enabled false", { ...BASE, control: { enabled: false } }],
  ])("%s: the file is not even read", (_n, policy) => {
    const e = setup(policy);
    e.write("garbage that would fail closed");
    expect(e.call(...BASH).code).toBe(0);
    e.write(fileWith(spec(1, "global", {})));
    expect(e.call(...BASH).code).toBe(0);
    expect(e.decisions().at(-1)?.policy?.layers.some((l) => l.level === "locks")).toBe(false);
  });

  it("outside enterprise mode no lock applies", () => {
    const root = tempDir("tg-locks-std-");
    const project = join(root, "project");
    mkdirSync(project);
    const rt = runtimeFor(root, new Fixture());
    const missing = join(root, "none.json");
    const r = runHook(JSON.stringify({ session_id: "s", hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } }), { ...envFor(root), CLAUDE_PROJECT_DIR: project }, project, {
      runtime: rt,
      locks: { path: missing, now: () => NOW },
      event: "PreToolUse",
      resolve: { exists: () => false },
    });
    expect(r.code).toBe(0);
  });

  it("a lower layer cannot switch it on or off: the section is ignored with a finding", () => {
    const { findings } = parseLowerLayer(JSON.stringify({ version: 1, protectedPaths: [], blockedCommands: [], control: { enabled: false } }), "project");
    expect(findings).toEqual([{ type: "policy_override_ignored", level: "project", detail: "section 'control' is only valid in the enterprise policy" }]);
  });

  it("parses the section in the enterprise policy only as a boolean", () => {
    expect(parseEnterprisePolicy(JSON.stringify(BASE)).control).toEqual({ enabled: false });
    expect(parseEnterprisePolicy(JSON.stringify(ON)).control).toEqual({ enabled: true });
    expect(() => parseEnterprisePolicy(JSON.stringify({ ...BASE, control: { enabled: "yes" } }))).toThrow();
    expect(() => parseEnterprisePolicy(JSON.stringify({ ...BASE, control: {} }))).toThrow();
  });
});

describe("protected path and defaults", () => {
  it("keeps /var/lib/tollgate/ among the always-protected system paths", () => {
    expect(systemProtectedPaths("linux")).toContain("/var/lib/tollgate/");
    expect(LOCKS_FILE).toBe("/var/lib/tollgate/control/locks.json");
  });
});

describe("property: the lock layer only tightens (hook level)", () => {
  let seed = 0x9e3779b9;
  const rnd = (): number => {
    seed ^= seed << 13;
    seed >>>= 0;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    seed >>>= 0;
    return seed / 0x100000000;
  };
  const pick = <T,>(items: readonly T[]): T => items[Math.floor(rnd() * items.length)] as T;

  it("calls allowed with locks are a subset of calls allowed without locks", () => {
    const calls: [string, Record<string, unknown>][] = [
      ["Bash", { command: "ls" }], ["Bash", { command: "git push --force origin main" }], ["Bash", { command: "rm -rf /" }],
      ["Read", { file_path: "/p/a.ts" }], ["WebFetch", { url: "https://example.org/" }], ["mcp__docs__search", {}], ["mcp__other__x", {}], ["EnterWorktree", {}],
    ];
    let denyByLock = 0;
    for (let run = 0; run < 25; run += 1) {
      const e = setup(rnd() < 0.5 ? ON : { ...ON, tools: { unchecked: "observe" } });
      const specs: LockSpec[] = [];
      for (let i = 0; i < Math.floor(rnd() * 4); i += 1) {
        const kind = pick(["user", "session", "tool", "global"] as const);
        const target = kind === "user" ? { uid: pick([uid, uid + 1]) } : kind === "session" ? { session_id: pick(["s-1", "s-2"]) } : kind === "tool" ? { tool: pick(["Bash", "Read", "mcp__docs__*", "WebFetch"]) } : {};
        specs.push(spec(i + 1, kind, target));
      }
      for (const [tool, input] of calls) {
        const sid = pick(["s-1", "s-2"]);
        e.write(emptyLocks("host-1", NOW_ISO));
        const without = e.call(tool, input.file_path === undefined ? input : { file_path: join(e.project, "a.ts") }, { session_id: sid });
        e.write(fileWith(...specs));
        const withLocks = e.call(tool, input.file_path === undefined ? input : { file_path: join(e.project, "a.ts") }, { session_id: sid });
        if (withLocks.code === 0) expect(without.code, `${tool} ${JSON.stringify(specs.map((s) => s.kind))}`).toBe(0);
        if (without.code === 0 && withLocks.code !== 0) denyByLock += 1;
        // a deny of the policy keeps its exit code class or becomes stricter, never an allow
        if (without.code !== 0) expect(withLocks.code).not.toBe(0);
      }
    }
    expect(denyByLock).toBeGreaterThan(0);
  });
});

describe("cost of the check", () => {
  it("measures the check with 200 entries (value printed; bound is generous)", () => {
    const e = setup();
    let f = emptyLocks("host-1", NOW_ISO);
    for (let i = 0; i < 200; i += 1) f = applyChange(f, serializeLocks(f), { op: "lock", spec: spec(i + 1, "user", { uid: 50_000 + i }) }, NOW_ISO).next;
    e.write(f);
    const input = { path: e.locksPath, ownerUid: owner, stopAt: e.root, uid, sessionId: "s-1", toolName: "Bash", nowMs: NOW };
    for (let i = 0; i < 50; i += 1) checkAdminLocks(input); // warm up
    const times: number[] = [];
    for (let i = 0; i < 500; i += 1) {
      const t0 = process.hrtime.bigint();
      const r = checkAdminLocks(input);
      times.push(Number(process.hrtime.bigint() - t0) / 1e6);
      expect(r.deny).toBeNull();
    }
    times.sort((a, b) => a - b);
    const p95 = times[Math.floor(times.length * 0.95)] as number;
    console.log(`admin lock check, 200 entries, in-process, warm: p50=${times[250]?.toFixed(3)} ms p95=${p95.toFixed(3)} ms (500 runs)`);
    expect(p95).toBeLessThan(25);
  });
});
