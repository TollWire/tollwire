import { chmodSync, mkdirSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { BLOCK_EXIT_CODE, runHook, UNCHECKED_DENY_EXIT_CODE, type HookDeps, type HookResult } from "../src/hook.js";
import { enterpriseLayout } from "../src/events/layout.js";
import { envFor, Fixture, readEvents, runtimeFor, tempDir } from "./events/helpers.js";

// Integration test for the admin lock flow: real control core of tollgate-enterprise (initLocks, serveRequest with
// the peer roles root / monitor) writes the lock file; the real hook of this package reads it. Nothing of the core logic is
// mocked; only paths, owner uid and clock are injected, as in adminLocks.test.ts and control*.test.ts.
// Why in this package: the hook is the side with external dependencies (zod, MCP SDK) and the side under CI coverage here,
// while the control core only needs node:*. The package tollgate-enterprise has no dependency on the plugin, so the core is
// loaded through a runtime path (dynamic import); no build output is needed and nothing is copied into this package.
// If tollgate-enterprise/src/control (core.ts, serve.ts) or vendor/controlProtocol.ts moves or is renamed, adjust the paths and
// the Core/Serve/Proto interfaces below.
// Not flaky by construction: injected clock, no sleeps, no network, no sockets (serveRequest takes the systemd instance name).

interface Ctx {
  paths: { locksFile: string };
  [k: string]: unknown;
}
interface Core {
  pathsIn: (stateDir: string, logDir: string) => Ctx["paths"];
  initLocks: (ctx: Ctx) => "created" | "exists" | "invalid";
}
interface Serve {
  serveRequest: (ctx: Ctx, instance: string, input: string | null, monitorUid: number | null) => string;
}
interface Proto {
  serializeRequest: (r: unknown) => string;
  parseResponse: (t: string) => Record<string, unknown> | null;
}
const enterprise = resolve(import.meta.dirname, "..", "..", "tollgate-enterprise", "src");
const load = <T,>(rel: string): Promise<T> => import(/* @vite-ignore */ join(enterprise, rel)) as Promise<T>;
const [core, serve, proto] = await Promise.all([load<Core>("control/core.ts"), load<Serve>("control/serve.ts"), load<Proto>("vendor/controlProtocol.ts")]);

const made: string[] = [];
const temp = (prefix: string): string => {
  const dir = tempDir(prefix);
  made.push(dir);
  return dir;
};
afterAll(() => {
  for (const dir of made.splice(0)) rmSync(dir, { recursive: true, force: true });
});

const owner = process.getuid?.() ?? 0;
const hookUid = 4242;
const MONITOR_UID = 990;
const ROOT_PEER = "1-4000-0";
const MONITOR_PEER = "2-4100-990";
const START = Date.parse("2026-10-18T09:00:00.000Z");
const uuid = (prefix: string, n: number): string => `${prefix}0000000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;
const BASE = { version: 2, revision: "acme-flow", protectedPaths: [], blockedCommands: [], allowedDependencies: { npm: [], pypi: [] } };
const ON = { ...BASE, control: { enabled: true } };
const OFF = { ...BASE, control: { enabled: false } };

function setup(policy: unknown = ON) {
  let now = START;
  let requests = 0;
  let ids = 0;
  const root = temp("tg-lockflow-");
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
  const stateDir = join(root, "var", "lib", "tollgate", "control");
  mkdirSync(stateDir, { recursive: true });
  for (const d of [join(root, "var"), join(root, "var", "lib"), join(root, "var", "lib", "tollgate"), stateDir]) chmodSync(d, 0o755);
  const logDir = join(root, "log", "control");
  mkdirSync(logDir, { recursive: true, mode: 0o750 });
  chmodSync(logDir, 0o750);
  const events = join(root, "events", String(owner));
  mkdirSync(events, { recursive: true, mode: 0o750 });

  const paths = core.pathsIn(stateDir, logDir);
  const ctx: Ctx = { paths, ownerUid: owner, stopAt: root, hostName: "host-1", version: "0.1.0", now: () => new Date(now), uuid: () => uuid("1", (ids += 1)), logUid: owner, lockOptions: { timeoutMs: 200, pollMs: 5 } };
  const deps: HookDeps = {
    runtime: rt,
    resolve: { ownerUid: owner, stopAt: root, paths: { adminDir: admin, policyFile } },
    enterpriseLayout: () => ({ ...enterpriseLayout("per_user", owner, rt.home), eventsDir: events, lockDir: events }),
    locks: { path: paths.locksFile, now: () => now, uid: hookUid },
  };
  const hook = (tool: string, input: Record<string, unknown>, session = "s-1"): HookResult =>
    runHook(JSON.stringify({ session_id: session, tool_use_id: "toolu_1", hook_event_name: "PreToolUse", tool_name: tool, tool_input: input }), env, project, { ...deps, event: "PreToolUse" });
  const bash = (session = "s-1"): HookResult => hook("Bash", { command: "echo hallo" }, session);
  const decisions = () => {
    try {
      return readEvents(events).flatMap((f) => f.events).filter((e) => e.type === "decision");
    } catch {
      return [];
    }
  };
  const send = (peer: string, request: Record<string, unknown>, monitorUid: number | null = MONITOR_UID): Record<string, unknown> => {
    requests += 1;
    const base = { requestId: uuid("2", requests), claimed: { uid: 1002, name: "alice" } };
    const reply = serve.serveRequest(ctx, peer, proto.serializeRequest({ ...base, ...request }), monitorUid);
    return proto.parseResponse(reply.trimEnd()) as Record<string, unknown>;
  };
  const lock = (peer: string, kind: string, target: unknown, expires: string | null = null) => send(peer, { op: "lock", kind, target, expires, reason: "incident 4711: suspected key leak" });
  const unlock = (peer: string, lockId: string | null) => send(peer, { op: "unlock", lockId, reason: "false alarm, checked with the owner" });
  return { ctx, root, paths, bash, hook, decisions, lock, unlock, advance: (ms: number) => (now += ms), now: () => now, stateDir };
}

describe("admin lock flow: control core writes, hook enforces", () => {
  it("allow -> lock (root) -> deny -> unlock (root) -> allow, with generations and decision events", () => {
    const e = setup();
    expect(core.initLocks(e.ctx)).toBe("created");
    expect(core.initLocks(e.ctx)).toBe("exists");

    const first = e.bash();
    expect(first.code).toBe(0);

    const locked = e.lock(ROOT_PEER, "tool", { tool: "Bash" });
    expect(locked).toMatchObject({ ok: true, result: "applied", generation: 1 });
    const lockId = locked.lock_id as string;

    const denied = e.bash();
    expect(denied.code).toBe(BLOCK_EXIT_CODE);
    expect(denied.message).toBe(
      ["TollGate guardrail: blocked.", `rule_id: ${lockId}`, "rule_kind: admin_lock", "detail: blocked by an administrator lock (tool).", "fix: locked by the administrator - contact your administrator."].join("\n"),
    );
    expect(denied.message).not.toMatch(/incident|4711|key leak/); // the reason of the administrator never reaches the agent
    // other tools are not affected by a tool lock
    expect(e.hook("Read", { file_path: join(e.root, "project", "a.ts") }).code).toBe(0);

    const unlocked = e.unlock(ROOT_PEER, lockId);
    expect(unlocked).toMatchObject({ ok: true, result: "applied", generation: 2 });
    expect(e.bash().code).toBe(0);

    const [d1, d2, , d4] = e.decisions();
    expect(d1?.decision).toMatchObject({ outcome: "allow" });
    expect(d1?.policy?.layers.at(-1)).toMatchObject({ level: "locks", generation: 0 });
    expect(d2?.decision).toMatchObject({ outcome: "deny", rule_kind: "admin_lock", rule_id: lockId });
    expect(d2?.policy?.layers.at(-1)).toMatchObject({ level: "locks", generation: 1 });
    expect(d4?.decision).toMatchObject({ outcome: "allow" });
    expect(d4?.policy?.layers.at(-1)).toMatchObject({ level: "locks", generation: 2 });
    expect(e.decisions()).toHaveLength(4);
  });

  it("emergency stop by the monitor peer blocks unchecked tools too; only root lifts it", () => {
    const e = setup();
    core.initLocks(e.ctx);
    const locked = e.lock(MONITOR_PEER, "global", {});
    expect(locked).toMatchObject({ ok: true, generation: 1 });
    expect(e.bash().code).toBe(BLOCK_EXIT_CODE);
    expect(e.hook("Read", { file_path: join(e.root, "project", "a.ts") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(e.unlock(MONITOR_PEER, null)).toEqual({ v: 1, ok: false, error: "forbidden" });
    expect(e.bash().code).toBe(BLOCK_EXIT_CODE);
    expect(e.unlock(ROOT_PEER, null)).toMatchObject({ ok: true, generation: 2 });
    expect(e.bash().code).toBe(0);
  });

  it("an unlock by the monitor peer is rejected: the file stays as it is and the lock stays in force", () => {
    const e = setup();
    core.initLocks(e.ctx);
    const lockId = e.lock(MONITOR_PEER, "tool", { tool: "Bash" }).lock_id as string;
    const before = readFileSync(e.paths.locksFile, "utf8");
    expect(e.unlock(MONITOR_PEER, lockId)).toEqual({ v: 1, ok: false, error: "forbidden" });
    expect(readFileSync(e.paths.locksFile, "utf8")).toBe(before);
    expect(e.bash().code).toBe(BLOCK_EXIT_CODE);
    // a peer that is neither root nor monitor cannot lock at all
    expect(e.lock("3-4200-1500", "global", {})).toEqual({ v: 1, ok: false, error: "forbidden" });
    expect(readFileSync(e.paths.locksFile, "utf8")).toBe(before);
  });

  it("a lock with an expiry stops applying when the clock reaches it (no sleep, injected clock)", () => {
    const e = setup();
    core.initLocks(e.ctx);
    const expires = new Date(START + 3_600_000).toISOString();
    expect(e.lock(ROOT_PEER, "tool", { tool: "Bash" }, expires)).toMatchObject({ ok: true, generation: 1 });
    expect(e.bash().code).toBe(BLOCK_EXIT_CODE);
    e.advance(3_599_999);
    expect(e.bash().code).toBe(BLOCK_EXIT_CODE);
    e.advance(1);
    expect(e.bash().code).toBe(0);
  });

  it("user lock: only the uid the hook sees; session lock: only that session", () => {
    const e = setup();
    core.initLocks(e.ctx);
    const other = e.lock(ROOT_PEER, "user", { uid: hookUid + 1 });
    expect(other).toMatchObject({ ok: true, generation: 1 });
    expect(e.bash().code).toBe(0);
    const mine = e.lock(ROOT_PEER, "user", { uid: hookUid });
    expect(mine).toMatchObject({ ok: true, generation: 2 });
    const denied = e.bash();
    expect(denied.code).toBe(BLOCK_EXIT_CODE);
    expect(denied.message).toContain(`rule_id: ${mine.lock_id as string}`);
    expect(e.hook("Read", { file_path: join(e.root, "project", "a.ts") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(e.unlock(ROOT_PEER, mine.lock_id as string)).toMatchObject({ ok: true, generation: 3 });
    expect(e.bash().code).toBe(0);

    const session = e.lock(ROOT_PEER, "session", { session_id: "s-7" });
    expect(session).toMatchObject({ ok: true, generation: 4 });
    expect(e.bash("s-7").code).toBe(BLOCK_EXIT_CODE);
    expect(e.bash("s-8").code).toBe(0);
    expect(e.bash("s-1").code).toBe(0);
  });

  describe("fail closed: an unusable lock file blocks every tool with lock_error", () => {
    const expectLockError = (e: ReturnType<typeof setup>): void => {
      const bash = e.bash();
      expect(bash.code).toBe(BLOCK_EXIT_CODE);
      expect(bash.message).toContain("rule_id: -\nrule_kind: lock_error\n");
      expect(bash.message).not.toContain(e.root);
      expect(e.hook("Read", { file_path: join(e.root, "project", "a.ts") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
      expect(e.hook("WebFetch", { url: "https://example.org/" }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
      expect(e.decisions().at(-1)?.decision).toMatchObject({ outcome: "deny", rule_kind: "lock_error", rule_id: null });
    };

    it("corrupt file after a valid generation; the core refuses to overwrite it; restoring it lifts the block", () => {
      const e = setup();
      core.initLocks(e.ctx);
      const good = readFileSync(e.paths.locksFile, "utf8");
      expect(e.bash().code).toBe(0);
      writeFileSync(e.paths.locksFile, "not json", { mode: 0o644 });
      expectLockError(e);
      expect(core.initLocks(e.ctx)).toBe("invalid"); // the installer step never overwrites an invalid file
      expect(e.lock(ROOT_PEER, "global", {})).toMatchObject({ ok: false, error: "locks_invalid" });
      writeFileSync(e.paths.locksFile, good, { mode: 0o644 });
      expect(e.bash().code).toBe(0);
    });

    it("lock file is a symbolic link", () => {
      const e = setup();
      core.initLocks(e.ctx);
      const real = join(e.stateDir, "real.json");
      renameSync(e.paths.locksFile, real);
      symlinkSync(real, e.paths.locksFile);
      expectLockError(e);
    });

    it("lock file writable by group or others (trust check); restoring the mode lifts the block", () => {
      for (const mode of [0o666, 0o664]) {
        const e = setup();
        core.initLocks(e.ctx);
        expect(e.bash().code).toBe(0);
        chmodSync(e.paths.locksFile, mode);
        expectLockError(e);
        chmodSync(e.paths.locksFile, 0o644);
        expect(e.bash().code).toBe(0);
      }
    });

    it("lock file missing", () => {
      const e = setup();
      expectLockError(e); // initLocks was never run
    });
  });

  it("without control.enabled a lock (and a broken file) has no effect", () => {
    const e = setup(OFF);
    core.initLocks(e.ctx);
    expect(e.lock(ROOT_PEER, "global", {})).toMatchObject({ ok: true, generation: 1 });
    expect(e.bash().code).toBe(0);
    writeFileSync(e.paths.locksFile, "garbage that would fail closed", { mode: 0o644 });
    expect(e.bash().code).toBe(0);
    const ds = e.decisions();
    expect(ds).toHaveLength(2);
    for (const d of ds) {
      expect(d.policy).toBeDefined();
      expect(d.policy?.layers.some((l) => l.level === "locks")).toBe(false);
    }
  });
});
