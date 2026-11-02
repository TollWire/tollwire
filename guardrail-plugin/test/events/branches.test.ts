import { mkdirSync, readdirSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeCommand } from "../../src/events/commandInfo.js";
import { enterpriseLayout, type Layout } from "../../src/events/layout.js";
import { EventLogger, type DecisionRecord } from "../../src/events/logger.js";
import { redactCommand } from "../../src/events/redact.js";
import { systemProcessFacts } from "../../src/events/lock.js";
import { ENTERPRISE_DEFAULTS } from "../../src/events/settings.js";
import { runHook, runMain } from "../../src/hook.js";
import { ALLOW, claude, envFor, Fixture, POLICY, readEvents, runtimeFor, standaloneStore, decisionDraft, tempDir } from "./helpers.js";

const uid = process.getuid?.() ?? 0;

describe("redaction corner cases", () => {
  it("handles lone backticks, trailing redirections, dynamic or missing programs", () => {
    expect(redactCommand("echo '`x'")?.text).toBe("echo `…`");
    expect(redactCommand("ls >")?.text).toContain("ls");
    expect(redactCommand("FOO=bar")).toEqual({ text: "FOO=bar", redactions: 0 });
    expect(redactCommand("$X --password=abc")?.text).toBe("$X --password=[REDACTED:credential]");
    expect(redactCommand("curl -H")?.text).toBe("curl -H");
    expect(redactCommand("docker login -ppw")?.text).toBe("docker login -p[REDACTED:password]");
    expect(redactCommand("htpasswd -b file")).toEqual({ text: "htpasswd -b file", redactions: 0 });
    expect(redactCommand("sudo htpasswd -b file user pw")?.text).toBe("sudo htpasswd -b file user [REDACTED:password]");
  });
});

describe("command analysis corner cases", () => {
  it("handles long options of tail, root projects and missing home", () => {
    expect(analyzeCommand("tail --lines=5 a.txt", { projectDir: "/repo" }).suppressible).toBe(true);
    expect(analyzeCommand("cat /etc/hostname", { projectDir: "/" }).suppressible).toBe(true);
    expect(analyzeCommand("ls ~/x", { projectDir: "/repo" }).suppressible).toBe(false);
  });
});

describe("logger corner cases", () => {
  function setup(root = tempDir()) {
    const fixture = new Fixture();
    const dir = join(root, "events", String(uid));
    mkdirSync(dir, { recursive: true, mode: 0o750 });
    const layout: Layout = { ...enterpriseLayout("per_user", uid, root), eventsDir: dir, lockDir: dir };
    const make = (rateLimit = 1, rt = runtimeFor(root, fixture)) => new EventLogger({ rt, env: envFor(root), enterprise: { layout, settings: { ...ENTERPRISE_DEFAULTS, rateLimit } }, policy: POLICY, findings: [] });
    return { root, dir, fixture, make };
  }
  const read = (paths?: string[]): DecisionRecord => ({
    claude: claude(),
    projectDir: "/repo",
    tool: { name: "Read", ...(paths ? { paths } : {}) },
    decision: { ...ALLOW, outcome: "observe" },
    suppressible: true,
    humanSession: false,
  });

  it("summarizes calls without paths, orders equal counts by path and bounds the path table", () => {
    const { dir, fixture, make } = setup();
    const logger = make();
    logger.recordDecision(read());
    logger.recordDecision(read());
    logger.recordDecision(read(["b.ts"]));
    logger.recordDecision(read(["a.ts"]));
    for (let i = 0; i < 210; i += 1) logger.recordDecision(read([`f${i}.ts`]));
    fixture.advance(61_000);
    logger.recordDecision(read());
    const summary = readEvents(dir)[0]?.events.find((e) => e.type === "suppressed");
    const top = (summary?.data as { top_paths: { path: string; count: number }[] }).top_paths;
    expect(top).toHaveLength(10);
    expect(top[0]).toEqual({ path: "a.ts", count: 1 });
    expect(top[1]).toEqual({ path: "b.ts", count: 1 });
    expect((summary?.data as { count: number }).count).toBe(213);
  });

  it("keeps the flood counters when a session is resumed", () => {
    const { dir, make } = setup();
    const logger = make(2);
    logger.recordDecision(read());
    logger.recordDecision(read());
    logger.recordDecision(read());
    logger.recordLifecycle({ kind: "session_start", claude: claude("s-1", { hook_event: "SessionStart" }), data: {}, humanSession: false });
    const events = readEvents(dir)[0]?.events ?? [];
    expect(events.map((e) => e.type)).toEqual(["chain_start", "decision", "decision", "session_start"]);
  });

  it("reports unexpected errors without details", () => {
    const { make, root } = setup();
    const facts = { ...systemProcessFacts, bootId: () => { throw new Error("secret detail"); } };
    const logger = make(1, runtimeFor(root, new Fixture(), { facts }));
    const result = logger.recordDecision({ ...read(), suppressible: false });
    expect(result).toMatchObject({ ok: false, block: true });
    expect((result as { message: string }).message).toContain("unexpected error");
    expect((result as { message: string }).message).not.toContain("secret detail");
  });

  it("ignores a frozen configuration of the wrong shape", () => {
    const root = tempDir();
    const { store, layout } = standaloneStore(root);
    store.transaction((tx) => tx.writeSession({ v: 1, session_id: "s-1", config: { enabled: "no" } as never }));
    const logger = new EventLogger({ rt: runtimeFor(root), env: envFor(root), enterprise: null, policy: POLICY, findings: [] });
    logger.recordDecision({ ...read(), suppressible: false, decision: ALLOW });
    expect(readEvents(layout.eventsDir)[0]?.events.map((e) => e.type)).toEqual(["chain_start", "decision"]);
  });

  it("an enterprise failure with a broken runtime still reports through the hook result", () => {
    const { make, root } = setup();
    const facts = { ...systemProcessFacts, bootId: () => { throw new Error("x"); } };
    const logger = make(1, runtimeFor(root, new Fixture(), { facts }));
    expect(logger.recordLifecycle({ kind: "session_end", claude: claude(), data: {}, humanSession: false })).toMatchObject({ ok: false });
  });
});

describe("writer corner cases", () => {
  it("treats a directory with the file name as unusable and takes the next name", () => {
    const { store, layout } = standaloneStore(tempDir());
    mkdirSync(layout.eventsDir, { recursive: true, mode: 0o700 });
    mkdirSync(join(layout.eventsDir, `u${uid}-20261011.jsonl`));
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    expect(readdirSync(layout.eventsDir).sort()).toEqual([`u${uid}-20261011-1.jsonl`, `u${uid}-20261011.jsonl`]);
  });
  it("lists files of several days in order", () => {
    const { store, layout } = standaloneStore(tempDir());
    mkdirSync(layout.eventsDir, { recursive: true, mode: 0o700 });
    for (const day of ["20261003", "20261001", "20261002"]) writeFileSync(join(layout.eventsDir, `u${uid}-${day}.jsonl`), "");
    expect(store.listFiles([]).map((f) => f.day)).toEqual(["20261001", "20261002", "20261003"]);
    const t = new Date("2026-01-01T00:00:00Z");
    utimesSync(join(layout.eventsDir, `u${uid}-20261001.jsonl`), t, t);
  });
});

describe("hook corner cases", () => {
  const base = { session_id: "s-1", hook_event_name: "PreToolUse" };
  function setup() {
    const root = tempDir();
    const project = join(root, "project");
    mkdirSync(project);
    return { root, project, rt: runtimeFor(root), env: { ...envFor(root), CLAUDE_PROJECT_DIR: project } };
  }
  const events = (root: string) => {
    try {
      return readEvents(join(root, "state", "tollgate", "events")).flatMap((f) => f.events);
    } catch {
      return [];
    }
  };

  it("logs <invalid> for a too long project directory and file path", () => {
    const s = setup();
    const long = join(s.root, "a".repeat(5000));
    const r = runHook(JSON.stringify({ ...base, tool_name: "Bash", tool_input: { command: "ls" } }), { ...s.env, CLAUDE_PROJECT_DIR: long }, long, { runtime: s.rt });
    expect(r.code).toBe(0);
    const edit = runHook(JSON.stringify({ ...base, tool_name: "Edit", tool_input: { file_path: join(s.project, "b".repeat(5000)) } }), s.env, s.project, { runtime: s.rt });
    expect(edit.code).toBe(2); // the path cannot be resolved
    const decisions = events(s.root).filter((e) => e.type === "decision");
    expect(decisions.map((e) => e.claude?.project_dir)).toEqual([undefined, undefined]);
    expect(decisions[1]?.tool?.paths).toEqual(["<invalid>"]);
  });
  it("lists invalid fields of rejected input and of lifecycle events", () => {
    const s = setup();
    runHook("{}", s.env, s.project, { runtime: s.rt });
    runHook(JSON.stringify({ session_id: "bad id", hook_event_name: "SessionEnd" }), s.env, s.project, { runtime: s.rt });
    const all = events(s.root);
    expect(all.find((e) => e.type === "decision")?.claude?.invalid_fields).toEqual(["session_id", "tool_name"]);
    expect(all.find((e) => e.type === "session_end")?.claude?.invalid_fields).toEqual(["session_id"]);
  });
  it("runMain uses the working directory when CLAUDE_PROJECT_DIR is not set", async () => {
    const s = setup();
    const env = envFor(s.root);
    const code = await runMain(async () => { throw new Error("x"); }, env, s.project, () => {}, { runtime: s.rt });
    expect(code).toBe(2);
    expect(events(s.root).some((e) => e.decision?.rule_kind === "internal_error")).toBe(true);
  });
});

import { packageVersion } from "../../src/events/runtime.js";
import { resolvePolicy } from "../../src/enterprise.js";
import { Tx } from "../../src/events/store.js";
import { chmodSync, readFileSync } from "node:fs";

describe("remaining safety nets", () => {
  it("packageVersion falls back to 'unknown'", () => {
    const dir = tempDir();
    expect(packageVersion(dir)).toBe("unknown");
    writeFileSync(join(dir, "package.json"), '{"version":5}');
    expect(packageVersion(dir)).toBe("unknown");
    writeFileSync(join(dir, "package.json"), '{"version":"1.2.3"}');
    expect(packageVersion(dir)).toBe("1.2.3");
  });

  it("an unusable bundled default policy fails closed in enterprise mode", () => {
    const root = tempDir();
    const admin = join(root, "etc", "tollgate");
    mkdirSync(admin, { recursive: true });
    chmodSync(join(root, "etc"), 0o755);
    chmodSync(admin, 0o755);
    const policyFile = join(admin, "policy.json");
    writeFileSync(policyFile, JSON.stringify({ version: 2, revision: "r", allowedDependencies: { npm: [], pypi: [] } }), { mode: 0o644 });
    chmodSync(policyFile, 0o644);
    const r = resolvePolicy({ env: { TOLLGATE_ENTERPRISE: "1" }, projectDir: root, platform: "linux", ownerUid: uid, stopAt: root, paths: { adminDir: admin, policyFile }, bundledPolicy: join(root, "missing.json") });
    expect(r).toEqual({ ok: false, kind: "policy_error", message: "default policy could not be loaded (fail closed)." });
  });

  it("refuses to append if the file changed after it was opened", () => {
    const { store, layout } = standaloneStore(tempDir());
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    const file = join(layout.eventsDir, `u${uid}-20261011.jsonl`);
    const draft = decisionDraft(store);
    Object.defineProperty(draft, "data", {
      enumerable: true,
      get: () => {
        chmodSync(file, 0o666); // tampering between the checks and the write
        return {};
      },
    });
    expect(() => store.transaction((tx: Tx) => tx.append([draft]))).toThrowError(/event file is unsafe/);
    expect(readFileSync(file, "utf8").split("\n").filter(Boolean)).toHaveLength(2);
  });
});
