import { existsSync, mkdirSync, readdirSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { enterpriseLayout, type Layout } from "../../src/events/layout.js";
import { EventLogger, type DecisionRecord, type LifecycleRecord, type LogContext, type PolicyFinding } from "../../src/events/logger.js";
import { ENTERPRISE_DEFAULTS } from "../../src/events/settings.js";
import { ALLOW, claude, DENY, envFor, Fixture, POLICY, readEvents, runtimeFor, tempDir, writeConfig } from "./helpers.js";

const uid = process.getuid?.() ?? 0;

function setup(root = tempDir(), overrides: Partial<LogContext> = {}, fixture = new Fixture()): { logger: EventLogger; root: string; fixture: Fixture; dir: string } {
  const ctx: LogContext = { rt: runtimeFor(root, fixture), env: envFor(root), enterprise: null, policy: POLICY, findings: [], ...overrides };
  const logger = new EventLogger(ctx);
  return { logger, root, fixture, dir: logger.layout.eventsDir };
}

function decision(patch: Partial<DecisionRecord> = {}): DecisionRecord {
  return {
    claude: claude(),
    projectDir: "/repo",
    tool: { name: "Bash", rawCommand: "curl -u a:b https://x", programs: ["curl"], paths: [], effects: ["network"] },
    decision: ALLOW,
    suppressible: false,
    humanSession: false,
    ...patch,
  };
}

function lifecycle(kind: LifecycleRecord["kind"], patch: Partial<LifecycleRecord> = {}): LifecycleRecord {
  return { kind, claude: claude("s-1", { hook_event: kind === "session_start" ? "SessionStart" : "SessionEnd", tool_use_id: null }), data: {}, humanSession: false, ...patch };
}

const types = (dir: string): string[] => readEvents(dir).flatMap((f) => f.events.map((e) => e.type));
const all = (dir: string) => readEvents(dir).flatMap((f) => f.events);

describe("stand-alone defaults (T24)", () => {
  it("logs decisions with program names but without command text", () => {
    const { logger, dir } = setup();
    expect(logger.recordDecision(decision())).toEqual({ ok: true });
    const [, event] = all(dir);
    expect(event?.type).toBe("decision");
    expect(event?.tool).toEqual({ name: "Bash", programs: ["curl"], paths: [], effects: ["network"], truncated: false });
    expect(event?.tool?.command).toBeUndefined();
    expect(event?.claude?.project_dir).toBeUndefined();
    expect(event?.policy).toEqual(POLICY);
    expect(event?.redactions).toBe(0);
    expect(JSON.stringify(event)).not.toContain("a:b");
  });

  it("logs the redacted command and the project directory only on opt-in", () => {
    const root = tempDir();
    writeConfig(root, '{"logging":{"commandDetail":"redacted","projectDir":true}}');
    const { logger, dir } = setup(root);
    logger.recordDecision(decision());
    const event = all(dir)[1];
    expect(event?.tool?.command).toBe("curl -u [REDACTED:credential] https://x");
    expect(event?.redactions).toBe(1);
    expect(event?.claude?.project_dir).toBe("/repo");
  });

  it("redacts secrets in the reason text", () => {
    const { logger, dir } = setup();
    logger.recordDecision(decision({ decision: { ...DENY, reason: "x https://u:p@h/ y" } }));
    const event = all(dir)[1];
    expect(event?.decision?.reason).toBe("x https://[REDACTED:userinfo]@h/ y");
    expect(event?.redactions).toBe(1);
  });

  it("skips observed tools unless tools = all", () => {
    const { logger, dir } = setup();
    expect(logger.recordDecision(decision({ decision: { ...ALLOW, outcome: "observe" }, tool: { name: "Read" } }))).toEqual({ ok: true });
    expect(existsSync(dir)).toBe(false);
  });

  it("an invalid user file keeps the log on", () => {
    const root = tempDir();
    writeConfig(root, '{"logging":{"enabled":"nope"}}');
    const { logger, dir } = setup(root);
    logger.recordDecision(decision());
    expect(types(dir)).toEqual(["chain_start", "decision"]);
  });
});

describe("switching off (T24)", () => {
  it("writes exactly one logging_disabled as the last event and nothing afterwards", () => {
    const root = tempDir();
    const { logger, dir } = setup(root);
    logger.recordDecision(decision());
    writeConfig(root, '{"logging":{"enabled":false}}');
    const first = logger.recordLifecycle(lifecycle("session_start", { claude: claude("s-2", { hook_event: "SessionStart" }) }));
    expect(first).toEqual({ ok: true, notice: "TollGate decision log is disabled (user configuration)." });
    logger.recordDecision(decision({ claude: claude("s-2") }));
    logger.recordLifecycle(lifecycle("session_start", { claude: claude("s-3", { hook_event: "SessionStart" }) }));
    logger.recordDecision(decision({ claude: claude("s-3") }));
    expect(types(dir)).toEqual(["chain_start", "decision", "logging_disabled"]);
    const last = all(dir).at(-1);
    expect(last?.data).toMatchObject({ config_sha256: expect.stringMatching(/^[0-9a-f]{64}$/) });
  });

  it("a session that started with the log on keeps logging when the file changes (frozen)", () => {
    const root = tempDir();
    const { logger, dir } = setup(root);
    logger.recordLifecycle(lifecycle("session_start"));
    writeConfig(root, '{"logging":{"enabled":false}}');
    logger.recordDecision(decision());
    logger.recordDecision(decision());
    expect(types(dir)).toEqual(["chain_start", "session_start", "decision", "decision"]);
    expect(existsSync(join(logger.layout.lockDir, "session-s-1.json"))).toBe(true);
    // the next session sees the change
    logger.recordLifecycle(lifecycle("session_start", { claude: claude("s-2", { hook_event: "SessionStart" }) }));
    expect(types(dir).at(-1)).toBe("logging_disabled");
  });

  it("a session that started with the log off stays off when the file is switched on", () => {
    const root = tempDir();
    writeConfig(root, '{"logging":{"enabled":false}}');
    const { logger, dir } = setup(root);
    logger.recordLifecycle(lifecycle("session_start"));
    writeConfig(root, '{"logging":{"enabled":true}}');
    logger.recordDecision(decision());
    expect(existsSync(dir) ? types(dir) : []).toEqual([]);
  });

  it("switching on again writes logging_enabled before the next event", () => {
    const root = tempDir();
    const { logger, dir } = setup(root);
    logger.recordDecision(decision());
    writeConfig(root, '{"logging":{"enabled":false}}');
    logger.recordLifecycle(lifecycle("session_start", { claude: claude("s-2", { hook_event: "SessionStart" }) }));
    writeConfig(root, '{"logging":{"enabled":true}}');
    logger.recordLifecycle(lifecycle("session_start", { claude: claude("s-3", { hook_event: "SessionStart" }) }));
    expect(types(dir)).toEqual(["chain_start", "decision", "logging_disabled", "logging_enabled", "session_start"]);
  });

  it("without a session_start the current file counts and the change is detected once", () => {
    const root = tempDir();
    const { logger, dir } = setup(root);
    logger.recordDecision(decision());
    writeConfig(root, '{"logging":{"enabled":false}}');
    logger.recordDecision(decision());
    logger.recordDecision(decision());
    expect(types(dir)).toEqual(["chain_start", "decision", "logging_disabled"]);
  });

  it("does not create any file when the log was never on", () => {
    const root = tempDir();
    writeConfig(root, '{"logging":{"enabled":false}}');
    const { logger, dir } = setup(root);
    expect(logger.recordDecision(decision())).toEqual({ ok: true });
    expect(existsSync(dir)).toBe(false);
  });

  it("an unusable session id falls back to the current file", () => {
    const root = tempDir();
    const { logger, dir } = setup(root);
    logger.recordDecision(decision({ claude: claude("<invalid>") }));
    expect(types(dir)).toEqual(["chain_start", "decision"]);
    logger.recordLifecycle(lifecycle("session_start", { claude: claude("<invalid>", { hook_event: "SessionStart" }) }));
    expect(readdirSync(logger.layout.lockDir).filter((n) => n.startsWith("session-"))).toEqual([]);
  });
});

describe("lifecycle events", () => {
  it("writes session_start with hashes and session_end, which removes the session file", () => {
    const root = tempDir();
    const { logger, dir } = setup(root);
    logger.recordLifecycle(lifecycle("session_start", { data: logger.sessionStartData("startup"), humanSession: true }));
    logger.recordLifecycle(lifecycle("subagent_start"));
    logger.recordLifecycle(lifecycle("subagent_stop"));
    logger.recordLifecycle(lifecycle("session_end", { data: { reason: "other" } }));
    expect(types(dir)).toEqual(["chain_start", "session_start", "subagent_start", "subagent_stop", "session_end"]);
    const start = all(dir)[1];
    expect(start?.data).toMatchObject({ source: "startup", plugin_version: "0.1.0", human_session: true, config_sha256: null });
    expect(start?.policy).toEqual(POLICY);
    expect(readdirSync(logger.layout.lockDir).filter((n) => n.startsWith("session-"))).toEqual([]);
  });

  it("session_start removes expired files", () => {
    const root = tempDir();
    const { logger, dir, fixture } = setup(root);
    logger.recordDecision(decision());
    const old = join(dir, `u${uid}-20250101.jsonl`);
    writeFileSync(old, "x");
    const t = new Date(fixture.time - 40 * 86_400_000);
    utimesSync(old, t, t);
    logger.recordLifecycle(lifecycle("session_start"));
    expect(existsSync(old)).toBe(false);
  });

  it("sessionStartData reports null for unknown sources and hashes dist", () => {
    const root = tempDir();
    const pluginRoot = join(root, "plugin");
    mkdirSync(join(pluginRoot, "dist", "sub"), { recursive: true });
    writeFileSync(join(pluginRoot, "dist", "a.js"), "a");
    writeFileSync(join(pluginRoot, "dist", "sub", "b.js"), "b");
    const { logger } = setup(root, { rt: runtimeFor(root, new Fixture(), { pluginRoot }) });
    const data = logger.sessionStartData("bad source!");
    expect(data.source).toBeNull();
    expect(data.plugin_files_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(logger.sessionStartData(undefined).source).toBeNull();
    expect(data.managed_settings_sha256 === null || typeof data.managed_settings_sha256 === "string").toBe(true);
    const { logger: bare } = setup(tempDir(), { rt: runtimeFor(root, new Fixture(), { pluginRoot: join(root, "none") }) });
    expect(bare.sessionStartData("resume")).toMatchObject({ source: "resume", plugin_files_sha256: null });
  });
});

describe("flood limit", () => {
  function limited(rateLimit: number): { logger: EventLogger; dir: string; fixture: Fixture; root: string } {
    const root = tempDir();
    const fixture = new Fixture();
    const layout = { ...enterpriseLayout("per_user", uid, join(root, "home")) };
    const dir = join(root, "events", String(uid));
    mkdirSync(dir, { recursive: true, mode: 0o750 });
    const enterprise = { layout: { ...layout, eventsDir: dir, lockDir: dir }, settings: { ...ENTERPRISE_DEFAULTS, rateLimit } };
    const logger = new EventLogger({ rt: runtimeFor(root, fixture), env: envFor(root), enterprise, policy: POLICY, findings: [] });
    return { logger, dir, fixture, root };
  }
  const read = (p: string[] = ["a.ts"]): DecisionRecord => decision({ decision: { ...ALLOW, outcome: "observe" }, tool: { name: "Read", paths: p }, suppressible: true });

  it("summarizes read-only events above the limit and writes one suppressed event later", () => {
    const { logger, dir, fixture } = limited(3);
    for (let i = 0; i < 6; i += 1) logger.recordDecision(read(i < 5 ? ["a.ts"] : ["b.ts"]));
    expect(types(dir).filter((t) => t === "decision")).toHaveLength(3);
    fixture.advance(61_000);
    logger.recordDecision(read());
    const s = all(dir).filter((e) => e.type === "suppressed");
    expect(s).toHaveLength(1);
    expect(s[0]?.data).toMatchObject({ count: 3, top_paths: [{ path: "a.ts", count: 2 }, { path: "b.ts", count: 1 }] });
    expect(typeof (s[0]?.data as { window_start: string }).window_start).toBe("string");
    expect(types(dir).filter((t) => t === "decision")).toHaveLength(4);
  });

  it("never summarizes denials or calls that are not read-only, and counts only read-only calls", () => {
    const { logger, dir } = limited(1);
    for (let i = 0; i < 4; i += 1) logger.recordDecision(decision({ decision: DENY, suppressible: false }));
    logger.recordDecision(read());
    expect(types(dir).filter((t) => t === "decision")).toHaveLength(5);
  });

  it("session_end flushes the summary", () => {
    const { logger, dir } = limited(1);
    for (let i = 0; i < 4; i += 1) logger.recordDecision(read());
    logger.recordLifecycle(lifecycle("session_end"));
    const tail = types(dir).slice(-2);
    expect(tail).toEqual(["suppressed", "session_end"]);
  });

  it("a limit of 0 disables summarizing", () => {
    const { logger, dir } = limited(0);
    for (let i = 0; i < 3; i += 1) logger.recordDecision(read());
    expect(types(dir).filter((t) => t === "decision")).toHaveLength(3);
  });

  it("works per session and not without a session id", () => {
    const { logger, dir } = limited(1);
    logger.recordDecision(decision({ ...read(), claude: claude("a") }));
    logger.recordDecision(decision({ ...read(), claude: claude("b") }));
    logger.recordDecision(decision({ ...read(), claude: claude("<invalid>") }));
    logger.recordDecision(decision({ ...read(), claude: claude("<invalid>") }));
    expect(types(dir).filter((t) => t === "decision")).toHaveLength(4);
  });
});

describe("policy findings", () => {
  it("reports findings once per change", () => {
    const findings: PolicyFinding[] = [
      { type: "policy_error", level: "project", id: "r1", detail: "regular expression rules are not allowed on this level" },
      { type: "policy_override_ignored", level: "project", detail: "logging ignored" },
    ];
    const root = tempDir();
    const { logger, dir } = setup(root, { findings });
    logger.recordDecision(decision());
    logger.recordDecision(decision());
    expect(types(dir)).toEqual(["chain_start", "policy_error", "policy_override_ignored", "decision", "decision"]);
    expect(all(dir)[1]?.data).toEqual({ findings: [{ level: "project", id: "r1", detail: "regular expression rules are not allowed on this level" }] });
    const { logger: changed } = setup(root, { findings: [findings[1] as PolicyFinding] });
    changed.recordDecision(decision());
    expect(types(dir).slice(5)).toEqual(["policy_override_ignored", "decision"]);
    const { logger: fixed } = setup(root, { findings: [] });
    fixed.recordDecision(decision());
    const { logger: again } = setup(root, { findings });
    again.recordDecision(decision());
    expect(types(dir).filter((t) => t === "policy_error")).toHaveLength(2);
  });
});

describe("write errors", () => {
  it("stand-alone: warns, does not block", () => {
    const root = tempDir();
    const { logger } = setup(root);
    mkdirSync(logger.layout.lockDir.slice(0, logger.layout.lockDir.lastIndexOf("/")), { recursive: true });
    writeFileSync(logger.layout.lockDir, "i am a file");
    const result = logger.recordDecision(decision());
    expect(result).toMatchObject({ ok: false, block: false });
    expect((result as { message: string }).message).toMatch(/could not be written/);
    expect((result as { message: string }).message).not.toContain(root);
  });

  it("stand-alone: a symlinked private directory is refused without a path in the message", () => {
    const root = tempDir();
    const { logger } = setup(root);
    mkdirSync(join(root, "state"), { recursive: true });
    mkdirSync(join(root, "elsewhere"));
    symlinkSync(join(root, "elsewhere"), logger.layout.lockDir);
    const result = logger.recordDecision(decision());
    expect(result).toMatchObject({ ok: false, block: false });
    expect(readdirSync(join(root, "elsewhere"))).toEqual([]);
  });

  it("enterprise: a missing user directory blocks, names the remedy and logs a fallback error", () => {
    const root = tempDir();
    const fixture = new Fixture();
    const dir = join(root, "events", String(uid));
    const layout: Layout = { ...enterpriseLayout("per_user", uid, join(root, "home")), eventsDir: dir, lockDir: dir };
    const logger = new EventLogger({ rt: runtimeFor(root, fixture), env: envFor(root), enterprise: { layout, settings: ENTERPRISE_DEFAULTS }, policy: POLICY, findings: [] });
    const result = logger.recordDecision(decision());
    expect(result).toEqual({
      ok: false,
      block: true,
      message: "TollGate enterprise mode: event directory missing. Ask your administrator to provision it (see the TollGate enterprise documentation).",
    });
    expect(existsSync(dir)).toBe(false);
    const fallback = join(root, "state", "tollgate", "events");
    const events = all(fallback);
    expect(events.map((e) => e.type)).toEqual(["chain_start", "log_error"]);
    expect(events[1]?.data).toMatchObject({ code: "dir_missing" });
  });

  it("enterprise: uses the fixed layout and ignores the user file", () => {
    const root = tempDir();
    writeConfig(root, '{"logging":{"enabled":false}}');
    const dir = join(root, "events", String(uid));
    mkdirSync(dir, { recursive: true, mode: 0o750 });
    const layout: Layout = { ...enterpriseLayout("per_user", uid, join(root, "home")), eventsDir: dir, lockDir: dir };
    const logger = new EventLogger({ rt: runtimeFor(root, new Fixture()), env: envFor(root), enterprise: { layout, settings: ENTERPRISE_DEFAULTS }, policy: { ...POLICY, enterprise_mode: true }, findings: [] });
    expect(logger.recordDecision(decision())).toEqual({ ok: true });
    expect(logger.recordLifecycle(lifecycle("session_start"))).toEqual({ ok: true });
    expect(types(dir)).toEqual(["chain_start", "decision", "session_start"]);
    expect(all(dir)[1]?.tool?.command).toBe("curl -u [REDACTED:credential] https://x"); // redacted in enterprise mode
    expect(statSync(join(dir, `u${uid}-20261011.jsonl`)).mode & 0o777).toBe(0o640);
    expect(existsSync(join(root, "state"))).toBe(false); // no stand-alone log
  });

  it("enterprise: logging.enabled false in the policy switches the log off", () => {
    const root = tempDir();
    const dir = join(root, "events", String(uid));
    mkdirSync(dir, { recursive: true, mode: 0o750 });
    const layout: Layout = { ...enterpriseLayout("per_user", uid, join(root, "home")), eventsDir: dir, lockDir: dir };
    const logger = new EventLogger({ rt: runtimeFor(root, new Fixture()), env: envFor(root), enterprise: { layout, settings: { ...ENTERPRISE_DEFAULTS, enabled: false } }, policy: POLICY, findings: [] });
    expect(logger.recordDecision(decision())).toEqual({ ok: true });
    expect(readdirSync(dir)).toEqual([]);
  });

  it("enterprise: observes all tools by default", () => {
    const root = tempDir();
    const dir = join(root, "events", String(uid));
    mkdirSync(dir, { recursive: true, mode: 0o750 });
    const layout: Layout = { ...enterpriseLayout("per_user", uid, join(root, "home")), eventsDir: dir, lockDir: dir };
    const logger = new EventLogger({ rt: runtimeFor(root, new Fixture()), env: envFor(root), enterprise: { layout, settings: ENTERPRISE_DEFAULTS }, policy: POLICY, findings: [] });
    logger.recordDecision(decision({ decision: { ...ALLOW, outcome: "observe" }, tool: { name: "WebFetch", domain: "example.org", effects: ["network"] } }));
    expect(all(dir)[1]).toMatchObject({ type: "decision", decision: { outcome: "observe" }, tool: { name: "WebFetch", domain: "example.org" } });
  });
});

describe("secrets in paths (security review finding 1)", () => {
  const TOKEN = `ghp_${"A1b2C3d4E5".repeat(3)}abcdef`;
  it("redacts tool.paths of a decision", () => {
    const { logger, dir } = setup();
    logger.recordDecision(decision({ tool: { name: "Read", paths: [`a/${TOKEN}.txt`, "src"], programs: [], effects: [] } }));
    const text = JSON.stringify(all(dir));
    expect(text).not.toContain(TOKEN);
    expect(all(dir)[1]?.tool?.paths).toEqual(["a/[REDACTED:secret].txt", "src"]);
    expect(all(dir)[1]?.redactions).toBe(1);
  });
  it("redacts the paths of a suppressed summary", () => {
    const root = tempDir();
    const fixture = new Fixture();
    const layout = { ...enterpriseLayout("per_user", uid, join(root, "home")) };
    const dir = join(root, "events", String(uid));
    mkdirSync(dir, { recursive: true, mode: 0o750 });
    const enterprise = { layout: { ...layout, eventsDir: dir, lockDir: dir }, settings: { ...ENTERPRISE_DEFAULTS, rateLimit: 1 } };
    const logger = new EventLogger({ rt: runtimeFor(root, fixture), env: envFor(root), enterprise, policy: POLICY, findings: [] });
    const rec = decision({ decision: { ...ALLOW, outcome: "observe" }, tool: { name: "Read", paths: [`${TOKEN}`] }, suppressible: true });
    for (let i = 0; i < 3; i += 1) logger.recordDecision(rec);
    fixture.advance(61_000);
    logger.recordDecision(rec);
    const s = all(dir).filter((e) => e.type === "suppressed");
    expect(s).toHaveLength(1);
    expect(JSON.stringify(all(dir))).not.toContain(TOKEN);
    expect(s[0]?.data).toMatchObject({ top_paths: [{ path: "[REDACTED:secret]", count: 2 }] });
  });
});
