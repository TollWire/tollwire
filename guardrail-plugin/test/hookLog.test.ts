import { chmodSync, linkSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { BLOCK_EXIT_CODE, eventFromArgs, runHook, runMain, UNCHECKED_DENY_EXIT_CODE, type HookDeps, type HookResult } from "../src/hook.js";
import { evaluateDetailed } from "../src/evaluate.js";
import { enterpriseLayout } from "../src/events/layout.js";
import type { Runtime } from "../src/events/runtime.js";
import type { TollgateEvent } from "../src/events/types.js";
import { envFor, Fixture, readEvents, runtimeFor, tempDir } from "./events/helpers.js";
import { BUNDLED_WITHOUT_TAINT } from "./helpers.js";

const uid = process.getuid?.() ?? 0;

interface Setup {
  root: string;
  project: string;
  rt: Runtime;
  env: NodeJS.ProcessEnv;
  deps: HookDeps;
  events: () => TollgateEvent[];
  run: (event: unknown, extraEnv?: NodeJS.ProcessEnv) => HookResult;
}

function setup(patch: { env?: NodeJS.ProcessEnv; runtime?: Partial<Runtime> } = {}): Setup {
  const root = tempDir("tg-hook-");
  const project = join(root, "project");
  mkdirSync(project);
  const fixture = new Fixture();
  const rt = runtimeFor(root, fixture, patch.runtime);
  const env = { ...envFor(root), CLAUDE_PROJECT_DIR: project, ...patch.env };
  // Pinned default policy without session taint (these tests run tool calls without a session start).
  const deps: HookDeps = { runtime: rt, resolve: { bundledPolicy: BUNDLED_WITHOUT_TAINT } };
  const eventsDir = join(root, "state", "tollgate", "events");
  const events = (): TollgateEvent[] => {
    try {
      return readEvents(eventsDir).flatMap((f) => f.events);
    } catch {
      return [];
    }
  };
  // Models a manifest that binds each entry to its event (`--event <name>`): the declared event is the one named on stdin.
  const run = (event: unknown, extraEnv: NodeJS.ProcessEnv = {}): HookResult => {
    const name = typeof event === "object" && event !== null ? (event as { hook_event_name?: unknown }).hook_event_name : undefined;
    return runHook(typeof event === "string" ? event : JSON.stringify(event), { ...env, ...extraEnv }, project, { ...deps, event: typeof name === "string" ? name : undefined });
  };
  return { root, project, rt, env, deps, events, run };
}

const base = { session_id: "s-1", tool_use_id: "toolu_1", permission_mode: "default", hook_event_name: "PreToolUse" };
const bash = (command: string, extra: Record<string, unknown> = {}) => ({ ...base, tool_name: "Bash", tool_input: { command }, ...extra });
const decisions = (s: Setup): TollgateEvent[] => s.events().filter((e) => e.type === "decision");

describe("one decision event per evaluation", () => {
  it("logs an allowed Bash call without command text", () => {
    const s = setup();
    expect(s.run(bash("ls -la src"))).toEqual({ code: 0 });
    const [event] = decisions(s);
    expect(event).toMatchObject({
      type: "decision",
      claude: { session_id: "s-1", tool_use_id: "toolu_1", hook_event: "PreToolUse", permission_mode: "default" },
      tool: { name: "Bash", programs: ["ls"], effects: [], paths: ["src"], truncated: false },
      decision: { outcome: "allow", rule_kind: "none", rule_id: null, reason: null, human_session: false },
      policy: { enterprise_mode: false, revision: null, layers: [{ level: "default" }] },
    });
    expect(event?.tool?.command).toBeUndefined();
    expect(s.events().map((e) => e.type)).toEqual(["chain_start", "decision"]);
  });

  it("writes exactly one decision per call, also for repeated calls", () => {
    const s = setup();
    for (let i = 0; i < 5; i += 1) s.run(bash("pwd"));
    s.run(bash("git push --force"));
    expect(decisions(s)).toHaveLength(6);
  });

  it("logs a denial with rule id and reason", () => {
    const s = setup();
    const r = s.run(bash("git push --force origin main"));
    expect(r.code).toBe(BLOCK_EXIT_CODE);
    expect(r.message).toContain("Force push is not allowed");
    expect(decisions(s)[0]).toMatchObject({
      tool: { programs: ["git"], effects: ["network"] },
      decision: { outcome: "deny", rule_kind: "blocked_command", rule_id: "blockedCommands[0]", reason: expect.stringContaining("Force push") },
    });
  });

  it("records the human session flag", () => {
    const s = setup();
    s.run({ ...base, tool_name: "Edit", tool_input: { file_path: join(s.project, "AGENTS.md") } }, { TOLLGATE_HUMAN_SESSION: "1" });
    expect(decisions(s)[0]?.decision).toMatchObject({ outcome: "allow", human_session: true });
  });

  it("validates the stdin fields and lists invalid ones", () => {
    const s = setup();
    s.run({ ...bash("ls"), session_id: "bad id\n", tool_use_id: "x".repeat(200) });
    expect(decisions(s)[0]?.claude).toMatchObject({ session_id: "<invalid>", tool_use_id: "<invalid>", invalid_fields: ["session_id", "tool_use_id"] });
  });

  it("logs the redacted command only when the user asks for it", () => {
    const s = setup();
    mkdirSync(join(s.root, "config", "tollgate"), { recursive: true });
    writeFileSync(join(s.root, "config", "tollgate", "config.json"), '{"logging":{"commandDetail":"redacted"}}');
    s.run(bash(`curl -u me:${"pw"} https://example.org`));
    expect(decisions(s)[0]?.tool?.command).toBe("curl -u [REDACTED:credential] https://example.org");
    expect(JSON.stringify(s.events())).not.toContain("me:pw");
  });
});

describe("rule_kind of every decision site", () => {
  const kindOf = (s: Setup, event: unknown, extraEnv?: NodeJS.ProcessEnv): string | undefined => {
    s.run(event, extraEnv);
    return decisions(s).at(-1)?.decision?.rule_kind;
  };

  it("maps the checks of write tools", () => {
    const s = setup();
    const write = (file_path: string, extra: Record<string, unknown> = {}) => ({ ...base, tool_name: "Write", tool_input: { file_path, content: "", ...extra } });
    expect(kindOf(s, write("/etc/passwd"))).toBe("outside_project");
    expect(kindOf(s, write(join(s.project, "AGENTS.md")))).toBe("protected_path");
    expect(decisions(s).at(-1)?.decision?.rule_id).toBe("AGENTS.md");
    symlinkSync("loop-b", join(s.project, "loop-a"));
    symlinkSync("loop-a", join(s.project, "loop-b"));
    expect(kindOf(s, write(join(s.project, "loop-a")))).toBe("path_unresolvable");
    writeFileSync(join(s.project, "a.txt"), "x");
    linkSync(join(s.project, "a.txt"), join(s.project, "b.txt"));
    expect(kindOf(s, write(join(s.project, "a.txt")))).toBe("hardlink_alias");
    const policy = join(s.root, "policy.json");
    writeFileSync(policy, JSON.stringify({ version: 1, protectedPaths: [], blockedCommands: [], allowedDependencies: { npm: [], pypi: [] } }));
    mkdirSync(join(s.project, "sub"));
    symlinkSync(policy, join(s.project, "sub", "p.json"));
    expect(kindOf(s, write(policy), { TOLLGATE_POLICY: policy })).toBe("protected_path"); // the extra layer from the environment: protected as a host file
    // the active base policy file (context.policyFile) keeps its own kind
    const emptyPolicy = { version: 1 as const, protectedPaths: [], blockedCommands: [], allowedDependencies: { npm: [], pypi: [] } };
    expect(evaluateDetailed(write(policy), emptyPolicy, { projectDir: s.project, humanSession: false, policyFile: policy, tmpdir: dirname(policy) })).toMatchObject({ allowed: false, kind: "active_policy" });
    const inside = join(s.project, "inside-policy.json");
    writeFileSync(inside, readFileSync(policy));
    expect(kindOf(s, write(inside), { TOLLGATE_POLICY: inside })).toBe("protected_path");
    expect(kindOf(s, { ...base, tool_name: "Write", tool_input: {} })).toBe("invalid_input");
  });

  it("maps dependency checks", () => {
    const s = setup();
    const manifest = (content: string) => ({ ...base, tool_name: "Write", tool_input: { file_path: join(s.project, "package.json"), content } });
    expect(kindOf(s, manifest('{"dependencies":{"left-pad":"1"}}'))).toBe("dependency");
    expect(kindOf(s, manifest("{nope"))).toBe("dependency_unverifiable");
    expect(kindOf(s, { ...base, tool_name: "Edit", tool_input: { file_path: join(s.project, "package.json"), old_string: "a", new_string: "b" } })).toBe("dependency_unverifiable");
  });

  it("maps the checks of Bash", () => {
    const s = setup();
    expect(kindOf(s, bash("echo 'open"))).toBe("parse_error");
    expect(kindOf(s, bash("echo x > AGENTS.md"))).toBe("write_target");
    expect(kindOf(s, bash("x".repeat(33_000)))).toBe("size_limit");
    expect(kindOf(s, { ...base, tool_name: "Bash", tool_input: {} })).toBe("invalid_input");
    expect(kindOf(s, { ...base, tool_name: "Bash", tool_input: { command: 5 } })).toBe("invalid_input");
  });

  it("maps invalid input and unusable policy", () => {
    const s = setup();
    expect(kindOf(s, "not json")).toBe("invalid_input");
    expect(decisions(s).at(-1)?.tool?.name).toBe("<invalid>");
    expect(kindOf(s, "{}")).toBe("invalid_input");
    expect(kindOf(s, '{"tool_name":"Bash","tool_input":[]}')).toBe("invalid_input");
    expect(kindOf(s, bash("ls"), { TOLLGATE_POLICY: "/does/not/exist.json" })).toBe("policy_error");
    expect(decisions(s).at(-1)?.decision?.reason).toBe("policy could not be loaded (fail closed).");
  });

  it("maps an exception during the evaluation to internal_error", () => {
    const s = setup();
    s.deps.evaluate = () => {
      throw new Error("boom");
    };
    const r = s.run(bash("ls"));
    expect(r.code).toBe(BLOCK_EXIT_CODE);
    expect(r.message).toContain("rule_kind: internal_error");
    expect(r.message).toContain("detail: input could not be evaluated (fail closed).");
    expect(r.message).not.toContain("boom");
    expect(decisions(s)[0]?.decision).toMatchObject({ outcome: "deny", rule_kind: "internal_error" });
  });

  it("runMain records an unexpected failure as internal_error", async () => {
    const s = setup();
    const errors: string[] = [];
    const code = await runMain(
      async () => {
        throw new Error("EIO");
      },
      s.env,
      s.project,
      (t) => errors.push(t),
      s.deps,
    );
    expect(code).toBe(BLOCK_EXIT_CODE);
    expect(errors.join("")).toContain("hook failed unexpectedly");
    expect(decisions(s)[0]?.decision).toMatchObject({ rule_kind: "internal_error", reason: "hook failed unexpectedly" });
    expect(decisions(s)[0]?.tool?.name).toBe("<invalid>");
  });

  it("runMain stays blocking if even the log of the failure cannot be written", async () => {
    const s = setup();
    mkdirSync(join(s.root, "state"), { recursive: true });
    writeFileSync(join(s.root, "state", "tollgate"), "a file where the directory should be");
    const code = await runMain(async () => { throw new Error("x"); }, s.env, s.project, () => {}, s.deps);
    expect(code).toBe(BLOCK_EXIT_CODE);
  });
});

describe("what cannot switch the log off or change the detail", () => {
  it("project policy, TOLLGATE_POLICY and the environment have no effect", () => {
    const s = setup({ env: { TOLLGATE_LOGGING: "off", TOLLGATE_LOG: "0", TOLLGATE_COMMAND_DETAIL: "redacted", TOLLGATE_ENTERPRISE_LOGGING: "false" } });
    mkdirSync(join(s.project, ".tollgate"));
    const policy = { version: 1, protectedPaths: [], blockedCommands: [], allowedDependencies: { npm: [], pypi: [] }, logging: { enabled: false, commandDetail: "redacted" } };
    writeFileSync(join(s.project, ".tollgate", "policy.json"), JSON.stringify(policy));
    s.run(bash("curl -u a:b https://x"));
    const explicit = join(s.root, "explicit.json");
    writeFileSync(explicit, JSON.stringify(policy));
    s.run(bash("curl -u a:b https://x"), { TOLLGATE_POLICY: explicit });
    expect(decisions(s)).toHaveLength(2);
    for (const d of decisions(s)) expect(d.tool?.command).toBeUndefined();
  });
});

describe("stand-alone: TOLLGATE_POLICY only tightens", () => {
  it("a loosening policy is ignored (policy_override_ignored event), a tightening rule applies", () => {
    const s = setup();
    const explicit = join(s.root, "explicit.json");
    writeFileSync(explicit, JSON.stringify({ version: 1, protectedPaths: [], blockedCommands: [{ id: "m", match: { literal: "secret-tool" }, reason: "no secret-tool" }], allowedDependencies: { npm: ["evil"], pypi: [] }, logging: { enabled: false } }));
    expect(s.run(bash("secret-tool lookup"), { TOLLGATE_POLICY: explicit }).code).toBe(BLOCK_EXIT_CODE);
    expect(s.run(bash("git push --force origin main"), { TOLLGATE_POLICY: explicit }).code).toBe(BLOCK_EXIT_CODE); // the bundled default still applies
    expect(s.events().filter((e) => e.type === "policy_override_ignored").length).toBeGreaterThan(0);
    // the loosening allowedDependencies (npm: ["evil"]) must not widen the bundled allowlist
    const manifest = { ...base, tool_name: "Write", tool_input: { file_path: join(s.project, "package.json"), content: '{"dependencies":{"evil":"1"}}' } };
    expect(s.run(manifest, { TOLLGATE_POLICY: explicit }).code).toBe(BLOCK_EXIT_CODE);
    expect(decisions(s).at(-1)?.decision?.rule_kind).toBe("dependency");
  });
});

describe("write errors", () => {
  function broken(): Setup {
    const s = setup();
    mkdirSync(join(s.root, "state"), { recursive: true });
    writeFileSync(join(s.root, "state", "tollgate"), "a file where the directory should be");
    return s;
  }
  it("stand-alone: warns and lets the call pass", () => {
    const s = broken();
    const r = s.run(bash("ls"));
    expect(r.code).toBe(0);
    expect(r.message).toContain("decision log could not be written");
    expect(r.message).not.toContain(s.root);
  });
  it("stand-alone: a denial stays a denial and mentions the log problem", () => {
    const s = broken();
    const r = s.run(bash("git push --force"));
    expect(r.code).toBe(BLOCK_EXIT_CODE);
    expect(r.message).toContain("Force push is not allowed");
    expect(r.message).toContain("decision log could not be written");
  });
});

describe("observed tools and lifecycle events", () => {
  it("observed tools are not logged by default and never blocked", () => {
    const s = setup();
    expect(s.run({ ...base, tool_name: "Read", tool_input: { file_path: join(s.project, "a.ts") } })).toEqual({ code: 0 });
    expect(s.events()).toEqual([]);
  });
  it("records session and subagent events and never blocks", () => {
    const s = setup();
    const life = (name: string, extra: Record<string, unknown> = {}) => s.run({ session_id: "s-1", hook_event_name: name, ...extra });
    expect(life("SessionStart", { source: "startup" })).toEqual({ code: 0 });
    expect(life("SubagentStart", { agent_id: "a1", agent_type: "Explore" })).toEqual({ code: 0 });
    expect(life("SubagentStop", { agent_id: "a1", agent_type: "Explore" })).toEqual({ code: 0 });
    expect(life("SessionEnd", { reason: "clear" })).toEqual({ code: 0 });
    const events = s.events();
    expect(events.map((e) => e.type)).toEqual(["chain_start", "session_start", "subagent_start", "subagent_stop", "session_end"]);
    expect(events[1]?.data).toMatchObject({ source: "startup", plugin_version: "0.1.0", human_session: false });
    expect(events[2]?.claude).toMatchObject({ agent_id: "a1", agent_type: "Explore", hook_event: "SubagentStart" });
    expect(events[4]?.data).toMatchObject({ reason: "clear" });
  });
  it("shows a notice when the user switched the log off", () => {
    const s = setup();
    mkdirSync(join(s.root, "config", "tollgate"), { recursive: true });
    writeFileSync(join(s.root, "config", "tollgate", "config.json"), '{"logging":{"enabled":false}}');
    const r = s.run({ session_id: "s-1", hook_event_name: "SessionStart", source: "startup" });
    expect(r).toEqual({ code: 0, message: "TollGate decision log is disabled (user configuration)." });
    expect(s.events()).toEqual([]);
  });
  it("lifecycle problems are reported but never block", () => {
    const s = setup();
    mkdirSync(join(s.root, "state"), { recursive: true });
    writeFileSync(join(s.root, "state", "tollgate"), "file");
    const r = s.run({ session_id: "s-1", hook_event_name: "SessionStart" });
    expect(r.code).toBe(0);
    expect(r.message).toContain("could not be written");
  });
  it("treats unknown hook events as tool calls", () => {
    const s = setup();
    expect(s.run({ ...bash("ls"), hook_event_name: "PostToolBatch" }).code).toBe(0);
    expect(decisions(s)[0]?.claude?.hook_event).toBe("PostToolBatch");
  });
});

describe("tool_result (T21, PostToolUse)", () => {
  const post = (tool: string, input: Record<string, unknown>, response: unknown, extra: Record<string, unknown> = {}) => ({
    session_id: "s-1",
    tool_use_id: "toolu_9",
    permission_mode: "default",
    hook_event_name: "PostToolUse",
    tool_name: tool,
    tool_input: input,
    tool_response: response,
    ...extra,
  });
  const results = (s: Setup): TollgateEvent[] => s.events().filter((e) => e.type === "tool_result");

  it("records a checked tool without any content of the response", () => {
    const s = setup();
    const secret = "TOPSECRET-OUTPUT-0123456789";
    expect(s.run(post("Bash", { command: "ls -la src" }, { stdout: secret, stderr: "", interrupted: false }))).toEqual({ code: 0 });
    const [event] = results(s);
    expect(event).toMatchObject({
      type: "tool_result",
      claude: { session_id: "s-1", tool_use_id: "toolu_9", hook_event: "PostToolUse" },
      tool: { name: "Bash", paths: ["src"], effects: [], truncated: false },
      data: { response_kind: "object", is_error: null, human_session: false },
    });
    expect(typeof event?.data?.response_bytes).toBe("number");
    expect(JSON.stringify(s.events())).not.toContain("TOPSECRET");
    expect(decisions(s)).toEqual([]);
  });

  it("with the stand-alone default only checked tools are recorded", () => {
    const s = setup();
    s.run(post("Read", { file_path: join(s.project, "a.ts") }, "content"));
    expect(results(s)).toEqual([]);
    s.run(post("Write", { file_path: join(s.project, "a.ts"), content: "x" }, { ok: true }));
    expect(results(s)).toHaveLength(1);
    expect(results(s)[0]?.tool).toMatchObject({ name: "Write", paths: ["a.ts"], effects: ["write"] });
  });

  it("reports kind, size and the error flag; a missing response is recorded as none", () => {
    const s = setup();
    s.run(post("Bash", { command: "ls" }, "plain text"));
    s.run(post("Bash", { command: "ls" }, ["a", "b"]));
    s.run(post("Bash", { command: "ls" }, { is_error: true }));
    s.run(post("Bash", { command: "ls" }, { isError: false }));
    s.run(post("Bash", { command: "ls" }, 42));
    s.run({ session_id: "s-1", hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "ls" } });
    const data = results(s).map((e) => e.data);
    expect(data.map((d) => d?.response_kind)).toEqual(["string", "array", "object", "object", "other", "none"]);
    expect(data.map((d) => d?.is_error)).toEqual([null, null, true, false, null, null]);
    expect(data[0]?.response_bytes).toBe(10);
    expect(data[5]?.response_bytes).toBeNull();
  });

  it("never blocks: invalid input, a failing log and the human-session flag", () => {
    const s = setup();
    expect(s.run(post("Bash", "not an object" as unknown as Record<string, unknown>, {})).code).toBe(0);
    expect(s.run({ session_id: "../bad", hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "ls" } }).code).toBe(0);
    const bad = results(s).at(-1);
    expect(bad?.claude?.session_id).toBe("<invalid>");
    expect(bad?.claude?.invalid_fields).toEqual(["session_id"]);
    expect(s.run({ session_id: "s-1", hook_event_name: "PostToolUse", tool_name: 5 }).code).toBe(0);
    expect(s.run(post("Bash", { command: "ls" }, {}), { TOLLGATE_HUMAN_SESSION: "1" }).code).toBe(0);
    expect(results(s).at(-1)?.data?.human_session).toBe(true);
    const broken = setup();
    mkdirSync(join(broken.root, "state"), { recursive: true });
    writeFileSync(join(broken.root, "state", "tollgate"), "file");
    const r = broken.run(post("Bash", { command: "ls" }, {}));
    expect(r.code).toBe(0);
    expect(r.message).toContain("could not be written");
  });

  it("an unusable policy neither blocks nor writes", () => {
    const s = setup({ env: { TOLLGATE_POLICY: join(tempDir("tg-nopolicy-"), "missing.json") } });
    expect(s.run(post("Bash", { command: "ls" }, {})).code).toBe(0);
    expect(results(s)).toEqual([]);
  });

  it("is subject to the flood limit like decisions: read-only calls beyond the limit are summarized", () => {
    const s = setup();
    for (let i = 0; i < 600; i += 1) s.run(post("Bash", { command: "ls" }, { n: i }, { tool_use_id: `toolu_${i}` }));
    const before = results(s).length;
    expect(before).toBe(600);
    s.run(post("Bash", { command: "ls" }, {}));
    expect(results(s)).toHaveLength(600);
  });

  it("the log stays valid: a tool_result event is chained like any other", () => {
    const s = setup();
    s.run(bash("ls"));
    s.run(post("Bash", { command: "ls" }, {}));
    const events = s.events();
    expect(events.map((e) => e.type)).toEqual(["chain_start", "decision", "tool_result"]);
    expect(events[2]?.prev_hash).toBe(events[1]?.hash);
    expect(events[2]?.seq).toBe(3);
  });
});

describe("always protected paths (T12)", () => {
  it("blocks agent writes to the user configuration and the log directories, in the project and outside", () => {
    const s = setup({ env: { CLAUDE_PROJECT_DIR: undefined } });
    const home = s.rt.home;
    const project = s.root; // contains home, config and state
    const run = (event: unknown) => runHook(JSON.stringify(event), { ...s.env, CLAUDE_PROJECT_DIR: project, HOME: home }, project, s.deps);
    const write = (file_path: string) => run({ ...base, tool_name: "Write", tool_input: { file_path, content: "" } });
    const config = join(s.root, "config", "tollgate", "config.json");
    for (const target of [config, join(s.root, "config", "tollgate", "other.json"), join(s.root, "state", "tollgate", "events", "u1-20261011.jsonl"), join(s.root, "state", "tollgate", ".state")]) {
      expect(write(target).code, target).toBe(BLOCK_EXIT_CODE);
    }
    expect(write(config).message).toContain("protected path");
    const bash2 = (command: string) => run(bash(command));
    expect(bash2(`echo '{}' > ${config}`).code).toBe(BLOCK_EXIT_CODE);
    expect(bash2(`sed -i s/a/b/ ${config}`).code).toBe(BLOCK_EXIT_CODE);
    expect(bash2(`rm -r ${join(s.root, "state", "tollgate")}`).code).toBe(BLOCK_EXIT_CODE);
    expect(bash2(`rm ${join(s.root, "state", "tollgate", "events", "*")}`).code).toBe(BLOCK_EXIT_CODE);
    expect(bash2(`echo hi > ${join(s.root, "notes.txt")}`).code).toBe(0);
    expect(write(join(s.root, "notes.txt")).code).toBe(0);
  });
  it("a human session may still change the user configuration", () => {
    const s = setup();
    const config = join(s.project, "cfg.json");
    expect(s.run({ ...base, tool_name: "Write", tool_input: { file_path: config, content: "" } }, { TOLLGATE_HUMAN_SESSION: "1" }).code).toBe(0);
  });
  it("blocks the system paths when the project contains them", () => {
    const s = setup();
    const run = (path: string) => runHook(JSON.stringify({ ...base, tool_name: "Write", tool_input: { file_path: path, content: "" } }), { ...s.env, CLAUDE_PROJECT_DIR: "/" }, "/", s.deps);
    for (const p of ["/opt/tollgate/bin/x", "/etc/tollgate/policy.json", "/var/log/tollgate/events/1/u1-20261011.jsonl", "/etc/claude-code/managed-settings.json", "/etc/claude-code/managed-settings.d/10.json"]) {
      expect(run(p).code, p).toBe(BLOCK_EXIT_CODE);
    }
    chmodSync(s.project, 0o755);
  });
});

describe("enterprise mode", () => {
  const POLICY = {
    version: 2,
    revision: "acme-1",
    protectedPaths: ["secrets/"],
    blockedCommands: [{ id: "no-wget", pattern: "\\bwget\\b", reason: "wget is not allowed." }],
    allowedDependencies: { npm: ["zod"], pypi: [] },
  };

  function enterprise(policy: unknown = POLICY, patch: { env?: NodeJS.ProcessEnv; runtime?: Partial<Runtime> } = {}): Setup & { dir: string; ev: () => TollgateEvent[] } {
    const s = setup({ env: { TOLLGATE_ENTERPRISE: "1", ...patch.env }, ...(patch.runtime ? { runtime: patch.runtime } : {}) });
    const admin = join(s.root, "etc", "tollgate");
    mkdirSync(admin, { recursive: true });
    chmodSync(join(s.root, "etc"), 0o755);
    chmodSync(admin, 0o755);
    const policyFile = join(admin, "policy.json");
    writeFileSync(policyFile, JSON.stringify(policy), { mode: 0o644 });
    chmodSync(policyFile, 0o644);
    const dir = join(s.root, "events", String(uid));
    mkdirSync(dir, { recursive: true, mode: 0o750 });
    s.deps.resolve = { ownerUid: uid, stopAt: s.root, paths: { adminDir: admin, policyFile }, bundledPolicy: BUNDLED_WITHOUT_TAINT };
    s.deps.enterpriseLayout = () => ({ ...enterpriseLayout("per_user", uid, s.rt.home), eventsDir: dir, lockDir: dir });
    const ev = (): TollgateEvent[] => {
      try {
        return readEvents(dir).flatMap((f) => f.events);
      } catch {
        return [];
      }
    };
    return { ...s, dir, ev };
  }

  it("records the results of all tools (tools = all) with the policy fields (T21)", () => {
    const e = enterprise();
    const post = (tool: string, input: Record<string, unknown>, response: unknown) => ({ session_id: "s-1", tool_use_id: "toolu_2", hook_event_name: "PostToolUse", tool_name: tool, tool_input: input, tool_response: response });
    expect(e.run(post("Read", { file_path: join(e.project, "a.ts") }, "file content that stays out of the log")).code).toBe(0);
    expect(e.run(post("mcp__srv__tool", {}, { isError: true })).code).toBe(0);
    expect(e.run(post("WebFetch", { url: "https://example.org/x" }, "body")).code).toBe(0);
    const results = e.ev().filter((x) => x.type === "tool_result");
    expect(results.map((r) => r.tool?.name)).toEqual(["Read", "mcp__srv__tool", "WebFetch"]);
    expect(results[0]?.tool).toMatchObject({ paths: ["a.ts"], effects: [] });
    expect(results[1]?.data).toMatchObject({ response_kind: "object", is_error: true });
    expect(results[2]?.tool?.effects).toEqual(["network"]);
    expect(results[0]?.policy).toMatchObject({ revision: "acme-1", enterprise_mode: true });
    expect(JSON.stringify(results)).not.toContain("stays out of the log");
  });

  it("applies the enterprise policy and logs redacted commands with policy fields", () => {
    const e = enterprise();
    expect(e.run(bash("wget http://example.org -u")).code).toBe(BLOCK_EXIT_CODE);
    expect(e.run(bash("curl -u a:b https://x")).code).toBe(0);
    const [deny, allow] = e.ev().filter((x) => x.type === "decision");
    expect(deny?.decision).toMatchObject({ outcome: "deny", rule_kind: "blocked_command", rule_id: "no-wget" });
    expect(deny?.policy).toMatchObject({ revision: "acme-1", enterprise_mode: true, layers: [{ level: "enterprise" }, { level: "default" }] });
    expect(allow?.tool?.command).toBe("curl -u [REDACTED:credential] https://x");
    expect(allow?.claude?.project_dir).toBe(e.project);
  });

  it("fails closed with policy_error if the enterprise policy is unusable", () => {
    const e = enterprise();
    chmodSync(join(e.root, "etc", "tollgate", "policy.json"), 0o666);
    const r = e.run(bash("ls"));
    expect(r.code).toBe(BLOCK_EXIT_CODE);
    expect(r.message).toContain("writable by group or others");
    expect(e.ev().find((x) => x.type === "decision")?.decision).toMatchObject({ outcome: "deny", rule_kind: "policy_error" });
    expect(e.ev().find((x) => x.type === "decision")?.policy).toMatchObject({ enterprise_mode: true, sha256: null, layers: [] });
    // With the enterprise signal a broken policy also stops the unchecked tools (exit code of the allowlist rule), so the allowlist cannot be switched off.
    expect(e.run({ ...base, tool_name: "Read", tool_input: { file_path: "a" } }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });

  it("denies every checked tool on macOS with enterprise_unsupported_platform", () => {
    const e = enterprise(POLICY, { runtime: { platform: "darwin" } });
    const r = e.run(bash("ls"));
    expect(r.code).toBe(BLOCK_EXIT_CODE);
    expect(r.message).toContain("Unternehmensmodus auf macOS nicht unterstützt");
    expect(r.message).toContain("Enterprise mode is not supported on macOS");
    expect(e.run({ ...base, tool_name: "Edit", tool_input: { file_path: join(e.project, "a.ts") } }).code).toBe(BLOCK_EXIT_CODE);
    const logged = readEvents(join(e.rt.home, "Library", "Logs", "TollGate")).flatMap((f) => f.events).filter((x) => x.type === "decision");
    expect(logged.map((x) => x.decision?.rule_kind)).toEqual(["enterprise_unsupported_platform", "enterprise_unsupported_platform"]);
    expect(logged[0]?.host.os).toBe("macos");
    expect(e.run({ ...base, tool_name: "Read", tool_input: {} }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });

  it("ignores TOLLGATE_HUMAN_SESSION unless the enterprise policy allows it", () => {
    const e = enterprise();
    const edit = { ...base, tool_name: "Edit", tool_input: { file_path: join(e.project, "AGENTS.md") } };
    expect(e.run(edit, { TOLLGATE_HUMAN_SESSION: "1" }).code).toBe(BLOCK_EXIT_CODE);
    expect(e.ev().find((x) => x.type === "decision")?.decision?.human_session).toBe(false);
    const allowed = enterprise({ ...POLICY, humanSession: { allowed: true } });
    expect(allowed.run(edit, { TOLLGATE_HUMAN_SESSION: "1" }).code).toBe(0);
    expect(allowed.ev().find((x) => x.type === "decision")?.decision?.human_session).toBe(true);
  });

  it("ignores TMPDIR and HOME from the environment", () => {
    const e = enterprise();
    const file = "/var/log/tollgate/events/x.jsonl";
    const run = (command: string, env: NodeJS.ProcessEnv) => runHook(JSON.stringify(bash(command)), { ...e.env, ...env }, e.project, e.deps);
    expect(runHook(JSON.stringify({ ...base, tool_name: "Write", tool_input: { file_path: file, content: "" } }), { ...e.env, TMPDIR: "/var/log/tollgate" }, e.project, e.deps).code).toBe(BLOCK_EXIT_CODE);
    const tmp = join(e.root, "scratch");
    mkdirSync(tmp);
    expect(run(`echo x > "$TMPDIR/out"`, { TMPDIR: "/tmp" }).code).toBe(BLOCK_EXIT_CODE);
    expect(run(`echo x > ~/.bashrc`, { HOME: e.project }).code).toBe(BLOCK_EXIT_CODE);
  });

  it("protects the directories the log really uses, whatever XDG_STATE_HOME says (security review finding 3)", () => {
    const e = enterprise(POLICY, { env: { XDG_STATE_HOME: join(tempDir("tg-xdg-"), "state") } });
    const shared = join(e.rt.home, ".local", "state", "tollgate");
    for (const target of [join(shared, "session-s-1.json"), join(shared, "state.json"), join(e.dir, "session-s-1.json")]) {
      expect(e.run(bash(`echo x > ${target}`)).code, target).toBe(BLOCK_EXIT_CODE);
      expect(e.run({ ...base, tool_name: "Write", tool_input: { file_path: target, content: "" } }).code, target).toBe(BLOCK_EXIT_CODE);
    }
  });

  it("rejects an unsuitable CLAUDE_PROJECT_DIR", () => {
    const e = enterprise();
    for (const dir of ["/", e.rt.home, "/etc/tollgate"]) {
      const r = runHook(JSON.stringify(bash("ls")), { ...e.env, CLAUDE_PROJECT_DIR: dir }, dir, e.deps);
      expect(r.code, dir).toBe(BLOCK_EXIT_CODE);
    }
    expect(e.ev().filter((x) => x.type === "decision").every((x) => x.decision?.rule_kind === "invalid_input")).toBe(true);
    const outside = runHook(JSON.stringify({ ...bash("ls"), cwd: "/etc" }), e.env, e.project, e.deps);
    expect(outside.code).toBe(BLOCK_EXIT_CODE);
  });

  it("ignores regular expression rules of the project policy and reports once", () => {
    const e = enterprise();
    mkdirSync(join(e.project, ".tollgate"));
    writeFileSync(join(e.project, ".tollgate", "policy.json"), JSON.stringify({ version: 1, protectedPaths: [], blockedCommands: [{ pattern: "ls", reason: "regex" }, { id: "m", match: { literal: "secret-tool" }, reason: "no secret-tool" }], allowedDependencies: { npm: ["zod", "evil"], pypi: [] }, logging: { enabled: false } }));
    expect(e.run(bash("ls")).code).toBe(0);
    expect(e.run(bash("secret-tool lookup")).code).toBe(BLOCK_EXIT_CODE);
    const types = e.ev().map((x) => x.type);
    expect(types.filter((t) => t === "policy_error")).toHaveLength(1);
    expect(types.filter((t) => t === "policy_override_ignored")).toHaveLength(1);
    expect(e.ev().filter((x) => x.type === "decision")).toHaveLength(2);
  });

  it("blocks a checked tool if the event directory is missing, with a message for the administrator", () => {
    const e = enterprise();
    e.deps.enterpriseLayout = () => ({ ...enterpriseLayout("per_user", uid, e.rt.home), eventsDir: join(e.root, "no-events", "1"), lockDir: join(e.root, "no-events", "1") });
    const r = e.run(bash("ls"));
    expect(r.code).toBe(BLOCK_EXIT_CODE);
    expect(r.message).toContain("event directory missing");
    expect(r.message).toContain("Ask your administrator to provision it");
    // Observed tools do not block (fail open).
    expect(e.run({ ...base, tool_name: "Read", tool_input: { file_path: "a" } }).code).toBe(0);
  });

  it("observes all tools and logs the target domain (policy with tools.unchecked = observe)", () => {
    const e = enterprise({ ...POLICY, tools: { unchecked: "observe" } });
    e.run({ ...base, tool_name: "WebFetch", tool_input: { url: "https://example.org/x?token=abc", prompt: "secret prompt" } });
    e.run({ ...base, tool_name: "mcp__x__y", tool_input: { a: 1 } });
    const [fetch, mcp] = e.ev().filter((x) => x.type === "decision");
    expect(fetch).toMatchObject({ decision: { outcome: "observe", rule_kind: "none" }, tool: { name: "WebFetch", domain: "example.org", effects: ["network"] } });
    expect(JSON.stringify(fetch)).not.toContain("secret prompt");
    expect(JSON.stringify(fetch)).not.toContain("token=abc");
    expect(mcp?.tool).toMatchObject({ name: "mcp__x__y", effects: ["unknown"] });
  });

  it("session_start carries the policy hashes", () => {
    const e = enterprise();
    e.run({ session_id: "s-1", hook_event_name: "SessionStart", source: "startup" });
    const start = e.ev().find((x) => x.type === "session_start");
    expect(start?.policy).toMatchObject({ revision: "acme-1", enterprise_mode: true });
    expect(start?.policy?.sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("search patterns never reach the log (security review finding 1)", () => {
  const TOKEN = `ghp_${"A1b2C3d4E5".repeat(3)}abcdef`;
  it.each([`grep -rn ${TOKEN} .`, 'rg -e "password=hunter2" src', `rg ${TOKEN} src`])("%s", (command) => {
    const s = setup();
    expect(s.run(bash(command))).toEqual({ code: 0 });
    const text = JSON.stringify(s.events());
    expect(text).not.toContain(TOKEN);
    expect(text).not.toContain("hunter2");
  });
});

describe("event name spoofing (declared event versus stdin)", () => {
  const force = { session_id: "s-1", tool_use_id: "toolu_1", tool_name: "Bash", tool_input: { command: "git push --force" } };
  const run = (s: Setup, event: unknown, declared?: string): HookResult => runHook(JSON.stringify(event), s.env, s.project, { ...s.deps, event: declared });

  it("a checked tool is evaluated whatever event name stdin claims, with or without a declaration", () => {
    for (const name of ["PostToolUse", "SessionStart", "SessionEnd", "SubagentStart", "SubagentStop"]) {
      const s = setup();
      expect(run(s, { ...force, hook_event_name: name }).code, `${name} without argv`).toBe(BLOCK_EXIT_CODE);
      expect(run(s, { ...force, hook_event_name: name }, "PreToolUse").code, `${name} declared PreToolUse`).toBe(BLOCK_EXIT_CODE);
      // The argument is part of the manifest command and cannot be forged by the caller: a matching declaration is trusted.
      expect(run(s, { ...force, hook_event_name: name }, name).code, `${name} declared the same`).toBe(0);
      expect(s.events().filter((e) => e.type === "decision")).toHaveLength(2);
    }
  });

  it("a contradiction is recorded: the declared event is logged and the stdin name is flagged", () => {
    const s = setup();
    expect(run(s, { ...force, hook_event_name: "PostToolUse" }, "PreToolUse").code).toBe(BLOCK_EXIT_CODE);
    const [deny] = decisions(s);
    expect(deny?.claude).toMatchObject({ hook_event: "PreToolUse", invalid_fields: ["hook_event_name_mismatch"] });
    expect(deny?.decision).toMatchObject({ outcome: "deny", rule_kind: "blocked_command" });
  });

  it("an unchecked tool with a lifecycle name under a PreToolUse declaration is a tool call, not a lifecycle event", () => {
    const s = setup();
    expect(run(s, { session_id: "s-1", tool_name: "Read", tool_input: { file_path: join(s.project, "a.ts") }, hook_event_name: "SessionEnd" }, "PreToolUse").code).toBe(0);
    expect(s.events().map((e) => e.type)).not.toContain("session_end");
  });

  it("a matching declaration keeps the non-tool handling", () => {
    const s = setup();
    expect(run(s, { session_id: "s-1", hook_event_name: "SessionStart", source: "startup" }, "SessionStart")).toEqual({ code: 0 });
    expect(run(s, { session_id: "s-1", tool_use_id: "t", hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "ls" }, tool_response: {} }, "PostToolUse").code).toBe(0);
    expect(s.events().map((e) => e.type)).toEqual(["chain_start", "session_start", "tool_result"]);
  });

  it("a lifecycle call under a different declaration is rejected as an invalid tool call (fail closed)", () => {
    const s = setup();
    expect(run(s, { session_id: "s-1", hook_event_name: "SessionStart" }, "PreToolUse").code).toBe(BLOCK_EXIT_CODE);
    expect(run(s, { session_id: "s-1", hook_event_name: "SessionStart" }, "<invalid>").code).toBe(BLOCK_EXIT_CODE);
    expect(s.events().map((e) => e.type)).not.toContain("session_start");
  });

  it("without a declaration (manifest from before --event) a non-tool event is still recorded", () => {
    const s = setup();
    expect(run(s, { session_id: "s-1", hook_event_name: "SessionStart" })).toEqual({ code: 0 });
    expect(s.events().map((e) => e.type)).toContain("session_start");
  });

  it("reads --event from the arguments", () => {
    expect(eventFromArgs([])).toBeUndefined();
    expect(eventFromArgs(["--event", "PostToolUse"])).toBe("PostToolUse");
    for (const bad of [["--event"], ["--event", ""], ["--event", "Post ToolUse"], ["--event", "a".repeat(65)]]) expect(eventFromArgs(bad)).toBe("<invalid>");
  });
});
