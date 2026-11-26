import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { Fixture, readEvents, runtimeFor, tempDir } from "./events/helpers.js";
import { checkAgent, checkAll, CLAUDE_PLUGIN_ID, formatText, runSelfTest, STATUS_AGENTS, type StatusAgent, type StatusDeps } from "../src/status.js";
import { parseArgs, recordToLog, runStatusCli } from "../src/statusCli.js";
import type { TollgateEvent } from "../src/events/types.js";

function put(path: string, content: unknown): string {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, typeof content === "string" ? content : JSON.stringify(content));
  return path;
}

interface Host {
  home: string;
  root: string;
  deps: StatusDeps;
  /** An existing hook binary of the package. */
  cli: (name: string) => string;
}

function host(selfTest: (a: StatusAgent) => boolean = () => true, patch: Partial<StatusDeps> = {}): Host {
  const root = tempDir("tg-status-");
  const home = join(root, "home");
  mkdirSync(home, { recursive: true });
  const cli = (name: string): string => put(join(root, "pkg", "dist", `${name}.js`), "// hook");
  return { home, root, cli, deps: { home, platform: "linux", env: {}, now: () => new Date("2026-11-26T10:00:00.000Z"), selfTest, ...patch } };
}

const codexHooks = (cmd: string): unknown => ({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: cmd, timeout: 10 }] }] } });
const status = (h: Host, a: StatusAgent): string => checkAgent(a, h.deps).status;

describe("codex", () => {
  it("ENFORCED: hook registered, target exists, self-test passes", () => {
    const h = host();
    put(join(h.home, ".codex", "hooks.json"), codexHooks(`node "${h.cli("codexHookCli")}"`));
    const r = checkAgent("codex", h.deps);
    expect(r).toMatchObject({ status: "ENFORCED", reason: "ok", hook_registered: true, target_exists: true, fail_closed: true, self_test: "pass", config_source: "~/.codex/hooks.json" });
  });
  it("UNPROTECTED: target missing", () => {
    const h = host();
    put(join(h.home, ".codex", "hooks.json"), codexHooks(`node "${join(h.root, "gone", "codexHookCli.js")}"`));
    expect(checkAgent("codex", h.deps)).toMatchObject({ status: "UNPROTECTED", reason: "target_missing", hook_registered: true, target_exists: false, self_test: "skipped" });
  });
  it("UNPROTECTED: config exists without the TollWire hook", () => {
    const h = host();
    put(join(h.home, ".codex", "hooks.json"), codexHooks("node /opt/other/hook.js"));
    expect(checkAgent("codex", h.deps)).toMatchObject({ status: "UNPROTECTED", reason: "no_hook_registered" });
  });
  it("UNPROTECTED: a hook of another agent does not count", () => {
    const h = host();
    put(join(h.home, ".codex", "hooks.json"), codexHooks(`node "${h.cli("grokHookCli")}"`));
    expect(status(h, "codex")).toBe("UNPROTECTED");
  });
  it("UNPROTECTED: self-test fails", () => {
    const h = host(() => false);
    put(join(h.home, ".codex", "hooks.json"), codexHooks(`node "${h.cli("codexHookCli")}"`));
    expect(checkAgent("codex", h.deps)).toMatchObject({ status: "UNPROTECTED", reason: "self_test_failed", self_test: "fail" });
  });
  it("UNPROTECTED: a throwing self-test counts as failed", () => {
    const h = host(() => {
      throw new Error("x");
    });
    put(join(h.home, ".codex", "hooks.json"), codexHooks(`node "${h.cli("codexHookCli")}"`));
    expect(checkAgent("codex", h.deps).self_test).toBe("fail");
  });
  it("UNPROTECTED: unreadable (invalid JSON) hook file", () => {
    const h = host();
    put(join(h.home, ".codex", "hooks.json"), "{ not json");
    expect(checkAgent("codex", h.deps)).toMatchObject({ status: "UNPROTECTED", reason: "config_unreadable" });
  });
  it("NOT_INSTALLED: no trace of the agent", () => {
    expect(checkAgent("codex", host().deps)).toMatchObject({ status: "NOT_INSTALLED", reason: "agent_not_found", hook_registered: false });
  });
  it("UNPROTECTED (not NOT_INSTALLED) when the agent directory exists without a hook", () => {
    const h = host();
    mkdirSync(join(h.home, ".codex"));
    expect(status(h, "codex")).toBe("UNPROTECTED");
  });
  it("agent found on PATH counts as installed", () => {
    const h = host();
    const bin = put(join(h.root, "bin", "codex"), "#!/bin/sh\n");
    const d = { ...h.deps, env: { PATH: dirname(bin) } };
    expect(checkAgent("codex", d).status).toBe("UNPROTECTED");
  });
  it("honours CODEX_HOME", () => {
    const h = host();
    const codexHome = join(h.root, "chome");
    put(join(codexHome, "hooks.json"), codexHooks(`node "${h.cli("codexHookCli")}"`));
    expect(checkAgent("codex", { ...h.deps, env: { CODEX_HOME: codexHome } })).toMatchObject({ status: "ENFORCED", config_source: "$CODEX_HOME/hooks.json" });
  });
  it("project scope only with projectDir", () => {
    const h = host();
    const project = join(h.root, "proj");
    put(join(project, ".codex", "hooks.json"), codexHooks(`node "${h.cli("codexHookCli")}"`));
    expect(status(h, "codex")).toBe("NOT_INSTALLED");
    expect(checkAgent("codex", { ...h.deps, projectDir: project })).toMatchObject({ status: "ENFORCED", config_source: "project:.codex/hooks.json" });
  });
  it("accepts the installed binary name on PATH", () => {
    const h = host();
    const bin = put(join(h.root, "bin", "tollgate-guard-codex"), "#!/bin/sh\n");
    put(join(h.home, ".codex", "hooks.json"), codexHooks("tollgate-guard-codex"));
    expect(checkAgent("codex", { ...h.deps, env: { PATH: dirname(bin) } }).status).toBe("ENFORCED");
    expect(checkAgent("codex", h.deps).status).toBe("UNPROTECTED"); // not on PATH
  });
});

describe("copilot", () => {
  const hooks = (cmd: string, event = "PreToolUse"): unknown => ({ version: 1, hooks: { [event]: [{ type: "command", bash: cmd, timeoutSec: 10 }] } });
  it("DEGRADED even with a correct configuration (timeout is fail-open)", () => {
    const h = host();
    put(join(h.home, ".copilot", "hooks", "tollwire.json"), hooks(`node ${h.cli("copilotHookCli")}`));
    expect(checkAgent("copilot", h.deps)).toMatchObject({ status: "DEGRADED", reason: "fail_open_on_timeout", fail_closed: false, self_test: "pass", config_source: "~/.copilot/hooks/tollwire.json" });
  });
  it("DEGRADED with a distinct reason when only the camelCase event is registered", () => {
    const h = host();
    put(join(h.home, ".copilot", "hooks", "t.json"), hooks(`node ${h.cli("copilotHookCli")}`, "preToolUse"));
    expect(checkAgent("copilot", h.deps)).toMatchObject({ status: "DEGRADED", reason: "shell_only_event_name" });
  });
  it("UNPROTECTED when the target is missing", () => {
    const h = host();
    put(join(h.home, ".copilot", "hooks", "t.json"), hooks("node /nope/copilotHookCli.js"));
    expect(status(h, "copilot")).toBe("UNPROTECTED");
  });
  it("repository hooks are read with projectDir", () => {
    const h = host();
    const project = join(h.root, "repo");
    put(join(project, ".github", "hooks", "g.json"), hooks(`node ${h.cli("copilotHookCli")}`));
    expect(checkAgent("copilot", { ...h.deps, projectDir: project })).toMatchObject({ status: "DEGRADED", config_source: "project:.github/hooks/g.json" });
  });
});

describe("grok", () => {
  const hooks = (cmd: string): unknown => ({ hooks: { PreToolUse: [{ matcher: "run_terminal_command", hooks: [{ type: "command", command: cmd }] }] } });
  it("DEGRADED (fail-open on crash and timeout)", () => {
    const h = host();
    put(join(h.home, ".grok", "hooks", "h.json"), hooks(`node "${h.cli("grokHookCli")}"`));
    expect(checkAgent("grok", h.deps)).toMatchObject({ status: "DEGRADED", reason: "fail_open_on_crash_or_timeout", fail_closed: false });
  });
  it("also found through the shared Claude settings", () => {
    const h = host();
    put(join(h.home, ".claude", "settings.json"), hooks(`node "${h.cli("grokHookCli")}"`));
    expect(checkAgent("grok", h.deps)).toMatchObject({ status: "DEGRADED", config_source: "~/.claude/settings.json" });
  });
  it("UNPROTECTED without a hook, NOT_INSTALLED without the agent", () => {
    const h = host();
    expect(status(h, "grok")).toBe("NOT_INSTALLED");
    mkdirSync(join(h.home, ".grok"));
    expect(status(h, "grok")).toBe("UNPROTECTED");
  });
});

describe("cursor", () => {
  const hooks = (cmd: string, failClosed?: boolean): unknown => ({ version: 1, hooks: { preToolUse: [{ command: cmd, matcher: "Shell|Write", ...(failClosed === undefined ? {} : { failClosed }), timeout: 10 }] } });
  it("ENFORCED with failClosed true", () => {
    const h = host();
    put(join(h.home, ".cursor", "hooks.json"), hooks(`node "${h.cli("cursorHookCli")}"`, true));
    expect(checkAgent("cursor", h.deps)).toMatchObject({ status: "ENFORCED", fail_closed: true, config_source: "~/.cursor/hooks.json" });
  });
  it("DEGRADED without failClosed, and with failClosed false", () => {
    for (const flag of [undefined, false]) {
      const h = host();
      put(join(h.home, ".cursor", "hooks.json"), hooks(`node "${h.cli("cursorHookCli")}"`, flag));
      expect(checkAgent("cursor", h.deps)).toMatchObject({ status: "DEGRADED", reason: "fail_open_default", fail_closed: false });
    }
  });
  it("DEGRADED when one of two entries lacks failClosed", () => {
    const h = host();
    const cmd = `node "${h.cli("cursorHookCli")}"`;
    put(join(h.home, ".cursor", "hooks.json"), { version: 1, hooks: { preToolUse: [{ command: cmd, failClosed: true }, { command: cmd }] } });
    expect(status(h, "cursor")).toBe("DEGRADED");
  });
  it("failClosed as a string is not true", () => {
    const h = host();
    put(join(h.home, ".cursor", "hooks.json"), { hooks: { preToolUse: [{ command: `node "${h.cli("cursorHookCli")}"`, failClosed: "true" }] } });
    expect(status(h, "cursor")).toBe("DEGRADED");
  });
  it("UNPROTECTED when the target is missing", () => {
    const h = host();
    put(join(h.home, ".cursor", "hooks.json"), hooks("node /nope/cursorHookCli.js", true));
    expect(status(h, "cursor")).toBe("UNPROTECTED");
  });
});

describe("claude-code", () => {
  const settings = (enabled: boolean | undefined): unknown => ({ enabledPlugins: enabled === undefined ? {} : { [CLAUDE_PLUGIN_ID]: enabled } });
  function install(h: Host): void {
    const dir = join(h.root, "plugins", "tollwire-guardrail");
    put(join(dir, "dist", "hookCli.js"), "// hook");
    put(join(h.home, ".claude", "plugins", "installed_plugins.json"), { version: 2, plugins: { [CLAUDE_PLUGIN_ID]: [{ scope: "user", installPath: dir, version: "0.1.6" }] } });
  }
  it("ENFORCED: plugin enabled and installed", () => {
    const h = host();
    put(join(h.home, ".claude", "settings.json"), settings(true));
    install(h);
    expect(checkAgent("claude-code", h.deps)).toMatchObject({ status: "ENFORCED", reason: "ok", fail_closed: true, self_test: "pass", config_source: "~/.claude/settings.json" });
  });
  it("UNPROTECTED: plugin enabled but not installed", () => {
    const h = host();
    put(join(h.home, ".claude", "settings.json"), settings(true));
    expect(checkAgent("claude-code", h.deps)).toMatchObject({ status: "UNPROTECTED", reason: "plugin_not_installed" });
  });
  it("UNPROTECTED: plugin installed but disabled, even if another scope enables it", () => {
    const h = host();
    put(join(h.home, ".claude", "settings.json"), settings(false));
    const project = join(h.root, "proj");
    put(join(project, ".claude", "settings.json"), settings(true));
    install(h);
    expect(checkAgent("claude-code", { ...h.deps, projectDir: project })).toMatchObject({ status: "UNPROTECTED", reason: "no_hook_registered" });
  });
  it("UNPROTECTED: Claude directory without the plugin", () => {
    const h = host();
    put(join(h.home, ".claude", "settings.json"), settings(undefined));
    expect(status(h, "claude-code")).toBe("UNPROTECTED");
  });
  it("ENFORCED: direct hook entry in the settings pointing to an existing target", () => {
    const h = host();
    put(join(h.home, ".claude", "settings.json"), { hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: `node "${h.cli("hookCli")}" --event PreToolUse` }] }] } });
    expect(checkAgent("claude-code", h.deps)).toMatchObject({ status: "ENFORCED", hook_registered: true });
  });
  it("a direct hook entry whose target is gone is UNPROTECTED", () => {
    const h = host();
    put(join(h.home, ".claude", "settings.json"), { hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "node /gone/dist/hookCli.js" }] }] } });
    expect(checkAgent("claude-code", h.deps)).toMatchObject({ status: "UNPROTECTED", reason: "plugin_not_installed", hook_registered: true });
  });
  it("codexHookCli.js is not mistaken for the Claude hook", () => {
    const h = host();
    put(join(h.home, ".claude", "settings.json"), { hooks: { PreToolUse: [{ hooks: [{ type: "command", command: `node "${h.cli("codexHookCli")}"` }] }] } });
    expect(checkAgent("claude-code", h.deps).hook_registered).toBe(false);
  });
});

describe("overall report", () => {
  it("covers all five agents and is deterministic", () => {
    const h = host();
    const r = checkAll(h.deps);
    expect(r.schema).toBe("tollgate.status.v1");
    expect(r.generated_at).toBe("2026-11-26T10:00:00.000Z");
    expect(r.agents.map((a) => a.agent)).toEqual([...STATUS_AGENTS]);
    expect(r.agents.every((a) => a.status === "NOT_INSTALLED")).toBe(true);
    expect(checkAll(h.deps)).toEqual(r);
  });
  it("no absolute path appears in the report", () => {
    const h = host();
    put(join(h.home, ".codex", "hooks.json"), codexHooks(`node "${h.cli("codexHookCli")}"`));
    expect(JSON.stringify(checkAll(h.deps))).not.toContain(h.root);
  });
});

describe("real self-test", () => {
  it.each(STATUS_AGENTS)("%s: the adapter denies a known case, without writing a log", (agent) => {
    expect(runSelfTest(agent)).toBe(true);
  });
});

describe("CLI", () => {
  function run(args: string[], h: Host, record = (): boolean => true): { code: number; out: string; err: string } {
    let out = "";
    let err = "";
    const code = runStatusCli(args, { out: (t) => (out += t), err: (t) => (err += t) }, { status: (p) => ({ ...h.deps, projectDir: p }), record });
    return { code, out, err };
  }
  it("text output, exit 0 without an UNPROTECTED agent", () => {
    const r = run([], host());
    expect(r.code).toBe(0);
    expect(r.out).toContain("NOT_INSTALLED");
    expect(formatText(checkAll(host().deps))).toContain("claude-code");
  });
  it("exit 1 with an UNPROTECTED agent; --json output parses", () => {
    const h = host();
    mkdirSync(join(h.home, ".codex"));
    const r = run(["--json"], h);
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out).agents.find((a: { agent: string }) => a.agent === "codex").status).toBe("UNPROTECTED");
  });
  it("DEGRADED alone is exit 0", () => {
    const h = host();
    put(join(h.home, ".grok", "hooks", "h.json"), { hooks: { PreToolUse: [{ hooks: [{ command: `node "${h.cli("grokHookCli")}"` }] }] } });
    expect(run([], h).code).toBe(0);
  });
  it("usage errors: unknown flag, relative or missing project", () => {
    for (const args of [["--bogus"], ["--project"], ["--project", "rel"], ["--project", "/a", "--project", "/b"]]) {
      const r = run(args, host());
      expect(r.code).toBe(2);
      expect(r.err).toContain("Usage");
    }
    expect(parseArgs(["--json", "--record", "--project", "/x"])).toEqual({ json: true, record: true, project: "/x" });
  });
  it("--record failure is exit 1 with a fixed message", () => {
    expect(run(["--record"], host(), () => false)).toMatchObject({ code: 1, err: expect.stringContaining("could not be written") });
    expect(run(["--record"], host(), () => {
      throw new Error("/secret/path");
    })).toMatchObject({ code: 1 });
  });
  it("an unexpected failure of the check prints no detail", () => {
    let err = "";
    const code = runStatusCli([], { out: () => undefined, err: (t) => (err += t) }, { status: () => { throw new Error("/secret/path at x"); }, record: () => true });
    expect(code).toBe(1);
    expect(err).not.toContain("/secret");
  });
});

describe("--record writes enforcement_status events", () => {
  it("one event per agent with the agent name and flat data, chain valid", () => {
    const root = tempDir("tg-rec-");
    const rt = runtimeFor(root, new Fixture());
    const h = host();
    put(join(h.home, ".grok", "hooks", "h.json"), { hooks: { PreToolUse: [{ hooks: [{ command: `node "${h.cli("grokHookCli")}"` }] }] } });
    mkdirSync(join(h.home, ".codex"));
    const report = checkAll(h.deps);
    const env = { XDG_STATE_HOME: join(root, "state"), XDG_CONFIG_HOME: join(root, "config") };
    expect(recordToLog(report, rt, env, root)).toBe(true);
    const dir = join(root, "state", "tollgate", "events");
    expect(existsSync(dir)).toBe(true);
    const events = readEvents(dir).flatMap((f) => f.events) as TollgateEvent[];
    const es = events.filter((e) => e.type === "enforcement_status");
    expect(es.map((e) => e.agent?.name)).toEqual(["claude-code", "codex", "copilot", "grok", "cursor"]);
    const grok = es.find((e) => e.agent?.name === "grok");
    expect(grok?.data).toMatchObject({ status: "DEGRADED", reason: "fail_open_on_crash_or_timeout", hook_registered: true, target_exists: true, fail_closed: false, self_test: "pass", human_session: false });
    expect(es.find((e) => e.agent?.name === "codex")?.data).toMatchObject({ status: "UNPROTECTED", reason: "no_hook_registered" });
    // flat scalars only
    for (const e of es) for (const v of Object.values(e.data ?? {})) expect(typeof v === "object" && v !== null).toBe(false);
    expect(readdirSync(dir).length).toBeGreaterThan(0);
    expect(readFileSync(join(dir, readdirSync(dir)[0] as string), "utf8")).not.toContain(h.root);
  });
});
