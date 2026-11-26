// Enforcement status per coding agent (`tollgate-guard-status`): a static check of the documented hook configuration
// locations plus an in-process self-test. The result is a statement of this host about itself, not proof: a user with
// root rights can forge the files, the self-test and the log. It is used to find agents that are not (or only partly)
// guarded, not to stop one.
import { lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, isAbsolute, join } from "node:path";
import { codexDecision } from "./adapters/codex.js";
import { copilotDecision } from "./adapters/copilot.js";
import { cursorDecision } from "./adapters/cursor.js";
import { grokDecision } from "./adapters/grok.js";
import { systemRuntime, managedSettingsPath } from "./events/runtime.js";
import type { EnforcementStatus } from "./events/types.js";
import { runHook, type HookDeps } from "./hook.js";

export const STATUS_SCHEMA = "tollgate.status.v1";
export const STATUS_AGENTS = ["claude-code", "codex", "copilot", "grok", "cursor"] as const;
export type StatusAgent = (typeof STATUS_AGENTS)[number];

/** Plugin id as forced by the managed settings template. */
export const CLAUDE_PLUGIN_ID = "tollwire-guardrail@tollwire";
const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_HOOK_FILES = 50;

export type SelfTest = "pass" | "fail" | "skipped";

export interface AgentReport {
  agent: StatusAgent;
  status: EnforcementStatus;
  /** Short machine-readable reason code. */
  reason: string;
  hook_registered: boolean;
  target_exists: boolean;
  /** The agent denies the call when the hook fails or times out (documented contract); false = fail-open; null = no hook found. */
  fail_closed: boolean | null;
  self_test: SelfTest;
  /** Where the registration was found, relative (`~/...`, `project:...`, `managed:...`); never an absolute path. */
  config_source: string | null;
}

export interface StatusReport {
  schema: typeof STATUS_SCHEMA;
  generated_at: string;
  agents: AgentReport[];
}

export interface StatusDeps {
  /** Home directory of the user whose configuration is checked. */
  home: string;
  platform: NodeJS.Platform;
  /** Only `PATH` and `CODEX_HOME` are read. */
  env: NodeJS.ProcessEnv;
  /** Optional project directory whose agent configuration is checked in addition to the user files. */
  projectDir?: string | undefined;
  now: () => Date;
  /** Known deny case through the adapter of the agent; true = denied as expected. */
  selfTest: (agent: StatusAgent) => boolean;
}

// --- file helpers -----------------------------------------------------------------------------------------------

function isRegularFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

interface JsonRead {
  found: boolean;
  /** The file exists but is too large, unreadable or not a JSON object. */
  unreadable: boolean;
  value: Record<string, unknown> | null;
}

function readJson(path: string): JsonRead {
  let info;
  try {
    info = lstatSync(path);
  } catch {
    return { found: false, unreadable: false, value: null };
  }
  if (!info.isFile() && !info.isSymbolicLink()) return { found: true, unreadable: true, value: null };
  try {
    if (statSync(path).size > MAX_CONFIG_BYTES) return { found: true, unreadable: true, value: null };
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return { found: true, unreadable: true, value: null };
    return { found: true, unreadable: false, value: parsed as Record<string, unknown> };
  } catch {
    return { found: true, unreadable: true, value: null };
  }
}

function jsonFilesIn(dir: string): string[] {
  try {
    return readdirSync(dir)
      .filter((n) => n.endsWith(".json"))
      .sort()
      .slice(0, MAX_HOOK_FILES)
      .map((n) => join(dir, n));
  } catch {
    return [];
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

// --- hook entries -----------------------------------------------------------------------------------------------

interface HookEntry {
  command: string;
  failClosed: boolean | null;
}

/**
 * The hook commands registered for `event` in a hooks object. Two shapes occur: nested (`[{matcher, hooks: [{command}]}]`:
 * Claude Code, Codex, Grok) and flat (`[{command | bash | powershell, failClosed}]`: Copilot, Cursor).
 */
function entriesFor(hooks: unknown, event: string): HookEntry[] {
  const list = asRecord(hooks)?.[event];
  if (!Array.isArray(list)) return [];
  const out: HookEntry[] = [];
  const take = (item: unknown): void => {
    const rec = asRecord(item);
    if (rec === null) return;
    const failClosed = typeof rec.failClosed === "boolean" ? rec.failClosed : null;
    for (const key of ["command", "bash", "powershell"]) {
      const value = rec[key];
      if (typeof value === "string") out.push({ command: value, failClosed });
    }
  };
  for (const item of list) {
    const rec = asRecord(item);
    if (rec !== null && Array.isArray(rec.hooks)) for (const inner of rec.hooks) take(inner);
    else take(item);
  }
  return out;
}

const SEP = String.raw`(?:^|[\\/\s"'])`;
const END = String.raw`(?=$|[\s"'])`;

/** The command mentions the TollWire hook of the agent, as a file (`dist/<file>.js`) or as the installed binary name. */
function matcherFor(agent: StatusAgent): RegExp {
  switch (agent) {
    case "claude-code":
      return new RegExp(`${SEP}(?:hookCli|hookCliPosix|hookCliWin)\\.js${END}|${SEP}tollgate-guard(?:\\.cmd)?${END}`);
    case "codex":
      return new RegExp(`${SEP}codexHookCli\\.js${END}|${SEP}tollgate-guard-codex(?:\\.cmd)?${END}`);
    case "copilot":
      return new RegExp(`${SEP}copilotHookCli\\.js${END}|${SEP}tollgate-guard-copilot(?:\\.cmd)?${END}`);
    case "grok":
      return new RegExp(`${SEP}grokHookCli\\.js${END}|${SEP}tollgate-guard-grok(?:\\.cmd)?${END}`);
    case "cursor":
      return new RegExp(`${SEP}cursorHookCli\\.js${END}|${SEP}tollgate-guard-cursor(?:\\.cmd)?${END}`);
  }
}

function binaryNameFor(agent: StatusAgent): string {
  return agent === "claude-code" ? "tollgate-guard" : `tollgate-guard-${agent}`;
}

function pathDirs(env: NodeJS.ProcessEnv): string[] {
  const raw = env.PATH ?? "";
  return raw.split(delimiter).filter((d) => d !== "" && isAbsolute(d));
}

function onPath(name: string, env: NodeJS.ProcessEnv, platform: NodeJS.Platform): boolean {
  const names = platform === "win32" ? [name, `${name}.cmd`, `${name}.exe`] : [name];
  return pathDirs(env).some((dir) => names.some((n) => isRegularFile(join(dir, n))));
}

/** Does the registered command point to a file that exists? Absolute `.js` path, `~/` path, or the installed binary on PATH. */
function targetExists(agent: StatusAgent, command: string, d: StatusDeps): boolean {
  const tokens = command.match(/"[^"]*"|'[^']*'|\S+/g) ?? [];
  const fileName = agent === "claude-code" ? /(?:^|[\\/])(?:hookCli|hookCliPosix|hookCliWin)\.js$/ : new RegExp(`(?:^|[\\\\/])${agent}HookCli\\.js$`);
  for (const raw of tokens) {
    const token = raw.replace(/^["']|["']$/g, "");
    if (fileName.test(token)) {
      const resolved = token.startsWith("~/") ? join(d.home, token.slice(2)) : token;
      if (isAbsolute(resolved) && isRegularFile(resolved)) return true;
    }
  }
  const bin = binaryNameFor(agent);
  const mentionsBin = tokens.some((t) => {
    const base = t.replace(/^["']|["']$/g, "").split(/[\\/]/).pop() ?? "";
    return base === bin || base === `${bin}.cmd`;
  });
  if (mentionsBin) {
    // An absolute path to the binary, or the bare name found on PATH.
    for (const raw of tokens) {
      const token = raw.replace(/^["']|["']$/g, "");
      if ((token.endsWith(`/${bin}`) || token.endsWith(`\\${bin}.cmd`)) && isAbsolute(token) && isRegularFile(token)) return true;
    }
    if (tokens.some((t) => t.replace(/^["']|["']$/g, "") === bin) && onPath(bin, d.env, d.platform)) return true;
  }
  return false;
}

// --- per agent configuration ------------------------------------------------------------------------------------

interface Registration {
  /** A hook entry of TollWire was found. */
  registered: boolean;
  /** At least one of them points to an existing target. */
  target: boolean;
  /** At least one hook file was present but unreadable. */
  unreadable: boolean;
  /** Cursor: every found entry sets `failClosed: true`. */
  allFailClosed: boolean;
  /** Copilot: only the camelCase event `preToolUse` was found. */
  camelOnly: boolean;
  source: string | null;
}

function emptyRegistration(): Registration {
  return { registered: false, target: false, unreadable: false, allFailClosed: true, camelOnly: false, source: null };
}

interface Source {
  path: string;
  label: string;
}

function userSources(agent: StatusAgent, d: StatusDeps): Source[] {
  const home = d.home;
  const project = d.projectDir;
  const out: Source[] = [];
  const add = (path: string, label: string): void => void out.push({ path, label });
  switch (agent) {
    case "claude-code":
      add(join(home, ".claude", "settings.json"), "~/.claude/settings.json");
      if (project !== undefined) {
        add(join(project, ".claude", "settings.json"), "project:.claude/settings.json");
        add(join(project, ".claude", "settings.local.json"), "project:.claude/settings.local.json");
      }
      break;
    case "codex": {
      const codexHome = d.env.CODEX_HOME !== undefined && isAbsolute(d.env.CODEX_HOME) ? d.env.CODEX_HOME : null;
      add(join(codexHome ?? join(home, ".codex"), "hooks.json"), codexHome === null ? "~/.codex/hooks.json" : "$CODEX_HOME/hooks.json");
      add("/etc/codex/hooks.json", "system:/etc/codex/hooks.json");
      if (project !== undefined) add(join(project, ".codex", "hooks.json"), "project:.codex/hooks.json");
      break;
    }
    case "copilot":
      for (const f of jsonFilesIn(join(home, ".copilot", "hooks"))) add(f, `~/.copilot/hooks/${f.split(/[\\/]/).pop()}`);
      if (project !== undefined) for (const f of jsonFilesIn(join(project, ".github", "hooks"))) add(f, `project:.github/hooks/${f.split(/[\\/]/).pop()}`);
      break;
    case "grok":
      for (const f of jsonFilesIn(join(home, ".grok", "hooks"))) add(f, `~/.grok/hooks/${f.split(/[\\/]/).pop()}`);
      // Grok also reads the shared Claude settings.
      add(join(home, ".claude", "settings.json"), "~/.claude/settings.json");
      if (project !== undefined) for (const f of jsonFilesIn(join(project, ".grok", "hooks"))) add(f, `project:.grok/hooks/${f.split(/[\\/]/).pop()}`);
      break;
    case "cursor":
      add(join(home, ".cursor", "hooks.json"), "~/.cursor/hooks.json");
      if (project !== undefined) add(join(project, ".cursor", "hooks.json"), "project:.cursor/hooks.json");
      break;
  }
  return out;
}

function hookRegistration(agent: StatusAgent, d: StatusDeps): Registration {
  const reg = emptyRegistration();
  const pattern = matcherFor(agent);
  const events = agent === "cursor" ? ["preToolUse"] : agent === "copilot" ? ["PreToolUse", "preToolUse"] : ["PreToolUse"];
  let pascalSeen = false;
  let camelSeen = false;
  for (const source of userSources(agent, d)) {
    const read = readJson(source.path);
    if (!read.found) continue;
    if (read.unreadable || read.value === null) {
      reg.unreadable = true;
      continue;
    }
    for (const event of events) {
      for (const entry of entriesFor(read.value.hooks, event)) {
        if (!pattern.test(entry.command)) continue;
        reg.registered = true;
        if (event === "PreToolUse") pascalSeen = true;
        else if (agent === "copilot") camelSeen = true;
        reg.source ??= source.label;
        if (entry.failClosed !== true) reg.allFailClosed = false;
        if (targetExists(agent, entry.command, d)) reg.target = true;
      }
    }
  }
  reg.camelOnly = agent === "copilot" && camelSeen && !pascalSeen;
  return reg;
}

/** Claude Code: the plugin (enabled in a settings file and installed) or a direct hook entry in the settings. */
function claudeRegistration(d: StatusDeps): Registration {
  const reg = hookRegistration("claude-code", d);
  const files: Source[] = [
    { path: managedSettingsPath(d.platform), label: "managed:managed-settings.json" },
    ...jsonFilesIn(join(managedSettingsPath(d.platform).replace(/[\\/][^\\/]*$/, ""), "managed-settings.d")).map((p) => ({ path: p, label: `managed:${p.split(/[\\/]/).pop()}` })),
    { path: join(d.home, ".claude", "settings.json"), label: "~/.claude/settings.json" },
    ...(d.projectDir !== undefined
      ? [
          { path: join(d.projectDir, ".claude", "settings.json"), label: "project:.claude/settings.json" },
          { path: join(d.projectDir, ".claude", "settings.local.json"), label: "project:.claude/settings.local.json" },
        ]
      : []),
  ];
  let enabledAt: string | null = null;
  let disabled = false;
  for (const f of files) {
    const read = readJson(f.path);
    if (!read.found) continue;
    if (read.unreadable || read.value === null) {
      reg.unreadable = true;
      continue;
    }
    const flag = asRecord(read.value.enabledPlugins)?.[CLAUDE_PLUGIN_ID];
    if (flag === true) enabledAt ??= f.label;
    else if (flag === false) disabled = true;
  }
  // An explicit "off" in any scope counts as off: the order of precedence is not evaluated (fails toward an alert).
  if (enabledAt !== null && !disabled) {
    reg.registered = true;
    reg.source = reg.source ?? enabledAt;
    if (pluginInstalled(d)) reg.target = true;
  }
  return reg;
}

/** `~/.claude/plugins/installed_plugins.json` lists the install path of each plugin; the hook entry point must exist there. */
function pluginInstalled(d: StatusDeps): boolean {
  const read = readJson(join(d.home, ".claude", "plugins", "installed_plugins.json"));
  if (read.value === null) return false;
  const plugins = asRecord(read.value.plugins) ?? read.value;
  const raw = plugins[CLAUDE_PLUGIN_ID];
  const list = Array.isArray(raw) ? raw : raw === undefined ? [] : [raw];
  for (const item of list) {
    const path = asRecord(item)?.installPath;
    if (typeof path === "string" && isAbsolute(path) && isRegularFile(join(path, "dist", "hookCli.js"))) return true;
  }
  return false;
}

const AGENT_DIRS: Readonly<Record<StatusAgent, string>> = {
  "claude-code": ".claude",
  codex: ".codex",
  copilot: ".copilot",
  grok: ".grok",
  cursor: ".cursor",
};
const AGENT_BINARIES: Readonly<Record<StatusAgent, string>> = {
  "claude-code": "claude",
  codex: "codex",
  copilot: "copilot",
  grok: "grok",
  cursor: "cursor-agent",
};

function agentPresent(agent: StatusAgent, d: StatusDeps): boolean {
  const dir = agent === "codex" && d.env.CODEX_HOME !== undefined && isAbsolute(d.env.CODEX_HOME) ? d.env.CODEX_HOME : join(d.home, AGENT_DIRS[agent]);
  return isDirectory(dir) || onPath(AGENT_BINARIES[agent], d.env, d.platform);
}

// --- classification ---------------------------------------------------------------------------------------------

/** Agents that continue when the hook times out or crashes, even with a correct configuration. */
const FAIL_OPEN: Readonly<Partial<Record<StatusAgent, string>>> = {
  copilot: "fail_open_on_timeout",
  grok: "fail_open_on_crash_or_timeout",
};

export function checkAgent(agent: StatusAgent, d: StatusDeps): AgentReport {
  const reg = agent === "claude-code" ? claudeRegistration(d) : hookRegistration(agent, d);
  const base = { agent, hook_registered: reg.registered, target_exists: reg.target, config_source: reg.source };
  if (!reg.registered) {
    if (!reg.unreadable && !agentPresent(agent, d)) {
      return { ...base, status: "NOT_INSTALLED", reason: "agent_not_found", fail_closed: null, self_test: "skipped" };
    }
    return { ...base, status: "UNPROTECTED", reason: reg.unreadable ? "config_unreadable" : "no_hook_registered", fail_closed: null, self_test: "skipped" };
  }
  if (!reg.target) {
    return { ...base, status: "UNPROTECTED", reason: agent === "claude-code" ? "plugin_not_installed" : "target_missing", fail_closed: null, self_test: "skipped" };
  }
  let selfTest: SelfTest;
  try {
    selfTest = d.selfTest(agent) ? "pass" : "fail";
  } catch {
    selfTest = "fail";
  }
  const failClosed = !(agent in FAIL_OPEN) && (agent !== "cursor" || reg.allFailClosed);
  if (selfTest === "fail") return { ...base, status: "UNPROTECTED", reason: "self_test_failed", fail_closed: failClosed, self_test: selfTest };
  if (agent === "copilot") {
    return { ...base, status: "DEGRADED", reason: reg.camelOnly ? "shell_only_event_name" : (FAIL_OPEN.copilot as string), fail_closed: false, self_test: selfTest };
  }
  const open = FAIL_OPEN[agent];
  if (open !== undefined) return { ...base, status: "DEGRADED", reason: open, fail_closed: false, self_test: selfTest };
  if (agent === "cursor" && !reg.allFailClosed) return { ...base, status: "DEGRADED", reason: "fail_open_default", fail_closed: false, self_test: selfTest };
  return { ...base, status: "ENFORCED", reason: "ok", fail_closed: true, self_test: selfTest };
}

export function checkAll(d: StatusDeps): StatusReport {
  return { schema: STATUS_SCHEMA, generated_at: d.now().toISOString(), agents: STATUS_AGENTS.map((a) => checkAgent(a, d)) };
}

// --- self-test --------------------------------------------------------------------------------------------------

const DENY_COMMAND = "git push --force";

/**
 * A known deny case through the adapter of the agent, in this process. Nothing is logged (`dryRun`), no state of the user is
 * touched (own temporary directory for project, home and taint state), the host policy is not consulted (no enterprise signal).
 * It shows that the engine of this package denies through the adapter; it does not run the registered target.
 */
export function runSelfTest(agent: StatusAgent): boolean {
  const root = mkdtempSync(join(tmpdir(), "tollgate-selftest-"));
  try {
    const project = join(root, "project");
    const home = join(root, "home");
    const env: NodeJS.ProcessEnv = {};
    const deps: HookDeps = {
      runtime: { ...systemRuntime(), home },
      resolve: { exists: () => false },
      taint: { dir: join(root, "taint"), releaseDir: join(root, "releases"), stopAt: root },
      dryRun: true,
    };
    const claudeShaped = JSON.stringify({ hook_event_name: "PreToolUse", session_id: "selftest", cwd: project, tool_name: "Bash", tool_input: { command: DENY_COMMAND } });
    switch (agent) {
      case "claude-code":
        return runHook(claudeShaped, env, project, { ...deps, agent: "claude-code" }).code === 2;
      case "codex": {
        const out = codexDecision(claudeShaped, env, project, deps);
        return out.code === 2 && asRecord(asRecord(JSON.parse(out.stdout))?.hookSpecificOutput)?.permissionDecision === "deny";
      }
      case "copilot": {
        const out = copilotDecision(claudeShaped, env, project, deps);
        return out.code === 2 && asRecord(JSON.parse(out.stdout))?.permissionDecision === "deny";
      }
      case "grok": {
        const stdin = JSON.stringify({ hook_event_name: "PreToolUse", sessionId: "selftest", cwd: project, toolName: "run_terminal_command", toolInput: { command: DENY_COMMAND } });
        const out = grokDecision(stdin, env, project, deps);
        return out.code === 2 && asRecord(JSON.parse(out.stdout))?.decision === "deny";
      }
      case "cursor": {
        const stdin = JSON.stringify({ hook_event_name: "preToolUse", conversation_id: "selftest", tool_use_id: "selftest", cwd: project, tool_name: "Shell", tool_input: { command: DENY_COMMAND } });
        const out = cursorDecision(stdin, env, project, deps);
        return out.code === 2 && asRecord(JSON.parse(out.stdout))?.permission === "deny";
      }
    }
  } catch {
    return false;
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

export function systemStatusDeps(env: NodeJS.ProcessEnv, projectDir?: string): StatusDeps {
  const rt = systemRuntime();
  return { home: rt.home, platform: rt.platform, env, projectDir, now: () => new Date(), selfTest: runSelfTest };
}

// --- output -----------------------------------------------------------------------------------------------------

export function formatText(report: StatusReport): string {
  const lines = ["TollWire guardrail status (statement of this host about itself, not proof)", ""];
  const width = Math.max(...report.agents.map((a) => a.agent.length));
  for (const a of report.agents) {
    const where = a.config_source === null ? "" : `  [${a.config_source}]`;
    lines.push(`${a.agent.padEnd(width)}  ${a.status.padEnd(13)} ${a.reason}${where}`);
  }
  return `${lines.join("\n")}\n`;
}
