// Decision logger: turns evaluated hook calls into events, applies the settings and handles write errors
//.
import { canonicalJson, sha256Hex } from "../vendor/hashchain.js";
import { commandFields } from "./event.js";
import { EventWriteError } from "./fsutil.js";
import { standaloneLayout, userConfigFile, type Layout } from "./layout.js";
import { redactText } from "./redact.js";
import { fileHash, locationEnv, managedSettingsPath, metaOf, pluginFilesHash, type Runtime } from "./runtime.js";
import { standaloneSettings, readUserConfig, type LogSettings, type UserConfig } from "./settings.js";
import { LogStore, readSessionFile, type FlowState, type SessionFile, type Tx } from "./store.js";
import { INVALID, type ClaudeFields, type DecisionFields, type Draft, type PolicyFields, type ToolFields } from "./types.js";
import type { Effect } from "./commandInfo.js";

/** A problem found while loading the policy that is reported as an event (not fatal). */
export interface PolicyFinding {
  type: "policy_error" | "policy_override_ignored";
  level: string;
  id?: string;
  detail: string;
}

export interface LogContext {
  rt: Runtime;
  env: NodeJS.ProcessEnv;
  /** Enterprise mode: fixed layout and settings from the enterprise policy. Null: stand-alone. */
  enterprise: { layout: Layout; settings: LogSettings } | null;
  policy: PolicyFields;
  findings: PolicyFinding[];
}

export type LogResult = { ok: true; notice?: string } | { ok: false; message: string; block: boolean };

export interface DecisionRecord {
  claude: ClaudeFields;
  /** Project directory for `claude.project_dir` (only logged if the settings ask for it). */
  projectDir: string | null;
  tool: { name: string; rawCommand?: string; programs?: string[]; paths?: string[]; effects?: Effect[]; domain?: string };
  decision: DecisionFields;
  /** Read-only call that may be summarized under the flood limit. */
  suppressible: boolean;
  humanSession: boolean;
}

/** Result of a tool call (`PostToolUse`): metadata only, never the content of the response. */
export interface ToolResultRecord {
  claude: ClaudeFields;
  tool: { name: string; paths?: string[]; effects?: Effect[] };
  /** `true` for the tools that the guardrail checks (Bash and the write tools). */
  checked: boolean;
  /** Read-only call that may be left out under the flood limit. */
  suppressible: boolean;
  data: { response_kind: string; response_bytes: number | null; is_error: boolean | null };
  humanSession: boolean;
}

/** Session taint events: `data` holds only ids, counters, tool or program names and hashes, never content. */
export interface TaintRecord {
  type: "taint_set" | "taint_release" | "taint_would_block";
  claude: ClaudeFields;
  data: Record<string, unknown>;
  humanSession: boolean;
}

export interface LifecycleRecord {
  kind: "session_start" | "session_end" | "subagent_start" | "subagent_stop";
  claude: ClaudeFields;
  data: Record<string, unknown>;
  humanSession: boolean;
}

const MISSING_DIRECTORY =
  "TollGate enterprise mode: event directory missing. Ask your administrator to provision it (see the TollGate enterprise documentation).";
const DISABLED_NOTICE = "TollGate decision log is disabled (user configuration).";
const MAX_FINDINGS = 20;
const TOP_PATHS = 10;

function hasId(sessionId: string): boolean {
  return sessionId !== INVALID;
}

export class EventLogger {
  readonly layout: Layout;
  readonly store: LogStore;
  private readonly configFile: string;

  constructor(private readonly ctx: LogContext) {
    const { rt, env } = ctx;
    const loc = locationEnv(env);
    this.layout = ctx.enterprise?.layout ?? standaloneLayout(loc, rt.platform, rt.home, rt.uid);
    this.configFile = userConfigFile(loc, rt.platform, rt.home);
    this.store = new LogStore(this.layout, metaOf(rt), { clock: rt.clock, uuid: rt.uuid, uid: rt.uid, ...(rt.facts ? { facts: rt.facts } : {}) });
  }

  // --- settings -------------------------------------------------------------------------------------------------

  /** Settings of a session: enterprise policy, or the frozen user file of the session, or the current user file. */
  private settingsFor(sessionId: string): { settings: LogSettings; configSha: string | null } {
    if (this.ctx.enterprise !== null) return { settings: this.ctx.enterprise.settings, configSha: null };
    if (hasId(sessionId)) {
      const frozen = readSessionFile(this.layout.lockDir, sessionId);
      if (frozen?.config !== undefined && isUserConfig(frozen.config)) {
        return { settings: standaloneSettings(frozen.config), configSha: frozen.config_sha256 ?? null };
      }
    }
    const current = readUserConfig(this.configFile);
    return { settings: standaloneSettings(current.config), configSha: current.sha256 };
  }

  // --- helpers --------------------------------------------------------------------------------------------------

  private fail(settings: LogSettings, error: unknown): LogResult {
    const code = error instanceof EventWriteError ? error.code : "io";
    const text = error instanceof EventWriteError ? error.message : "unexpected error";
    if (this.ctx.enterprise !== null) this.fallbackError(code, text);
    const message = code === "dir_missing" && this.ctx.enterprise !== null ? MISSING_DIRECTORY : `TollGate: the decision log could not be written (${text}).`;
    return { ok: false, message, block: settings.onWriteError === "block" };
  }

  /** Enterprise: a `log_error` at the fallback location in the private directory of the user, if possible. */
  private fallbackError(code: string, text: string): void {
    try {
      const { rt, env } = this.ctx;
      const layout = standaloneLayout(locationEnv(env), rt.platform, rt.home, rt.uid);
      const store = new LogStore(layout, metaOf(rt), { clock: rt.clock, uuid: rt.uuid, uid: rt.uid, ...(rt.facts ? { facts: rt.facts } : {}) });
      store.transaction((tx) => tx.append([store.draft("log_error", { data: { reason: `enterprise event log not writable: ${text}`, code } })]));
    } catch {
      // No fallback location: the error is reported through the hook result.
    }
  }

  private findingDrafts(tx: Tx): Draft[] {
    const findings = this.ctx.findings.slice(0, MAX_FINDINGS);
    const hash = findings.length === 0 ? undefined : sha256Hex(canonicalJson(findings));
    if (hash === tx.findingsHash) return [];
    // Change tracked: report once per change, not on every call.
    tx.update({ findings_sha256: hash as string });
    const drafts: Draft[] = [];
    for (const type of ["policy_error", "policy_override_ignored"] as const) {
      const list = findings.filter((f) => f.type === type);
      if (list.length > 0) drafts.push(this.store.draft(type, { policy: this.ctx.policy, data: { findings: list.map(({ level, id, detail }) => ({ level, id: id ?? null, detail })) } }));
    }
    return drafts;
  }

  /** Applies the flood limit; returns the drafts to write (a summary of the previous window, maybe the decision itself). */
  private flood(tx: Tx, sessionId: string, limit: number, record: { suppressible: boolean; tool: { paths?: string[] | undefined } } | null, claude: ClaudeFields, flush: boolean): { pre: Draft[]; skip: boolean } {
    if (!hasId(sessionId)) return { pre: [], skip: false };
    const file = tx.readSession(sessionId);
    const now = this.ctx.rt.clock().getTime();
    const minute = Math.floor(now / 60_000);
    let flow = file?.flood;
    const pre: Draft[] = [];
    if (flow !== undefined && flow.suppressed > 0 && (flush || flow.window !== minute)) {
      pre.push(this.suppressedDraft(flow, claude));
      flow = { window: flow.window, count: flow.count, suppressed: 0, paths: {} };
    }
    if (record === null || !record.suppressible || limit <= 0) {
      if (file !== undefined && file !== null && flow !== file.flood) tx.writeSession({ ...file, ...(flow ? { flood: flow } : {}) });
      return { pre, skip: false };
    }
    if (flow === undefined || flow.window !== minute) flow = { window: minute, count: 0, suppressed: 0, paths: {} };
    let skip = false;
    if (flow.count >= limit) {
      flow = { ...flow, suppressed: flow.suppressed + 1, paths: bump(flow.paths, (record.tool.paths ?? []).map((p) => redactText(p).text)) };
      skip = true;
    } else {
      flow = { ...flow, count: flow.count + 1 };
    }
    const base: SessionFile = file ?? { v: 1, session_id: sessionId };
    tx.writeSession({ ...base, flood: flow });
    return { pre, skip };
  }

  private suppressedDraft(flow: FlowState, claude: ClaudeFields): Draft {
    const top = Object.entries(flow.paths)
      .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
      .slice(0, TOP_PATHS)
      .map(([path, count]) => ({ path: redactText(path).text, count }));
    return this.store.draft("suppressed", {
      claude: { ...claude, tool_use_id: null, agent_id: null, agent_type: null, permission_mode: null },
      data: { count: flow.suppressed, window_start: new Date(flow.window * 60_000).toISOString(), top_paths: top },
    });
  }

  /** Stand-alone: the log was switched off (or on) in the user file; write the one boundary event per change. */
  private transition(tx: Tx, enabled: boolean, configSha: string | null): Draft[] {
    if (this.ctx.enterprise !== null) return [];
    if (!enabled) {
      if (tx.logging !== "on") return [];
      tx.update({ logging: "off" });
      return [this.store.draft("logging_disabled", { data: { config_sha256: configSha } })];
    }
    const drafts = tx.logging === "off" ? [this.store.draft("logging_enabled", { data: { config_sha256: configSha } })] : [];
    if (tx.logging !== "on") tx.update({ logging: "on" });
    return drafts;
  }

  private disabled(settings: LogSettings, configSha: string | null): LogResult {
    if (this.ctx.enterprise !== null) return { ok: true };
    try {
      if (this.store.peekState().logging !== "on") return { ok: true };
      this.store.transaction((tx) => {
        const drafts = this.transition(tx, false, configSha);
        if (drafts.length > 0) tx.append(drafts);
      });
      return { ok: true };
    } catch (error) {
      return this.fail(settings, error);
    }
  }

  // --- public ---------------------------------------------------------------------------------------------------

  /** One `decision` (or `observe`) event per evaluated call. Never throws. */
  recordDecision(rec: DecisionRecord): LogResult {
    let settings: LogSettings = this.ctx.enterprise?.settings ?? standaloneSettings({ enabled: true, commandDetail: "none", projectDir: false });
    try {
      const resolved = this.settingsFor(rec.claude.session_id);
      settings = resolved.settings;
      if (rec.decision.outcome === "observe" && settings.tools === "checked") return { ok: true };
      if (!settings.enabled) return this.disabled(settings, resolved.configSha);
      const cmd = commandFields(rec.tool.rawCommand ?? "", rec.tool.rawCommand === undefined ? "none" : settings.commandDetail, rec.tool.rawCommand === undefined ? false : settings.commandHash);
      const reason = rec.decision.reason === null ? null : redactText(rec.decision.reason);
      const tool: ToolFields = { name: rec.tool.name, truncated: false };
      if (cmd.command !== undefined) tool.command = cmd.command;
      if (cmd.command_sha256 !== undefined) tool.command_sha256 = cmd.command_sha256;
      if (rec.tool.programs !== undefined) tool.programs = rec.tool.programs;
      let pathRedactions = 0;
      if (rec.tool.paths !== undefined) {
        // A path may carry a secret (a token in a file name); the log never holds it in clear text.
        tool.paths = rec.tool.paths.map((p) => {
          const r = redactText(p);
          pathRedactions += r.redactions;
          return r.text;
        });
      }
      if (rec.tool.effects !== undefined) tool.effects = rec.tool.effects;
      if (rec.tool.domain !== undefined) tool.domain = rec.tool.domain;
      const claude: ClaudeFields = { ...rec.claude };
      if (settings.projectDir && rec.projectDir !== null) claude.project_dir = rec.projectDir;
      const decision: DecisionFields = { ...rec.decision, reason: reason === null ? null : reason.text };
      this.store.transaction((tx) => {
        const drafts = [...this.transition(tx, true, resolved.configSha), ...this.findingDrafts(tx)];
        const flood = this.flood(tx, rec.claude.session_id, settings.rateLimit, rec, rec.claude, false);
        drafts.push(...flood.pre);
        if (!flood.skip) {
          drafts.push(
            this.store.draft("decision", {
              claude,
              tool,
              redactions: cmd.redactions + (reason?.redactions ?? 0) + pathRedactions,
              decision,
              policy: this.ctx.policy,
            }),
          );
        }
        if (drafts.length > 0) tx.append(drafts);
      });
      return { ok: true };
    } catch (error) {
      return this.fail(settings, error);
    }
  }

  /**
   * One `tool_result` event per finished tool call. Content of the response is never logged, only its kind, size and an
   * error flag. With `tools = checked` only the checked tools are recorded. Never throws.
   */
  recordToolResult(rec: ToolResultRecord): LogResult {
    let settings: LogSettings = this.ctx.enterprise?.settings ?? standaloneSettings({ enabled: true, commandDetail: "none", projectDir: false });
    try {
      const resolved = this.settingsFor(rec.claude.session_id);
      settings = resolved.settings;
      if (!rec.checked && settings.tools === "checked") return { ok: true };
      if (!settings.enabled) return this.disabled(settings, resolved.configSha);
      const tool: ToolFields = { name: rec.tool.name, truncated: false };
      let pathRedactions = 0;
      if (rec.tool.paths !== undefined) {
        tool.paths = rec.tool.paths.map((p) => {
          const r = redactText(p);
          pathRedactions += r.redactions;
          return r.text;
        });
      }
      if (rec.tool.effects !== undefined) tool.effects = rec.tool.effects;
      this.store.transaction((tx) => {
        const drafts = [...this.transition(tx, true, resolved.configSha), ...this.findingDrafts(tx)];
        const flood = this.flood(tx, rec.claude.session_id, settings.rateLimit, rec, rec.claude, false);
        drafts.push(...flood.pre);
        if (!flood.skip) {
          drafts.push(this.store.draft("tool_result", { claude: rec.claude, tool, redactions: pathRedactions, policy: this.ctx.policy, data: { ...rec.data, human_session: rec.humanSession } }));
        }
        if (drafts.length > 0) tx.append(drafts);
      });
      return { ok: true };
    } catch (error) {
      return this.fail(settings, error);
    }
  }

  /** Taint events. Written whenever the log is enabled (also with `tools = checked`); never summarized. Never throws. */
  recordTaint(rec: TaintRecord): LogResult {
    let settings: LogSettings = this.ctx.enterprise?.settings ?? standaloneSettings({ enabled: true, commandDetail: "none", projectDir: false });
    try {
      const resolved = this.settingsFor(rec.claude.session_id);
      settings = resolved.settings;
      if (!settings.enabled) return this.disabled(settings, resolved.configSha);
      this.store.transaction((tx) => {
        const drafts = [...this.transition(tx, true, resolved.configSha), ...this.findingDrafts(tx)];
        drafts.push(this.store.draft(rec.type, { claude: rec.claude, policy: this.ctx.policy, data: { ...rec.data, human_session: rec.humanSession } }));
        tx.append(drafts);
      });
      return { ok: true };
    } catch (error) {
      return this.fail(settings, error);
    }
  }

  /** Session and subagent events. Never throws. */
  recordLifecycle(rec: LifecycleRecord): LogResult {
    let settings: LogSettings = this.ctx.enterprise?.settings ?? standaloneSettings({ enabled: true, commandDetail: "none", projectDir: false });
    try {
      const id = rec.claude.session_id;
      const standalone = this.ctx.enterprise === null;
      let config: ReturnType<typeof readUserConfig> | null = null;
      let configSha: string | null = null;
      if (rec.kind === "session_start" && standalone) {
        // Read and freeze the user file for this session.
        config = readUserConfig(this.configFile);
        settings = standaloneSettings(config.config);
        configSha = config.sha256;
      } else {
        const resolved = this.settingsFor(id);
        settings = resolved.settings;
        configSha = resolved.configSha;
      }
      const notice = standalone && !settings.enabled && rec.kind === "session_start" ? DISABLED_NOTICE : undefined;
      if (rec.kind === "session_start" && standalone && config !== null) {
        // Freeze (even if the log is off, so that the session keeps the value); also removes expired files.
        const frozen = config;
        this.store.transaction((tx) => {
          if (hasId(id)) {
            const previous = tx.readSession(id);
            tx.writeSession({ v: 1, session_id: id, config: frozen.config, config_sha256: frozen.sha256, ...(previous?.flood ? { flood: previous.flood } : {}) });
          }
          tx.cleanup(this.ctx.rt.clock());
          if (!settings.enabled) {
            const drafts = this.transition(tx, false, configSha);
            if (drafts.length > 0) tx.append(drafts);
            return;
          }
          this.appendLifecycle(tx, rec, settings, configSha);
        });
        return notice === undefined ? { ok: true } : { ok: true, notice };
      }
      if (!settings.enabled) return this.disabled(settings, configSha);
      this.store.transaction((tx) => {
        this.appendLifecycle(tx, rec, settings, configSha);
        if (rec.kind === "session_end" && hasId(id)) tx.removeSession(id);
      });
      return { ok: true };
    } catch (error) {
      return this.fail(settings, error);
    }
  }

  private appendLifecycle(tx: Tx, rec: LifecycleRecord, settings: LogSettings, configSha: string | null): void {
    const drafts = [...this.transition(tx, true, configSha), ...this.findingDrafts(tx)];
    const flood = this.flood(tx, rec.claude.session_id, settings.rateLimit, null, rec.claude, rec.kind === "session_end");
    drafts.push(...flood.pre);
    const data = { ...rec.data };
    if (rec.kind === "session_start") data.config_sha256 = configSha;
    drafts.push(this.store.draft(rec.kind, { claude: rec.claude, policy: this.ctx.policy, data: { ...data, human_session: rec.humanSession } }));
    tx.append(drafts);
  }

  /** Data of the `session_start` event: plugin and managed-settings hashes (self-report). */
  sessionStartData(source: unknown): Record<string, unknown> {
    const rt = this.ctx.rt;
    return {
      source: typeof source === "string" && /^[A-Za-z0-9_.-]{1,32}$/.test(source) ? source : null,
      plugin_version: rt.version,
      plugin_files_sha256: pluginFilesHash(rt.pluginRoot),
      managed_settings_sha256: fileHash(managedSettingsPath(rt.platform)),
    };
  }
}

function isUserConfig(value: unknown): value is UserConfig {
  const c = value as UserConfig;
  return typeof c?.enabled === "boolean" && (c.commandDetail === "none" || c.commandDetail === "redacted") && typeof c.projectDir === "boolean";
}

function bump(paths: Record<string, number>, add: readonly string[]): Record<string, number> {
  const out = { ...paths };
  for (const p of add) {
    // At most 200 distinct paths per window.
    if (p in out || Object.keys(out).length < 200) out[p] = (out[p] ?? 0) + 1;
  }
  return out;
}
