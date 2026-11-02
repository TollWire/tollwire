#!/usr/bin/env node
// Claude Code hook. For PreToolUse, exit code 2 blocks the tool call; stderr is shown to the agent.
// Fails closed: unreadable input or policy blocks the call. Every evaluation writes one event to the decision log
//; session and subagent events are recorded and never block.
import { isAbsolute } from "node:path";
import { z } from "zod";
import { checkAdminLocks, type LockLayer } from "./adminLocks.js";
import { detailFor, formatBlock, shortCommand, shortPath, type BlockMessage } from "./blockMessage.js";
import { alwaysProtectedPaths, detectEnterprise, LOCKS_FILE, projectDirProblem, resolvePolicy, uncheckedToolAllowed, type Resolution, type ResolveOptions } from "./enterprise.js";
import { evaluateDetailed, WRITE_TOOLS, type Context, type Detailed } from "./evaluate.js";
import { isEntryPoint } from "./entry.js";
import { analyzeCommand, projectRelative } from "./events/commandInfo.js";
import { validateInput, validPath } from "./events/fields.js";
import { enterpriseLayout, type Layout } from "./events/layout.js";
import { EventLogger, type DecisionRecord, type LogContext, type LogResult, type ToolResultRecord } from "./events/logger.js";
import { observedTool } from "./events/observe.js";
import { locationEnv, systemRuntime, type Runtime } from "./events/runtime.js";
import { ENTERPRISE_DEFAULTS } from "./events/settings.js";
import { INVALID, type ClaudeFields, type DecisionFields, type PolicyFields, type RuleKind } from "./events/types.js";
import type { TaintSource } from "./taint.js";
import { taintMark, taintPost, taintPre, taintSessionStart, taintWouldBlock, type TaintContext, type TaintDeny, type TaintDeps } from "./taintHook.js";
import { canonicalJson, sha256Hex } from "./vendor/hashchain.js";

export const BLOCK_EXIT_CODE = 2;
/**
 * Exit code for "unchecked tool not on the enterprise allowlist". It is not 2 on purpose: the manifest entry for unchecked tools
 * turns every failure of the hook (crash, timeout, exit 2 from a misbehaving program) into "do not block", and maps only this code
 * to a block. A hook registered without that wrapper treats the code as a non-blocking error, like any code other than 0 and 2.
 */
export const UNCHECKED_DENY_EXIT_CODE = 42;

export interface HookResult {
  code: number;
  message?: string;
}

/** Injection points for tests; production uses the defaults. */
export interface HookDeps {
  runtime?: Runtime;
  resolve?: Partial<Pick<ResolveOptions, "ownerUid" | "stopAt" | "exists" | "paths" | "bundledPolicy" | "macosAccepted" | "aclProbe" | "groupWritableParents" | "execPath" | "nodePrefix">>;
  enterpriseLayout?: (variant: "per_user" | "shared", rt: Runtime) => Layout;
  /**
   * Hook event the manifest binds to this call (`--event <name>` in the command). Only a call whose declared event equals the
   * event named on stdin is handled as a session, subagent or result event; see `runHook`.
   */
  event?: string | undefined;
  /** Replaces the evaluation (tests of the `internal_error` path). */
  evaluate?: typeof evaluateDetailed;
  /** Admin locks: file location, clock and the uid to match; production uses the defaults (`LOCKS_FILE`, `Date.now`, the runtime uid). */
  locks?: { path?: string; now?: () => number; uid?: number | null };
  /** Session taint: state and release directories (tests); production uses the defaults of `taintHook.ts`. */
  taint?: TaintDeps;
}

const EventSchema = z.object({
  tool_name: z.string().min(1),
  tool_input: z.record(z.string(), z.unknown()).default({}),
  cwd: z.unknown().optional(),
});

const LIFECYCLE: Readonly<Record<string, "session_start" | "session_end" | "subagent_start" | "subagent_stop">> = {
  SessionStart: "session_start",
  SessionEnd: "session_end",
  SubagentStart: "subagent_start",
  SubagentStop: "subagent_stop",
};

const CHECKED_TOOLS = new Set(["Bash", ...WRITE_TOOLS]);

/** Kinds of block whose message names the target of the call. */
const TARGET_KINDS: ReadonlySet<RuleKind> = new Set<RuleKind>([
  "protected_path", "active_policy", "path_unresolvable", "outside_project", "hardlink_alias", "parse_error", "blocked_command",
  "write_target", "dependency_unverifiable", "dependency", "size_limit", "taint",
]);

// Messages that must exist even if building one fails: computed once at load from fixed input (same pattern as ERROR_MESSAGE in
// adminLocks.ts). The catch branches below use these and never call `formatBlock` again.
const MSG_UNCHECKED = formatBlock({ kind: "unchecked_tool", ruleId: "tools.unchecked", detail: detailFor("unchecked_tool", "") });
const MSG_POLICY = formatBlock({ kind: "policy_error", ruleId: null, detail: "the guardrail policy is unusable, so the call is blocked (fail closed)." });
const MSG_LOCK_EVAL = formatBlock({ kind: "lock_error", ruleId: null, detail: "the administrator lock state could not be evaluated, so the call is blocked (fail closed)." });
const MSG_EVAL = formatBlock({ kind: "internal_error", ruleId: null, detail: "input could not be evaluated (fail closed)." });
const MSG_UNEXPECTED = formatBlock({ kind: "internal_error", ruleId: null, detail: "hook failed unexpectedly (fail closed)." });
const MSG_INPUT = formatBlock({ kind: "invalid_input", ruleId: null, detail: "hook input is invalid (fail closed)." });
const MSG_LOG = formatBlock({ kind: "log_write_error", ruleId: null, detail: "the decision log could not be written (fail closed)." });
const MSG_TAINT_EVAL = formatBlock({ kind: "taint", ruleId: "taint.state", detail: "the session taint could not be evaluated, so the call is blocked (fail closed)." });
const TAINT_RECORD_FAILED = "the session taint could not be recorded before reading untrusted content (fail closed).";

/** Message of a block; the constant if building it fails. */
function blockText(block: BlockMessage, fallback: string): string {
  try {
    return formatBlock(block);
  } catch {
    return fallback;
  }
}

/**
 * Finishes a block of an unchecked tool; `run` returns null if nothing is blocked. Whatever goes wrong (allowlist lookup,
 * message, decision log), the answer stays the deny with exit code 42: exit 2 would be read as "do not block" by the manifest
 * entry for unchecked tools (review findings, #52).
 */
function uncheckedDeny(run: () => HookResult | null, fallback: string): HookResult | null {
  try {
    const result = run();
    return result !== null && result.code === BLOCK_EXIT_CODE ? { ...result, code: UNCHECKED_DENY_EXIT_CODE } : result;
  } catch {
    return { code: UNCHECKED_DENY_EXIT_CODE, message: fallback };
  }
}

function failed(kind: RuleKind, reason: string): Detailed {
  return { allowed: false, reason, kind, ruleId: null };
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function policyFields(resolution: Resolution, enterpriseSignal: boolean, lockLayer: LockLayer | null): PolicyFields {
  if (!resolution.ok) return { revision: null, sha256: null, layers: [], enterprise_mode: enterpriseSignal };
  return {
    revision: resolution.revision,
    // The lock layer is listed but not part of the policy hash: a new lock must not look like a policy change.
    sha256: sha256Hex(canonicalJson(resolution.layers)),
    layers: lockLayer === null ? resolution.layers : [...resolution.layers, lockLayer],
    enterprise_mode: resolution.enterprise !== null,
  };
}

export function loggerFor(rt: Runtime, env: NodeJS.ProcessEnv, resolution: Resolution, signal: boolean, deps: HookDeps, lockLayer: LockLayer | null = null): EventLogger {
  const layoutOf = deps.enterpriseLayout ?? ((variant, r) => enterpriseLayout(variant, r.uid ?? 0, r.home, r.platform));
  let enterprise: LogContext["enterprise"] = null;
  if (resolution.ok && resolution.enterprise !== null) {
    enterprise = { layout: layoutOf(resolution.enterprise.settings.layout, rt), settings: resolution.enterprise.settings };
  } else if (!resolution.ok && signal && (rt.platform === "linux" || (rt.platform === "darwin" && resolution.kind !== "enterprise_unsupported_platform"))) {
    // The policy is unusable, but the log goes to the enterprise location with the default settings.
    enterprise = { layout: layoutOf(ENTERPRISE_DEFAULTS.layout, rt), settings: ENTERPRISE_DEFAULTS };
  }
  return new EventLogger({
    rt,
    env,
    enterprise,
    policy: policyFields(resolution, signal, lockLayer),
    findings: resolution.ok ? resolution.findings : [],
  });
}

function summarize(result: LogResult): string | undefined {
  if (result.ok) return result.notice;
  return result.message;
}

/** Writes the final result: a block stays a block; a failed log write blocks only if configured and only a checked tool. */
function conclude(base: HookResult, log: LogResult, checked: boolean): HookResult {
  const note = summarize(log);
  if (!log.ok && log.block && checked && base.code === 0) {
    return { code: BLOCK_EXIT_CODE, message: blockText({ kind: "log_write_error", ruleId: null, detail: `${log.message} (fail closed)` }, MSG_LOG) };
  }
  if (note === undefined) return base;
  return base.message === undefined ? { ...base, message: note } : { ...base, message: `${base.message}\n${note}` };
}

export function runHook(stdin: string, env: NodeJS.ProcessEnv, cwd: string, deps: HookDeps = {}): HookResult {
  const rt = deps.runtime ?? systemRuntime();
  const projectDir = env.CLAUDE_PROJECT_DIR || cwd;
  const exists = deps.resolve?.exists;
  const signal = detectEnterprise(env, rt.platform, exists).active;
  const resolution = resolvePolicy({ env, projectDir, platform: rt.platform, ...deps.resolve });
  let logger: EventLogger | undefined;
  // Set by the lock check before the first decision event of a tool call is written.
  let lockLayer: LockLayer | null = null;
  const log = (): EventLogger => (logger ??= loggerFor(rt, env, resolution, signal, deps, lockLayer));

  let raw: unknown;
  try {
    raw = JSON.parse(stdin);
  } catch {
    return rejectInput(log, {}, undefined, "hook input is not valid JSON (fail closed).", projectDir);
  }
  const object = asRecord(raw);
  // The event name on stdin is attacker-influenced input (an agent cannot write it, but a malformed or forged call could carry
  // any name). A call is handled as a non-tool event (session, subagent, result) only if
  //  - the event declared by the manifest through `--event` equals the one on stdin, or
  //  - nothing is declared (manifests from before `--event`) and no checked tool (Bash, Edit, Write, MultiEdit,
  //    NotebookEdit) is named: the old behaviour for the fail-open entries, safe because a checked tool is still evaluated.
  // Everything else is evaluated as a tool call, and a contradiction between declaration and stdin is recorded in the event.
  const stdinEvent = typeof object.hook_event_name === "string" ? object.hook_event_name : undefined;
  const nonTool = stdinEvent !== undefined && (LIFECYCLE[stdinEvent] !== undefined || stdinEvent === "PostToolUse");
  const checkedTool = typeof object.tool_name === "string" && CHECKED_TOOLS.has(object.tool_name);
  const declared = deps.event;
  const mismatch = declared !== undefined && declared !== stdinEvent;
  if (nonTool && !mismatch && (declared !== undefined || !checkedTool)) {
    const lifecycle = LIFECYCLE[stdinEvent as string];
    if (lifecycle !== undefined) {
      try {
        return runLifecycle(lifecycle, object, log, resolution, env, rt, projectDir, deps);
      } catch {
        return { code: 0 }; // session and subagent events never block
      }
    }
    try {
      return runToolResult(object, log, projectDir, env, resolution, rt, deps);
    } catch {
      return { code: 0 }; // a result event never blocks
    }
  }

  const parsed = EventSchema.safeParse(raw);
  if (!parsed.success) {
    return rejectInput(log, object, object.tool_name, "hook input has an unexpected structure (fail closed).", projectDir);
  }
  const event = parsed.data;
  const checked = CHECKED_TOOLS.has(event.tool_name);
  const { claude, toolName, invalid } = validateInput(object, event.tool_name);
  const finding = [...invalid, ...(mismatch ? ["hook_event_name_mismatch"] : [])];
  // The declared event is the trusted one; the contradicting stdin value is not logged as the event.
  const baseClaude: ClaudeFields = { ...claude, ...(mismatch && declared !== undefined && /^[A-Za-z]{1,64}$/.test(declared) ? { hook_event: declared } : {}), ...(finding.length > 0 ? { invalid_fields: finding } : {}) };
  const enterprise = resolution.ok ? resolution.enterprise : null;
  // `let`: a tainted session loses the human-session exception, see the taint check below.
  let humanSession = env.TOLLGATE_HUMAN_SESSION === "1" && (enterprise === null || enterprise.policy.humanSessionAllowed);
  const cwdValue = typeof event.cwd === "string" && isAbsolute(event.cwd) ? event.cwd : undefined;

  const record = (decision: DecisionFields, info: Partial<DecisionRecord["tool"]> = {}, suppressible = false): DecisionRecord => ({
    claude: baseClaude,
    projectDir: validPath(projectDir) ?? INVALID,
    tool: { name: toolName, ...info },
    decision,
    suppressible,
    humanSession,
  });
  const decisionOf = (d: Detailed): DecisionFields => ({
    outcome: d.allowed ? "allow" : "deny",
    rule_kind: d.allowed ? "none" : d.kind,
    rule_id: d.allowed ? null : d.ruleId,
    reason: d.allowed ? null : d.reason,
    human_session: humanSession,
  });
  // Shortened target for the message to the agent (never for the log): the command or file path of the call, the name of an unchecked tool.
  const targetOf = (kind: RuleKind): string | undefined => {
    try {
      if (kind === "unchecked_tool") return toolName === INVALID ? "(invalid name)" : shortPath(toolName);
      if (!TARGET_KINDS.has(kind)) return undefined;
      // No command text for an oversized command (nothing of it is processed for the message).
      if (event.tool_name === "Bash" && kind === "size_limit") return undefined;
      if (event.tool_name === "Bash") return typeof event.tool_input.command === "string" ? (shortCommand(event.tool_input.command) ?? "(command not shown)") : undefined;
      const filePath = event.tool_input.file_path ?? event.tool_input.notebook_path;
      if (typeof filePath !== "string" || filePath === "") return undefined;
      return shortPath(isAbsolute(filePath) ? projectRelative(filePath, projectDir) : filePath);
    } catch {
      return undefined;
    }
  };
  const finish = (d: Detailed, info: Partial<DecisionRecord["tool"]> = {}, suppressible = false, text?: string): HookResult => {
    const base: HookResult = d.allowed
      ? { code: 0 }
      : { code: BLOCK_EXIT_CODE, message: text ?? formatBlock({ kind: d.kind, ruleId: d.ruleId, target: targetOf(d.kind), detail: detailFor(d.kind, d.reason) }) };
    return conclude(base, log().recordDecision(record(decisionOf(d), info, suppressible)), checked);
  };

  if (!resolution.ok) {
    // Policy unusable (or enterprise mode on an unsupported platform): fail closed for every checked tool.
    // Unchecked tools stay open only outside enterprise mode. With the enterprise signal a broken policy (also one that a repository
    // file can cause) must not switch the tool allowlist off, so these tools are blocked as well (exit code of the allowlist rule).
    if (!checked && !signal) return { code: 0 };
    const run = (): HookResult => finish(failed(resolution.kind, resolution.message), {}, false, formatBlock({ kind: resolution.kind, ruleId: null, detail: resolution.message }));
    return checked ? run() : (uncheckedDeny(run, MSG_POLICY) as HookResult);
  }

  // Admin locks: before the split into checked and unchecked tools, so that they apply to every tool. Only with
  // the enterprise signal on Linux and `control.enabled`; without it the lock file is not looked at.
  if (enterprise !== null && enterprise.policy.control.enabled && rt.platform === "linux") {
    // Nothing in this block may end in an exception: the manifest entry for unchecked tools turns every failure of the hook
    // (also exit 2) into "do not block" and maps only exit 42 to a block. So any failure here is a deny with the exit code of the
    // tool class (fail closed), even if the decision log cannot be written.
    const failClosed = (): HookResult => ({
      code: checked ? BLOCK_EXIT_CODE : UNCHECKED_DENY_EXIT_CODE,
      message: MSG_LOCK_EVAL,
    });
    try {
      const check = checkAdminLocks({
        path: deps.locks?.path ?? LOCKS_FILE,
        ownerUid: deps.resolve?.ownerUid ?? 0,
        stopAt: deps.resolve?.stopAt,
        uid: deps.locks?.uid !== undefined ? deps.locks.uid : (rt.uid ?? null),
        sessionId: claude.session_id,
        toolName: event.tool_name,
        nowMs: (deps.locks?.now ?? Date.now)(),
      });
      if (logger === undefined) lockLayer = check.layer;
      if (check.deny !== null) {
        const denied: Detailed = { allowed: false, reason: check.deny.reason, kind: check.deny.kind, ruleId: check.deny.ruleId };
        const result = finish(denied, {}, false, check.deny.message);
        // An unchecked tool is blocked through the exit code of the allowlist rule.
        return !checked && result.code === BLOCK_EXIT_CODE ? { ...result, code: UNCHECKED_DENY_EXIT_CODE } : result;
      }
    } catch {
      return failClosed();
    }
  }

  // Session taint: the state is read here, after the admin locks and before the split into checked and unchecked
  // tools, so that it covers every tool; a tainted session loses the human-session exception before the evaluation. The block
  // itself comes after the policy and the tool allowlist (`applyTaint`): a call that they deny keeps their reason. Mode `enforce`
  // fails closed: any failure here blocks with the exit code of the tool class.
  const taintPolicy = resolution.policy.taint;
  let taintCtx: TaintContext | null = null;
  let taintSource: TaintSource | null = null;
  let taintDeny: TaintDeny | null = null;
  const taintEnforced = taintPolicy !== undefined && taintPolicy.mode === "enforce";
  if (taintPolicy !== undefined && taintPolicy.mode !== "off") {
    taintCtx = { policy: taintPolicy, enterprise: enterprise !== null, rt, env, projectDir, cwd: cwdValue, claude: baseClaude, humanSession, log, deps: deps.taint };
    try {
      const pre = taintPre(taintCtx, event.tool_name, event.tool_input, checked);
      taintSource = pre.source;
      taintDeny = pre.deny;
      // Mode `observe` never changes a decision, so the human-session exception stays there.
      if (pre.tainted === true && taintEnforced) humanSession = false;
    } catch {
      if (taintEnforced) return { code: checked ? BLOCK_EXIT_CODE : UNCHECKED_DENY_EXIT_CODE, message: MSG_TAINT_EVAL };
    }
  }
  /**
   * For a call that the policy allows: the taint block (`enforce`) or its record (`observe`), else the taint mark of a source.
   * Returns the decision to use.
   */
  /** Block message of a taint deny: the logged reason plus the release hint for the human (the hint is never logged). */
  const taintText = (d: Detailed): string | undefined => {
    if (d.allowed || d.kind !== "taint" || taintDeny === null || d.ruleId !== taintDeny.ruleId) return undefined;
    return blockText({ kind: "taint", ruleId: d.ruleId, target: targetOf("taint"), detail: `${d.reason} ${taintDeny.hint}` }, MSG_TAINT_EVAL);
  };
  const applyTaint = (allowed: Detailed): Detailed => {
    if (taintCtx === null) return allowed;
    if (taintDeny !== null) {
      if (taintEnforced) return { allowed: false, reason: taintDeny.reason, kind: "taint", ruleId: taintDeny.ruleId };
      taintWouldBlock(taintCtx, event.tool_name, taintDeny);
    }
    if (taintSource !== null && !taintMark(taintCtx, taintSource) && taintEnforced) return { allowed: false, reason: TAINT_RECORD_FAILED, kind: "taint", ruleId: "taint.state" };
    return allowed;
  };

  if (!checked) {
    // Observed tools: no evaluation. Fail open, also if the log cannot be written or anything goes wrong.
    // Exception, enterprise mode only: with `tools.unchecked = deny` a tool that is not on the allowlist is blocked.
    if (enterprise !== null) {
      const deny = uncheckedDeny(() => {
        if (uncheckedToolAllowed(event.tool_name, enterprise.policy.uncheckedTools)) return null;
        const shown = toolName === INVALID ? "(invalid name)" : toolName;
        const denied: Detailed = { allowed: false, reason: `the tool ${shown} is not on the enterprise tool allowlist.`, kind: "unchecked_tool", ruleId: "tools.unchecked" };
        return finish(denied);
      }, MSG_UNCHECKED);
      if (deny !== null) return deny;
    }
    const tainted = applyTaint({ allowed: true });
    if (!tainted.allowed) return uncheckedDeny(() => finish(tainted, {}, false, taintText(tainted)), MSG_TAINT_EVAL) as HookResult;
    try {
      const info = observedTool(event.tool_name, event.tool_input, { projectDir, cwd: cwdValue });
      const observe: DecisionFields = { outcome: "observe", rule_kind: "none", rule_id: null, reason: null, human_session: humanSession };
      const tool = { paths: info.paths, effects: info.effects, ...(info.domain === undefined ? {} : { domain: info.domain }) };
      return conclude({ code: 0 }, log().recordDecision(record(observe, tool, info.suppressible)), false);
    } catch {
      return { code: 0 };
    }
  }

  if (enterprise !== null) {
    const problem = projectDirProblem(projectDir, cwdValue, rt.home, rt.platform);
    if (problem !== null) return finish(failed("invalid_input", `${problem}.`));
  }

  const toolInfo = checkedToolInfo(event.tool_name, event.tool_input, projectDir, cwdValue, enterprise !== null ? rt.home : env.HOME, env);
  let decision: Detailed;
  try {
    const context: Context = {
      projectDir,
      humanSession,
      cwd: cwdValue,
      home: enterprise !== null ? rt.home : env.HOME,
      tmpdir: enterprise !== null ? undefined : env.TMPDIR,
      policyFile: resolution.policyFile,
      extraProtected: [...alwaysProtectedPaths(rt.platform, locationEnv(env), rt.home, rt.uid, log().layout), ...resolution.protectedFiles],
    };
    decision = (deps.evaluate ?? evaluateDetailed)({ tool_name: event.tool_name, tool_input: event.tool_input }, resolution.policy, context);
  } catch {
    return finish(failed("internal_error", "input could not be evaluated"), {}, false, MSG_EVAL);
  }
  if (decision.allowed) decision = applyTaint(decision);
  return finish(decision, toolInfo.info, toolInfo.suppressible && decision.allowed, taintText(decision));
}

interface ToolInfo {
  info: Partial<DecisionRecord["tool"]>;
  suppressible: boolean;
}

function checkedToolInfo(tool: string, input: Record<string, unknown>, projectDir: string, cwd: string | undefined, home: string | undefined, env: NodeJS.ProcessEnv): ToolInfo {
  try {
    if (tool === "Bash") {
      const command = typeof input.command === "string" ? input.command : undefined;
      if (command === undefined) return { info: { effects: ["unknown"] }, suppressible: false };
      const a = analyzeCommand(command, { projectDir, cwd, home, env });
      return { info: { rawCommand: command, programs: a.programs, paths: a.paths, effects: a.effects }, suppressible: a.suppressible };
    }
    const filePath = input.file_path ?? input.notebook_path;
    const paths = typeof filePath === "string" && filePath !== "" ? [validPath(filePath) === null ? INVALID : isAbsolute(filePath) ? projectRelative(filePath, projectDir) : filePath] : [];
    return { info: { paths, effects: ["write"] }, suppressible: false };
  } catch {
    return { info: { effects: ["unknown"] }, suppressible: false };
  }
}

function rejectInput(log: () => EventLogger, object: Record<string, unknown>, toolName: unknown, message: string, projectDir: string): HookResult {
  const { claude, toolName: name, invalid } = validateInput(object, toolName);
  const result = log().recordDecision({
    claude: invalid.length > 0 ? { ...claude, invalid_fields: invalid } : claude,
    projectDir: validPath(projectDir) ?? INVALID,
    tool: { name },
    decision: { outcome: "deny", rule_kind: "invalid_input", rule_id: null, reason: message, human_session: false },
    suppressible: false,
    humanSession: false,
  });
  return conclude({ code: BLOCK_EXIT_CODE, message: blockText({ kind: "invalid_input", ruleId: null, detail: message }, MSG_INPUT) }, result, true);
}

function runLifecycle(
  kind: "session_start" | "session_end" | "subagent_start" | "subagent_stop",
  object: Record<string, unknown>,
  log: () => EventLogger,
  resolution: Resolution,
  env: NodeJS.ProcessEnv,
  rt: Runtime,
  projectDir: string,
  deps: HookDeps,
): HookResult {
  const { claude, invalid } = validateInput(object, "lifecycle");
  const fields: ClaudeFields = invalid.length > 0 ? { ...claude, invalid_fields: invalid } : claude;
  const humanSession = env.TOLLGATE_HUMAN_SESSION === "1" && !(resolution.ok && resolution.enterprise !== null && !resolution.enterprise.policy.humanSessionAllowed);
  const logger = log();
  const data = kind === "session_start" ? logger.sessionStartData(object.source) : kind === "session_end" && typeof object.reason === "string" ? { reason: object.reason.slice(0, 64) } : {};
  const result = logger.recordLifecycle({ kind, claude: fields, data, humanSession });
  const taintPolicy = resolution.ok ? resolution.policy.taint : undefined;
  if (kind === "session_start" && resolution.ok && taintPolicy !== undefined && taintPolicy.mode !== "off") {
    taintSessionStart({ policy: taintPolicy, enterprise: resolution.enterprise !== null, rt, env, projectDir, claude: fields, humanSession, log, deps: deps.taint }, object.source);
  }
  // These events can never block the session; problems are only reported.
  return result.ok ? (result.notice === undefined ? { code: 0 } : { code: 0, message: result.notice }) : { code: 0, message: result.message };
}

/** Kind and size of a `tool_response`; its content is never logged. */
function responseFacts(response: unknown): ToolResultRecord["data"] {
  if (response === undefined || response === null) return { response_kind: "none", response_bytes: null, is_error: null };
  const kind = typeof response === "string" ? "string" : Array.isArray(response) ? "array" : typeof response === "object" ? "object" : "other";
  let bytes: number | null;
  try {
    bytes = typeof response === "string" ? Buffer.byteLength(response, "utf8") : Buffer.byteLength(JSON.stringify(response) ?? "", "utf8");
  } catch {
    bytes = null;
  }
  // Best effort: a flag that the response itself carries (for example MCP results); absent means unknown.
  const flag = asRecord(response);
  const isError = typeof flag.is_error === "boolean" ? flag.is_error : typeof flag.isError === "boolean" ? flag.isError : null;
  return { response_kind: kind, response_bytes: bytes, is_error: isError };
}

/** `PostToolUse`: records the result of a tool call (T21). Never blocks; problems are only reported. */
function runToolResult(object: Record<string, unknown>, log: () => EventLogger, projectDir: string, env: NodeJS.ProcessEnv, resolution: Resolution, rt: Runtime, deps: HookDeps = {}): HookResult {
  if (!resolution.ok) return { code: 0 };
  const name = object.tool_name;
  const { claude, toolName, invalid } = validateInput(object, name);
  const fields: ClaudeFields = invalid.length > 0 ? { ...claude, invalid_fields: invalid } : claude;
  const input = asRecord(object.tool_input);
  const cwdValue = typeof object.cwd === "string" && isAbsolute(object.cwd) ? object.cwd : undefined;
  const checked = typeof name === "string" && CHECKED_TOOLS.has(name);
  const enterprise = resolution.enterprise;
  const humanSession = env.TOLLGATE_HUMAN_SESSION === "1" && (enterprise === null || enterprise.policy.humanSessionAllowed);
  const home = enterprise !== null ? rt.home : env.HOME;
  let tool: ToolResultRecord["tool"] = { name: toolName };
  let suppressible = false;
  try {
    if (typeof name === "string" && !checked) {
      const info = observedTool(name, input, { projectDir, cwd: cwdValue });
      tool = { name: toolName, paths: info.paths, effects: info.effects };
      suppressible = info.suppressible;
    } else if (name === "Bash" && typeof input.command === "string") {
      const a = analyzeCommand(input.command, { projectDir, cwd: cwdValue, home, env });
      tool = { name: toolName, paths: a.paths, effects: a.effects };
      suppressible = a.suppressible;
    } else if (checked) {
      const filePath = input.file_path ?? input.notebook_path;
      if (typeof filePath === "string" && filePath !== "") tool = { name: toolName, paths: [validPath(filePath) === null ? INVALID : isAbsolute(filePath) ? projectRelative(filePath, projectDir) : filePath], effects: ["write"] };
    }
  } catch {
    tool = { name: toolName };
  }
  const result = log().recordToolResult({ claude: fields, tool, checked, suppressible, data: responseFacts(object.tool_response), humanSession });
  // Session taint: the result of a source taints the session (also if the check before the call did not record it).
  const taintPolicy = resolution.policy.taint;
  if (typeof name === "string" && taintPolicy !== undefined && taintPolicy.mode !== "off") {
    taintPost({ policy: taintPolicy, enterprise: enterprise !== null, rt, env, projectDir, cwd: cwdValue, claude: fields, humanSession, log, deps: deps.taint }, name, input);
  }
  return result.ok ? (result.notice === undefined ? { code: 0 } : { code: 0, message: result.notice }) : { code: 0, message: result.message };
}

/** Value of `--event <name>` in the arguments; `<invalid>` if present but malformed; undefined if absent. */
export function eventFromArgs(argv: readonly string[]): string | undefined {
  const i = argv.indexOf("--event");
  if (i < 0) return undefined;
  const v = argv[i + 1];
  return v !== undefined && /^[A-Za-z]{1,64}$/.test(v) ? v : INVALID;
}

export async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  // Strict UTF-8 like the repo hook: invalid bytes reject (fail closed) instead of being replaced.
  return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
}

/** Best effort: records an `internal_error` decision when the hook failed before it could evaluate anything. */
function logInternalError(env: NodeJS.ProcessEnv, cwd: string, deps: HookDeps): void {
  try {
    const rt = deps.runtime ?? systemRuntime();
    const projectDir = env.CLAUDE_PROJECT_DIR || cwd;
    const signal = detectEnterprise(env, rt.platform, deps.resolve?.exists).active;
    const resolution = resolvePolicy({ env, projectDir, platform: rt.platform, ...deps.resolve });
    loggerFor(rt, env, resolution, signal, deps).recordDecision({
      claude: { session_id: INVALID, tool_use_id: null, agent_id: null, agent_type: null, hook_event: "PreToolUse", permission_mode: null, invalid_fields: ["session_id"] },
      projectDir: null,
      tool: { name: INVALID },
      decision: { outcome: "deny", rule_kind: "internal_error", rule_id: null, reason: "hook failed unexpectedly", human_session: false },
      suppressible: false,
      humanSession: false,
    });
  } catch {
    // Nothing more can be done; the exit code still blocks.
  }
}

/**
 * Entry point logic. Every failure (unreadable stdin, unexpected exceptions) exits with 2: any other
 * non-zero code is a non-blocking error for Claude Code, i.e. it would fail open.
 */
export async function runMain(
  readInput: () => Promise<string>,
  env: NodeJS.ProcessEnv,
  cwd: string,
  writeError: (text: string) => void,
  deps: HookDeps = {},
): Promise<number> {
  let result: HookResult;
  try {
    result = runHook(await readInput(), env, cwd, deps);
  } catch {
    result = { code: BLOCK_EXIT_CODE, message: MSG_UNEXPECTED };
    logInternalError(env, cwd, deps);
  }
  try {
    if (result.message) writeError(`${result.message}\n`);
  } catch {
    // stderr unavailable: the exit code still blocks.
  }
  return result.code;
}

if (isEntryPoint(import.meta.url)) {
  process.exit(await runMain(readStdin, process.env, process.cwd(), (text) => process.stderr.write(text)));
}
