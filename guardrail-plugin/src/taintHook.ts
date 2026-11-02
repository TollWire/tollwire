// Session taint in the hook: the check before a tool call, the marking after an allowed or finished call and the
// session start. Event data is flat (scalars only) so that SIEMs that cannot decode arrays of objects (Wazuh) can match it.
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { ClaudeFields } from "./events/types.js";
import type { EventLogger } from "./events/logger.js";
import { standaloneLayout, userProtectedDirs } from "./events/layout.js";
import { locationEnv, type Runtime } from "./events/runtime.js";
import { readAdminRelease, restrictionOf, sourceOf, TAINT_RELEASE_DIR, taintStateDir, TaintStore, type ClassifyContext, type Restriction, type TaintSource } from "./taint.js";
import type { TaintPolicy } from "./taintPolicy.js";

/** Fixed wrapper of the enterprise installation (installed by the installer patch). */
export const ENTERPRISE_WRAPPER = "/opt/tollgate/sbin/tollgate-taint";

export interface TaintDeps {
  /** Directory of the state files (default: see `taintDirFor`). */
  dir?: string;
  /** Directory of the enterprise release files (default `/var/lib/tollgate/taint/releases`). */
  releaseDir?: string;
  /** Owner of the release files and their parents (default root). */
  ownerUid?: number;
  stopAt?: string | undefined;
}

export interface TaintContext {
  policy: TaintPolicy;
  enterprise: boolean;
  rt: Runtime;
  env: NodeJS.ProcessEnv;
  projectDir: string;
  cwd?: string | undefined;
  claude: ClaudeFields;
  humanSession: boolean;
  log: () => EventLogger;
  deps?: TaintDeps | undefined;
}

export interface TaintDeny {
  ruleId: string;
  /** For the decision log: no paths, no session id. */
  reason: string;
  /** For the human only (block message, not logged): how to release, with the full path of the command. */
  hint: string;
}

export interface TaintPre {
  /** The call is restricted and the session is tainted (a block in `enforce`, a `taint_would_block` record in `observe`), or null. */
  deny: TaintDeny | null;
  /** The session is tainted (state read for this call), or unknown (null: the state was not needed). */
  tainted: boolean | null;
  /** The result of this call would taint the session. */
  source: TaintSource | null;
}

/** Enterprise: fixed `<home>/.local/state/tollgate/taint` (not from the environment); stand-alone: `<private log dir>/taint`. */
export function taintDirFor(rt: Runtime, env: NodeJS.ProcessEnv, enterprise: boolean): string {
  if (enterprise) return join(rt.home, ".local", "state", "tollgate", "taint");
  return taintStateDir(standaloneLayout(locationEnv(env), rt.platform, rt.home, rt.uid).lockDir);
}

function classifyContext(ctx: TaintContext, dir: string | null): ClassifyContext {
  const home = ctx.enterprise ? ctx.rt.home : (ctx.env.HOME ?? ctx.rt.home);
  let user: string[] = [];
  try {
    user = userProtectedDirs(locationEnv(ctx.env), ctx.rt.platform, ctx.rt.home, ctx.rt.uid);
  } catch {
    user = [];
  }
  return { projectDir: ctx.projectDir, cwd: ctx.cwd, home, secretDirs: [...(dir === null ? [] : [dir]), ...user] };
}

function storeOf(ctx: TaintContext, dir: string): TaintStore {
  return new TaintStore({ dir, uid: ctx.rt.uid, clock: ctx.rt.clock, uuid: ctx.rt.uuid });
}

function nowIso(ctx: TaintContext): string {
  return ctx.rt.clock().toISOString();
}

function record(ctx: TaintContext, type: "taint_set" | "taint_release" | "taint_would_block", data: Record<string, unknown>): void {
  // Best effort: the decision event of the call carries the block itself; a failed write is reported there.
  ctx.log().recordTaint({ type, claude: ctx.claude, data: { mode: ctx.policy.mode, ...data }, humanSession: ctx.humanSession });
}

/**
 * Current taint of the session. A missing or bad state is replaced by a tainted one (logged), so that a human can release a
 * defined state. In enterprise mode with `release: admin` a matching root-owned release is consumed here. Never throws:
 * every failure counts as tainted.
 */
function currentTaint(ctx: TaintContext, dir: string): boolean {
  const sid = ctx.claude.session_id;
  try {
    const store = storeOf(ctx, dir);
    const check = store.check(sid);
    if (!check.ok) {
      if (check.problem === "session_invalid") return true;
      const kind = check.problem === "state_invalid" ? "state_invalid" : "state_missing";
      const t = store.taint(sid, { kind, name: check.problem, at: nowIso(ctx) });
      record(ctx, "taint_set", { source_kind: kind, source_name: check.problem, previous: check.problem, invalid_sha256: check.sha256, epoch: t.state.epoch, taint_seq: t.state.taint_seq });
      return true;
    }
    if (!check.tainted) return false;
    const adminRelease = ctx.enterprise && ctx.policy.release === "admin";
    if (adminRelease && ctx.rt.uid !== undefined) {
      const release = readAdminRelease(ctx.rt.uid, sid, { dir: ctx.deps?.releaseDir ?? TAINT_RELEASE_DIR, ownerUid: ctx.deps?.ownerUid ?? 0, stopAt: ctx.deps?.stopAt });
      if (release !== null && release.epoch === check.state.epoch && release.taint_seq === check.state.taint_seq) {
        const next = store.release(sid, release.epoch, release.taint_seq, "admin", release.id);
        record(ctx, "taint_release", { via: "admin", by_uid: release.by_uid, release_id: release.id, epoch: next.epoch, taint_seq: next.taint_seq });
        return false;
      }
    }
    return true;
  } catch {
    return true;
  }
}

/**
 * Before a tool call. Reads the state only if the call is restricted in a tainted session (or a human session writes, which a
 * tainted session must not do). Throws only if the classification itself fails; the caller then fails closed in `enforce`.
 */
export function taintPre(ctx: TaintContext, tool: string, input: Record<string, unknown>, checkedTool: boolean): TaintPre {
  // A broken runtime (no home directory) must not touch calls that are neither restricted nor sources: the directory is
  // only needed for those, and without it the session counts as tainted.
  let dir: string | null;
  try {
    dir = ctx.deps?.dir ?? taintDirFor(ctx.rt, ctx.env, ctx.enterprise);
  } catch {
    dir = null;
  }
  const cc = classifyContext(ctx, dir);
  const restriction: Restriction | null = restrictionOf(tool, input, ctx.policy, cc);
  const source = sourceOf(tool, input, ctx.policy, cc);
  // A human session keeps its exception for protected paths only while the session is clean: the state is read for every
  // checked tool (Bash included), not only for the write tools.
  if (restriction === null && !(ctx.humanSession && checkedTool)) return { deny: null, tainted: null, source };
  const tainted = inheritedTaint(ctx) || dir === null || currentTaint(ctx, dir);
  if (!tainted || restriction === null) return { deny: null, tainted, source };
  const ruleId = `taint.${restriction.category}`;
  const reason = `the session is tainted (it read untrusted content): ${restriction.reason}.`;
  return { deny: { ruleId, reason, hint: releaseHint(ctx) }, tainted, source };
}

/** Mode `observe`: records the block that `enforce` would have made. Never throws. */
export function taintWouldBlock(ctx: TaintContext, tool: string, deny: TaintDeny): void {
  try {
    record(ctx, "taint_would_block", { rule_id: deny.ruleId, category: deny.ruleId.slice("taint.".length), tool: tool.slice(0, 128) });
  } catch {
    // observe mode never blocks
  }
}

/** Marks the session tainted after an allowed call (`pre`) or a finished one (`post`). Returns false if it could not be recorded. */
export function taintMark(ctx: TaintContext, source: TaintSource): boolean {
  const dir = ctx.deps?.dir ?? taintDirFor(ctx.rt, ctx.env, ctx.enterprise);
  try {
    const t = storeOf(ctx, dir).taint(ctx.claude.session_id, { kind: source.kind, name: source.name, at: nowIso(ctx) });
    if (t.transition) record(ctx, "taint_set", { source_kind: source.kind, source_name: source.name, previous: t.previous, epoch: t.state.epoch, taint_seq: t.state.taint_seq });
    return true;
  } catch {
    return false;
  }
}

/** PostToolUse: the classification of the finished call; marks if it is a source. Never throws. */
export function taintPost(ctx: TaintContext, tool: string, input: Record<string, unknown>): void {
  try {
    const dir = ctx.deps?.dir ?? taintDirFor(ctx.rt, ctx.env, ctx.enterprise);
    const source = sourceOf(tool, input, ctx.policy, classifyContext(ctx, dir));
    if (source !== null) taintMark(ctx, source);
  } catch {
    // a result event never blocks
  }
}

/**
 * Taint inherited through the environment: `TOLLGATE_TAINTED=1` in the hook's environment marks the session tainted for its whole
 * life (tightening only; a release does not lift it). A launcher (sandbox runner, wrapper) sets it for an agent started from a
 * tainted context. The hook manifest must pass the variable through; see the design notes.
 */
export function inheritedTaint(ctx: Pick<TaintContext, "env">): boolean {
  return ctx.env.TOLLGATE_TAINTED === "1";
}

/** How a human lifts the taint: the command, with the full path of this installation as a fallback. */
export function releaseHint(ctx: TaintContext): string {
  const sid = ctx.claude.session_id;
  if (inheritedTaint(ctx)) return "The taint was inherited from the environment (TOLLGATE_TAINTED=1) and lasts for the whole session.";
  if (ctx.enterprise && ctx.policy.release === "admin") {
    // The fixed wrapper exists only once the installer patch is applied; otherwise the program itself is named.
    const command = existsSync(ENTERPRISE_WRAPPER) ? ENTERPRISE_WRAPPER : `/opt/tollgate/node/bin/node ${join(ctx.rt.pluginRoot, "dist", "taintCli.js")}`;
    return `A human releases it: ask your administrator to run 'sudo ${command} admin-release --uid ${ctx.rt.uid ?? "<uid>"} --session ${sid}'.`;
  }
  return `A human releases it in their own terminal: 'tollgate-taint release --session ${sid}' (or 'node ${join(ctx.rt.pluginRoot, "dist", "taintCli.js")} release --session ${sid}').`;
}

/** SessionStart: key and state of the session (`startup`/`clear`: clean; otherwise a missing state becomes tainted). Never throws. */
export function taintSessionStart(ctx: TaintContext, source: unknown): void {
  try {
    const dir = ctx.deps?.dir ?? taintDirFor(ctx.rt, ctx.env, ctx.enterprise);
    const fresh = source === "startup" || source === "clear";
    const store = storeOf(ctx, dir);
    const r = store.init(ctx.claude.session_id, fresh);
    if (inheritedTaint(ctx)) {
      const t = store.taint(ctx.claude.session_id, { kind: "inherited", name: "TOLLGATE_TAINTED", at: nowIso(ctx) });
      if (t.transition) record(ctx, "taint_set", { source_kind: "inherited", source_name: "TOLLGATE_TAINTED", previous: t.previous, epoch: t.state.epoch, taint_seq: t.state.taint_seq });
      return;
    }
    if (r.outcome === "tainted_missing" && r.check.ok) {
      record(ctx, "taint_set", { source_kind: "state_missing", source_name: "resume", previous: "state_missing", epoch: r.check.state.epoch, taint_seq: r.check.state.taint_seq });
    }
  } catch {
    // session events never block; a missing state counts as tainted later
  }
}
