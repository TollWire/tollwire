// Admin locks in the hook. Called only with the enterprise signal on Linux and `control.enabled` in the
// enterprise policy. The lock file is root-owned state written by `tollgate-control`; here it is only read.
//  - a hit is a deny (`admin_lock`) for every tool, checked or not; there is no result that allows something;
//  - an unusable file (missing, unsafe, too large, invalid) is a deny for every tool (`lock_error`): an emergency stop must
//    not fail because its file cannot be read. Only root can cause that, because owner and parents must be root.
import { formatBlock } from "./blockMessage.js";
import { readTrustedFile } from "./enterprise.js";
import { lockDecision, parseLocks, type LockKind, type LocksFile } from "./vendor/locks.js";

export interface LockCheckInput {
  path: string;
  /** Required owner of the file and of every directory above it (root = 0). */
  ownerUid: number;
  stopAt?: string | undefined;
  uid: number | null;
  sessionId: string;
  toolName: string;
  nowMs: number;
}

/** What goes into `policy.layers` of the event: `{level: "locks", sha256, generation}`. */
export interface LockLayer {
  level: "locks";
  sha256: string;
  generation?: number;
}

export interface LockDeny {
  kind: "admin_lock" | "lock_error";
  /** Id of the lock; null for `lock_error`. */
  ruleId: string | null;
  /** For the decision log. No administrator text exists in the file, so nothing sensitive can be in it. */
  reason: string;
  /** For the agent: no reason of the administrator, no detail of the failure. */
  message: string;
}

export interface LockCheck {
  layer: LockLayer | null;
  deny: LockDeny | null;
}

const ERROR_MESSAGE = formatBlock({ kind: "lock_error", ruleId: null, detail: "the administrator lock state is unusable, so all tool calls are blocked (fail closed)." });

export function checkAdminLocks(input: LockCheckInput): LockCheck {
  const trusted = readTrustedFile(input.path, { ownerUid: input.ownerUid, stopAt: input.stopAt, what: "lock file" });
  if (!trusted.ok) return { layer: null, deny: { kind: "lock_error", ruleId: null, reason: `administrator lock state is unusable: ${trusted.reason}.`, message: ERROR_MESSAGE } };
  let file: LocksFile;
  try {
    file = parseLocks(trusted.text);
  } catch {
    return { layer: { level: "locks", sha256: trusted.sha256 }, deny: { kind: "lock_error", ruleId: null, reason: "administrator lock state is unusable: the lock file is invalid.", message: ERROR_MESSAGE } };
  }
  const layer: LockLayer = { level: "locks", sha256: trusted.sha256, generation: file.generation };
  const hit = lockDecision({ uid: input.uid, sessionId: input.sessionId, toolName: input.toolName }, file, input.nowMs);
  if (hit === null) return { layer, deny: null };
  const label: Record<LockKind, string> = { user: "user", session: "session", tool: "tool", global: "emergency stop" };
  return {
    layer,
    deny: {
      kind: "admin_lock",
      ruleId: hit.id,
      reason: `blocked by an administrator lock (${label[hit.kind]}).`,
      message: formatBlock({ kind: "admin_lock", ruleId: hit.id, detail: `blocked by an administrator lock (${label[hit.kind]}).` }),
    },
  };
}
