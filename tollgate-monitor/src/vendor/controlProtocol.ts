// Request/response of the control socket between the monitor (client) and `tollgate-control` (helper).
// One JSON object per line, strict key sets, fixed error codes. Shared by both sides (mirrored copies, see README).
// Nothing in a response carries paths, stack traces or text of an exception.
import { checkTarget, LocksError, MAX_UID, REASON_MAX, REASON_MIN, type LockKind } from "./locks.js";

export const PROTOCOL_VERSION = 1;
export const MAX_REQUEST_BYTES = 8192;
export const MAX_RESPONSE_BYTES = 128 * 1024;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const NAME = /^[A-Za-z0-9_.@-]{1,64}$/;
const TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
// Control characters, DEL, C1, line and paragraph separators, bidi controls: never in a reason (it ends up in logs and the SIEM).
const FORBIDDEN_IN_REASON = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/;

export type RequestOp = "lock" | "unlock" | "list";

export interface Claimed {
  uid: number;
  name: string;
}

export type ControlRequest =
  | { op: "lock"; requestId: string; kind: LockKind; target: unknown; expires: string | null; reason: string; claimed: Claimed }
  | { op: "unlock"; requestId: string; lockId: string | null; reason: string; claimed: Claimed } // lockId null: the global lock
  | { op: "list"; requestId: string };

export type ErrorCode = "bad_request" | "forbidden" | "locks_invalid" | "invalid_target" | "invalid_expiry" | "limit" | "not_found" | "replay" | "audit_failed" | "write_failed" | "busy" | "unavailable" | "internal";

export const ERROR_MESSAGES: Readonly<Record<ErrorCode, string>> = {
  bad_request: "The request is not valid.",
  forbidden: "This operation is not permitted for the caller.",
  locks_invalid: "The lock state is not valid; nothing was changed.",
  invalid_target: "The target is not valid.",
  invalid_expiry: "The expiry is not valid.",
  limit: "The lock list is full.",
  not_found: "No such lock.",
  replay: "The request was already processed.",
  audit_failed: "The audit entry could not be written; nothing was changed.",
  write_failed: "The lock state could not be written.",
  busy: "The control helper is busy.",
  unavailable: "The control helper is not available.",
  internal: "The request could not be processed.",
};

export interface LockSummary {
  id: string;
  kind: LockKind;
  target: Record<string, unknown>;
  created: string;
  expires: string | null;
  via: "monitor" | "cli";
}

export type ControlResponse =
  | { v: 1; ok: true; result: "applied" | "exists" | "extended"; lock_id: string; expires: string | null; generation: number; sha256: string }
  | { v: 1; ok: true; result: "list"; generation: number; sha256: string; global: LockSummary | null; locks: LockSummary[] }
  | { v: 1; ok: false; error: ErrorCode };

export class ProtocolError extends Error {
  constructor() {
    super("bad request");
    this.name = "ProtocolError";
  }
}

function bad(): never {
  throw new ProtocolError();
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
}

function keys(v: Record<string, unknown>, expected: readonly string[]): void {
  const own = Object.keys(v);
  if (own.length !== expected.length || !expected.every((k) => Object.hasOwn(v, k))) bad();
}

/** True if `text` is a usable reason (8..500 characters, no control characters, no leading or trailing blanks). */
export function validReason(text: unknown): text is string {
  return typeof text === "string" && text.length >= REASON_MIN && text.length <= REASON_MAX && text === text.trim() && !FORBIDDEN_IN_REASON.test(text);
}

function claimed(v: Record<string, unknown>): Claimed {
  const uid = v.claimed_uid;
  const name = v.claimed_name;
  if (typeof uid !== "number" || !Number.isInteger(uid) || uid < 1 || uid > MAX_UID) bad();
  if (typeof name !== "string" || !NAME.test(name)) bad();
  return { uid, name };
}

/** Strict parser for one request line. Throws `ProtocolError` (no detail). */
export function parseRequest(text: string): ControlRequest {
  if (Buffer.byteLength(text, "utf8") > MAX_REQUEST_BYTES) bad();
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return bad();
  }
  if (!isRecord(raw) || raw.v !== PROTOCOL_VERSION) bad();
  // Same idea as the strict parser of the lock file: JSON.parse keeps the LAST of two equal keys, so a line with a duplicate
  // key (or odd spacing, other escapes) is not what a client writes. Only the compact form of the parsed value is accepted.
  if (JSON.stringify(raw) !== text) bad();
  const requestId = raw.request_id;
  if (typeof requestId !== "string" || !UUID.test(requestId)) bad();
  if (raw.op === "list") {
    keys(raw, ["v", "op", "request_id"]);
    return { op: "list", requestId };
  }
  if (raw.op === "lock") {
    keys(raw, ["v", "op", "request_id", "kind", "target", "expires", "reason", "claimed_uid", "claimed_name"]);
    const kind = raw.kind;
    if (kind !== "user" && kind !== "session" && kind !== "tool" && kind !== "global") bad();
    if (!validReason(raw.reason)) bad();
    const expires = raw.expires;
    if (expires !== null && (typeof expires !== "string" || !TIMESTAMP.test(expires))) bad();
    return { op: "lock", requestId, kind, target: raw.target, expires, reason: raw.reason, claimed: claimed(raw) };
  }
  if (raw.op === "unlock") {
    keys(raw, ["v", "op", "request_id", "lock_id", "reason", "claimed_uid", "claimed_name"]);
    const lockId = raw.lock_id;
    if (lockId !== null && (typeof lockId !== "string" || !UUID.test(lockId))) bad();
    if (!validReason(raw.reason)) bad();
    return { op: "unlock", requestId, lockId, reason: raw.reason, claimed: claimed(raw) };
  }
  return bad();
}

/** The line that a client sends. */
export function serializeRequest(request: ControlRequest): string {
  if (request.op === "list") return `${JSON.stringify({ v: PROTOCOL_VERSION, op: "list", request_id: request.requestId })}\n`;
  const base = { v: PROTOCOL_VERSION, op: request.op, request_id: request.requestId, reason: request.reason, claimed_uid: request.claimed.uid, claimed_name: request.claimed.name };
  if (request.op === "unlock") return `${JSON.stringify({ ...base, lock_id: request.lockId })}\n`;
  return `${JSON.stringify({ ...base, kind: request.kind, target: request.target, expires: request.expires })}\n`;
}

export function serializeResponse(response: ControlResponse): string {
  return `${JSON.stringify(response)}\n`;
}

/** Maps a `LocksError` of the change to the code that goes back to the caller. */
export function errorCodeOf(error: unknown): ErrorCode {
  if (!(error instanceof LocksError)) return "internal";
  if (error.code === "target") return "invalid_target";
  if (error.code === "expiry") return "invalid_expiry";
  if (error.code === "limit") return "limit";
  return "bad_request";
}

/** Validates a target without applying it (the prepare step of the monitor). Throws `ProtocolError`. */
export function checkTargetOrThrow(kind: LockKind, target: unknown): void {
  try {
    checkTarget(kind, target);
  } catch {
    bad();
  }
}

/**
 * Strict parser for a response line (client side). A response that does not fit is `null`; the caller reports `unavailable`.
 */
export function parseResponse(text: string): ControlResponse | null {
  if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(raw) || raw.v !== PROTOCOL_VERSION || typeof raw.ok !== "boolean") return null;
  try {
    if (!raw.ok) {
      keys(raw, ["v", "ok", "error"]);
      const error = raw.error;
      if (typeof error !== "string" || !Object.hasOwn(ERROR_MESSAGES, error)) return null;
      return { v: 1, ok: false, error: error as ErrorCode };
    }
    const sha = raw.sha256;
    const generation = raw.generation;
    if (typeof sha !== "string" || !/^[0-9a-f]{64}$/.test(sha) || typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 0) return null;
    if (raw.result === "list") {
      keys(raw, ["v", "ok", "result", "generation", "sha256", "global", "locks"]);
      if (!Array.isArray(raw.locks) || raw.locks.length > 200) return null;
      const summary = (e: unknown): LockSummary => {
        if (!isRecord(e)) bad();
        keys(e, ["id", "kind", "target", "created", "expires", "via"]);
        if (typeof e.id !== "string" || !UUID.test(e.id) || !isRecord(e.target)) bad();
        const kind = e.kind;
        if (kind !== "user" && kind !== "session" && kind !== "tool" && kind !== "global") bad();
        const via = e.via;
        if (via !== "monitor" && via !== "cli") bad();
        if (typeof e.created !== "string" || !TIMESTAMP.test(e.created) || (e.expires !== null && (typeof e.expires !== "string" || !TIMESTAMP.test(e.expires)))) bad();
        checkTarget(kind, e.target);
        return { id: e.id, kind, target: e.target, created: e.created, expires: e.expires as string | null, via };
      };
      return { v: 1, ok: true, result: "list", generation, sha256: sha, global: raw.global === null ? null : summary(raw.global), locks: raw.locks.map(summary) };
    }
    if (raw.result === "applied" || raw.result === "exists" || raw.result === "extended") {
      keys(raw, ["v", "ok", "result", "lock_id", "expires", "generation", "sha256"]);
      if (typeof raw.lock_id !== "string" || !UUID.test(raw.lock_id)) return null;
      if (raw.expires !== null && (typeof raw.expires !== "string" || !TIMESTAMP.test(raw.expires))) return null;
      return { v: 1, ok: true, result: raw.result, lock_id: raw.lock_id, expires: raw.expires, generation, sha256: sha };
    }
  } catch {
    return null;
  }
  return null;
}
