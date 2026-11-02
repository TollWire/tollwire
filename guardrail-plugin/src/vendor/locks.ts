// Admin locks (`tollgate.locks.v1`): strict parser, canonical serializer, evaluation and the pure state change.
// One source for the guardrail hook, the root helper `tollgate-control`, the CLI and the monitor (mirrored copies, see README).
// Node built-ins only; the hash helpers come from the sibling file `hashchain.ts` (in the mirrored directories next to this file).
//
// The schema knows only locks. There is no field that allows anything, so a lock file can only tighten.
import { canonicalJson, sha256Hex } from "./hashchain.js";

export const LOCKS_SCHEMA = "tollgate.locks.v1";
/** `prev_sha256` of generation 0 (and of a first file). */
export const LOCKS_GENESIS = "0".repeat(64);
export const MAX_LOCKS_BYTES = 64 * 1024;
export const MAX_LOCKS = 200;
/** Longest lifetime of a lock with an expiry (the value is an assumption, open to review). */
export const MAX_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;
export const REASON_MIN = 8;
export const REASON_MAX = 500;
export const MAX_UID = 4294967294;

/** A tool name, or `mcp__<server>__*` for every tool of one MCP server (same rule as the enterprise policy). */
export const TOOL_PATTERN = /^(?:[A-Za-z][A-Za-z0-9_.:-]{0,127}|mcp__[A-Za-z0-9.:-]{1,32}(?:_[A-Za-z0-9.:-]{1,32}){0,3}__\*)$/;
export const SESSION_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HOST = /^[A-Za-z0-9._-]{1,253}$/;
const TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

export type LockKind = "user" | "session" | "tool" | "global";
export type LockVia = "monitor" | "cli";
export type LockTarget = { uid: number } | { session_id: string } | { tool: string } | Record<string, never>;

export interface LockEntry {
  id: string;
  kind: LockKind;
  target: LockTarget;
  created: string;
  expires: string | null;
  /**
   * The uid the caller NAMED (`claimed_uid`). Over the socket this is the monitor's own statement and can be false (TM-C1); for
   * the CLI it is the sudo user. Never use it as proof of who locked: that is `peer_uid`.
   */
  by_uid: number;
  via: LockVia;
  event_id: string;
  /**
   * The uid of the peer as the kernel reports it (systemd instance name; 0 for the CLI under sudo). Written by the helper
   * since the red-team finding B1; absent in entries written earlier (the parser accepts both forms, the serializer writes
   * what the entry has, so an old file stays byte-identical until its entries change).
   */
  peer_uid?: number;
}

export interface LocksFile {
  schema: typeof LOCKS_SCHEMA;
  host: string;
  generation: number;
  updated: string;
  prev_sha256: string;
  global: LockEntry | null;
  locks: LockEntry[];
}

export type LocksErrorCode = "too_large" | "not_json" | "not_canonical" | "schema" | "limit" | "expiry" | "target";

/** The message names the rule, never the content. */
export class LocksError extends Error {
  constructor(
    readonly code: LocksErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "LocksError";
  }
}

function fail(code: LocksErrorCode, message: string): never {
  throw new LocksError(code, message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], what: string): void {
  const own = Object.keys(value);
  if (own.length !== keys.length || !keys.every((k) => Object.hasOwn(value, k))) fail("schema", `${what}: unexpected or missing fields`);
}

function uidOf(value: unknown, what: string, min = 1): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > MAX_UID) fail("schema", `${what}: not a valid uid`);
  return value;
}

function timestamp(value: unknown, what: string): string {
  if (typeof value !== "string" || !TIMESTAMP.test(value)) fail("schema", `${what}: not a timestamp`);
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) fail("schema", `${what}: not a timestamp`);
  return value;
}

/** Validates the target of one kind; returns a fresh object with exactly the permitted field. */
export function checkTarget(kind: LockKind, target: unknown): LockTarget {
  if (!isRecord(target)) fail("target", "the target is not an object");
  if (kind === "global") {
    exactKeys(target, [], "target");
    return {};
  }
  if (kind === "user") {
    exactKeys(target, ["uid"], "target");
    const uid = target.uid;
    if (typeof uid !== "number" || !Number.isInteger(uid) || uid < 1 || uid > MAX_UID) fail("target", "the uid is not valid");
    return { uid };
  }
  if (kind === "session") {
    exactKeys(target, ["session_id"], "target");
    const id = target.session_id;
    if (typeof id !== "string" || !SESSION_PATTERN.test(id)) fail("target", "the session id is not valid");
    return { session_id: id };
  }
  if (kind === "tool") {
    exactKeys(target, ["tool"], "target");
    const tool = target.tool;
    if (typeof tool !== "string" || !TOOL_PATTERN.test(tool)) fail("target", "the tool pattern is not valid");
    return { tool };
  }
  return fail("target", "unknown kind");
}

const ENTRY_KEYS = ["id", "kind", "target", "created", "expires", "by_uid", "via", "event_id"] as const;

function checkEntry(raw: unknown, kind: "global" | "list", index: string): LockEntry {
  if (!isRecord(raw)) fail("schema", `${index}: not an object`);
  // `peer_uid` is optional (files of generations written before B1 do not have it); every other key is required.
  exactKeys(raw, Object.hasOwn(raw, "peer_uid") ? [...ENTRY_KEYS, "peer_uid"] : ENTRY_KEYS, index);
  const k = raw.kind;
  if (kind === "global" ? k !== "global" : k !== "user" && k !== "session" && k !== "tool") fail("schema", `${index}: wrong kind`);
  const id = raw.id;
  const eventId = raw.event_id;
  if (typeof id !== "string" || !UUID.test(id) || typeof eventId !== "string" || !UUID.test(eventId)) fail("schema", `${index}: not a UUID`);
  const via = raw.via;
  if (via !== "monitor" && via !== "cli") fail("schema", `${index}: wrong via`);
  const created = timestamp(raw.created, `${index}.created`);
  let expires: string | null = null;
  if (raw.expires !== null) {
    expires = timestamp(raw.expires, `${index}.expires`);
    const span = Date.parse(expires) - Date.parse(created);
    if (span <= 0 || span > MAX_EXPIRY_MS) fail("expiry", `${index}: expiry outside 0..30 days after creation`);
  }
  const target = (() => {
    try {
      return checkTarget(k as LockKind, raw.target);
    } catch {
      return fail("schema", `${index}: invalid target`);
    }
  })();
  const entry: LockEntry = { id, kind: k as LockKind, target, created, expires, by_uid: uidOf(raw.by_uid, `${index}.by_uid`), via, event_id: eventId };
  if (Object.hasOwn(raw, "peer_uid")) entry.peer_uid = uidOf(raw.peer_uid, `${index}.peer_uid`, 0);
  return entry;
}

/** Checks an already parsed object (no size or canonical-form check). Returns a clean copy. */
export function checkLocks(raw: unknown): LocksFile {
  if (!isRecord(raw)) fail("schema", "not an object");
  exactKeys(raw, ["schema", "host", "generation", "updated", "prev_sha256", "global", "locks"], "file");
  if (raw.schema !== LOCKS_SCHEMA) fail("schema", "wrong schema");
  if (typeof raw.host !== "string" || !HOST.test(raw.host)) fail("schema", "host");
  const generation = raw.generation;
  if (typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 0) fail("schema", "generation");
  const updated = timestamp(raw.updated, "updated");
  if (typeof raw.prev_sha256 !== "string" || !HEX64.test(raw.prev_sha256)) fail("schema", "prev_sha256");
  if (!Array.isArray(raw.locks)) fail("schema", "locks");
  if (raw.locks.length > MAX_LOCKS) fail("limit", "more than 200 locks");
  const global = raw.global === null ? null : checkEntry(raw.global, "global", "global");
  const locks = raw.locks.map((e, i) => checkEntry(e, "list", `locks[${i}]`));
  const ids = new Set<string>();
  for (const e of [...(global === null ? [] : [global]), ...locks]) {
    if (ids.has(e.id)) fail("schema", "duplicate id");
    ids.add(e.id);
  }
  return { schema: LOCKS_SCHEMA, host: raw.host, generation, updated, prev_sha256: raw.prev_sha256, global, locks };
}

/** The exact bytes of a locks file: canonical JSON and one newline. */
export function serializeLocks(file: LocksFile): string {
  return `${canonicalJson(file)}\n`;
}

/** SHA-256 over the bytes of the file (the value of `prev_sha256` of the next generation and of `sha256_after`). */
export function locksSha256(text: string): string {
  return sha256Hex(text);
}

/**
 * Strict parser. Accepts only the canonical form that `serializeLocks` writes, so duplicate keys, odd spacing and unknown
 * fields cannot hide anything (the SHA-256 of the file is then well defined as well).
 */
export function parseLocks(text: string): LocksFile {
  if (Buffer.byteLength(text, "utf8") > MAX_LOCKS_BYTES) fail("too_large", "larger than 64 KiB");
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return fail("not_json", "not valid JSON");
  }
  const file = checkLocks(raw);
  if (serializeLocks(file) !== text) fail("not_canonical", "not in canonical form");
  return file;
}

export function emptyLocks(host: string, nowIso: string): LocksFile {
  return { schema: LOCKS_SCHEMA, host, generation: 0, updated: nowIso, prev_sha256: LOCKS_GENESIS, global: null, locks: [] };
}

export function isActive(entry: LockEntry, nowMs: number): boolean {
  return entry.expires === null || Date.parse(entry.expires) > nowMs;
}

/** Folding for the comparison with a lock: only ever widens what a lock hits (case, Unicode compatibility forms). */
function fold(text: string): string {
  return text.normalize("NFKC").toLowerCase();
}

/**
 * True if the lock `pattern` (a tool name or `mcp__<server>__*`) covers `name`. Not the allowlist rule: an allowlist entry must be
 * exact about what it allows, a lock should hit as much as it can. So `mcp__evil__*` also covers `mcp__evil__a__b`, and the
 * comparison ignores case (`bash` locks `Bash`). It can only deny more.
 */
export function lockToolMatches(pattern: string, name: string): boolean {
  const p = fold(pattern);
  const n = fold(name);
  if (!p.endsWith("__*")) return n === p;
  const prefix = p.slice(0, -1);
  return n.startsWith(prefix) && n.length > prefix.length;
}

/** The rule of the enterprise tool allowlist (`uncheckedToolAllowed`): exact, and no `__` in the tool part of a wildcard match. */
export function toolMatches(pattern: string, name: string): boolean {
  if (!pattern.endsWith("__*")) return name === pattern;
  const prefix = pattern.slice(0, -1);
  if (!name.startsWith(prefix)) return false;
  const rest = name.slice(prefix.length);
  return rest.length > 0 && !rest.includes("__");
}

export interface LockCall {
  /** Numeric uid of the process that runs the hook; null if unknown. */
  uid: number | null;
  sessionId: string;
  toolName: string;
}

export interface LockHit {
  kind: LockKind;
  id: string;
}

/**
 * The only evaluation of locks: a hit means deny, `null` means "no lock applies" and leaves the decision of the policy
 * untouched. There is no result that could override a deny of the policy.
 */
export function lockDecision(call: LockCall, file: LocksFile, nowMs: number): LockHit | null {
  if (file.global !== null && isActive(file.global, nowMs)) return { kind: "global", id: file.global.id };
  for (const e of file.locks) {
    if (!isActive(e, nowMs)) continue;
    const t = e.target as Record<string, unknown>;
    if (e.kind === "user" && call.uid !== null && t.uid === call.uid) return { kind: "user", id: e.id };
    if (e.kind === "session" && t.session_id === call.sessionId) return { kind: "session", id: e.id };
    if (e.kind === "tool" && typeof t.tool === "string" && lockToolMatches(t.tool, call.toolName)) return { kind: "tool", id: e.id };
  }
  return null;
}

// ---- state change (helper and CLI) ------------------------------------------------------------------------------------

export interface LockSpec {
  id: string;
  kind: LockKind;
  target: unknown;
  expires: string | null;
  by_uid: number;
  via: LockVia;
  event_id: string;
  /** Kernel-reported uid of the caller (see `LockEntry.peer_uid`); omitted by callers that have none. */
  peer_uid?: number | null;
}

export type Change = { op: "lock"; spec: LockSpec } | { op: "unlock"; lockId: string } | { op: "unlock_global" };

export interface Applied {
  next: LocksFile;
  text: string;
  sha256: string;
  /**
   * `applied`: the file changed; `exists`: an equal active lock exists that lasts at least as long (no new one);
   * `extended`: an equal lock exists but the request lasts longer (unlimited beats any date): same id, new generation;
   * `not_found`: unlock of an unknown id.
   */
  result: "applied" | "exists" | "extended" | "not_found";
  /** Expiry of the lock that was added, found or extended (null: until removed). */
  expires: string | null;
  /** Id of the lock that was added, found or removed. */
  lockId: string | null;
  /** Locks that were past their expiry and left the file with this change. */
  expired: LockEntry[];
}

/** An extended lock describes its last author: the old `peer_uid` must not survive next to a new `by_uid`. */
function withoutPeer(entry: LockEntry): LockEntry {
  const rest = { ...entry };
  delete rest.peer_uid;
  return rest;
}

/**
 * Builds the next generation from `prev` (parsed from `prevText`). Pure: no clock, no file. Expired locks are removed first.
 * Throws `LocksError` for an invalid request or a result over the limits (the caller rejects and keeps the old file).
 * `exists` and `not_found` still advance nothing: the returned `next` equals `prev` then and `text` is `prevText`.
 */
export function applyChange(prev: LocksFile, prevText: string, change: Change, nowIso: string): Applied {
  const nowMs = Date.parse(nowIso);
  const expired = [...(prev.global !== null && !isActive(prev.global, nowMs) ? [prev.global] : []), ...prev.locks.filter((e) => !isActive(e, nowMs))];
  let global = prev.global !== null && isActive(prev.global, nowMs) ? prev.global : null;
  let locks = prev.locks.filter((e) => isActive(e, nowMs));
  let result: Applied["result"] = "applied";
  let lockId: string | null = null;
  let expiresOut: string | null = null;
  const longer = (have: string | null, want: string | null): boolean => have !== null && (want === null || Date.parse(want) > Date.parse(have));

  if (change.op === "lock") {
    const s = change.spec;
    if (!UUID.test(s.id) || !UUID.test(s.event_id)) fail("schema", "request ids");
    if (s.via !== "monitor" && s.via !== "cli") fail("schema", "via");
    uidOf(s.by_uid, "by_uid");
    const peer: { peer_uid?: number } = s.peer_uid === undefined || s.peer_uid === null ? {} : { peer_uid: uidOf(s.peer_uid, "peer_uid", 0) };
    const target = checkTarget(s.kind, s.target);
    let expires: string | null = null;
    if (s.expires !== null) {
      expires = timestamp(s.expires, "expires");
      const span = Date.parse(expires) - nowMs;
      if (span <= 0 || span > MAX_EXPIRY_MS) fail("expiry", "expiry outside 0..30 days from now");
    }
    const entry: LockEntry = { id: s.id, kind: s.kind, target, created: nowIso, expires, by_uid: s.by_uid, via: s.via, event_id: s.event_id, ...peer };
    if (s.kind === "global") {
      if (global !== null) {
        result = "exists";
        lockId = global.id;
        expiresOut = global.expires;
        if (longer(global.expires, expires)) {
          global = { ...withoutPeer(global), created: nowIso, expires, by_uid: s.by_uid, via: s.via, event_id: s.event_id, ...peer };
          result = "extended";
          expiresOut = expires;
        }
      } else global = entry;
    } else {
      const key = canonicalJson(target);
      const same = locks.find((e) => e.kind === s.kind && canonicalJson(e.target) === key);
      if (same !== undefined) {
        result = "exists";
        lockId = same.id;
        expiresOut = same.expires;
        if (longer(same.expires, expires)) {
          // The administrator asked for more than the lock gives: the lock gets the longer time (never shorter), same id.
          locks = locks.map((e) => (e.id === same.id ? { ...withoutPeer(e), created: nowIso, expires, by_uid: s.by_uid, via: s.via, event_id: s.event_id, ...peer } : e));
          result = "extended";
          expiresOut = expires;
        }
      } else {
        locks = [...locks, entry];
        if (locks.length > MAX_LOCKS) fail("limit", "more than 200 locks");
      }
    }
    if (result === "applied") {
      lockId = s.id;
      expiresOut = expires;
    }
  } else if (change.op === "unlock") {
    const found = locks.find((e) => e.id === change.lockId);
    if (found === undefined) result = "not_found";
    else {
      locks = locks.filter((e) => e.id !== change.lockId);
      lockId = found.id;
    }
  } else if (change.op === "unlock_global") {
    if (global === null) result = "not_found";
    else {
      lockId = global.id;
      global = null;
    }
  }
  // Nothing to write: an equal lock exists or the id is unknown, and no lock expired. Otherwise the expired locks go with this generation.
  if ((result === "exists" || result === "not_found") && expired.length === 0) return { next: prev, text: prevText, sha256: locksSha256(prevText), result, lockId, expires: expiresOut, expired };
  const next: LocksFile = { schema: LOCKS_SCHEMA, host: prev.host, generation: prev.generation + 1, updated: nowIso, prev_sha256: locksSha256(prevText), global, locks };
  const text = serializeLocks(next);
  if (Buffer.byteLength(text, "utf8") > MAX_LOCKS_BYTES) fail("limit", "the file would be larger than 64 KiB");
  // The next generation must pass the strict parser (the hook uses the same one).
  parseLocks(text);
  return { next, text, sha256: locksSha256(text), result, lockId, expires: expiresOut, expired };
}
