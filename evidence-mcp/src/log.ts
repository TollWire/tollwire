import { randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import { hostname } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { z } from "zod";
import { EVENT_TYPES } from "./controls.js";
import { canonicalJson, entryHash as hashEntry, GENESIS_HASH } from "./vendor/hashchain.js";

// Hash-chain primitives (canonical JSON, SHA-256) live in src/vendor/hashchain.ts; the output is unchanged.
export { canonicalJson, GENESIS_HASH };

const MAX_TEXT = 2_000;
const MAX_DETAILS = 20_000;

/** Patterns that indicate secrets; such content must never enter the evidence log. */
// Prefix-anchored formats only (low false-positive rate); not a replacement for a full secret scanner.
const SECRET_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----/, // PEM/OpenSSH/PKCS#8 and PGP private keys
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{40,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bsk-(ant-)?[A-Za-z0-9_-]{20,}\b/,
  /\bxox[abpr]-[A-Za-z0-9-]{10,}\b/, // Slack tokens (xoxb, xoxp, xoxa, xoxr)
  /\bhooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/, // Slack incoming webhook
  /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b/, // Stripe secret and restricted keys
  /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/, // Google API key (exactly 39 characters)
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, // JWT (JSON header and payload, signed)
  /\bnpm_[A-Za-z0-9]{36}\b/, // npm access token
  /\bglpat-[A-Za-z0-9_-]{20,}/, // GitLab personal access token
];

export const EventInputSchema = z.object({
  type: z.enum(EVENT_TYPES),
  summary: z.string().min(1).max(MAX_TEXT),
  actor: z.string().min(1).max(200),
  ref: z.string().max(500).optional(),
  details: z.record(z.string(), z.unknown()).optional(),
});
export type EventInput = z.infer<typeof EventInputSchema>;

export interface EvidenceEntry extends EventInput {
  seq: number;
  ts: string;
  prev_hash: string;
  hash: string;
}

export function containsSecret(text: string): boolean {
  return SECRET_PATTERNS.some((p) => p.test(text));
}

export function entryHash(entry: Omit<EvidenceEntry, "hash">): string {
  return hashEntry(entry);
}

const StoredEntrySchema = EventInputSchema.extend({
  seq: z.number().int().positive(),
  ts: z.string().datetime(),
  prev_hash: z.string().regex(/^[0-9a-f]{64}$/),
  hash: z.string().regex(/^[0-9a-f]{64}$/),
});

export interface LogRead {
  entries: EvidenceEntry[];
  /** Line number (1-based) and reason of the first unreadable record, if any. */
  malformed?: { line: number; reason: string };
}

/**
 * Reads the log; stops at the first malformed record and reports it instead of throwing. Throws EvidenceError if the
 * log is a symbolic link, not a regular file or has more than one hard link (readEvidenceFile).
 */
export function readLog(path: string): LogRead {
  const content = readEvidenceFile(resolve(path));
  return content === null ? { entries: [] } : parseLog(content);
}

/** Parses log content; stops at the first malformed record and reports it instead of throwing. */
export function parseLog(content: string): LogRead {
  const entries: EvidenceEntry[] = [];
  const lines = content.split("\n");
  for (const [index, line] of lines.entries()) {
    if (line.trim() === "") continue;
    let raw: unknown;
    try {
      raw = JSON.parse(line);
    } catch {
      return { entries, malformed: { line: index + 1, reason: "invalid JSON" } };
    }
    const parsed = StoredEntrySchema.safeParse(raw);
    if (!parsed.success) return { entries, malformed: { line: index + 1, reason: "invalid record structure" } };
    entries.push(parsed.data as EvidenceEntry);
  }
  return { entries };
}

export function readEntries(path: string): EvidenceEntry[] {
  return readLog(path).entries;
}

/** Verifies the chain and reports unreadable records as integrity failures. */
export function verifyLog(path: string): Verification {
  return verifyLogRead(readLog(path));
}

/** Same as verifyLog for an already read log, so callers can verify and use one consistent snapshot. */
export function verifyLogRead({ entries, malformed }: LogRead): Verification {
  if (malformed) {
    return { valid: false, count: entries.length, brokenAt: entries.length + 1, reason: `${malformed.reason} at line ${malformed.line}` };
  }
  return verifyEntries(entries);
}

const LOCK_TIMEOUT_MS = 5_000;
/** Only for lock files without a readable owner (crash between create and write). */
const LOCK_UNOWNED_STALE_MS = 30_000;

interface LockOwner {
  pid: number;
  host: string;
  token: string;
}

function readLockOwner(lock: string): LockOwner | null {
  try {
    const owner = JSON.parse(readFileSync(lock, "utf8")) as Partial<LockOwner>;
    if (typeof owner.pid === "number" && typeof owner.host === "string" && typeof owner.token === "string") {
      return owner as LockOwner;
    }
  } catch {
    // Missing, empty or partially written lock file.
  }
  return null;
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * A lock is stale only if its owner provably no longer runs: same host and dead PID, or no
 * readable owner for LOCK_UNOWNED_STALE_MS. A live writer is never considered stale, however long
 * it takes; locks from another host are never broken automatically (fail closed).
 */
function isStale(lock: string, owner: LockOwner | null): boolean {
  if (owner) return owner.host === hostname() && !processAlive(owner.pid);
  return Date.now() - statSync(lock).mtimeMs > LOCK_UNOWNED_STALE_MS;
}

/**
 * Breaks a stale lock without racing other waiters: the lock is moved aside atomically and only
 * deleted if it is still the one judged stale; otherwise it is restored.
 */
function breakStaleLock(lock: string, stale: LockOwner | null): void {
  const aside = `${lock}.${randomUUID()}.stale`;
  try {
    renameSync(lock, aside);
  } catch {
    return; // Already removed or replaced by another waiter.
  }
  const moved = readLockOwner(aside);
  if ((moved?.token ?? null) !== (stale?.token ?? null)) {
    try {
      linkSync(aside, lock); // Restore a lock that was taken over meanwhile; fails if a new one exists.
    } catch {
      // A newer lock exists; the moved one is no longer authoritative.
    }
  }
  rmSync(aside, { force: true });
}

/** Cross-process lock via an exclusive lock file carrying an ownership token (pid, host, token). */
export function withLock<T>(path: string, fn: () => T, timeoutMs = LOCK_TIMEOUT_MS): T {
  const lock = `${path}.lock`;
  const self: LockOwner = { pid: process.pid, host: hostname(), token: randomUUID() };
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const fd = openSync(lock, "wx", 0o600);
      try {
        writeSync(fd, JSON.stringify(self));
      } finally {
        closeSync(fd);
      }
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      try {
        const owner = readLockOwner(lock);
        if (isStale(lock, owner)) breakStaleLock(lock, owner);
      } catch {
        // Lock vanished between checks; retry.
      }
      if (Date.now() > deadline) throw new EvidenceError(`Evidence log is locked by another process (${basename(lock)}).`);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
    }
  }
  try {
    return fn();
  } finally {
    // Release only our own lock; never remove a lock another process holds.
    if (readLockOwner(lock)?.token === self.token) rmSync(lock, { force: true });
  }
}

export class EvidenceError extends Error {}

/**
 * Refuses an evidence file with more than one hard link: a planted hard link (e.g. to a file elsewhere owned by the same
 * user) would make appends and the 0600 chmod land in that other file, and reads would report its content.
 */
function assertSingleLink(info: { nlink: number }): void {
  if (info.nlink > 1) throw new EvidenceError("Evidence file has multiple hard links; refusing to use it.");
}

/**
 * Refuses a write target that is a symbolic link, not a regular file or has more than one hard link, so a pre-planted
 * link cannot redirect evidence writes. Call it before reading the target, too, so nothing is read through such a link.
 */
export function assertWritableTarget(path: string): void {
  let info;
  try {
    info = lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (info.isSymbolicLink()) throw new EvidenceError("Evidence file is a symbolic link; refusing to write.");
  if (!info.isFile()) throw new EvidenceError("Evidence file is not a regular file; refusing to write.");
  assertSingleLink(info);
}

/**
 * Reads an evidence file (log or anchor file) through one descriptor that is checked before reading: no symbolic link at
 * the final component (lstat plus O_NOFOLLOW where available), regular file, a single hard link. Check and read thus
 * refer to the same file. Returns null if the file does not exist.
 */
export function readEvidenceFile(path: string): string | null {
  let info;
  try {
    info = lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
  if (info.isSymbolicLink()) throw new EvidenceError("Evidence file is a symbolic link; refusing to read.");
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);
  let fd: number;
  try {
    fd = openSync(path, flags);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    if (code === "ELOOP") throw new EvidenceError("Evidence file is a symbolic link; refusing to read.");
    throw error;
  }
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile()) throw new EvidenceError("Evidence file is not a regular file; refusing to read.");
    assertSingleLink(opened);
    return readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
}

/**
 * Appends to an evidence file (log or anchor file) without following a symlink at the final path component
 * (lstat check plus O_NOFOLLOW where the platform has it) and restricts it to owner read/write via the opened
 * descriptor (POSIX), so permissions are never changed on a link target.
 */
export function appendPrivate(path: string, data: string): void {
  assertWritableTarget(path);
  const flags = constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | (constants.O_NOFOLLOW ?? 0);
  let fd: number;
  try {
    fd = openSync(path, flags, 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new EvidenceError("Evidence file is a symbolic link; refusing to write.");
    throw error;
  }
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile()) throw new EvidenceError("Evidence file is not a regular file; refusing to write.");
    assertSingleLink(opened); // on the opened descriptor, before any chmod or write
    if (process.platform !== "win32") {
      if ((fstatSync(fd).mode & 0o077) !== 0) fchmodSync(fd, 0o600);
      if ((fstatSync(fd).mode & 0o077) !== 0) throw new EvidenceError("Evidence file permissions cannot be restricted to the owner.");
    }
    const buffer = Buffer.from(data, "utf8");
    let offset = 0;
    while (offset < buffer.length) offset += writeSync(fd, buffer, offset, buffer.length - offset);
  } finally {
    closeSync(fd);
  }
}

/**
 * Trusted root of a log location: the project directory if the log lies inside it, else the log's own directory
 * (an explicitly configured location outside the project is the operator's choice and is not walked).
 */
export function resolveLogRoot(logPath: string, projectDir: string): string {
  const logDir = dirname(resolve(logPath));
  const project = resolve(projectDir);
  return isInside(project, logDir) ? project : logDir;
}

function isInside(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/**
 * Refuses a log location whose directories between `root` (exclusive) and the log file are symbolic links or not
 * directories, so a planted link (e.g. `.tollgate/evidence -> elsewhere`) cannot redirect evidence reads and writes.
 * The root itself is trusted (it may legitimately be reached via a link). Missing components end the walk; they are
 * created by the writer and checked again under the lock. A log outside `root` is refused.
 */
export function assertNoSymlinkedDirs(path: string, root: string): void {
  const base = resolve(root);
  const logDir = dirname(resolve(path));
  if (!isInside(base, logDir)) throw new EvidenceError("Evidence log lies outside its configured root; refusing to use it.");
  let current = base;
  for (const part of relative(base, logDir).split(sep).filter(Boolean)) {
    current = join(current, part);
    let info;
    try {
      info = lstatSync(current);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    if (info.isSymbolicLink()) throw new EvidenceError("Evidence directory is a symbolic link; refusing to use it.");
    if (!info.isDirectory()) throw new EvidenceError("Evidence directory path contains a non-directory; refusing to use it.");
  }
}

export interface AppendOptions {
  /** Trusted root for assertNoSymlinkedDirs; default: the log's own directory (nothing below it to walk). */
  root?: string;
  /** Runs under the lock on the verified entries before the append; throw to refuse the event. */
  precondition?: (entries: readonly EvidenceEntry[]) => void;
}

export function appendEntry(path: string, input: EventInput, now: Date = new Date(), options: AppendOptions = {}): EvidenceEntry {
  const parsed = EventInputSchema.parse(input);
  const serialized = canonicalJson(parsed);
  if (serialized.length > MAX_DETAILS) throw new EvidenceError("Event is too large.");
  if (containsSecret(serialized)) throw new EvidenceError("Event appears to contain a secret; refusing to record it.");
  // One resolved path for every check and every I/O step (lock, read, append), independent of later cwd changes.
  const file = resolve(path);
  const root = options.root ?? dirname(file);
  assertNoSymlinkedDirs(file, root); // before mkdir, so no directory is created through a planted link
  mkdirSync(dirname(file), { recursive: true });
  assertNoSymlinkedDirs(file, root); // before the lock file is created
  return withLock(file, () => {
    assertNoSymlinkedDirs(file, root); // a component may have been swapped while waiting for the lock
    assertWritableTarget(file);
    // One snapshot for verification, precondition and the trailing-newline check.
    const content = readEvidenceFile(file) ?? "";
    const read = parseLog(content);
    const verification = verifyLogRead(read);
    if (!verification.valid) {
      throw new EvidenceError(`Evidence log is corrupted at seq ${verification.brokenAt} (${verification.reason}); refusing to append.`);
    }
    const existing = read.entries;
    options.precondition?.(existing);
    const last = existing.at(-1);
    const base = { ...parsed, seq: (last?.seq ?? 0) + 1, ts: now.toISOString(), prev_hash: last?.hash ?? GENESIS_HASH };
    const entry: EvidenceEntry = { ...base, hash: entryHash(base) };
    const separator = content.length > 0 && !content.endsWith("\n") ? "\n" : "";
    appendPrivate(file, `${separator}${JSON.stringify(entry)}\n`);
    return entry;
  });
}

export interface Verification {
  valid: boolean;
  count: number;
  brokenAt?: number;
  reason?: string;
}

export function verifyEntries(entries: EvidenceEntry[]): Verification {
  let prev = GENESIS_HASH;
  for (const [index, entry] of entries.entries()) {
    const { hash, ...rest } = entry;
    if (entry.seq !== index + 1) return { valid: false, count: entries.length, brokenAt: entry.seq, reason: "sequence gap" };
    if (entry.prev_hash !== prev) return { valid: false, count: entries.length, brokenAt: entry.seq, reason: "chain broken" };
    if (entryHash(rest) !== hash) return { valid: false, count: entries.length, brokenAt: entry.seq, reason: "hash mismatch" };
    prev = hash;
  }
  return { valid: true, count: entries.length };
}
