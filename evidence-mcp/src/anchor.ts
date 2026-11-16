// External anchors for the evidence hash chain.
// An anchor pins {seq, hash, ts, count} of the latest entry. Stored outside the machine (signed tag,
// digest comment), it detects a rewritten or truncated log even if the whole chain was recomputed.
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { z } from "zod";
import {
  appendEntry,
  appendPrivate,
  assertNoSymlinkedDirs,
  assertWritableTarget,
  canonicalJson,
  EvidenceError,
  GENESIS_HASH,
  readEvidenceFile,
  readLog,
  verifyLogRead,
  withLock,
  type AppendOptions,
  type EventInput,
  type EvidenceEntry,
  type Verification,
} from "./log.js";
import { entryHash } from "./vendor/hashchain.js";

const HEX64 = /^[0-9a-f]{64}$/;
/** Upper bound for anchors passed in one verification call. */
export const MAX_ANCHORS = 1_000;

export const AnchorSchema = z.object({
  seq: z.number().int().positive(),
  hash: z.string().regex(HEX64),
  ts: z.string().datetime(),
  count: z.number().int().positive(),
});
export type Anchor = z.infer<typeof AnchorSchema>;

const StoredAnchorSchema = AnchorSchema.extend({
  created_at: z.string().datetime(),
  prev_anchor_hash: z.string().regex(HEX64),
  anchor_hash: z.string().regex(HEX64),
});
export type StoredAnchor = z.infer<typeof StoredAnchorSchema>;

/** Anchor store next to the log: `<log>.anchors.jsonl` (append-only, hash-linked, 0600). */
export function anchorFilePath(logPath: string): string {
  return `${logPath}.anchors.jsonl`;
}

/** Only the four anchor fields, so stored records or extra keys never leak into the external line. */
export function toAnchor(value: Anchor): Anchor {
  return { seq: value.seq, hash: value.hash, ts: value.ts, count: value.count };
}

/** Canonical JSON line of an anchor, ready to be copied into external storage. */
export function anchorLine(anchor: Anchor): string {
  return canonicalJson(toAnchor(anchor));
}

export function anchorRecordHash(record: Omit<StoredAnchor, "anchor_hash">): string {
  const { seq, hash, ts, count, created_at, prev_anchor_hash } = record;
  return entryHash({ seq, hash, ts, count, created_at, prev_anchor_hash });
}

export interface AnchorFileStatus {
  present: boolean;
  valid: boolean;
  /** Number of records whose structure and hash link were verified. */
  count: number;
  /** 1-based record number of the first failure. */
  brokenAt?: number;
  reason?: string;
}

export interface AnchorFileInspection {
  status: AnchorFileStatus;
  /** Verified records only (prefix up to the first failure). */
  records: StoredAnchor[];
}

/**
 * Reads and verifies the anchor file's own hash chain; stops at the first failure instead of throwing. Throws
 * EvidenceError if the anchor file is a symbolic link, not a regular file or has more than one hard link.
 */
export function inspectAnchorFile(logPath: string): AnchorFileInspection {
  const content = readEvidenceFile(anchorFilePath(resolve(logPath)));
  if (content === null) return { status: { present: false, valid: true, count: 0 }, records: [] };
  const records: StoredAnchor[] = [];
  const fail = (reason: string): AnchorFileInspection => ({
    status: { present: true, valid: false, count: records.length, brokenAt: records.length + 1, reason },
    records,
  });
  let prev = GENESIS_HASH;
  let lastSeq = 0;
  for (const line of content.split("\n")) {
    if (line.trim() === "") continue;
    let raw: unknown;
    try {
      raw = JSON.parse(line);
    } catch {
      return fail("invalid JSON");
    }
    const parsed = StoredAnchorSchema.safeParse(raw);
    if (!parsed.success) return fail("invalid anchor record structure");
    const record = parsed.data;
    if (record.prev_anchor_hash !== prev) return fail("anchor chain broken");
    if (anchorRecordHash(record) !== record.anchor_hash) return fail("anchor hash mismatch");
    if (record.count !== record.seq) return fail("inconsistent anchor (count differs from seq)");
    if (record.seq < lastSeq) return fail("anchor regression (seq decreases)");
    records.push(record);
    prev = record.anchor_hash;
    lastSeq = record.seq;
  }
  return { status: { present: true, valid: true, count: records.length }, records };
}

export interface AnchorCheck {
  valid: boolean;
  /** Anchors confirmed against the log. */
  checked: number;
  failedAnchor?: Anchor;
  /** Index of the failed anchor in the list passed in. */
  failedIndex?: number;
  reason?: string;
}

/** Checks anchors against an already verified, gap-free entry list (entries[i].seq === i + 1). */
export function checkAnchors(entries: readonly EvidenceEntry[], anchors: readonly unknown[]): AnchorCheck {
  let checked = 0;
  for (const [index, candidate] of anchors.entries()) {
    const parsed = AnchorSchema.safeParse(candidate);
    if (!parsed.success) return { valid: false, checked, failedIndex: index, reason: "invalid anchor" };
    const anchor = toAnchor(parsed.data);
    const fail = (reason: string): AnchorCheck => ({ valid: false, checked, failedAnchor: anchor, failedIndex: index, reason });
    if (anchor.count !== anchor.seq) return fail("inconsistent anchor (count differs from seq)");
    const entry = entries[anchor.seq - 1];
    if (!entry || entry.seq !== anchor.seq) return fail(`anchored entry seq ${anchor.seq} missing (log truncated or rewritten)`);
    if (entry.hash !== anchor.hash) return fail(`hash at seq ${anchor.seq} differs from anchor (log rewritten)`);
    if (entry.ts !== anchor.ts) return fail(`timestamp at seq ${anchor.seq} differs from anchor`);
    checked += 1;
  }
  return { valid: true, checked };
}

export interface AnchorVerification extends Verification {
  checked: number;
  failedAnchor?: Anchor;
  failedIndex?: number;
}

/**
 * Verifies the chain AND that for every anchor the entry at anchor.seq exists with exactly that hash
 * and timestamp. Detects a recomputed (rewritten) chain and truncation relative to the anchors.
 */
export function verifyAgainstAnchors(path: string, anchors: readonly unknown[]): AnchorVerification {
  const read = readLog(path);
  const chain = verifyLogRead(read);
  if (!chain.valid) return { ...chain, checked: 0, reason: `chain: ${chain.reason ?? "invalid"}` };
  return { ...checkAnchors(read.entries, anchors), count: chain.count };
}

export interface AnchoredLogVerification extends AnchorVerification {
  /** Where the failed anchor came from. */
  failedSource?: "anchor_file" | "input";
  anchorFile: AnchorFileStatus;
  /** Caller-supplied (external) anchors confirmed against the log. */
  externalAnchorsChecked: number;
  /**
   * True only if the result is valid AND at least one external anchor was confirmed. Only external anchors protect
   * against a full rewrite; `valid: true` with `anchored: false` means "consistent with itself", not "unaltered".
   */
  anchored: boolean;
}

/**
 * Verification used by `verify_log`: the chain, the anchor file (if present) and caller-supplied anchors.
 * The anchor file is read BEFORE the log: anchors only reference entries that existed when they were
 * written, so a concurrent append + anchor between both reads cannot cause a false alarm.
 */
export function verifyLogWithAnchors(path: string, external: readonly unknown[] = []): AnchoredLogVerification {
  const log = resolve(path);
  const file = inspectAnchorFile(log);
  const fileAnchors = file.records.map(toAnchor);
  const result = verifyAgainstAnchors(log, [...fileAnchors, ...external]);
  const externalAnchorsChecked = Math.max(0, result.checked - fileAnchors.length);
  const out: AnchoredLogVerification = { ...result, anchorFile: file.status, externalAnchorsChecked, anchored: false };
  if (result.failedIndex !== undefined) out.failedSource = result.failedIndex < fileAnchors.length ? "anchor_file" : "input";
  if (out.valid && !file.status.valid) {
    out.valid = false;
    out.reason = `anchor file: ${file.status.reason ?? "invalid"} at record ${file.status.brokenAt ?? "?"}`;
  }
  out.anchored = out.valid && externalAnchorsChecked > 0;
  return out;
}

export interface AnchorCreation {
  /** False if the latest stored anchor already covers the current head (idempotent). */
  created: boolean;
  anchor: Anchor;
  record: StoredAnchor;
  line: string;
}

export interface CreateAnchorOptions {
  now?: Date;
  lockTimeoutMs?: number;
  /** Trusted root for assertNoSymlinkedDirs; default: the log's own directory. */
  root?: string;
}

/**
 * Anchors the latest entry. Never records an evidence event itself: the `anchor` event documents the EXTERNAL storage and
 * is recorded by the human afterwards (recordEvent); recording it here would move the head past the anchor and make
 * create_anchor non-idempotent. Runs under the log's lock (withLock), so it cannot interleave with appends
 * or other anchor writes. Refuses to anchor an empty or corrupted log, a corrupted anchor file, or a log
 * that contradicts an earlier anchor (fail closed: a rewritten log must never be re-anchored silently).
 */
export function createAnchor(path: string, options: CreateAnchorOptions = {}): AnchorCreation {
  // One resolved path for every check and every I/O step (lock, log, anchor file).
  const log = resolve(path);
  // No log (and possibly no directory for the lock file) means nothing to anchor; never create directories here.
  const root = options.root ?? dirname(log);
  assertNoSymlinkedDirs(log, root); // before the existence check, so nothing is probed through a planted link
  if (!existsSync(log)) throw new EvidenceError("Evidence log is empty; nothing to anchor.");
  return withLock(
    log,
    () => {
      assertNoSymlinkedDirs(log, root);
      const read = readLog(log);
      const chain = verifyLogRead(read);
      if (!chain.valid) {
        throw new EvidenceError(`Evidence log is corrupted at seq ${chain.brokenAt} (${chain.reason}); refusing to anchor.`);
      }
      const last = read.entries.at(-1);
      if (!last) throw new EvidenceError("Evidence log is empty; nothing to anchor.");
      const target = anchorFilePath(log);
      assertWritableTarget(target); // before reading it, so nothing is read or written through a planted link
      const file = inspectAnchorFile(log);
      if (!file.status.valid) {
        throw new EvidenceError(`Anchor file is corrupted at record ${file.status.brokenAt} (${file.status.reason}); refusing to append.`);
      }
      const check = checkAnchors(read.entries, file.records);
      if (!check.valid) throw new EvidenceError(`Evidence log contradicts a stored anchor (${check.reason}); refusing to anchor.`);

      const anchor: Anchor = { seq: last.seq, hash: last.hash, ts: last.ts, count: read.entries.length };
      const line = anchorLine(anchor);
      const previous = file.records.at(-1);
      if (previous && previous.seq === anchor.seq && previous.hash === anchor.hash) {
        return { created: false, anchor, record: previous, line };
      }
      const base = { ...anchor, created_at: (options.now ?? new Date()).toISOString(), prev_anchor_hash: previous?.anchor_hash ?? GENESIS_HASH };
      const record: StoredAnchor = { ...base, anchor_hash: anchorRecordHash(base) };
      const content = readEvidenceFile(target) ?? "";
      const separator = content.length > 0 && !content.endsWith("\n") ? "\n" : "";
      appendPrivate(target, `${separator}${JSON.stringify(record)}\n`);
      return { created: true, anchor, record, line };
    },
    options.lockTimeoutMs,
  );
}

/** Suggested command for the human; tag name and message contain only digits, hex and ISO characters. */
export function signedTagCommand(anchor: Anchor, createdAt: string): string {
  return `git tag -s ${anchorTagName(anchor, createdAt)} -m '${anchorLine(anchor)}'`;
}

/** Suggested tag name, also used as `ref` of the later `anchor` event. */
export function anchorTagName(anchor: Anchor, createdAt: string): string {
  return `evidence-anchor-${createdAt.slice(0, 10)}-seq${anchor.seq}`;
}

/** Where the human stored the anchor outside the machine, e.g. in a signed git tag. */
export const ANCHOR_STORAGE = ["signed_tag", "digest_comment"] as const;

export const AnchorEventDetailsSchema = z.object({
  anchor: AnchorSchema,
  storage: z.enum(ANCHOR_STORAGE),
});

/**
 * Records an evidence event. An `anchor` event documents that the human stored an anchor externally; it must carry
 * `ref` (tag name or comment URL), `details.anchor` and `details.storage`, and the anchor must match the log (checked
 * under the lock, fail closed). The next anchor then covers the event itself.
 */
export function recordEvent(path: string, input: EventInput, now: Date = new Date(), options: Omit<AppendOptions, "precondition"> = {}): EvidenceEntry {
  if (input.type !== "anchor") return appendEntry(path, input, now, options);
  const details = AnchorEventDetailsSchema.safeParse(input.details);
  if (!details.success) {
    throw new EvidenceError("An anchor event needs details.anchor {seq, hash, ts, count} and details.storage (signed_tag or digest_comment).");
  }
  if (!input.ref) throw new EvidenceError("An anchor event needs ref (tag name or comment URL of the external copy).");
  const anchor = toAnchor(details.data.anchor);
  const event: EventInput = { ...input, details: { ...input.details, anchor, storage: details.data.storage } };
  return appendEntry(path, event, now, {
    ...options,
    precondition: (entries) => {
      const check = checkAnchors(entries, [anchor]);
      if (!check.valid) throw new EvidenceError(`Anchor does not match the evidence log (${check.reason}); refusing to record the anchor event.`);
    },
  });
}
