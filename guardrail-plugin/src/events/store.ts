// Writer of the decision log: lock, checked descriptors, hash chain, rotation, corruption handling.
import { closeSync, constants, fchmodSync, fstatSync, lstatSync, mkdirSync, chmodSync, openSync, readdirSync, readSync, rmSync, unlinkSync, writeSync, type Stats } from "node:fs";
import { join } from "node:path";
import { chainHash } from "../vendor/hashchain.js";
import { fitDraft, serializeEvent } from "./event.js";
import { errnoCode, EventWriteError, NOCTTY, NOFOLLOW, NONBLOCK, readSmallFile, safeLstat, writeFileAtomic } from "./fsutil.js";
import { EVENT_FILE, eventFileName, type Layout } from "./layout.js";
import { acquireLock, systemProcessFacts, type ProcessFacts } from "./lock.js";
import { GENESIS, SCHEMA, type Draft, type EventType, type TollgateEvent } from "./types.js";

export const TAIL_BYTES = 16 * 1024;
export const MAX_FILE_BYTES = 64 * 1024 * 1024;
export const MAX_ALTERNATES = 8;
export const RETENTION_DAYS = 30;
const SESSION_FILE = /^session-([A-Za-z0-9_.:-]{1,128})\.json$/;
const HEX64 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface Meta {
  host: { name: string; os: string };
  user: { name: string; id: string };
  source: { component: string; version: string };
}

export interface StoreDeps {
  clock: () => Date;
  uuid: () => string;
  facts?: ProcessFacts;
  /** Rotation size; default 64 MiB (injectable for tests). */
  maxFileBytes?: number;
  /** User id that must own directories and files; default: the process user. */
  uid?: number | undefined;
}

/** Small per-user state (`.state` in the lock directory). Informational only; the chain itself is read from the files. */
export interface State {
  v: 1;
  logging?: "on" | "off";
  last?: { file: string; ts: string };
  findings_sha256?: string;
}

export interface FlowState {
  window: number;
  count: number;
  suppressed: number;
  paths: Record<string, number>;
}

export interface SessionFile {
  v: 1;
  session_id: string;
  config?: { enabled: boolean; commandDetail: "none" | "redacted"; projectDir: boolean };
  config_sha256?: string | null;
  flood?: FlowState;
}

// --- file checks ----------------------------------------------------------------------------------------------------

export interface FileExpectation {
  uid: number | undefined;
  mode: number;
  gid: number | undefined;
}

type StatLike = Pick<Stats, "isFile" | "nlink" | "uid" | "gid" | "mode">;

/** Reason why an opened event file must not be used, or null. `mode` is compared on the permission bits. */
export function fileProblem(st: StatLike, expect: FileExpectation): string | null {
  if (!st.isFile()) return "not a regular file";
  if (st.nlink !== 1) return "more than one hard link";
  if (expect.uid !== undefined && st.uid !== expect.uid) return "owned by another user";
  if (expect.gid !== undefined && st.gid !== expect.gid) return "wrong group";
  if (expect.uid !== undefined && (st.mode & 0o777) !== expect.mode) return "unexpected mode";
  return null;
}

export type Tail =
  | { status: "empty" }
  | { status: "ok"; chain_id: string; seq: number; hash: string }
  | { status: "corrupt"; chain_id: string | null; seq: number | null; lastValidHash: string | null }
  | { status: "unsafe"; reason: string };

function validRecord(line: string): { chain_id: string; seq: number; hash: string } | null {
  try {
    const r = JSON.parse(line) as Record<string, unknown>;
    if (r === null || typeof r !== "object" || r.schema !== SCHEMA) return null;
    const { chain_id: chainId, seq, hash, prev_hash: prev } = r;
    if (typeof chainId !== "string" || !UUID.test(chainId) || typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 1) return null;
    if (typeof hash !== "string" || !HEX64.test(hash) || typeof prev !== "string" || !HEX64.test(prev)) return null;
    if (chainHash(r) !== hash) return null;
    return { chain_id: chainId, seq, hash };
  } catch {
    return null;
  }
}

/** Evaluates the last (up to 16 KiB) of a file: the last line must be complete and have a valid hash. */
export function evaluateTail(bytes: Buffer, fileSize: number): Tail {
  if (fileSize === 0) return { status: "empty" };
  const text = bytes.toString("utf8");
  const complete = text.endsWith("\n");
  let lines = text.split("\n");
  if (complete) lines.pop(); // the empty piece after the final newline
  if (fileSize > bytes.length) lines = lines.slice(1); // the first piece may start in the middle of a line
  const lastLine = complete ? lines[lines.length - 1] : undefined;
  if (lastLine !== undefined) {
    const ok = validRecord(lastLine);
    if (ok !== null) return { status: "ok", ...ok };
  }
  // Corrupt: link the new chain to the last valid event of the window.
  const completeLines = complete ? lines : lines.slice(0, -1);
  for (let i = completeLines.length - 1; i >= 0; i -= 1) {
    const ok = validRecord(completeLines[i] as string);
    if (ok !== null) return { status: "corrupt", chain_id: ok.chain_id, seq: ok.seq, lastValidHash: ok.hash };
  }
  return { status: "corrupt", chain_id: null, seq: null, lastValidHash: null };
}

function readTailFd(fd: number, size: number): Tail {
  const start = Math.max(0, size - TAIL_BYTES);
  const buffer = Buffer.alloc(size - start);
  let offset = 0;
  while (offset < buffer.length) {
    const n = readSync(fd, buffer, offset, buffer.length - offset, start + offset);
    if (n === 0) break;
    offset += n;
  }
  return evaluateTail(buffer.subarray(0, offset), size);
}

interface OpenFile {
  fd: number;
  size: number;
  ino: number;
  dev: number;
}

type OpenResult = ({ kind: "ok" } & OpenFile) | { kind: "unsafe"; reason: string };

export class LogStore {
  private dirGid: number | undefined;

  constructor(
    readonly layout: Layout,
    readonly meta: Meta,
    private readonly services: StoreDeps,
  ) {}

  get clock(): () => Date {
    return this.services.clock;
  }

  get uuid(): () => string {
    return this.services.uuid;
  }

  /** Expected owner of directories and files. */
  get owner(): number | undefined {
    return this.uid;
  }

  get maxFileBytes(): number {
    return this.services.maxFileBytes ?? MAX_FILE_BYTES;
  }

  private get uid(): number | undefined {
    return this.services.uid ?? (typeof process.getuid === "function" ? process.getuid() : undefined);
  }

  private expectation(): FileExpectation {
    return { uid: this.uid, mode: this.layout.fileMode, gid: this.layout.checkGroup ? this.dirGid : undefined };
  }

  /** A new draft with the fixed fields of this host and user. */
  draft(type: EventType, extra: Partial<Draft> = {}): Draft {
    return { event_id: this.services.uuid(), ts: this.services.clock().toISOString(), type, host: this.meta.host, user: this.meta.user, source: this.meta.source, ...extra };
  }

  private ensureDir(path: string, create: boolean, ownerOnly: boolean): Stats {
    let st = safeLstat(path);
    if (st === null) {
      if (!create) throw new EventWriteError("event directory missing", "dir_missing");
      try {
        mkdirSync(path, { recursive: true, mode: 0o700 });
      } catch {
        throw new EventWriteError("directory cannot be created", "io");
      }
      st = safeLstat(path);
    }
    if (st === null || st.isSymbolicLink() || !st.isDirectory()) throw new EventWriteError("directory is not a real directory", "dir_unsafe");
    if (this.uid !== undefined && ownerOnly) {
      if (st.uid !== this.uid) throw new EventWriteError("directory is owned by another user", "dir_unsafe");
      if (create && (st.mode & 0o077) !== 0) chmodSync(path, 0o700);
    }
    return st;
  }

  private prepareDirs(): void {
    const l = this.layout;
    this.ensureDir(l.lockDir, l.createLockDir, true);
    const events = l.eventsDir === l.lockDir ? safeLstat(l.eventsDir) : this.ensureDir(l.eventsDir, l.createEventsDir, l.kind !== "enterprise-shared");
    this.dirGid = events?.gid;
  }

  /** Runs `fn` under the lock of the log directory. The state file is written back if `fn` changed it. */
  transaction<T>(fn: (tx: Tx) => T): T {
    this.prepareDirs();
    const release = acquireLock(join(this.layout.lockDir, ".lock"), this.services.facts ?? systemProcessFacts);
    try {
      const tx = new Tx(this);
      try {
        return fn(tx);
      } finally {
        tx.flushState();
      }
    } finally {
      release();
    }
  }

  /** Reads the state file without the lock (for the decision whether a lock is needed at all). */
  peekState(): State {
    return this.readState();
  }

  /** @internal */
  readState(): State {
    try {
      const file = readSmallFile(join(this.layout.lockDir, ".state"), 16 * 1024);
      if (file === null) return { v: 1 };
      const parsed = JSON.parse(file.text) as Partial<State>;
      const state: State = { v: 1 };
      if (parsed.logging === "on" || parsed.logging === "off") state.logging = parsed.logging;
      if (parsed.last && typeof parsed.last.file === "string" && typeof parsed.last.ts === "string") state.last = { file: parsed.last.file, ts: parsed.last.ts };
      if (typeof parsed.findings_sha256 === "string" && HEX64.test(parsed.findings_sha256)) state.findings_sha256 = parsed.findings_sha256;
      return state;
    } catch {
      return { v: 1 };
    }
  }

  /** @internal */
  openEventFile(name: string): OpenResult {
    const path = join(this.layout.eventsDir, name);
    const pre = safeLstat(path);
    if (pre?.isSymbolicLink() === true) return { kind: "unsafe", reason: "symbolic link" };
    const base = constants.O_WRONLY | constants.O_APPEND | NOFOLLOW | NONBLOCK | NOCTTY;
    let fd: number;
    try {
      fd = openSync(path, base | constants.O_CREAT | constants.O_EXCL, this.layout.fileMode);
    } catch (error) {
      if (errnoCode(error) !== "EEXIST") throw new EventWriteError("event file cannot be created", errnoCode(error) === "ENOENT" ? "dir_missing" : "io");
      try {
        fd = openSync(path, base);
      } catch (inner) {
        const code = errnoCode(inner);
        if (code === "ELOOP") return { kind: "unsafe", reason: "symbolic link" };
        if (code === "ENXIO" || code === "EISDIR" || code === "EACCES" || code === "EPERM") return { kind: "unsafe", reason: "not writable or not a regular file" };
        throw new EventWriteError("event file cannot be opened", "io");
      }
    }
    try {
      let st = fstatSync(fd);
      let problem = fileProblem(st, this.expectation());
      if (problem === "unexpected mode" && st.isFile() && st.nlink === 1 && st.uid === this.uid) {
        fchmodSync(fd, this.layout.fileMode); // correction only; the mode was given at creation
        st = fstatSync(fd);
        problem = fileProblem(st, this.expectation());
      }
      if (problem !== null) {
        closeSync(fd);
        return { kind: "unsafe", reason: problem };
      }
      return { kind: "ok", fd, size: st.size, ino: st.ino, dev: st.dev };
    } catch (error) {
      closeSync(fd);
      if (error instanceof EventWriteError) throw error;
      throw new EventWriteError("event file cannot be checked", "io");
    }
  }

  /** Reads the tail of an existing event file through a checked read-only descriptor. */
  readTail(name: string, identity?: { ino: number; dev: number }): Tail {
    const path = join(this.layout.eventsDir, name);
    const pre = safeLstat(path);
    if (pre === null) return { status: "unsafe", reason: "missing" };
    if (pre.isSymbolicLink()) return { status: "unsafe", reason: "symbolic link" };
    let fd: number;
    try {
      fd = openSync(path, constants.O_RDONLY | NOFOLLOW | NONBLOCK | NOCTTY);
    } catch {
      return { status: "unsafe", reason: "cannot be opened" };
    }
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) return { status: "unsafe", reason: "not a regular file" };
      if (st.nlink !== 1) return { status: "unsafe", reason: "more than one hard link" };
      if (this.uid !== undefined && st.uid !== this.uid) return { status: "unsafe", reason: "owned by another user" };
      if (identity !== undefined && (st.ino !== identity.ino || st.dev !== identity.dev)) return { status: "unsafe", reason: "file was replaced" };
      return readTailFd(fd, st.size);
    } catch {
      return { status: "unsafe", reason: "cannot be read" };
    } finally {
      closeSync(fd);
    }
  }

  /** Event files of this user, oldest first. If the directory cannot be listed (layout S), only the files in `fallback`. */
  listFiles(fallback: readonly string[]): { name: string; day: string; n: number }[] {
    let names: string[];
    try {
      names = readdirSync(this.layout.eventsDir);
    } catch {
      names = [...fallback];
    }
    const out: { name: string; day: string; n: number }[] = [];
    for (const name of names) {
      const m = EVENT_FILE.exec(name);
      if (m === null || Number(m[1]) !== this.layout.fileUid) continue;
      out.push({ name, day: m[2] as string, n: Number(m[3] ?? 0) });
    }
    return out.sort((a, b) => (a.day === b.day ? a.n - b.n : a.day < b.day ? -1 : 1));
  }

  /** Stand-alone retention: removes expired files with the expected names; never follows links, never leaves the directories. */
  cleanup(now: Date, days = RETENTION_DAYS): number {
    let removed = 0;
    const limit = days * 86_400_000;
    const sweep = (dir: string, pattern: RegExp): void => {
      const dirInfo = safeLstat(dir);
      if (dirInfo === null || !dirInfo.isDirectory() || dirInfo.isSymbolicLink()) return;
      let names: string[];
      try {
        names = readdirSync(dir);
      } catch {
        return;
      }
      for (const name of names) {
        if (!pattern.test(name)) continue;
        try {
          const st = lstatSync(join(dir, name));
          if (st.isFile() && !st.isSymbolicLink() && now.getTime() - st.mtimeMs > limit) {
            unlinkSync(join(dir, name));
            removed += 1;
          }
        } catch {
          // Gone or not removable: not an error.
        }
      }
    };
    sweep(this.layout.eventsDir, EVENT_FILE);
    sweep(this.layout.lockDir, SESSION_FILE);
    return removed;
  }
}

/** Reads a session file without the lock; null if it is missing, invalid or too large. */
export function readSessionFile(lockDir: string, id: string): SessionFile | null {
  if (!SESSION_FILE.test(`session-${id}.json`)) return null;
  try {
    const file = readSmallFile(join(lockDir, `session-${id}.json`), 16 * 1024);
    if (file === null) return null;
    const raw = JSON.parse(file.text) as Partial<SessionFile>;
    if (raw === null || typeof raw !== "object" || raw.v !== 1 || raw.session_id !== id) return null;
    return raw as SessionFile;
  } catch {
    return null;
  }
}

interface Plan {
  file: OpenFile;
  name: string;
  chainId: string;
  seq: number;
  prev: string;
  markers: Draft[];
}

export class Tx {
  private state: State;
  private dirty = false;

  constructor(private readonly store: LogStore) {
    this.state = store.readState();
  }

  get logging(): "on" | "off" | undefined {
    return this.state.logging;
  }

  get findingsHash(): string | undefined {
    return this.state.findings_sha256;
  }

  update(patch: Partial<Pick<State, "logging" | "findings_sha256">>): void {
    this.state = { ...this.state, ...patch };
    this.dirty = true;
  }

  flushState(): void {
    if (!this.dirty) return;
    this.dirty = false;
    try {
      writeFileAtomic(join(this.store.layout.lockDir, ".state"), JSON.stringify(this.state), 0o600);
    } catch {
      // The state is informational; a write failure must not stop logging.
    }
  }

  // --- sessions ---

  private sessionPath(id: string): string | null {
    return SESSION_FILE.test(`session-${id}.json`) ? join(this.store.layout.lockDir, `session-${id}.json`) : null;
  }

  readSession(id: string): SessionFile | null {
    return readSessionFile(this.store.layout.lockDir, id);
  }

  writeSession(file: SessionFile): void {
    const path = this.sessionPath(file.session_id);
    if (path !== null) writeFileAtomic(path, JSON.stringify(file), 0o600);
  }

  removeSession(id: string): void {
    const path = this.sessionPath(id);
    if (path !== null) rmSync(path, { force: true });
  }

  cleanup(now: Date): number {
    return this.store.cleanup(now);
  }

  // --- append ---

  private plan(day: string): Plan {
    const store = this.store;
    const layout = store.layout;
    const uid = layout.fileUid;
    const findings: { name: string; reason: string }[] = [];
    let corruption: Extract<Tail, { status: "corrupt" }> & { file: string } | null = null;
    const files = store.listFiles(this.state.last ? [this.state.last.file] : []);
    let chosen: (OpenFile & { name: string; n: number }) | null = null;
    for (let n = 0; n <= MAX_ALTERNATES; n += 1) {
      const name = eventFileName(uid, day, n);
      const opened = store.openEventFile(name);
      if (opened.kind === "unsafe") {
        findings.push({ name, reason: opened.reason });
        if (!layout.alternateFiles) throw new EventWriteError("event file is unsafe", "file_unsafe");
        continue;
      }
      if (opened.size >= store.maxFileBytes) {
        closeSync(opened.fd);
        continue;
      }
      if (opened.size > 0) {
        const tail = store.readTail(name, { ino: opened.ino, dev: opened.dev });
        if (tail.status === "ok") {
          return this.finishPlan(
            { ...opened, name, n },
            { chainId: tail.chain_id, seq: tail.seq + 1, prev: tail.hash },
            [],
            findings,
          );
        }
        closeSync(opened.fd);
        if (tail.status === "corrupt") corruption = { ...tail, file: name };
        else findings.push({ name, reason: tail.status === "unsafe" ? tail.reason : "unreadable" });
        continue;
      }
      chosen = { ...opened, name, n };
      break;
    }
    if (chosen === null) throw new EventWriteError("no usable event file", "file_unsafe");
    // The chosen file is empty: continue the chain from the newest earlier file.
    if (corruption === null) {
      for (let i = files.length - 1; i >= 0; i -= 1) {
        const f = files[i] as { name: string; day: string; n: number };
        if (f.name === chosen.name || f.day > day || (f.day === day && f.n >= chosen.n)) continue;
        const tail = store.readTail(f.name);
        if (tail.status === "ok") {
          return this.finishPlan(chosen, { chainId: tail.chain_id, seq: tail.seq + 1, prev: tail.hash }, [store.draft("chain_continue", { data: { file: chosen.name } })], findings);
        }
        if (tail.status === "corrupt") {
          corruption = { ...tail, file: f.name };
          break;
        }
      }
    }
    if (corruption !== null) {
      const broken = corruption;
      const markers = [
        store.draft("chain_start", {
          data: { reason: "corruption", broken_file: broken.file, broken_chain_id: broken.chain_id, broken_seq: broken.seq },
        }),
        store.draft("log_error", { data: { reason: "event file tail is not a valid event", file: broken.file } }),
      ];
      return this.finishPlan(chosen, { chainId: store.uuid(), seq: 1, prev: broken.lastValidHash ?? GENESIS }, markers, findings);
    }
    const last = this.state.last;
    const reason = last === undefined ? "new" : store.clock().getTime() - Date.parse(last.ts) > RETENTION_DAYS * 86_400_000 ? "retention" : "missing_previous";
    return this.finishPlan(chosen, { chainId: store.uuid(), seq: 1, prev: GENESIS }, [store.draft("chain_start", { data: { reason } })], findings);
  }

  private finishPlan(
    file: OpenFile & { name: string; n: number },
    pos: { chainId: string; seq: number; prev: string },
    markers: Draft[],
    findings: { name: string; reason: string }[],
  ): Plan {
    const errors = findings.slice(0, 3).map((f) => this.store.draft("log_error", { data: { reason: `unusable event file: ${f.reason}`, file: f.name } }));
    return { file, name: file.name, chainId: pos.chainId, seq: pos.seq, prev: pos.prev, markers: [...markers, ...errors] };
  }

  /** Chains and appends the drafts (with the markers the chain needs) to the current event file. */
  append(drafts: Draft[]): void {
    const first = drafts[0];
    if (first === undefined) return;
    const plan = this.plan(first.ts.slice(0, 10).replace(/-/g, ""));
    try {
      let seq = plan.seq;
      let prev = plan.prev;
      const lines: string[] = [];
      for (const draft of [...plan.markers, ...drafts]) {
        const fitted = fitDraft(draft);
        const body = { schema: SCHEMA, ...fitted, chain_id: plan.chainId, seq, prev_hash: prev };
        const event: TollgateEvent = { ...body, hash: chainHash(body) } as TollgateEvent;
        lines.push(`${serializeEvent(event)}\n`);
        prev = event.hash;
        seq += 1;
      }
      // Check again right before writing; the file must still be the one that was opened.
      const st = fstatSync(plan.file.fd);
      const problem = fileProblem(st, { uid: this.store.owner, mode: this.store.layout.fileMode, gid: undefined });
      if (problem !== null) throw new EventWriteError("event file is unsafe", "file_unsafe");
      const buffer = Buffer.from(lines.join(""), "utf8");
      let offset = 0;
      while (offset < buffer.length) offset += writeSync(plan.file.fd, buffer, offset, buffer.length - offset);
    } catch (error) {
      if (error instanceof EventWriteError) throw error;
      throw new EventWriteError("event file cannot be written", "io");
    } finally {
      closeSync(plan.file.fd);
    }
    if (this.state.last?.file !== plan.name) {
      this.state = { ...this.state, last: { file: plan.name, ts: first.ts } };
      this.dirty = true;
    }
  }
}
