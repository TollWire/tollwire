#!/usr/bin/env node
// `tollgate-taint`: status and release of the session taint. The release is for a human in a real terminal, never
// for the agent: it needs a terminal on stdin and stdout, refuses inside a Claude Code tool call (`CLAUDECODE`), shows a random
// code that has to be typed back, and the hook blocks the command for the agent in a tainted session.
//
//   tollgate-taint status [--session ID]                     state of the own sessions
//   tollgate-taint release --session ID                      stand-alone (or enterprise with `taint.release: user`)
//   sudo tollgate-taint admin-release --uid N --session ID   enterprise: root writes a release file that the hook consumes
import { randomBytes, randomInt, randomUUID } from "node:crypto";
import { chmodSync, closeSync, constants, fchmodSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, renameSync, rmSync, writeSync } from "node:fs";
import { join } from "node:path";
import { detectEnterprise, resolvePolicy } from "./enterprise.js";
import { isEntryPoint } from "./entry.js";
import type { EventLogger } from "./events/logger.js";
import { systemRuntime, type Runtime } from "./events/runtime.js";
import { sanitize } from "./events/sanitize.js";
import { loggerFor } from "./hook.js";
import { releaseFileName, serializeTaintRelease, TAINT_RELEASE_DIR, TAINT_RELEASE_SCHEMA, TaintStore, type TaintState } from "./taint.js";
import { taintDirFor } from "./taintHook.js";
import { SESSION_PATTERN } from "./vendor/locks.js";

const USAGE =
  "Usage: tollgate-taint status [--session ID]\n" +
  "       tollgate-taint release --session ID\n" +
  "       sudo tollgate-taint admin-release --uid UID --session ID\n" +
  "  release and admin-release need a terminal and a typed confirmation code; they are for a human, not for an agent.\n";

export interface TaintCliIo {
  out: (text: string) => void;
  err: (text: string) => void;
  /** stdin and stdout are terminals. */
  isTty: boolean;
  /** One line typed by the user (without the line end), or null at end of input. */
  readLine: () => string | null;
}

export interface TaintCliDeps {
  rt: Runtime;
  env: NodeJS.ProcessEnv;
  /** Effective uid of the process (root check of admin-release). */
  euid: number | undefined;
  /** State directory of the calling user (default: as the hook). */
  dir?: string;
  releaseDir?: string;
  /** Required owner of the release directories (default root; tests inject). */
  releaseOwnerUid?: number;
  /** Directories at or above this path are not checked (tests; the hook uses the same `stopAt`). */
  releaseStopAt?: string;
  /** Home directory of a uid from the user database (admin-release). */
  homeOf?: (uid: number) => string | null;
  /** Logger for the release event of the calling user; null if no log can be written (then no release). */
  logger?: (sessionId: string) => EventLogger | null;
  code?: () => string;
  uuid?: () => string;
  /** Stand-alone or enterprise mode with `taint.release` (default: from the policy of the current directory). */
  mode?: () => { enterprise: boolean; release: "admin" | "user" };
}

function parseArgs(argv: readonly string[]): Map<string, string> | null {
  const out = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i];
    const v = argv[i + 1];
    if (k === undefined || v === undefined || !["--session", "--uid"].includes(k) || out.has(k)) return null;
    out.set(k, v);
  }
  return out;
}

function confirmCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let i = 0; i < 6; i += 1) code += alphabet[randomInt(alphabet.length)];
  return code;
}

function describe(s: TaintState): string[] {
  const lines = [
    `session ${sanitize(s.session_id)}: ${s.status} (taint_seq ${s.taint_seq}, since ${s.updated})`,
    ...s.sources.map((src) => `  source: ${src.kind} ${sanitize(src.name)} at ${src.at}`),
  ];
  if (s.released !== null) lines.push(`  last release: ${s.released.via} at ${s.released.at} (${s.released.release_id})`);
  return lines;
}

/** Asks for the code; true only if the user typed it exactly. */
function confirmed(io: TaintCliIo, deps: TaintCliDeps, what: string): boolean {
  const code = (deps.code ?? confirmCode)();
  io.out(`${what}\nOnly confirm if you, a human, reviewed what the session read. Type ${code} to confirm: `);
  const line = io.readLine();
  if (line === null || line.trim() !== code) {
    io.err("Not confirmed; nothing was changed.\n");
    return false;
  }
  return true;
}

function humanChannel(io: TaintCliIo, env: NodeJS.ProcessEnv): string | null {
  if (!io.isTty) return "a release needs a terminal on stdin and stdout (it is not for scripts or agents)";
  if (env.CLAUDECODE !== undefined || env.CLAUDE_CODE_ENTRYPOINT !== undefined) return "a release cannot be run from inside a Claude Code session";
  return null;
}

function cmdStatus(args: Map<string, string>, io: TaintCliIo, deps: TaintCliDeps, dir: string): number {
  const store = new TaintStore({ dir, uid: deps.rt.uid, clock: deps.rt.clock, uuid: deps.rt.uuid });
  const wanted = args.get("--session");
  if (wanted !== undefined) {
    const check = store.check(wanted);
    io.out(`${check.ok ? describe(check.state).join("\n") : `session ${sanitize(wanted)}: tainted (${check.problem})`}\n`);
    return 0;
  }
  let names: string[] = [];
  try {
    names = readdirSync(dir).filter((n) => /^s-[0-9a-f]{40}\.json$/.test(n)).sort();
  } catch {
    io.out("no taint state\n");
    return 0;
  }
  for (const name of names) {
    let id: string | null = null;
    try {
      const parsed = JSON.parse(readFileSync(join(dir, name), "utf8")) as { session_id?: unknown };
      id = typeof parsed.session_id === "string" && SESSION_PATTERN.test(parsed.session_id) ? parsed.session_id : null;
    } catch {
      id = null;
    }
    if (id === null) {
      io.out(`${name}: unreadable or invalid (counts as tainted)\n`);
      continue;
    }
    const check = store.check(id);
    io.out(`${check.ok ? describe(check.state).join("\n") : `session ${sanitize(id)}: tainted (${check.problem})`}\n`);
  }
  if (names.length === 0) io.out("no taint state\n");
  return 0;
}

function defaultMode(deps: TaintCliDeps): { enterprise: boolean; release: "admin" | "user" } {
  const enterprise = detectEnterprise(deps.env, deps.rt.platform).active;
  if (!enterprise) return { enterprise, release: "user" };
  const r = resolvePolicy({ env: deps.env, projectDir: process.cwd(), platform: deps.rt.platform });
  return { enterprise, release: r.ok && r.policy.taint?.release === "user" ? "user" : "admin" };
}

function cmdRelease(args: Map<string, string>, io: TaintCliIo, deps: TaintCliDeps, dir: string): number {
  const sid = args.get("--session");
  if (sid === undefined || args.has("--uid") || !SESSION_PATTERN.test(sid)) {
    io.err(USAGE);
    return 2;
  }
  const problem = humanChannel(io, deps.env);
  if (problem !== null) {
    io.err(`tollgate-taint: ${problem}.\n`);
    return 1;
  }
  const mode = (deps.mode ?? (() => defaultMode(deps)))();
  if (mode.enterprise && mode.release !== "user") {
    io.err("tollgate-taint: in enterprise mode only the administrator lifts a taint (sudo tollgate-taint admin-release).\n");
    return 1;
  }
  const store = new TaintStore({ dir, uid: deps.rt.uid, clock: deps.rt.clock, uuid: deps.rt.uuid });
  const check = store.check(sid);
  if (!check.ok) {
    io.err(`tollgate-taint: the state of this session is unusable (${check.problem}); the hook replaces it with a tainted state on its next restricted call - run status again then.\n`);
    return 1;
  }
  if (!check.tainted) {
    io.out("The session is not tainted; nothing to release.\n");
    return 0;
  }
  if (!confirmed(io, deps, describe(check.state).join("\n"))) return 1;
  const logger = (deps.logger ?? (() => null))(sid);
  const releaseId = (deps.uuid ?? randomUUID)();
  if (logger === null) {
    io.err("tollgate-taint: the decision log is not available; no release without a record.\n");
    return 1;
  }
  const logged = logger.recordTaint({
    type: "taint_release",
    claude: { session_id: sid, tool_use_id: null, agent_id: null, agent_type: null, hook_event: "TaintCli", permission_mode: null },
    data: { via: "user", release_id: releaseId, epoch: check.state.epoch, taint_seq: check.state.taint_seq },
    humanSession: true,
  });
  if (!logged.ok) {
    io.err("tollgate-taint: the release could not be recorded in the decision log; nothing was changed.\n");
    return 1;
  }
  try {
    store.release(sid, check.state.epoch, check.state.taint_seq, "user", releaseId);
  } catch (error) {
    io.err(`tollgate-taint: ${sanitize((error as Error).message)}.\n`);
    return 1;
  }
  io.out(`Released (release ${releaseId}). A new untrusted read taints the session again.\n`);
  return 0;
}

/** `/etc/passwd`: home directory of a uid. */
export function passwdHome(uid: number, passwd = "/etc/passwd"): string | null {
  try {
    for (const line of readFileSync(passwd, "utf8").split("\n")) {
      const f = line.split(":");
      if (f.length >= 7 && f[2] === String(uid) && (f[5] ?? "").startsWith("/")) return f[5] as string;
    }
  } catch {
    return null;
  }
  return null;
}

/** Why root must not read below `dir` of user `uid`, or null: a link, a foreign owner or a directory writable by others. */
export function userPathProblem(dir: string, uid: number, stopAt?: string): string | null {
  let path = "";
  for (const part of dir.split("/").filter((p) => p !== "")) {
    path = `${path}/${part}`;
    if (stopAt !== undefined && (stopAt === path || stopAt.startsWith(`${path}/`))) continue;
    let info;
    try {
      info = lstatSync(path);
    } catch {
      return "a directory is missing or unreadable";
    }
    if (info.isSymbolicLink() || !info.isDirectory()) return "a part of the path is a link or not a directory";
    if (info.uid !== 0 && info.uid !== uid) return "a directory belongs to another user";
    // group or others may write: a member could swap a directory for a link (a sticky directory such as /tmp only lets owners rename)
    if ((info.mode & 0o022) !== 0 && (info.mode & 0o1000) === 0) return "a directory is writable by group or others";
  }
  return null;
}

/** Creates `dir` and its missing parents root-owned 0755; refuses links, foreign owners and group/world-writable directories. */
function ensureRootDir(dir: string, ownerUid: number, stopAt: string | undefined): void {
  const parts = dir.split("/").filter((p) => p !== "");
  let path = "";
  for (const p of parts) {
    path = `${path}/${p}`;
    if (stopAt !== undefined && (stopAt === path || stopAt.startsWith(`${path}/`))) continue;
    try {
      const info = lstatSync(path);
      if (info.isSymbolicLink() || !info.isDirectory()) throw new Error("a directory of the release path is a link or not a directory");
      if (info.uid !== ownerUid || (info.mode & 0o022) !== 0) throw new Error("a directory of the release path is not root-owned or is writable by others");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      mkdirSync(path, { mode: 0o755 });
      chmodSync(path, 0o755); // independent of the umask
    }
  }
}

function cmdAdminRelease(args: Map<string, string>, io: TaintCliIo, deps: TaintCliDeps): number {
  const sid = args.get("--session");
  const uidText = args.get("--uid");
  if (sid === undefined || uidText === undefined || !SESSION_PATTERN.test(sid) || !/^[1-9][0-9]{0,9}$/.test(uidText)) {
    io.err(USAGE);
    return 2;
  }
  const uid = Number(uidText);
  if (deps.euid !== 0) {
    io.err("tollgate-taint: admin-release must run as root (sudo).\n");
    return 1;
  }
  const sudoUid = deps.env.SUDO_UID;
  if (sudoUid === undefined || !/^[1-9][0-9]{0,9}$/.test(sudoUid)) {
    io.err("tollgate-taint: run admin-release through sudo as an administrator (SUDO_UID missing).\n");
    return 1;
  }
  if (Number(sudoUid) === uid) {
    io.err("tollgate-taint: an administrator cannot release a session of their own account (four-eyes).\n");
    return 1;
  }
  const problem = humanChannel(io, deps.env);
  if (problem !== null) {
    io.err(`tollgate-taint: ${problem}.\n`);
    return 1;
  }
  const home = (deps.homeOf ?? passwdHome)(uid);
  if (home === null) {
    io.err("tollgate-taint: unknown uid.\n");
    return 1;
  }
  const dir = deps.dir ?? join(home, ".local", "state", "tollgate", "taint");
  // root reads a directory that the user controls: no symbolic link on the whole path, every directory owned by root or the user
  // and not writable by others (otherwise a link could point root at another file).
  const pathProblem = userPathProblem(dir, uid, deps.releaseStopAt);
  if (pathProblem !== null) {
    io.err(`tollgate-taint: the state directory of the user is not safe to read (${pathProblem}).\n`);
    return 1;
  }
  const store = new TaintStore({ dir, uid, clock: deps.rt.clock, uuid: deps.rt.uuid });
  const check = store.check(sid);
  if (!check.ok) {
    io.err(`tollgate-taint: the state of this session is unusable (${check.problem}); the hook replaces it with a tainted state on the user's next restricted call - run admin-release again then.\n`);
    return 1;
  }
  if (!check.tainted) {
    io.out("The session is not tainted; nothing to release.\n");
    return 0;
  }
  if (!confirmed(io, deps, `uid ${uid}\n${describe(check.state).join("\n")}`)) return 1;
  const releaseDir = deps.releaseDir ?? TAINT_RELEASE_DIR;
  const release = { schema: TAINT_RELEASE_SCHEMA, id: (deps.uuid ?? randomUUID)(), session_id: sid, uid, epoch: check.state.epoch, taint_seq: check.state.taint_seq, created: deps.rt.clock().toISOString(), by_uid: Number(sudoUid) } as const;
  const target = join(releaseDir, releaseFileName(uid, sid));
  const tmp = join(releaseDir, `.tmp-${randomBytes(8).toString("hex")}`);
  let fd: number | undefined;
  try {
    ensureRootDir(releaseDir, deps.releaseOwnerUid ?? 0, deps.releaseStopAt);
    fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o644);
    fchmodSync(fd, 0o644); // independent of the umask
    writeSync(fd, serializeTaintRelease(release));
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(tmp, target);
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    rmSync(tmp, { force: true });
    io.err(`tollgate-taint: the release file cannot be written (${sanitize((error as Error).message)}).\n`);
    return 1;
  }
  io.out(`Release ${release.id} written. The hook lifts the taint on the user's next restricted call and records taint_release in the user's decision log.\n`);
  return 0;
}

/** Runs the CLI; returns the exit code (0 done, 1 refused or failed, 2 usage). */
export function runTaintCli(argv: readonly string[], io: TaintCliIo, deps: TaintCliDeps): number {
  const [command, ...rest] = argv;
  const args = parseArgs(rest);
  if (args === null) {
    io.err(USAGE);
    return 2;
  }
  try {
    if (command === "status") return cmdStatus(args, io, deps, deps.dir ?? taintDirFor(deps.rt, deps.env, (deps.mode ?? (() => defaultMode(deps)))().enterprise));
    if (command === "release") return cmdRelease(args, io, deps, deps.dir ?? taintDirFor(deps.rt, deps.env, (deps.mode ?? (() => defaultMode(deps)))().enterprise));
    if (command === "admin-release") return cmdAdminRelease(args, io, deps);
  } catch (error) {
    io.err(`tollgate-taint: ${sanitize((error as Error).message)}\n`);
    return 1;
  }
  io.err(USAGE);
  return 2;
}

/** System calls of the confirmation input (tests inject a scripted terminal). */
export interface LineReaderDeps {
  /** Opens a path for reading, non-blocking (the wait limit applies there too); throws if it cannot. */
  open: (path: string) => number;
  /** Reads up to `buf.length` bytes; throws errno errors such as EAGAIN. */
  read: (fd: number, buf: Buffer) => number;
  close: (fd: number) => void;
  /** Waits synchronously. */
  sleep: (ms: number) => void;
  now: () => number;
}

const systemLineReader: LineReaderDeps = {
  open: (path) => openSync(path, constants.O_RDONLY | (constants.O_NOCTTY ?? 0) | (constants.O_NONBLOCK ?? 0)),
  read: (fd, buf) => readSync(fd, buf, 0, buf.length, null),
  close: (fd) => closeSync(fd),
  sleep: (ms) => {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  },
  now: () => Date.now(),
};

/** Longest wait for a line while the terminal reports "no input yet"; after that: not confirmed. */
export const CONFIRM_WAIT_MS = 10 * 60 * 1000;
const RETRY_SLEEP_MS = 50;

/**
 * One line typed by the user (without the line end), or null (not confirmed).
 *
 * Reads from the controlling terminal `/dev/tty`, opened on its own and non-blocking. Node puts its stdin into
 * non-blocking mode once `process.stdin` is touched (the TTY check does), and `readSync(0)` then fails with EAGAIN at
 * once; the earlier reader took that for the end of input (field test 2026-10-30). If `/dev/tty` cannot be opened,
 * stdin is read instead. Either way EAGAIN/EWOULDBLOCK means "no complete line yet: wait and read again" (polling),
 * up to `waitMs`. The line is decoded as UTF-8 at its end, so multi-byte characters stay intact.
 * Fails closed: end of input (also after a partial line), any other read error, a line longer than 64 bytes and the
 * end of the wait give null.
 */
export function readConfirmationLine(deps: LineReaderDeps = systemLineReader, waitMs = CONFIRM_WAIT_MS): string | null {
  let fd = 0;
  let own = false;
  try {
    fd = deps.open("/dev/tty");
    own = true;
  } catch {
    fd = 0;
  }
  try {
    const buf = Buffer.alloc(1);
    const start = deps.now();
    const bytes: number[] = [];
    for (;;) {
      let n: number;
      try {
        n = deps.read(fd, buf);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if ((code === "EAGAIN" || code === "EWOULDBLOCK") && deps.now() - start < waitMs) {
          deps.sleep(RETRY_SLEEP_MS);
          continue;
        }
        return null;
      }
      if (n === 0) return null;
      const b = buf[0] ?? 0;
      if (b === 0x0a) return Buffer.from(bytes).toString("utf8").replace(/\r$/, "");
      if (bytes.length >= 64) return null;
      bytes.push(b);
    }
  } finally {
    if (own) deps.close(fd);
  }
}

if (isEntryPoint(import.meta.url)) {
  const rt = systemRuntime();
  const env = process.env;
  const deps: TaintCliDeps = {
    rt,
    env,
    euid: typeof process.geteuid === "function" ? process.geteuid() : undefined,
    logger: () => {
      const resolution = resolvePolicy({ env, projectDir: process.cwd(), platform: rt.platform });
      return loggerFor(rt, env, resolution, detectEnterprise(env, rt.platform).active, {});
    },
  };
  const io: TaintCliIo = { out: (t) => process.stdout.write(t), err: (t) => process.stderr.write(t), isTty: process.stdin.isTTY === true && process.stdout.isTTY === true, readLine: () => readConfirmationLine() };
  process.exit(runTaintCli(process.argv.slice(2), io, deps));
}
