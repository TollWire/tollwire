// Cross-process lock for the log directory. The lock file lives in a directory that only the user
// can write (private directory or own event directory), never in a directory others can write.
import { randomUUID } from "node:crypto";
import { closeSync, constants, linkSync, lstatSync, openSync, readFileSync, renameSync, rmSync, statSync, writeSync } from "node:fs";
import { hostname } from "node:os";
import { errnoCode, EventWriteError, NOCTTY, NOFOLLOW, readSmallFile, sleepMs } from "./fsutil.js";

export const LOCK_WAIT_MS = 2_000;
/** The directory is writable only by the user, so a lock can only be the user's own: after this age any lock may be taken over. */
export const LOCK_FORCE_AFTER_MS = 10_000;

export interface LockOwner {
  pid: number;
  host: string;
  token: string;
  boot_id: string | null;
  pid_ns: string | null;
  start: string | null;
}

/** Process facts used to decide whether a lock owner is gone (injectable for tests). */
export interface ProcessFacts {
  pid: number;
  host: string;
  bootId: () => string | null;
  pidNamespace: () => string | null;
  startTime: (pid: number) => string | null;
  alive: (pid: number) => boolean;
  now: () => number;
}

function readLinux(path: string): string | null {
  try {
    return readFileSync(path, "utf8").trim();
  } catch {
    return null;
  }
}

/** Field 22 (starttime) of /proc/<pid>/stat; the command name in field 2 may contain spaces and parentheses. */
export function parseStartTime(stat: string): string | null {
  const rest = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
  return rest[19] ?? null;
}

export const systemProcessFacts: ProcessFacts = {
  pid: process.pid,
  host: hostname(),
  bootId: () => (process.platform === "linux" ? readLinux("/proc/sys/kernel/random/boot_id") : null),
  pidNamespace: () => {
    if (process.platform !== "linux") return null;
    try {
      return String(statSync("/proc/self/ns/pid").ino);
    } catch {
      return null;
    }
  },
  startTime: (pid) => {
    if (process.platform !== "linux") return null;
    const stat = readLinux(`/proc/${pid}/stat`);
    return stat === null ? null : parseStartTime(stat);
  },
  alive: (pid) => {
    try {
      process.kill(pid, 0);
      return true;
    } catch (error) {
      return errnoCode(error) === "EPERM";
    }
  },
  now: () => Date.now(),
};

function ownerOf(facts: ProcessFacts): LockOwner {
  return { pid: facts.pid, host: facts.host, token: randomUUID(), boot_id: facts.bootId(), pid_ns: facts.pidNamespace(), start: facts.startTime(facts.pid) };
}

function readOwner(lock: string): LockOwner | null {
  try {
    const file = readSmallFile(lock, 1024);
    if (file === null) return null;
    const o = JSON.parse(file.text) as Partial<LockOwner>;
    if (typeof o.pid === "number" && typeof o.host === "string" && typeof o.token === "string") {
      return { pid: o.pid, host: o.host, token: o.token, boot_id: o.boot_id ?? null, pid_ns: o.pid_ns ?? null, start: o.start ?? null };
    }
  } catch {
    // Missing, partly written or foreign lock file.
  }
  return null;
}

/** The owner is provably gone: other boot, other PID namespace, no such process, or the process start differs (PID reuse). */
export function ownerGone(owner: LockOwner, facts: ProcessFacts): boolean {
  if (owner.host !== facts.host) return false; // locks of other hosts are only taken over by force
  const boot = facts.bootId();
  if (owner.boot_id !== null && boot !== null && owner.boot_id !== boot) return true;
  const ns = facts.pidNamespace();
  if (owner.pid_ns !== null && ns !== null && owner.pid_ns !== ns) return true;
  if (!facts.alive(owner.pid)) return true;
  const start = facts.startTime(owner.pid);
  return owner.start !== null && start !== null && owner.start !== start;
}

export function breakLock(lock: string, observed: LockOwner | null): void {
  const aside = `${lock}.${randomUUID()}.stale`;
  try {
    renameSync(lock, aside);
  } catch {
    return; // already removed or replaced by another waiter
  }
  const moved = readOwner(aside);
  if ((moved?.token ?? null) !== (observed?.token ?? null)) {
    try {
      linkSync(aside, lock); // a different lock was taken over meanwhile: put it back (fails if a newer one exists)
    } catch {
      // A newer lock exists; the moved one is no longer authoritative.
    }
  }
  rmSync(aside, { force: true });
}

/** Acquires the lock; returns the function that releases it. Throws EventWriteError(`lock_timeout`) after the wait time. */
export function acquireLock(lock: string, facts: ProcessFacts = systemProcessFacts, waitMs = LOCK_WAIT_MS, forceAfterMs = LOCK_FORCE_AFTER_MS): () => void {
  const self = ownerOf(facts);
  const deadline = facts.now() + waitMs;
  for (;;) {
    try {
      const fd = openSync(lock, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW | NOCTTY, 0o600);
      try {
        writeSync(fd, JSON.stringify(self));
      } finally {
        closeSync(fd);
      }
      break;
    } catch (error) {
      if (errnoCode(error) !== "EEXIST") throw new EventWriteError("lock cannot be created", errnoCode(error) === "ENOENT" ? "dir_missing" : "io");
      try {
        const info = lstatSync(lock);
        const owner = info.isFile() ? readOwner(lock) : null;
        // A lock that is not a regular file (planted link, FIFO) is never an owner's lock.
        if (!info.isFile() || facts.now() - info.mtimeMs > forceAfterMs || (owner !== null && ownerGone(owner, facts))) breakLock(lock, owner);
      } catch {
        // The lock vanished between the checks; try again.
      }
      if (facts.now() > deadline) throw new EventWriteError("log is locked by another process", "lock_timeout");
      sleepMs(20);
    }
  }
  return () => {
    // Release only our own lock; never remove one that was taken over.
    if (readOwner(lock)?.token === self.token) rmSync(lock, { force: true });
  };
}
