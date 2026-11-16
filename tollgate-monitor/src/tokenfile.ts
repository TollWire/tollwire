// Token files: created exclusively, never followed through a link, removed at the end, orphans of
// ended processes removed at the next start. The token never appears in argv or in the environment of a child process.
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, unlinkSync, writeSync } from "node:fs";
import { join } from "node:path";
import { NOCTTY, NOFOLLOW } from "./vendor/fsutil.js";

export class TokenFileError extends Error {
  constructor(
    message: string,
    readonly code: "dir_missing" | "dir_unsafe" | "exists" | "io",
  ) {
    super(message);
    this.name = "TokenFileError";
  }
}

export interface RuntimeDirOptions {
  /** Required owner (the effective uid). */
  uid: number;
  /** Create the directory (mode 0700) if it is missing. */
  create: boolean;
  /** Bits that must not be set in the mode: 0o077 for a private directory, 0o022 for a directory others may traverse (0711). */
  forbidden: number;
}

/** Checks (and maybe creates) the directory of the token files: a real directory of the effective user, no write rights for others. */
export function ensureRuntimeDir(dir: string, o: RuntimeDirOptions): void {
  let info;
  try {
    info = lstatSync(dir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new TokenFileError("token directory cannot be inspected", "io");
    if (!o.create) throw new TokenFileError("token directory is missing", "dir_missing");
    try {
      mkdirSync(dir, { mode: 0o700 });
      info = lstatSync(dir);
    } catch {
      throw new TokenFileError("token directory cannot be created", "io");
    }
  }
  if (info.isSymbolicLink() || !info.isDirectory()) throw new TokenFileError("token directory is not a real directory", "dir_unsafe");
  if (info.uid !== o.uid) throw new TokenFileError("token directory has the wrong owner", "dir_unsafe");
  if ((info.mode & o.forbidden) !== 0) throw new TokenFileError("token directory has too wide a mode", "dir_unsafe");
}

/** Creates the file with `O_CREAT|O_EXCL|O_NOFOLLOW` and mode 0600 and writes the token. */
export function createTokenFile(path: string, token: string): void {
  let fd: number;
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW | NOCTTY, 0o600);
  } catch (error) {
    throw new TokenFileError("token file cannot be created", (error as NodeJS.ErrnoException).code === "EEXIST" ? "exists" : "io");
  }
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.nlink !== 1) throw new TokenFileError("token file is not a plain file", "dir_unsafe");
    const bytes = Buffer.from(`${token}\n`, "utf8");
    let off = 0;
    while (off < bytes.length) off += writeSync(fd, bytes, off, bytes.length - off);
  } catch (error) {
    closeSync(fd);
    removeTokenFile(path);
    throw error instanceof TokenFileError ? error : new TokenFileError("token file cannot be written", "io");
  }
  closeSync(fd);
}

/** Removes a token file; a missing file is fine. */
export function removeTokenFile(path: string): void {
  try {
    unlinkSync(path);
  } catch {
    // Already gone, or not ours to remove.
  }
}

export function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Removes token files of processes that no longer exist. `pattern` has the process id as its first group. Only regular
 * files of `uid` are touched, and never the file of the process itself.
 */
export function cleanStaleTokenFiles(dir: string, pattern: RegExp, uid: number, ownPid: number, alive: (pid: number) => boolean = processAlive): string[] {
  const removed: string[] = [];
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return removed;
  }
  for (const name of names.slice(0, 1000)) {
    const m = pattern.exec(name);
    if (m === null) continue;
    const pid = Number(m[1]);
    if (!Number.isSafeInteger(pid) || pid === ownPid || alive(pid)) continue;
    const path = join(dir, name);
    try {
      const info = lstatSync(path);
      if (!info.isFile() || info.uid !== uid) continue;
      unlinkSync(path);
      removed.push(name);
    } catch {
      // Not removable: left in place.
    }
  }
  return removed;
}
