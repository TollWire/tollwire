// File-system helpers of the decision log: descriptor-based, no symlink following, bounded sizes.
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, readSync, renameSync, rmSync, writeSync, type Stats } from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";

export const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
export const NONBLOCK = constants.O_NONBLOCK ?? 0;
export const NOCTTY = constants.O_NOCTTY ?? 0;

/** Failure of the log writer; `code` is a stable short name, the message holds no paths or stack traces. */
export class EventWriteError extends Error {
  constructor(
    message: string,
    readonly code: "dir_missing" | "dir_unsafe" | "file_unsafe" | "lock_timeout" | "io",
  ) {
    super(message);
    this.name = "EventWriteError";
  }
}

export function errnoCode(error: unknown): string | undefined {
  return (error as NodeJS.ErrnoException | undefined)?.code;
}

export function sleepMs(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export interface SmallFile {
  text: string;
  bytes: Buffer;
}

/**
 * Reads a small regular file through one checked descriptor. Returns null if the file does not exist. Throws
 * EventWriteError for a symlink (unless `followLinks`), a non-regular file or a file larger than `maxBytes`.
 */
export function readSmallFile(path: string, maxBytes: number, followLinks = false): SmallFile | null {
  let fd: number;
  try {
    if (!followLinks) {
      const info = lstatSync(path);
      if (info.isSymbolicLink()) throw new EventWriteError("file is a symbolic link", "file_unsafe");
    }
    fd = openSync(path, constants.O_RDONLY | (followLinks ? 0 : NOFOLLOW) | NONBLOCK | NOCTTY);
  } catch (error) {
    if (error instanceof EventWriteError) throw error;
    const code = errnoCode(error);
    if (code === "ENOENT" || code === "ENOTDIR") return null;
    if (code === "ELOOP") throw new EventWriteError("file is a symbolic link", "file_unsafe");
    throw new EventWriteError("file cannot be opened", "io");
  }
  try {
    const info = fstatSync(fd);
    if (!info.isFile()) throw new EventWriteError("not a regular file", "file_unsafe");
    if (info.size > maxBytes) throw new EventWriteError("file too large", "file_unsafe");
    const bytes = Buffer.alloc(info.size);
    let offset = 0;
    while (offset < bytes.length) {
      const n = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (n === 0) break;
      offset += n;
    }
    const used = bytes.subarray(0, offset);
    return { text: used.toString("utf8"), bytes: used };
  } catch (error) {
    if (error instanceof EventWriteError) throw error;
    throw new EventWriteError("file cannot be read", "io");
  } finally {
    closeSync(fd);
  }
}

/** Writes a file atomically (temporary file with O_EXCL, then rename). */
export function writeFileAtomic(path: string, data: string, mode: number): void {
  const temporary = join(dirname(path), `.tmp-${randomUUID()}`);
  let fd: number | undefined;
  try {
    fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW | NOCTTY, mode);
    const buffer = Buffer.from(data, "utf8");
    let offset = 0;
    while (offset < buffer.length) offset += writeSync(fd, buffer, offset, buffer.length - offset);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temporary, path);
  } catch {
    if (fd !== undefined) closeSync(fd);
    rmSync(temporary, { force: true });
    throw new EventWriteError("file cannot be written", "io");
  }
}

export function safeLstat(path: string): Stats | null {
  try {
    return lstatSync(path);
  } catch (error) {
    const code = errnoCode(error);
    if (code === "ENOENT" || code === "ENOTDIR") return null;
    throw new EventWriteError("path cannot be inspected", "io");
  }
}
