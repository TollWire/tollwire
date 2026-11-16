// Hardened reader for event files: used by `tollgate-events verify`, later by relay and monitor.
// It replaces the unbounded read of the evidence log: size limit, chunked reading, line limit, checks on the descriptor.
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readSync, type Stats } from "node:fs";
import { join } from "node:path";
import { EVENT_FILE } from "./layout.js";
import { NOCTTY, NOFOLLOW, NONBLOCK } from "./fsutil.js";

export const MAX_READ_BYTES = 65 * 1024 * 1024;
export const MAX_LINE_BYTES = 8 * 1024;
const CHUNK = 64 * 1024;
/** Directory scan limit (entries per run). */
export const MAX_DIRECTORY_ENTRIES = 1000;

export type FindingKind =
  | "symlink"
  | "not_regular"
  | "unreadable"
  | "replaced"
  | "oversize"
  | "line_too_long"
  | "invalid_utf8"
  | "incomplete_line"
  | "hardlink"
  | "owner"
  | "mode"
  | "directory_limit";

export interface ReadFinding {
  kind: FindingKind;
  file: string;
  line?: number;
  detail: string;
}

export interface ReadLine {
  no: number;
  text: string;
}

export interface ReadOutcome {
  file: string;
  /** False if the file was refused (link, FIFO, device, unreadable). */
  read: boolean;
  lines: ReadLine[];
  findings: ReadFinding[];
  /** Metadata findings only (links, owner, mode): the content was still read. */
  metaOk: boolean;
}

export interface ReadOptions {
  /** Expected owner; a different owner is a metadata finding. */
  uid?: number | undefined;
  /** Largest acceptable permission bits (default 0o640): any other bit is a metadata finding. */
  maxMode?: number | undefined;
  maxBytes?: number | undefined;
}

function refuse(file: string, kind: FindingKind, detail: string): ReadOutcome {
  return { file, read: false, lines: [], findings: [{ kind, file, detail }], metaOk: false };
}

/**
 * Reads an event file: `lstat`, open without following links (`O_NOFOLLOW|O_NONBLOCK|O_NOCTTY`), `fstat` on the
 * descriptor (same file as `lstat`, regular), size limit (reads up to the limit and reports the rest), 64 KiB chunks,
 * lines over 8 KiB and invalid UTF-8 reported and skipped. A hard link, a foreign owner or too wide a mode are metadata
 * findings; the content is read nevertheless.
 */
export function readEventFile(path: string, options: ReadOptions = {}): ReadOutcome {
  let pre: Stats;
  try {
    pre = lstatSync(path);
  } catch {
    return refuse(path, "unreadable", "file does not exist or cannot be inspected");
  }
  if (pre.isSymbolicLink()) return refuse(path, "symlink", "symbolic links are not read");
  if (!pre.isFile()) return refuse(path, "not_regular", "only regular files are read");
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | NOFOLLOW | NONBLOCK | NOCTTY);
  } catch {
    return refuse(path, "unreadable", "file cannot be opened");
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return refuse(path, "not_regular", "only regular files are read");
    if (st.ino !== pre.ino || st.dev !== pre.dev) return refuse(path, "replaced", "the file was replaced while it was opened");
    const findings: ReadFinding[] = [];
    if (st.nlink > 1) findings.push({ kind: "hardlink", file: path, detail: `${st.nlink} hard links` });
    if (options.uid !== undefined && st.uid !== options.uid) findings.push({ kind: "owner", file: path, detail: "owned by another user" });
    const maxMode = options.maxMode ?? 0o640;
    if ((st.mode & 0o777 & ~maxMode) !== 0) findings.push({ kind: "mode", file: path, detail: `mode ${(st.mode & 0o777).toString(8)} is wider than ${maxMode.toString(8)}` });
    const limit = options.maxBytes ?? MAX_READ_BYTES;
    const toRead = Math.min(st.size, limit);
    if (st.size > limit) findings.push({ kind: "oversize", file: path, detail: `${st.size - limit} bytes beyond the limit were not read` });
    const lines: ReadLine[] = [];
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let pending: Buffer = Buffer.alloc(0);
    let lineNo = 1;
    let position = 0;
    const emit = (bytes: Buffer, complete: boolean): void => {
      if (bytes.length > MAX_LINE_BYTES) {
        findings.push({ kind: "line_too_long", file: path, line: lineNo, detail: "line longer than 8 KiB" });
      } else if (!complete) {
        findings.push({ kind: "incomplete_line", file: path, line: lineNo, detail: "last line has no newline" });
      } else {
        try {
          lines.push({ no: lineNo, text: decoder.decode(bytes) });
        } catch {
          findings.push({ kind: "invalid_utf8", file: path, line: lineNo, detail: "line is not valid UTF-8" });
        }
      }
      lineNo += 1;
    };
    const buffer = Buffer.alloc(CHUNK);
    while (position < toRead) {
      const n = readSync(fd, buffer, 0, Math.min(CHUNK, toRead - position), position);
      if (n === 0) break;
      position += n;
      let chunk = Buffer.concat([pending, buffer.subarray(0, n)]);
      let newline = chunk.indexOf(10);
      while (newline >= 0) {
        emit(chunk.subarray(0, newline), true);
        chunk = chunk.subarray(newline + 1);
        newline = chunk.indexOf(10);
      }
      // A line that is already too long is dropped early so that memory stays bounded.
      pending = chunk.length > MAX_LINE_BYTES + 1 ? Buffer.alloc(MAX_LINE_BYTES + 1) : Buffer.from(chunk);
    }
    if (pending.length > 0) emit(pending, false);
    return { file: path, read: true, lines, findings, metaOk: findings.every((f) => !["hardlink", "owner", "mode"].includes(f.kind)) };
  } catch {
    return refuse(path, "unreadable", "file cannot be read");
  } finally {
    closeSync(fd);
  }
}

/** Names of the event files in a directory, oldest first (day, then alternate number). Bounded scan. */
export function listEventFiles(dir: string): { names: string[]; findings: ReadFinding[] } {
  const findings: ReadFinding[] = [];
  let entries: string[];
  try {
    const info = lstatSync(dir);
    if (info.isSymbolicLink() || !info.isDirectory()) return { names: [], findings: [{ kind: "not_regular", file: dir, detail: "not a real directory" }] };
    entries = readdirSync(dir);
  } catch {
    return { names: [], findings: [{ kind: "unreadable", file: dir, detail: "directory cannot be listed" }] };
  }
  if (entries.length > MAX_DIRECTORY_ENTRIES) {
    findings.push({ kind: "directory_limit", file: dir, detail: `${entries.length} entries; only the first ${MAX_DIRECTORY_ENTRIES} were scanned` });
    entries = entries.slice(0, MAX_DIRECTORY_ENTRIES);
  }
  const names = entries
    .map((name) => ({ name, m: EVENT_FILE.exec(name) }))
    .filter((e): e is { name: string; m: RegExpExecArray } => e.m !== null)
    .sort((a, b) => {
      const ka = `${a.m[1]?.padStart(12, "0")}-${a.m[2]}-${String(Number(a.m[3] ?? 0)).padStart(4, "0")}`;
      const kb = `${b.m[1]?.padStart(12, "0")}-${b.m[2]}-${String(Number(b.m[3] ?? 0)).padStart(4, "0")}`;
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    })
    .map((e) => e.name);
  return { names, findings };
}

export function joinPath(dir: string, name: string): string {
  return join(dir, name);
}
