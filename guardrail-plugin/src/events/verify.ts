// Chain verification of event files (`tollgate-events verify`).
import { chainHash } from "../vendor/hashchain.js";
import { readEventFile, joinPath, MAX_DIRECTORY_ENTRIES, type ReadFinding, type ReadOptions } from "./reader.js";
import { EVENT_FILE } from "./layout.js";
import { GENESIS, SCHEMA } from "./types.js";
import { lstatSync, readdirSync } from "node:fs";

const HEX64 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface ChainFinding {
  kind: "invalid_json" | "invalid_event" | "hash_mismatch" | "chain_broken" | "start_invalid" | "unlinked" | "link_mismatch";
  file: string;
  line: number;
  detail: string;
}

/**
 * Finding of the reader or of the path expansion: `no_event_files` (a directory without event files), `no_events` (a chain
 * source whose files hold no event, e.g. truncated to 0 bytes), `unknown_file` (a `*.jsonl` that matches no known name).
 */
export interface PathFinding extends Omit<ReadFinding, "kind"> {
  kind: ReadFinding["kind"] | "no_event_files" | "no_events" | "unknown_file";
}

export interface VerifyReport {
  files: number;
  events: number;
  chains: string[];
  chainFindings: ChainFinding[];
  readFindings: PathFinding[];
  /** Chain and format are valid (metadata findings do not count). */
  chainOk: boolean;
  /** Also no metadata finding. */
  metaOk: boolean;
}

interface Last {
  chain_id: string;
  seq: number;
  hash: string;
}

function validEvent(e: Record<string, unknown>): string | null {
  if (e.schema !== SCHEMA) return "schema is not tollgate.event.v1";
  if (typeof e.chain_id !== "string" || !UUID.test(e.chain_id)) return "chain_id is not a UUID";
  if (typeof e.seq !== "number" || !Number.isSafeInteger(e.seq) || e.seq < 1) return "seq is not a positive integer";
  if (typeof e.hash !== "string" || !HEX64.test(e.hash)) return "hash is not 64 hex digits";
  if (typeof e.prev_hash !== "string" || !HEX64.test(e.prev_hash)) return "prev_hash is not 64 hex digits";
  if (typeof e.type !== "string" || typeof e.ts !== "string" || typeof e.event_id !== "string") return "type, ts or event_id missing";
  return null;
}

/** Verifies the given files in order as one stream of chains. */
export function verifyFiles(files: readonly string[], options: ReadOptions = {}): VerifyReport {
  const report: VerifyReport = { files: 0, events: 0, chains: [], chainFindings: [], readFindings: [], chainOk: true, metaOk: true };
  let last: Last | null = null;
  for (const file of files) {
    const outcome = readEventFile(file, options);
    report.files += 1;
    report.readFindings.push(...outcome.findings);
    if (!outcome.read) continue; // a refused file leaves a gap; chain_continue after it is judged against the last verified event
    for (const line of outcome.lines) {
      if (line.text === "") continue;
      const at = (kind: ChainFinding["kind"], detail: string): void => {
        report.chainFindings.push({ kind, file, line: line.no, detail });
      };
      let parsed: unknown;
      try {
        parsed = JSON.parse(line.text);
      } catch {
        at("invalid_json", "the line is not valid JSON");
        continue;
      }
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        at("invalid_event", "the line is not a JSON object");
        continue;
      }
      const e = parsed as Record<string, unknown>;
      const problem = validEvent(e);
      if (problem !== null) {
        at("invalid_event", problem);
        continue;
      }
      report.events += 1;
      if (chainHash(e) !== e.hash) {
        at("hash_mismatch", "the hash does not match the content");
        continue;
      }
      const seq = e.seq as number;
      const chainId = e.chain_id as string;
      const type = e.type as string;
      if (type === "chain_start") {
        const data = (e.data ?? {}) as Record<string, unknown>;
        if (seq !== 1) at("start_invalid", "chain_start must have seq 1");
        else if (data.reason !== "corruption" && e.prev_hash !== GENESIS) at("start_invalid", "chain_start must start at the genesis hash");
        else if (data.reason === "corruption" && last !== null && data.broken_chain_id === last.chain_id && e.prev_hash !== last.hash) {
          at("link_mismatch", "the corruption link does not point to the last valid event");
        }
        if (!report.chains.includes(chainId)) report.chains.push(chainId);
      } else if (last === null || last.chain_id !== chainId) {
        if (type === "chain_continue") at("unlinked", "chain_continue without a verified predecessor");
        else at("chain_broken", "event of an unknown chain");
        if (!report.chains.includes(chainId)) report.chains.push(chainId);
      } else if (seq !== last.seq + 1) {
        at("chain_broken", `sequence gap (expected ${last.seq + 1}, found ${seq})`);
      } else if (e.prev_hash !== last.hash) {
        at("chain_broken", "prev_hash does not match the previous event");
      }
      last = { chain_id: chainId, seq, hash: e.hash as string };
    }
  }
  const meta = (f: PathFinding): boolean => f.kind === "hardlink" || f.kind === "owner" || f.kind === "mode";
  report.chainOk = report.chainFindings.length === 0 && report.readFindings.every(meta);
  report.metaOk = !report.readFindings.some(meta);
  return report;
}

/**
 * Prefixes of the service chain files (`<prefix>-<YYYYMMDD>[-<n>].jsonl`, ChainWriter of the enterprise package and
 * the admin view package): control (lock service), monitor (admin audit), relay (spool), host (heartbeat), send and sendcfg
 * (sender). A test compares this list with the `prefix:` values of the ChainWriter calls.
 */
export const SERVICE_PREFIXES = ["control", "monitor", "relay", "host", "send", "sendcfg"] as const;
export const SERVICE_EVENT_FILE = new RegExp(`^(${SERVICE_PREFIXES.join("|")})-([0-9]{8})(?:-([0-9]+))?\\.jsonl$`);

/** Compares two digit strings as numbers, whatever their length. */
export function compareDigits(a: string, b: string): number {
  const x = a.replace(/^0+(?=[0-9])/, "");
  const y = b.replace(/^0+(?=[0-9])/, "");
  if (x.length !== y.length) return x.length - y.length;
  return x < y ? -1 : x > y ? 1 : 0;
}

interface Entry {
  name: string;
  day: string;
  n: string;
}

/** The one order of the files of a chain source: day, then alternate number (none = 0), oldest first. */
function compareEntries(a: Entry, b: Entry): number {
  return a.day < b.day ? -1 : a.day > b.day ? 1 : compareDigits(a.n, b.n);
}

export interface EventGroups {
  /** One group per chain source (user files per uid first, then service files per prefix), each oldest first. */
  groups: string[][];
  /** `*.jsonl` entries that match neither the user nor a service name. */
  unknown: string[];
  findings: ReadFinding[];
}

/** Groups of event files in a directory. The directory is listed once; a listing error is a finding (fail closed). */
export function listEventGroups(dir: string): EventGroups {
  const findings: ReadFinding[] = [];
  let entries: string[];
  try {
    const info = lstatSync(dir);
    if (info.isSymbolicLink() || !info.isDirectory()) return { groups: [], unknown: [], findings: [{ kind: "not_regular", file: dir, detail: "not a real directory" }] };
    entries = readdirSync(dir);
  } catch {
    return { groups: [], unknown: [], findings: [{ kind: "unreadable", file: dir, detail: "directory cannot be listed" }] };
  }
  if (entries.length > MAX_DIRECTORY_ENTRIES) {
    findings.push({ kind: "directory_limit", file: dir, detail: `${entries.length} entries; only the first ${MAX_DIRECTORY_ENTRIES} were scanned` });
    entries = entries.slice(0, MAX_DIRECTORY_ENTRIES);
  }
  const users = new Map<string, Entry[]>();
  const services = new Map<string, Entry[]>();
  const unknown: string[] = [];
  for (const name of entries) {
    const user = EVENT_FILE.exec(name);
    const service = user === null ? SERVICE_EVENT_FILE.exec(name) : null;
    const m = user ?? service;
    if (m === null) {
      if (name.endsWith(".jsonl")) unknown.push(joinPath(dir, name));
      continue;
    }
    const target = user !== null ? users : services;
    const key = m[1] as string;
    target.set(key, [...(target.get(key) ?? []), { name, day: m[2] as string, n: m[3] ?? "0" }]);
  }
  const ordered = [
    ...[...users.entries()].sort((a, b) => compareDigits(a[0], b[0]) || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)),
    ...[...services.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)),
  ];
  const groups = ordered.map(([, list]) => [...list].sort(compareEntries).map((e) => joinPath(dir, e.name)));
  return { groups, unknown: unknown.sort(), findings };
}

/** Removes trailing separators so that `link/` is examined as the link itself, not as its target. */
export function trimTrailingSeparators(path: string): string {
  const trimmed = path.replace(/[/\\]+$/, "");
  return trimmed === "" ? path.slice(0, 1) : trimmed;
}

/**
 * Expands paths: a directory becomes its event files (one group per chain source, oldest first), a file stays.
 * Consecutive files given directly form one group (one stream, as before). Findings: `no_event_files` for a directory
 * without event files (not when only the scan limit hid them: `directory_limit` says that), `unknown_file` per unknown
 * `*.jsonl`. The CLI decides which of them fail.
 */
export function expandPaths(paths: readonly string[]): { files: string[]; groups: string[][]; findings: PathFinding[] } {
  const groups: string[][] = [];
  const findings: PathFinding[] = [];
  let loose: string[] | null = null;
  for (const raw of paths) {
    const path = trimTrailingSeparators(raw);
    let isDirectory = false;
    try {
      const info = lstatSync(path);
      isDirectory = info.isDirectory() && !info.isSymbolicLink();
    } catch {
      // Not found: handled when the file is read.
    }
    if (isDirectory) {
      loose = null;
      const listing = listEventGroups(path);
      findings.push(...listing.findings);
      for (const file of listing.unknown) findings.push({ kind: "unknown_file", file, detail: "not a known event file name; not verified" });
      groups.push(...listing.groups);
      if (listing.groups.length === 0 && listing.findings.length === 0) {
        findings.push({ kind: "no_event_files", file: path, detail: "the directory contains no event files" });
      }
    } else {
      if (loose === null) {
        loose = [];
        groups.push(loose);
      }
      loose.push(path);
    }
  }
  return { files: groups.flat(), groups, findings };
}

/**
 * Verifies each group as its own stream of chains (no link across groups) and merges the reports. A group whose files
 * were read without findings but hold no event yields `no_events` (files truncated to 0 bytes look like a valid log).
 */
export function verifyGroups(groups: readonly (readonly string[])[], options: ReadOptions = {}): { report: VerifyReport; noEvents: PathFinding[] } {
  const total: VerifyReport = { files: 0, events: 0, chains: [], chainFindings: [], readFindings: [], chainOk: true, metaOk: true };
  const noEvents: PathFinding[] = [];
  for (const group of groups) {
    const r = verifyFiles(group, options);
    total.files += r.files;
    total.events += r.events;
    total.chains.push(...r.chains.filter((c) => !total.chains.includes(c)));
    total.chainFindings.push(...r.chainFindings);
    total.readFindings.push(...r.readFindings);
    total.chainOk &&= r.chainOk;
    total.metaOk &&= r.metaOk;
    if (r.files > 0 && r.events === 0 && r.chainOk) {
      noEvents.push({ kind: "no_events", file: group[0] as string, detail: `${r.files} file(s) of this chain source hold no events` });
    }
  }
  return { report: total, noEvents };
}
