// Read-only event sources of the monitor: the own event files (user view) or the relay spool (admin view).
// Everything goes through the hardened reader of the guardrail plugin (src/vendor/reader.ts): no symbolic links, no
// special files, size and line limits. Files with an unexpected owner, mode or link count are reported and not shown.
import { lstatSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { ChainVerifier, eventProblem, SCHEMA, type ChainFinding } from "./chain.js";
import type { Limits } from "./limits.js";
import { maskDeep } from "./mask.js";
import { chainHash } from "./vendor/hashchain.js";
import { EVENT_FILE } from "./vendor/layout.js";
import { listEventFiles, MAX_DIRECTORY_ENTRIES, MAX_READ_BYTES, readEventFile, type ReadFinding } from "./vendor/reader.js";

export const SPOOL_FILE = /^relay-([0-9]{8})(?:-([0-9]+))?\.jsonl$/;

export interface Query {
  limit: number;
  sinceMs: number;
  nowMs: number;
  type?: string | undefined;
  session?: string | undefined;
  /** Numeric user id as text (admin view only; the user view always filters by its own id). */
  user?: string | undefined;
}

export interface RelayMeta {
  file: string | null;
  owner_uid: number | null;
  chain_ok: boolean | null;
  meta_ok: boolean | null;
  received: string | null;
}

export interface ViewEvent {
  event: Record<string, unknown>;
  relay: RelayMeta | null;
}

export interface SourceFinding {
  kind: string;
  /** File name without directory. */
  file: string;
  detail: string;
}

export interface Listing {
  events: ViewEvent[];
  hasMore: boolean;
  /** Less was read than asked for (scan budget or file size limit). */
  truncated: boolean;
  findings: SourceFinding[];
}

export interface SessionSummary {
  session_id: string;
  first_ts: string;
  last_ts: string;
  events: number;
  denies: number;
  user: { name: string; id: string } | null;
  host: string | null;
}

export interface SessionListing {
  sessions: SessionSummary[];
  truncated: boolean;
  findings: SourceFinding[];
}

export interface VerifyResult {
  ok: boolean;
  /** All files were checked within the byte budget. */
  complete: boolean;
  files: number;
  events: number;
  chains: number;
  findings: ChainFinding[];
  more_findings: number;
  read_findings: SourceFinding[];
  /** Spool only: events inside relay records that were checked, and records the relay itself marked as not ok. */
  embedded: { checked: number; relay_flagged: number } | null;
  checked_at: string;
}

export interface EventSource {
  readonly kind: "user" | "spool";
  list(q: Query): Listing;
  sessions(q: Query): SessionListing;
  verify(nowMs: number): Promise<VerifyResult>;
}

export type SourceConfig =
  | { kind: "user"; dir: string; uid: number; maxMode: number }
  | { kind: "spool"; dir: string; ownerUid: number; maxMode: number };

const yieldToLoop = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));
const MAX_SEEN = 50_000;
const BATCH = 1000;

function utcDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10).replaceAll("-", "");
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function str(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function base(path: string): string {
  const i = path.lastIndexOf("/");
  return i < 0 ? path : path.slice(i + 1);
}

function toFinding(f: ReadFinding): SourceFinding {
  return { kind: f.kind, file: base(f.file), detail: f.detail };
}

export class FileSource implements EventSource {
  readonly kind: "user" | "spool";

  constructor(
    private readonly cfg: SourceConfig,
    private readonly limits: Limits,
  ) {
    this.kind = cfg.kind;
  }

  private get ownerUid(): number {
    return this.cfg.kind === "user" ? this.cfg.uid : this.cfg.ownerUid;
  }

  /** File names (oldest first) with their UTC day. */
  private files(): { names: { name: string; day: string }[]; findings: SourceFinding[] } {
    if (this.cfg.kind === "user") {
      const uid = String(this.cfg.uid);
      // No events directory yet (the plugin has not run for this user): an empty log, not an error.
      if (missing(this.cfg.dir)) return { names: [], findings: [] };
      const listing = listEventFiles(this.cfg.dir);
      const names = listing.names.flatMap((name) => {
        const m = EVENT_FILE.exec(name);
        return m !== null && m[1] === uid ? [{ name, day: m[2] as string }] : [];
      });
      return { names, findings: listing.findings.map(toFinding) };
    }
    const findings: SourceFinding[] = [];
    let entries: string[];
    try {
      const info = lstatSync(this.cfg.dir);
      if (info.isSymbolicLink() || !info.isDirectory()) return { names: [], findings: [{ kind: "not_regular", file: base(this.cfg.dir), detail: "not a real directory" }] };
      entries = readdirSync(this.cfg.dir);
    } catch {
      return { names: [], findings: [{ kind: "unreadable", file: base(this.cfg.dir), detail: "directory cannot be listed" }] };
    }
    if (entries.length > MAX_DIRECTORY_ENTRIES) {
      findings.push({ kind: "directory_limit", file: base(this.cfg.dir), detail: `only the first ${MAX_DIRECTORY_ENTRIES} entries were scanned` });
      entries = entries.slice(0, MAX_DIRECTORY_ENTRIES);
    }
    const names = entries
      .map((name) => ({ name, m: SPOOL_FILE.exec(name) }))
      .filter((e): e is { name: string; m: RegExpExecArray } => e.m !== null)
      .sort((a, b) => {
        const ka = `${a.m[1]}-${String(Number(a.m[2] ?? 0)).padStart(4, "0")}`;
        const kb = `${b.m[1]}-${String(Number(b.m[2] ?? 0)).padStart(4, "0")}`;
        return ka < kb ? -1 : ka > kb ? 1 : 0;
      })
      .map((e) => ({ name: e.name, day: e.m[1] as string }));
    return { names, findings };
  }

  private size(path: string): number {
    try {
      return lstatSync(path).size;
    } catch {
      return 0;
    }
  }

  /** The line as a view event, or null if it is not an event of this source or not asked for. */
  private view(text: string): ViewEvent | null {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return null;
    }
    const o = record(parsed);
    if (o === null || o.schema !== SCHEMA || typeof o.type !== "string" || typeof o.ts !== "string" || typeof o.event_id !== "string") return null;
    let event: Record<string, unknown> = o;
    let relay: RelayMeta | null = null;
    if (this.cfg.kind === "spool" && o.type === "relay_record") {
      const data = record(o.data);
      const inner = record(data?.event);
      if (data === null || inner === null || inner.schema !== SCHEMA || typeof inner.type !== "string" || typeof inner.ts !== "string" || typeof inner.event_id !== "string") return null;
      event = inner;
      relay = {
        file: str(data.file),
        owner_uid: typeof data.owner_uid === "number" ? data.owner_uid : null,
        chain_ok: typeof data.chain_ok === "boolean" ? data.chain_ok : null,
        meta_ok: typeof data.meta_ok === "boolean" ? data.meta_ok : null,
        received: str(data.received),
      };
    }
    if (this.cfg.kind === "user") {
      // Only the own events, whatever the files contain.
      const user = record(event.user);
      if (user === null || String(user.id) !== String(this.cfg.uid)) return null;
    }
    return { event, relay };
  }

  private matches(v: ViewEvent, q: Query): boolean {
    const ts = Date.parse(v.event.ts as string);
    if (!Number.isFinite(ts) || ts < q.sinceMs) return false;
    if (q.type !== undefined && v.event.type !== q.type) return false;
    if (q.session !== undefined && record(v.event.claude)?.session_id !== q.session) return false;
    if (q.user !== undefined && String(record(v.event.user)?.id) !== q.user) return false;
    return true;
  }

  /** Visits matching events, newest first, within the scan budget. `visit` returns false to stop. */
  private scan(q: Query, visit: (v: ViewEvent) => boolean): { truncated: boolean; findings: SourceFinding[] } {
    const listing = this.files();
    const findings = [...listing.findings];
    const sinceDay = utcDay(q.sinceMs);
    let used = 0;
    let truncated = false;
    const seen = new Set<string>();
    for (const file of [...listing.names].reverse()) {
      if (file.day < sinceDay) continue;
      const remaining = this.limits.scanBytes - used;
      if (remaining <= 0) {
        truncated = true;
        break;
      }
      const path = join(this.cfg.dir, file.name);
      used += Math.min(this.size(path), remaining);
      const outcome = readEventFile(path, { uid: this.ownerUid, maxMode: this.cfg.maxMode, maxBytes: Math.min(remaining, MAX_READ_BYTES) });
      for (const f of outcome.findings) {
        findings.push(toFinding(f));
        if (f.kind === "oversize") truncated = true;
      }
      // A file with a foreign owner, wrong mode or extra links is reported, its content is not shown.
      if (!outcome.read || !outcome.metaOk) continue;
      for (let i = outcome.lines.length - 1; i >= 0; i -= 1) {
        const v = this.view((outcome.lines[i] as { text: string }).text);
        if (v === null || !this.matches(v, q)) continue;
        const id = v.event.event_id as string;
        if (seen.has(id)) continue;
        if (seen.size < MAX_SEEN) seen.add(id);
        if (!visit(v)) return { truncated, findings };
      }
    }
    return { truncated, findings };
  }

  list(q: Query): Listing {
    const events: ViewEvent[] = [];
    let hasMore = false;
    const r = this.scan(q, (v) => {
      if (events.length >= q.limit) {
        hasMore = true;
        return false;
      }
      events.push(v);
      return true;
    });
    return { events, hasMore, truncated: r.truncated, findings: r.findings };
  }

  sessions(q: Query): SessionListing {
    const map = new Map<string, SessionSummary>();
    let capped = false;
    const r = this.scan(q, (v) => {
      const id = str(record(v.event.claude)?.session_id);
      if (id === null) return true;
      let s = map.get(id);
      const ts = v.event.ts as string;
      if (s === undefined) {
        if (map.size >= this.limits.maxSessions) {
          capped = true;
          return true;
        }
        const user = record(v.event.user);
        const host = record(v.event.host);
        s = {
          session_id: id,
          first_ts: ts,
          last_ts: ts,
          events: 0,
          denies: 0,
          user: user !== null ? { name: String(user.name), id: String(user.id) } : null,
          host: str(host?.name),
        };
        map.set(id, s);
      }
      s.events += 1;
      if (record(v.event.decision)?.outcome === "deny") s.denies += 1;
      if (Date.parse(ts) < Date.parse(s.first_ts)) s.first_ts = ts;
      if (Date.parse(ts) > Date.parse(s.last_ts)) s.last_ts = ts;
      return true;
    });
    const sessions = [...map.values()].sort((a, b) => (a.last_ts < b.last_ts ? 1 : a.last_ts > b.last_ts ? -1 : 0));
    return { sessions, truncated: r.truncated || capped, findings: r.findings };
  }

  async verify(nowMs: number): Promise<VerifyResult> {
    const listing = this.files();
    const readFindings: SourceFinding[] = [...listing.findings];
    const verifier = new ChainVerifier();
    const embeddedLast = new Map<string, { seq: number; hash: string }>();
    const embeddedSeen = new Set<string>();
    let embeddedChecked = 0;
    let relayFlagged = 0;
    let budget = this.limits.verifyBytes;
    let complete = true;
    let files = 0;
    for (const file of listing.names) {
      if (budget <= 0) {
        complete = false;
        break;
      }
      const path = join(this.cfg.dir, file.name);
      const allowed = Math.min(budget, MAX_READ_BYTES);
      budget -= Math.min(this.size(path), allowed);
      const outcome = readEventFile(path, { uid: this.ownerUid, maxMode: this.cfg.maxMode, maxBytes: allowed });
      files += 1;
      for (const f of outcome.findings) {
        readFindings.push(toFinding(f));
        if (f.kind === "oversize") complete = false;
      }
      if (!outcome.read) continue;
      for (let i = 0; i < outcome.lines.length; i += 1) {
        const line = outcome.lines[i] as { no: number; text: string };
        const e = verifier.feed(file.name, line.no, line.text);
        if (e !== null && this.cfg.kind === "spool" && e.type === "relay_record") {
          const data = record(e.data);
          const inner = record(data?.event);
          if (data?.chain_ok === false || data?.meta_ok === false) relayFlagged += 1;
          if (inner === null || eventProblem(inner) !== null) {
            verifier.note("invalid_event", file.name, line.no, "embedded event is not a valid event");
          } else if (chainHash(inner) !== inner.hash) {
            verifier.note("hash_mismatch", file.name, line.no, "embedded event hash does not match the content");
          } else if (!embeddedSeen.has(inner.event_id as string)) {
            embeddedSeen.add(inner.event_id as string);
            embeddedChecked += 1;
            const chain = inner.chain_id as string;
            const seq = inner.seq as number;
            const prior = embeddedLast.get(chain);
            // The first event seen of a chain may start anywhere (retention); after that the links must hold.
            if (prior !== undefined && inner.type !== "chain_start" && (seq !== prior.seq + 1 || inner.prev_hash !== prior.hash)) {
              verifier.note("chain_broken", file.name, line.no, "embedded events of a user chain are not contiguous");
            }
            embeddedLast.set(chain, { seq, hash: inner.hash as string });
          }
        }
        if ((i + 1) % BATCH === 0) await yieldToLoop();
      }
      await yieldToLoop();
    }
    const report = verifier.report();
    const ok = complete && report.findings.length === 0 && report.moreFindings === 0 && readFindings.length === 0;
    return {
      ok,
      complete,
      files,
      events: report.events,
      chains: report.chains,
      findings: report.findings,
      more_findings: report.moreFindings,
      read_findings: readFindings.slice(0, 100),
      embedded: this.cfg.kind === "spool" ? { checked: embeddedChecked, relay_flagged: relayFlagged } : null,
      checked_at: new Date(nowMs).toISOString(),
    };
  }
}

/** Event as the API shows it: masked strings, no prototype tricks. */
export function present(v: ViewEvent): { event: unknown; relay: unknown } {
  return { event: maskDeep(v.event), relay: v.relay === null ? null : maskDeep(v.relay) };
}

function missing(path: string): boolean {
  try {
    lstatSync(path);
    return false;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "ENOENT";
  }
}
