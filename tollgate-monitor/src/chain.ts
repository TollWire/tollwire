// Chain verification of event files, line by line (monitor endpoint /api/v1/verify). Same rules as `tollgate-events verify`
// of the guardrail plugin (docs/events-v1.md): schema, hash, `seq` continuity, `prev_hash` links, chain markers.
import { chainHash, GENESIS_HASH } from "./vendor/hashchain.js";

export const SCHEMA = "tollgate.event.v1";
const HEX64 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_FINDINGS = 100;

export type ChainFindingKind = "invalid_json" | "invalid_event" | "hash_mismatch" | "chain_broken" | "start_invalid" | "unlinked" | "link_mismatch";

export interface ChainFinding {
  kind: ChainFindingKind;
  /** File name without directory. */
  file: string;
  line: number;
  detail: string;
}

export interface ChainReport {
  events: number;
  chains: number;
  findings: ChainFinding[];
  /** Findings beyond the list limit. */
  moreFindings: number;
}

interface Last {
  chain_id: string;
  seq: number;
  hash: string;
}

/** Validates the fields every event needs for the chain; returns a short problem text or null. */
export function eventProblem(e: Record<string, unknown>): string | null {
  if (e.schema !== SCHEMA) return "schema is not tollgate.event.v1";
  if (typeof e.chain_id !== "string" || !UUID.test(e.chain_id)) return "chain_id is not a UUID";
  if (typeof e.seq !== "number" || !Number.isSafeInteger(e.seq) || e.seq < 1) return "seq is not a positive integer";
  if (typeof e.hash !== "string" || !HEX64.test(e.hash)) return "hash is not 64 hex digits";
  if (typeof e.prev_hash !== "string" || !HEX64.test(e.prev_hash)) return "prev_hash is not 64 hex digits";
  if (typeof e.type !== "string" || typeof e.ts !== "string" || typeof e.event_id !== "string") return "type, ts or event_id missing";
  return null;
}

export class ChainVerifier {
  private last: Last | null = null;
  private events = 0;
  private readonly chains = new Set<string>();
  private readonly findings: ChainFinding[] = [];
  private more = 0;

  private add(kind: ChainFindingKind, file: string, line: number, detail: string): void {
    if (this.findings.length < MAX_FINDINGS) this.findings.push({ kind, file, line, detail });
    else this.more += 1;
  }

  /** Feeds one line (in file order, files oldest first). Returns the parsed event if it is valid and its hash matches. */
  feed(file: string, line: number, text: string): Record<string, unknown> | null {
    if (text === "") return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      this.add("invalid_json", file, line, "the line is not valid JSON");
      return null;
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      this.add("invalid_event", file, line, "the line is not a JSON object");
      return null;
    }
    const e = parsed as Record<string, unknown>;
    const problem = eventProblem(e);
    if (problem !== null) {
      this.add("invalid_event", file, line, problem);
      return null;
    }
    this.events += 1;
    if (chainHash(e) !== e.hash) {
      this.add("hash_mismatch", file, line, "the hash does not match the content");
      return null;
    }
    const seq = e.seq as number;
    const chainId = e.chain_id as string;
    const type = e.type as string;
    if (type === "chain_start") {
      const data = (e.data ?? {}) as Record<string, unknown>;
      if (seq !== 1) this.add("start_invalid", file, line, "chain_start must have seq 1");
      else if (data.reason !== "corruption" && e.prev_hash !== GENESIS_HASH) this.add("start_invalid", file, line, "chain_start must start at the genesis hash");
      else if (data.reason === "corruption" && this.last !== null && data.broken_chain_id === this.last.chain_id && e.prev_hash !== this.last.hash) {
        this.add("link_mismatch", file, line, "the corruption link does not point to the last valid event");
      }
      this.chains.add(chainId);
    } else if (this.last === null || this.last.chain_id !== chainId) {
      this.add(type === "chain_continue" ? "unlinked" : "chain_broken", file, line, type === "chain_continue" ? "chain_continue without a verified predecessor" : "event of an unknown chain");
      this.chains.add(chainId);
    } else if (seq !== this.last.seq + 1) {
      this.add("chain_broken", file, line, `sequence gap (expected ${this.last.seq + 1}, found ${seq})`);
    } else if (e.prev_hash !== this.last.hash) {
      this.add("chain_broken", file, line, "prev_hash does not match the previous event");
    }
    this.last = { chain_id: chainId, seq, hash: e.hash as string };
    return e;
  }

  /** Records a finding of the caller (for example about an embedded event). */
  note(kind: ChainFindingKind, file: string, line: number, detail: string): void {
    this.add(kind, file, line, detail);
  }

  report(): ChainReport {
    return { events: this.events, chains: this.chains.size, findings: [...this.findings], moreFindings: this.more };
  }
}
