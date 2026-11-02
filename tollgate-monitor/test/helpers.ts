import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request, type IncomingHttpHeaders } from "node:http";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll } from "vitest";
import { Monitor, type Audit, type MonitorOptions } from "../src/http.js";
import { DEFAULT_LIMITS, type Limits } from "../src/limits.js";
import { FileSource, type EventSource } from "../src/source.js";
import { chainHash, GENESIS_HASH } from "../src/vendor/hashchain.js";
import { issueToken, type IssuedToken } from "../src/vendor/token.js";

const made: string[] = [];
export function tmp(prefix = "tg-mon-"): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.push(dir);
  return dir;
}
afterAll(() => {
  for (const dir of made.splice(0)) rmSync(dir, { recursive: true, force: true });
});

/** The uid of the test process, whatever it is (tests must not depend on it). */
export const UID = process.getuid?.() ?? 0;
/** A fixed "now" so that file names and time windows are stable. */
export const NOW = Date.parse("2026-10-16T12:00:00.000Z");
export const DAY = "20261016";
export const CHAIN = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const CHAIN2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

export interface Spec {
  chain?: string;
  seq: number;
  prev: string;
  type?: string;
  uid?: number | string;
  name?: string;
  ts?: string;
  session?: string;
  outcome?: string;
  toolName?: string;
  reason?: string | null;
  data?: Record<string, unknown>;
  id?: string;
  host?: string;
}

export function makeEvent(s: Spec): Record<string, unknown> {
  const type = s.type ?? "decision";
  const base: Record<string, unknown> = {
    schema: "tollgate.event.v1",
    event_id: s.id ?? `00000000-0000-4000-8000-${String(s.seq).padStart(6, "0")}${(s.chain ?? CHAIN).slice(0, 6)}`,
    ts: s.ts ?? new Date(NOW - 60_000 + s.seq * 1000).toISOString(),
    chain_id: s.chain ?? CHAIN,
    seq: s.seq,
    type,
    host: { name: s.host ?? "host-1", os: "linux" },
    user: { name: s.name ?? "alice", id: String(s.uid ?? UID) },
    source: { component: "tollgate-guardrail", version: "0.1.0" },
    prev_hash: s.prev,
  };
  if (type === "decision" || type === "tool_result") {
    base.claude = { session_id: s.session ?? "s-1", tool_use_id: "tu-1", agent_id: null, agent_type: null, hook_event: "PreToolUse", permission_mode: "default" };
    base.tool = { name: s.toolName ?? "Bash", programs: ["git"], paths: [], effects: [], truncated: false };
    base.decision = { outcome: s.outcome ?? "allow", rule_kind: "none", rule_id: null, reason: s.reason ?? null, human_session: false };
  }
  if (s.data !== undefined) base.data = s.data;
  else if (type === "chain_start") base.data = { reason: "new" };
  return { ...base, hash: chainHash(base) };
}

/** A valid chain: `chain_start` followed by the given specs (seq and prev are filled in). */
export function chain(specs: Omit<Spec, "seq" | "prev">[], chainId = CHAIN, uid: number | string = UID): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [makeEvent({ chain: chainId, seq: 1, prev: GENESIS_HASH, type: "chain_start", uid })];
  for (const s of specs) {
    const prev = out.at(-1) as Record<string, unknown>;
    out.push(makeEvent({ uid, ...s, chain: chainId, seq: out.length + 1, prev: prev.hash as string }));
  }
  return out;
}

export function writeLines(path: string, lines: unknown[], mode = 0o600): void {
  writeFileSync(path, lines.map((l) => (typeof l === "string" ? l : JSON.stringify(l))).join("\n") + "\n", { mode });
  chmodSync(path, mode);
}

export function userDir(events: unknown[], uid = UID, mode = 0o600): string {
  const dir = tmp();
  writeLines(join(dir, `u${uid}-${DAY}.jsonl`), events, mode);
  return dir;
}

/** A relay_record envelope around a user event, as the relay writes it. */
export function relayRecord(inner: Record<string, unknown>, o: { chain_ok?: boolean; meta_ok?: boolean } = {}): Record<string, unknown> {
  return { schema: "tollgate.relay_record.v1", received: new Date(NOW).toISOString(), file: `u${UID}-${DAY}.jsonl`, owner_uid: UID, chain_ok: o.chain_ok ?? true, meta_ok: o.meta_ok ?? true, event: inner };
}

export function spoolDir(inners: Record<string, unknown>[]): { dir: string; events: Record<string, unknown>[] } {
  const dir = tmp("tg-spool-");
  const events = chain(inners.map((e) => ({ type: "relay_record", data: relayRecord(e) })), CHAIN2, UID);
  writeLines(join(dir, `relay-${DAY}.jsonl`), events, 0o640);
  return { dir, events };
}

export function userSource(dir: string, limits: Partial<Limits> = {}, uid = UID): FileSource {
  return new FileSource({ kind: "user", dir, uid, maxMode: 0o600 }, { ...DEFAULT_LIMITS, ...limits });
}

export function spoolSource(dir: string, limits: Partial<Limits> = {}): FileSource {
  return new FileSource({ kind: "spool", dir, ownerUid: UID, maxMode: 0o640 }, { ...DEFAULT_LIMITS, ...limits });
}

export interface Running {
  monitor: Monitor;
  port: number;
  token: IssuedToken;
  audit: { entries: { action: string; details: Record<string, unknown> }[]; fail: boolean };
  now: { value: number };
  get(path: string, headers?: Record<string, string | undefined>, method?: string): Promise<Reply>;
  auth(path: string, headers?: Record<string, string | undefined>, method?: string): Promise<Reply>;
}

export interface Reply {
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
  json: () => any; // eslint-disable-line @typescript-eslint/no-explicit-any
}

const running: Monitor[] = [];
afterAll(async () => {
  await Promise.all(running.splice(0).map((m) => m.close()));
});

export async function startMonitor(source: EventSource, o: { mode?: "user" | "admin"; limits?: Partial<Limits>; withAudit?: boolean } = {}): Promise<Running> {
  const now = { value: NOW };
  const token = issueToken(NOW, 3_600_000);
  const audit = { entries: [] as { action: string; details: Record<string, unknown> }[], fail: false };
  const sink: Audit = {
    record(action, details) {
      if (audit.fail) throw new Error("audit down");
      audit.entries.push({ action, details });
    },
  };
  const opts: MonitorOptions = { mode: o.mode ?? "user", source, token, version: "0.0.0-test", limits: o.limits ?? {}, clock: () => now.value, ...(o.withAudit === true ? { audit: sink } : {}) };
  const monitor = new Monitor(opts);
  running.push(monitor);
  const port = await monitor.listen(0);
  const get = (path: string, headers: Record<string, string | undefined> = {}, method = "GET"): Promise<Reply> =>
    new Promise((resolve, reject) => {
      const h: Record<string, string> = { Host: `127.0.0.1:${port}` };
      for (const [k, v] of Object.entries(headers)) {
        if (v === undefined) delete h[k];
        else h[k] = v;
      }
      const req = request({ host: "127.0.0.1", port, path, method, headers: h }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body, json: () => JSON.parse(body) });
        });
      });
      req.on("error", reject);
      req.end();
    });
  const auth = (path: string, headers: Record<string, string | undefined> = {}, method = "GET"): Promise<Reply> => get(path, { Authorization: `Bearer ${token.value}`, ...headers }, method);
  return { monitor, port, token, audit, now, get, auth };
}

/** Sends raw bytes and returns what comes back until the server closes the connection or `waitMs` pass. */
export function raw(port: number, text: string, waitMs = 400): Promise<string> {
  return new Promise((resolve) => {
    const socket = connect(port, "127.0.0.1", () => socket.write(text));
    let out = "";
    socket.on("data", (d) => (out += d.toString("latin1")));
    const done = (): void => {
      socket.destroy();
      resolve(out);
    };
    socket.on("close", done);
    socket.on("error", done);
    setTimeout(done, waitMs);
  });
}

export function ensureDir(path: string): string {
  mkdirSync(path, { recursive: true });
  return path;
}
