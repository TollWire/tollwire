// HTTP server of the monitor: 127.0.0.1 only, GET only, token for /api/*, strict checks of Host,
// Origin and Sec-Fetch-Site (DNS rebinding, cross-site requests), strict headers, time and resource limits.
// Error answers carry a fixed code and message; they never contain paths, stack traces or text of an exception.
// nosemgrep: tollgate.raw-socket-needs-threat-model-js threat model reviewed (monitor: loopback listener 127.0.0.1, no outbound connection)
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { ActionError, wrapLegacyControl, type AdminActions } from "./adminActions.js";
import { DEFAULT_LIMITS, type Limits } from "./limits.js";
import { maskDeep } from "./mask.js";
import { WindowLimiter } from "./ratelimit.js";
import { present, type EventSource, type Query, type VerifyResult } from "./source.js";
import { checkToken, parseBearer, type IssuedToken } from "./vendor/token.js";
import { ASSETS } from "./web/assets.js";

export const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "Content-Security-Policy": CSP,
  "Cross-Origin-Resource-Policy": "same-origin",
  "Cross-Origin-Opener-Policy": "same-origin",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
  "X-Frame-Options": "DENY",
};

const MESSAGES: Readonly<Record<string, string>> = {
  bad_request: "The request is not valid.",
  forbidden_host: "The Host header is not accepted.",
  forbidden_origin: "The request origin is not accepted.",
  unauthorized: "A valid access token is required.",
  token_expired: "The access token has expired.",
  method_not_allowed: "Only GET is supported.",
  not_found: "Not found.",
  invalid_parameter: "A query parameter is not valid.",
  too_many_requests: "Too many requests.",
  too_many_streams: "All live-view seats are taken.",
  verify_busy: "A verification is already running.",
  audit_unavailable: "The access log cannot be written; no data is delivered.",
  unsupported_media_type: "The content type must be application/json.",
  payload_too_large: "The request body is too large.",
  invalid_action: "The action is not valid.",
  confirm_invalid: "The confirmation is missing, expired, already used or does not match the action.",
  control_unavailable: "The control helper is not available.",
  control_failed: "The control helper did not carry out the action.",
  read_failed: "The data could not be read.",
};

/** Writes the access log of the admin view (`monitor_access`). Throws if the entry cannot be written. */
export interface Audit {
  record(action: string, details: Record<string, unknown>): void;
}

export interface MonitorOptions {
  mode: "user" | "admin";
  source: EventSource;
  token: IssuedToken;
  version: string;
  audit?: Audit | null;
  /** Admin actions, injected by the admin entry point. Only honoured in admin mode; without it every POST is refused. */
  actions?: AdminActions | null;
  /** @deprecated Old way (options of the action service); use `actions`. TODO: remove after monitor-control-private.patch is applied. */
  control?: object | null;
  limits?: Partial<Limits>;
  clock?: () => number;
}

/** Write endpoints of the admin view. No query string, exactly these paths. */
const POST_PATHS: ReadonlySet<string> = new Set(["/api/v1/admin/actions/prepare", "/api/v1/admin/actions/commit"]);
const MAX_BODY_BYTES = 4096;
const JSON_TYPE = /^application\/json(?:; ?charset=utf-8)?$/i;

const TYPE = /^[a-z_]{1,40}$/;
const SESSION = /^[A-Za-z0-9_.:-]{1,128}$/;
const UID = /^[0-9]{1,10}$/;
const LIMIT = /^[0-9]{1,4}$/;
const SINCE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,3})?Z$/;

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly extra: Record<string, string> = {},
  ) {
    super(code);
  }
}

interface StreamState {
  res: ServerResponse;
  timers: NodeJS.Timeout[];
  closed: boolean;
}

export class Monitor {
  readonly server: Server;
  private readonly limits: Limits;
  private readonly now: () => number;
  private readonly requests: WindowLimiter;
  private readonly authFailures: WindowLimiter;
  private readonly prepares = new WindowLimiter(10, 60_000);
  private readonly commits = new WindowLimiter(10, 60_000);
  private readonly actions: AdminActions | null;
  private readonly streams = new Set<StreamState>();
  private verifyRunning = false;
  private verifyCache: { atMs: number; result: VerifyResult } | null = null;
  private port = 0;

  constructor(private readonly opts: MonitorOptions) {
    this.limits = { ...DEFAULT_LIMITS, ...opts.limits };
    // Admin actions must leave a trace in the access log: without an audit sink the monitor refuses to start (F6).
    const injected = opts.actions ?? (opts.control === undefined || opts.control === null ? null : wrapLegacyControl(opts.control));
    if (injected !== null && (opts.audit === undefined || opts.audit === null)) throw new Error("admin actions need the access log");
    this.actions = opts.mode === "admin" ? injected : null;
    this.now = opts.clock ?? Date.now;
    this.requests = new WindowLimiter(this.limits.requestsPerSecond, 1000);
    this.authFailures = new WindowLimiter(this.limits.authFailuresPerMinute, 60_000);
    this.server = createServer({ maxHeaderSize: this.limits.maxHeaderBytes, requestTimeout: this.limits.requestTimeoutMs, headersTimeout: this.limits.headersTimeoutMs, keepAliveTimeout: this.limits.keepAliveTimeoutMs, connectionsCheckingInterval: Math.max(100, Math.min(1000, this.limits.headersTimeoutMs)) }, (req, res) => this.handle(req, res));
    this.server.maxConnections = this.limits.maxConnections;
    this.server.maxHeadersCount = 40;
    // Malformed requests: a fixed answer, then the connection is closed.
    this.server.on("clientError", (_error, socket) => {
      if (socket.writable) socket.end(`HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
      else socket.destroy();
    });
    // No upgrades, no CONNECT.
    this.server.on("upgrade", (_req, socket) => socket.destroy());
    this.server.on("connect", (_req, socket) => socket.destroy());
  }

  /** Binds 127.0.0.1. `port` 0 picks a free port. Rejects with the Node error (code EADDRINUSE for a fixed port in use). */
  listen(port = 0): Promise<number> {
    return new Promise((resolve, reject) => {
      const onError = (error: Error): void => reject(error);
      this.server.once("error", onError);
      this.server.listen({ port, host: "127.0.0.1", exclusive: true }, () => {
        this.server.off("error", onError);
        this.port = (this.server.address() as AddressInfo).port;
        resolve(this.port);
      });
    });
  }

  close(): Promise<void> {
    for (const s of [...this.streams]) this.endStream(s, "end");
    return new Promise((resolve) => {
      this.server.close(() => resolve());
      this.server.closeAllConnections();
    });
  }

  // ---- request handling -----------------------------------------------------------------------------------------

  private send(res: ServerResponse, status: number, type: string, body: string, extra: Record<string, string> = {}): void {
    if (res.headersSent) return;
    res.writeHead(status, { ...SECURITY_HEADERS, "Content-Type": type, "Content-Length": Buffer.byteLength(body), ...extra });
    res.end(body);
  }

  private json(res: ServerResponse, status: number, value: unknown, extra: Record<string, string> = {}): void {
    this.send(res, status, "application/json; charset=utf-8", JSON.stringify(value), extra);
  }

  private fail(res: ServerResponse, error: HttpError): void {
    this.json(res, error.status, { error: error.code, message: MESSAGES[error.code] ?? "Error." }, error.extra);
  }

  private handle(req: IncomingMessage, res: ServerResponse): void {
    try {
      this.route(req, res);
    } catch (error) {
      // Nothing of the exception reaches the client or the log.
      this.fail(res, error instanceof HttpError ? error : new HttpError(500, "read_failed"));
    }
  }

  private countOf(req: IncomingMessage, name: string): number {
    let n = 0;
    for (let i = 0; i < req.rawHeaders.length; i += 2) if ((req.rawHeaders[i] as string).toLowerCase() === name) n += 1;
    return n;
  }

  /** Host, Origin and Sec-Fetch-Site checks; throws HttpError. */
  private checkOrigin(req: IncomingMessage): void {
    const remote = req.socket.remoteAddress;
    if (remote !== "127.0.0.1" && remote !== "::ffff:127.0.0.1") throw new HttpError(403, "forbidden_host");
    if (this.countOf(req, "host") !== 1) throw new HttpError(400, "bad_request");
    const host = req.headers.host;
    if (host !== `127.0.0.1:${this.port}` && host !== `localhost:${this.port}`) throw new HttpError(403, "forbidden_host");
    const origin = req.headers.origin;
    const site = req.headers["sec-fetch-site"];
    if (this.countOf(req, "origin") > 1 || this.countOf(req, "sec-fetch-site") > 1) throw new HttpError(400, "bad_request");
    // Origin: absent, or exactly the page's own origin. `null` and every other origin are refused.
    if (origin !== undefined && origin !== `http://${host}`) throw new HttpError(403, "forbidden_origin");
    // Browsers always send Sec-Fetch-Site; a request with Origin but without it is not trusted.
    if (site !== undefined ? site !== "same-origin" && site !== "none" : origin !== undefined) throw new HttpError(403, "forbidden_origin");
  }

  private route(req: IncomingMessage, res: ServerResponse): void {
    this.checkOrigin(req);
    if (req.method === "POST" && this.actions !== null && POST_PATHS.has(req.url ?? "")) {
      this.post(req, res);
      return;
    }
    if (req.method !== "GET") throw new HttpError(405, "method_not_allowed", { Allow: "GET" });
    // No body on GET; no absolute-form or otherwise odd request target.
    if (req.headers["content-length"] !== undefined && req.headers["content-length"] !== "0") throw new HttpError(400, "bad_request");
    if (req.headers["transfer-encoding"] !== undefined) throw new HttpError(400, "bad_request");
    const target = req.url ?? "";
    if (target.length > this.limits.maxUrlLength || !/^\/(?!\/)[\x21-\x7e]*$/.test(target) || target.includes("\\")) throw new HttpError(400, "bad_request");
    const q = target.indexOf("?");
    const path = q < 0 ? target : target.slice(0, q);
    const query = q < 0 ? "" : target.slice(q + 1);

    const asset = Object.hasOwn(ASSETS, path) ? ASSETS[path] : undefined;
    if (asset !== undefined) {
      if (query !== "") throw new HttpError(404, "not_found");
      this.send(res, 200, asset.type, asset.body);
      return;
    }
    if (!path.startsWith("/api/")) throw new HttpError(404, "not_found");

    // Authentication first: nothing about the routes or parameters is revealed without a token.
    const now = this.now();
    const auth = checkToken(this.countOf(req, "authorization") === 1 ? parseBearer(req.headers.authorization) : null, this.opts.token, now);
    if (auth !== "ok") {
      if (!this.authFailures.hit(now)) throw new HttpError(429, "too_many_requests", { "Retry-After": String(Math.ceil(this.authFailures.retryAfterMs(now) / 1000)) });
      throw new HttpError(401, auth === "expired" ? "token_expired" : "unauthorized", { "WWW-Authenticate": "Bearer" });
    }
    if (!this.requests.hit(now)) throw new HttpError(429, "too_many_requests", { "Retry-After": "1" });

    switch (path) {
      case "/api/v1/health":
        this.noQuery(query);
        this.json(res, 200, { status: "ok", mode: this.opts.mode, source: this.opts.source.kind, version: this.opts.version, admin_actions: this.actions !== null, time: new Date(now).toISOString(), token_expires_at: new Date(this.opts.token.expiresAtMs).toISOString() });
        return;
      case "/api/v1/events":
        this.events(res, query, now);
        return;
      case "/api/v1/sessions":
        this.sessions(res, query, now);
        return;
      case "/api/v1/stream":
        this.noQuery(query);
        this.stream(req, res, now);
        return;
      case "/api/v1/verify":
        this.noQuery(query);
        this.verify(res, now);
        return;
      case "/api/v1/admin/locks":
        if (this.actions === null) throw new HttpError(404, "not_found");
        this.noQuery(query);
        this.lockView(res);
        return;
      default:
        throw new HttpError(404, "not_found");
    }
  }

  // ---- admin actions (POST) -------------------------------------------------------------------------------------

  /** Refuses what a cross-site page could still send: needs the exact own Origin, `Sec-Fetch-Site: same-origin`, JSON. */
  private checkPost(req: IncomingMessage): void {
    const host = req.headers.host;
    if (req.headers.origin !== `http://${host}`) throw new HttpError(403, "forbidden_origin");
    if (req.headers["sec-fetch-site"] !== "same-origin") throw new HttpError(403, "forbidden_origin");
    if (this.countOf(req, "content-type") !== 1 || !JSON_TYPE.test(req.headers["content-type"] ?? "")) throw new HttpError(415, "unsupported_media_type");
    if (req.headers["content-encoding"] !== undefined) throw new HttpError(415, "unsupported_media_type");
    const length = req.headers["content-length"];
    if (length !== undefined && (!/^[0-9]{1,5}$/.test(length) || Number(length) > MAX_BODY_BYTES)) throw new HttpError(413, "payload_too_large");
  }

  private readBody(req: IncomingMessage): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      let settled = false;
      const end = (error: HttpError | null, value?: unknown): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error !== null) reject(error);
        else resolve(value);
      };
      const timer = setTimeout(() => {
        end(new HttpError(400, "bad_request"));
        req.destroy();
      }, Math.min(this.limits.requestTimeoutMs, 5000));
      req.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          end(new HttpError(413, "payload_too_large"));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on("error", () => end(new HttpError(400, "bad_request")));
      req.on("end", () => {
        try {
          const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
          end(null, JSON.parse(text));
        } catch {
          end(new HttpError(400, "bad_request"));
        }
      });
    });
  }

  private post(req: IncomingMessage, res: ServerResponse): void {
    const run = async (): Promise<void> => {
      const actions = this.actions as AdminActions;
      const now = this.now();
      // Order: token first (nothing is revealed without it), then the cross-site checks, then limits, then the body.
      const auth = checkToken(this.countOf(req, "authorization") === 1 ? parseBearer(req.headers.authorization) : null, this.opts.token, now);
      if (auth !== "ok") {
        if (!this.authFailures.hit(now)) throw new HttpError(429, "too_many_requests", { "Retry-After": String(Math.ceil(this.authFailures.retryAfterMs(now) / 1000)) });
        throw new HttpError(401, auth === "expired" ? "token_expired" : "unauthorized", { "WWW-Authenticate": "Bearer" });
      }
      if (!this.requests.hit(now)) throw new HttpError(429, "too_many_requests", { "Retry-After": "1" });
      this.checkPost(req);
      const commit = req.url === "/api/v1/admin/actions/commit";
      const limiter = commit ? this.commits : this.prepares;
      if (!limiter.hit(now)) throw new HttpError(429, "too_many_requests", { "Retry-After": String(Math.ceil(limiter.retryAfterMs(now) / 1000)) });
      const body = await this.readBody(req);
      if (body === null || typeof body !== "object" || Array.isArray(body)) throw new HttpError(400, "bad_request");
      const fields = body as Record<string, unknown>;
      try {
        if (!commit) {
          if (Object.keys(fields).length !== 1 || !Object.hasOwn(fields, "action")) throw new HttpError(400, "bad_request");
          const prepared = actions.prepare(fields.action, now);
          this.audit("admin_prepare", { kind: prepared.summary.kind, target: prepared.summary.target });
          this.json(res, 200, prepared);
          return;
        }
        if (Object.keys(fields).length !== 2 || !Object.hasOwn(fields, "action") || !Object.hasOwn(fields, "confirm_id")) throw new HttpError(400, "bad_request");
        const done = await actions.commit(fields.confirm_id, fields.action, now, (action, details) => this.audit(action, details));
        this.json(res, 200, done);
      } catch (error) {
        if (error instanceof ActionError) {
          const status = error.code === "invalid_action" ? 400 : error.code === "confirm_invalid" ? 409 : 503;
          this.json(res, status, { error: error.code, message: MESSAGES[error.code], ...(error.detail === null ? {} : { control_code: error.detail }) });
          return;
        }
        throw error;
      }
    };
    run().catch((error: unknown) => this.fail(res, error instanceof HttpError ? error : new HttpError(500, "read_failed")));
  }

  private lockView(res: ServerResponse): void {
    const actions = this.actions as AdminActions;
    this.audit("admin_locks", {});
    let view;
    try {
      view = actions.locks();
    } catch {
      throw new HttpError(500, "read_failed");
    }
    this.json(res, 200, { host: actions.hostName, ...view });
  }

  // ---- parameters -----------------------------------------------------------------------------------------------

  private noQuery(query: string): void {
    if (query !== "") throw new HttpError(400, "invalid_parameter");
  }

  private params(query: string, allowed: readonly string[], now: number): Query {
    const seen = new Map<string, string>();
    if (query !== "") {
      for (const part of query.split("&")) {
        const eq = part.indexOf("=");
        let key: string;
        let value: string;
        try {
          key = decodeURIComponent(eq < 0 ? part : part.slice(0, eq));
          value = eq < 0 ? "" : decodeURIComponent(part.slice(eq + 1));
        } catch {
          throw new HttpError(400, "invalid_parameter");
        }
        if (!allowed.includes(key) || seen.has(key) || value.length > 128) throw new HttpError(400, "invalid_parameter");
        seen.set(key, value);
      }
    }
    const out: Query = { limit: this.limits.defaultLimit, sinceMs: now - this.limits.defaultSinceMs, nowMs: now };
    const limit = seen.get("limit");
    if (limit !== undefined) {
      if (!LIMIT.test(limit)) throw new HttpError(400, "invalid_parameter");
      const n = Number(limit);
      if (n < 1 || n > this.limits.maxLimit) throw new HttpError(400, "invalid_parameter");
      out.limit = n;
    }
    const since = seen.get("since");
    if (since !== undefined) {
      const ms = SINCE.test(since) ? Date.parse(since) : Number.NaN;
      if (!Number.isFinite(ms) || ms < now - this.limits.maxSinceMs || ms > now) throw new HttpError(400, "invalid_parameter");
      out.sinceMs = ms;
    }
    const type = seen.get("type");
    if (type !== undefined) {
      if (!TYPE.test(type)) throw new HttpError(400, "invalid_parameter");
      out.type = type;
    }
    const session = seen.get("session");
    if (session !== undefined) {
      if (!SESSION.test(session)) throw new HttpError(400, "invalid_parameter");
      out.session = session;
    }
    const user = seen.get("user");
    if (user !== undefined) {
      if (!UID.test(user)) throw new HttpError(400, "invalid_parameter");
      out.user = user;
    }
    return out;
  }

  private allowed(...names: string[]): string[] {
    // The user view cannot ask for other users at all.
    return this.opts.mode === "admin" ? names : names.filter((n) => n !== "user");
  }

  private audit(action: string, details: Record<string, unknown>): void {
    const audit = this.opts.audit;
    if (audit === null || audit === undefined) return;
    try {
      audit.record(action, details);
    } catch {
      throw new HttpError(503, "audit_unavailable");
    }
  }

  private describe(q: Query): Record<string, unknown> {
    return { limit: q.limit, since: new Date(q.sinceMs).toISOString(), type: q.type ?? null, session: q.session ?? null, user: q.user ?? null };
  }

  // ---- routes ---------------------------------------------------------------------------------------------------

  private events(res: ServerResponse, query: string, now: number): void {
    const q = this.params(query, this.allowed("limit", "since", "type", "session", "user"), now);
    this.audit("events", this.describe(q));
    let listing;
    try {
      listing = this.opts.source.list(q);
    } catch {
      throw new HttpError(500, "read_failed");
    }
    const items: unknown[] = [];
    let bytes = 0;
    let cut = false;
    for (const v of listing.events) {
      const item = present(v);
      const size = Buffer.byteLength(JSON.stringify(item)) + 1;
      if (bytes + size > this.limits.responseBytes) {
        cut = true;
        break;
      }
      bytes += size;
      items.push(item);
    }
    this.json(res, 200, { events: items, has_more: listing.hasMore || cut, truncated: listing.truncated || cut, findings: maskDeep(listing.findings.slice(0, 50)) });
  }

  private sessions(res: ServerResponse, query: string, now: number): void {
    const q = this.params(query, this.allowed("since", "type", "session", "user"), now);
    this.audit("sessions", this.describe(q));
    let result;
    try {
      result = this.opts.source.sessions({ ...q, limit: this.limits.maxLimit });
    } catch {
      throw new HttpError(500, "read_failed");
    }
    this.json(res, 200, { sessions: maskDeep(result.sessions), truncated: result.truncated, findings: maskDeep(result.findings.slice(0, 50)) });
  }

  private verify(res: ServerResponse, now: number): void {
    const cache = this.verifyCache;
    if (cache !== null && now - cache.atMs < this.limits.verifyCacheMs && now >= cache.atMs) {
      this.json(res, 200, maskDeep(cache.result));
      return;
    }
    if (this.verifyRunning) throw new HttpError(429, "verify_busy", { "Retry-After": "2" });
    this.audit("verify", {});
    this.verifyRunning = true;
    this.opts.source.verify(now).then(
      (result) => {
        this.verifyRunning = false;
        this.verifyCache = { atMs: this.now(), result };
        this.json(res, 200, maskDeep(result));
      },
      () => {
        this.verifyRunning = false;
        this.fail(res, new HttpError(500, "read_failed"));
      },
    );
  }

  // ---- live view (SSE) ------------------------------------------------------------------------------------------

  private stream(req: IncomingMessage, res: ServerResponse, now: number): void {
    // A seat is taken only after authentication (checked before) and limited.
    if (this.streams.size >= this.limits.sseSeats) throw new HttpError(503, "too_many_streams", { "Retry-After": "5" });
    this.audit("stream_open", {});
    const state: StreamState = { res, timers: [], closed: false };
    this.streams.add(state);
    res.writeHead(200, { ...SECURITY_HEADERS, "Content-Type": "text/event-stream; charset=utf-8", Connection: "keep-alive", "X-Accel-Buffering": "no" });
    res.write(": ready\n\n");
    const seen = new Set<string>();
    const order: string[] = [];
    const remember = (id: string): void => {
      seen.add(id);
      order.push(id);
      if (order.length > 5000) seen.delete(order.shift() as string);
    };
    try {
      for (const v of this.opts.source.list({ limit: 1000, sinceMs: now - 120_000, nowMs: now }).events) remember(v.event.event_id as string);
    } catch {
      // The first poll reports the problem.
    }
    let drainSince: number | null = null;
    const poll = (): void => {
      if (state.closed) return;
      const t = this.now();
      if (res.writableNeedDrain) {
        // Backpressure: nothing is queued for a slow client; a client that does not catch up is disconnected.
        drainSince ??= t;
        if (t - drainSince > this.limits.sseDrainMs) this.endStream(state, "slow");
        return;
      }
      drainSince = null;
      try {
        const fresh = this.opts.source.list({ limit: 200, sinceMs: t - 120_000, nowMs: t }).events.filter((v) => !seen.has(v.event.event_id as string)).reverse();
        for (const v of fresh) {
          remember(v.event.event_id as string);
          res.write(`data: ${JSON.stringify(present(v))}\n\n`);
        }
      } catch {
        res.write(`event: error\ndata: ${JSON.stringify({ error: "read_failed" })}\n\n`);
      }
    };
    state.timers.push(setInterval(poll, this.limits.ssePollMs));
    state.timers.push(setInterval(() => { if (!res.writableNeedDrain) res.write(": keep-alive\n\n"); }, this.limits.sseKeepAliveMs));
    state.timers.push(setTimeout(() => this.endStream(state, "end"), this.limits.sseMaxMs));
    for (const timer of state.timers) timer.unref();
    res.on("close", () => this.endStream(state, null));
    req.on("error", () => this.endStream(state, null));
  }

  private endStream(state: StreamState, reason: "end" | "slow" | null): void {
    if (state.closed) return;
    state.closed = true;
    for (const t of state.timers) {
      clearInterval(t);
      clearTimeout(t);
    }
    this.streams.delete(state);
    try {
      this.opts.audit?.record("stream_close", { reason: reason ?? "client" });
    } catch {
      // The end of a stream cannot be refused; the missing entry shows in the access log chain of the next start.
    }
    if (reason !== null && !state.res.writableEnded) {
      try {
        if (reason === "end") state.res.end("event: end\ndata: {}\n\n");
        else state.res.destroy();
      } catch {
        state.res.destroy();
      }
    }
  }
}
