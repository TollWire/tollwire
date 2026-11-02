import { appendFileSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { connect } from "node:net";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CSP } from "../src/http.js";
import type { EventSource } from "../src/source.js";
import { chain, DAY, makeEvent, NOW, raw, startMonitor, UID, userDir, userSource } from "./helpers.js";

const SECURITY = ["content-security-policy", "cross-origin-resource-policy", "cross-origin-opener-policy", "x-content-type-options", "referrer-policy", "cache-control"] as const;

function basic(): { dir: string; events: Record<string, unknown>[] } {
  const events = chain([{ outcome: "deny", reason: "Force push is not allowed.", session: "s-1" }, { session: "s-2", toolName: "Edit" }]);
  return { dir: userDir(events), events };
}

describe("binding and static files", () => {
  it("binds to 127.0.0.1 only and serves the page without data and without a token", async () => {
    const m = await startMonitor(userSource(basic().dir));
    expect(m.monitor.server.address()).toMatchObject({ address: "127.0.0.1", family: "IPv4" });
    const page = await m.get("/");
    expect(page.status).toBe(200);
    expect(page.headers["content-type"]).toContain("text/html");
    expect(page.body).toContain("/app.js");
    expect(page.body).not.toContain(m.token.value);
    expect((await m.get("/app.js")).status).toBe(200);
    expect((await m.get("/style.css")).status).toBe(200);
  });

  it("sends the security headers with the exact policy on every kind of answer", async () => {
    const m = await startMonitor(userSource(basic().dir));
    const answers = [await m.get("/"), await m.get("/nope"), await m.get("/api/v1/health"), await m.auth("/api/v1/health"), await m.get("/", {}, "POST"), await m.get("/", { Host: "evil.example" })];
    for (const a of answers) {
      for (const h of SECURITY) expect(a.headers[h], `${a.status} ${h}`).toBeDefined();
      expect(a.headers["content-security-policy"]).toBe(CSP);
      expect(a.headers["cross-origin-resource-policy"]).toBe("same-origin");
      expect(a.headers["cross-origin-opener-policy"]).toBe("same-origin");
      expect(a.headers["x-content-type-options"]).toBe("nosniff");
      expect(a.headers["referrer-policy"]).toBe("no-referrer");
      expect(a.headers["cache-control"]).toBe("no-store");
      expect(Object.keys(a.headers).filter((k) => k.startsWith("access-control-"))).toEqual([]);
    }
    expect(CSP).toBe("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'");
  });

  it("knows only the exact static routes", async () => {
    const m = await startMonitor(userSource(basic().dir));
    for (const path of ["/index.htm", "/app.js/", "/app.js?x=1", "/..%2f..%2fetc%2fpasswd", "/../etc/passwd", "/%2e%2e/", "/static/app.js", "/constructor", "/__proto__", "/toString"]) {
      expect((await m.get(path)).status, path).toBe(404);
    }
  });
});

describe("Host, Origin and request target (DNS rebinding, cross-site)", () => {
  it("refuses a wrong Host for static files and for the API, even with a valid token", async () => {
    const m = await startMonitor(userSource(basic().dir));
    for (const host of ["evil.example", "evil.example:" + m.port, "127.0.0.1", "localhost", "127.0.0.1:1", `127.0.0.1:${m.port}.evil.example`, `[::1]:${m.port}`, `0.0.0.0:${m.port}`, `LOCALHOST:${m.port}`]) {
      expect((await m.get("/", { Host: host })).status, host).toBe(403);
      expect((await m.auth("/api/v1/events", { Host: host })).status, host).toBe(403);
    }
  });

  it("accepts 127.0.0.1:port and localhost:port", async () => {
    const m = await startMonitor(userSource(basic().dir));
    expect((await m.auth("/api/v1/health", { Host: `localhost:${m.port}` })).status).toBe(200);
    expect((await m.auth("/api/v1/health", { Host: `127.0.0.1:${m.port}` })).status).toBe(200);
  });

  it("refuses duplicate Host headers, absolute request targets and a double slash", async () => {
    const m = await startMonitor(userSource(basic().dir));
    const host = `127.0.0.1:${m.port}`;
    expect(await raw(m.port, `GET / HTTP/1.1\r\nHost: ${host}\r\nHost: evil.example\r\nConnection: close\r\n\r\n`)).toMatch(/^HTTP\/1\.1 400/);
    expect(await raw(m.port, `GET / HTTP/1.1\r\nHost: evil.example\r\nHost: ${host}\r\nConnection: close\r\n\r\n`)).toMatch(/^HTTP\/1\.1 400/);
    expect(await raw(m.port, `GET http://${host}/ HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`)).toMatch(/^HTTP\/1\.1 400/);
    expect(await raw(m.port, `GET //evil.example/ HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`)).toMatch(/^HTTP\/1\.1 400/);
    expect(await raw(m.port, `GET /\\x HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`)).toMatch(/^HTTP\/1\.1 400/);
    expect(await raw(m.port, `GET / HTTP/1.1\r\nConnection: close\r\n\r\n`)).toMatch(/^HTTP\/1\.1 400/);
    expect(await raw(m.port, `GET / HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n`)).toMatch(/^HTTP\/1\.1 (400|403)/);
  });

  it("refuses a body and chunked transfer on GET", async () => {
    const m = await startMonitor(userSource(basic().dir));
    const host = `127.0.0.1:${m.port}`;
    expect(await raw(m.port, `GET / HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd`)).toMatch(/^HTTP\/1\.1 400/);
    expect(await raw(m.port, `GET / HTTP/1.1\r\nHost: ${host}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n`)).toMatch(/^HTTP\/1\.1 400/);
  });

  it("checks Origin: absent or exactly the own origin", async () => {
    const m = await startMonitor(userSource(basic().dir));
    const own = `http://127.0.0.1:${m.port}`;
    for (const origin of ["http://evil.example", "null", `http://localhost:${m.port}`, `https://127.0.0.1:${m.port}`, `${own}/`, `${own}.evil.example`]) {
      const r = await m.auth("/api/v1/health", { Origin: origin, "Sec-Fetch-Site": "same-origin" });
      expect(r.status, origin).toBe(403);
      expect(r.json().error).toBe("forbidden_origin");
    }
    expect((await m.auth("/api/v1/health", { Origin: own, "Sec-Fetch-Site": "same-origin" })).status).toBe(200);
    expect((await m.auth("/api/v1/health")).status).toBe(200);
  });

  it("checks Sec-Fetch-Site: same-origin and none pass; cross-site, same-site and an Origin without it do not", async () => {
    const m = await startMonitor(userSource(basic().dir));
    for (const site of ["same-origin", "none"]) expect((await m.auth("/api/v1/health", { "Sec-Fetch-Site": site })).status, site).toBe(200);
    for (const site of ["cross-site", "same-site", "", "SAME-ORIGIN", "other"]) {
      expect((await m.auth("/api/v1/health", { "Sec-Fetch-Site": site })).status, site).toBe(403);
      expect((await m.get("/", { "Sec-Fetch-Site": site })).status, site).toBe(403);
    }
    expect((await m.auth("/api/v1/health", { Origin: `http://127.0.0.1:${m.port}` })).status).toBe(403);
  });

  it("answers only GET: other methods get 405 without CORS headers, preflights are refused", async () => {
    const m = await startMonitor(userSource(basic().dir));
    for (const method of ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]) {
      const r = await m.auth("/api/v1/events", {}, method);
      expect(r.status, method).toBe(405);
      expect(r.headers.allow).toBe("GET");
      expect(r.headers["access-control-allow-origin"]).toBeUndefined();
    }
    const preflight = await m.get("/api/v1/events", { Origin: "http://evil.example", "Access-Control-Request-Method": "GET", "Sec-Fetch-Site": "cross-site" }, "OPTIONS");
    expect(preflight.status).toBe(403);
    expect(preflight.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("does not accept upgrades or CONNECT", async () => {
    const m = await startMonitor(userSource(basic().dir));
    const host = `127.0.0.1:${m.port}`;
    expect(await raw(m.port, `GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)).toBe("");
    expect(await raw(m.port, `CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n`)).toBe("");
  });
});

describe("token", () => {
  it("every API route needs a valid Bearer token; unknown routes do not reveal themselves", async () => {
    const m = await startMonitor(userSource(basic().dir));
    for (const path of ["/api/v1/health", "/api/v1/events", "/api/v1/sessions", "/api/v1/stream", "/api/v1/verify", "/api/v1/unknown", "/api/", "/api/v1/events?limit=1"]) {
      const r = await m.get(path);
      expect(r.status, path).toBe(401);
      expect(r.headers["www-authenticate"]).toBe("Bearer");
      expect(r.json().error).toBe("unauthorized");
    }
  });

  it("refuses wrong, malformed and misplaced tokens", async () => {
    const m = await startMonitor(userSource(basic().dir));
    const t = m.token.value;
    const bad: Record<string, string>[] = [
      { Authorization: "Bearer wrong" },
      { Authorization: "Bearer" },
      { Authorization: `Basic ${t}` },
      { Authorization: `bearer ${t}` },
      { Authorization: `Bearer ${t}x` },
      { Authorization: `Bearer ${t.slice(0, -1)}` },
      { Authorization: t },
      { Authorization: `Bearer ${"a".repeat(600)}` },
      { Cookie: `token=${t}` },
      { "X-Token": t },
    ];
    for (const h of bad) expect((await m.get("/api/v1/health", h)).status, JSON.stringify(Object.keys(h))).toBe(401);
    expect((await m.get(`/api/v1/health?token=${t}`)).status).toBe(401); // the query is not a way to pass the token
    expect((await m.get(`/api/v1/health?token=${t}`, { Authorization: `Bearer ${t}` })).status).toBe(400);
  });

  it("refuses two Authorization headers", async () => {
    const m = await startMonitor(userSource(basic().dir));
    const r = await raw(m.port, `GET /api/v1/health HTTP/1.1\r\nHost: 127.0.0.1:${m.port}\r\nAuthorization: Bearer ${m.token.value}\r\nAuthorization: Bearer x\r\nConnection: close\r\n\r\n`);
    expect(r).toMatch(/^HTTP\/1\.1 401/);
  });

  it("an expired token is refused with its own code", async () => {
    const m = await startMonitor(userSource(basic().dir));
    expect((await m.auth("/api/v1/health")).status).toBe(200);
    m.now.value = m.token.expiresAtMs;
    const r = await m.auth("/api/v1/health");
    expect(r.status).toBe(401);
    expect(r.json().error).toBe("token_expired");
  });

  it("bounds failed attempts without locking out the valid token", async () => {
    const m = await startMonitor(userSource(basic().dir), { limits: { authFailuresPerMinute: 3 } });
    const codes: number[] = [];
    for (let i = 0; i < 6; i += 1) codes.push((await m.get("/api/v1/health", { Authorization: "Bearer nope" })).status);
    expect(codes).toEqual([401, 401, 401, 429, 429, 429]);
    expect((await m.auth("/api/v1/health")).status).toBe(200);
    m.now.value += 61_000;
    expect((await m.get("/api/v1/health", { Authorization: "Bearer nope" })).status).toBe(401);
  });

  it("limits authenticated requests per second", async () => {
    const m = await startMonitor(userSource(basic().dir), { limits: { requestsPerSecond: 3 } });
    const codes: number[] = [];
    for (let i = 0; i < 5; i += 1) codes.push((await m.auth("/api/v1/health")).status);
    expect(codes).toEqual([200, 200, 200, 429, 429]);
    const limited = await m.auth("/api/v1/health");
    expect(limited.headers["retry-after"]).toBe("1");
    m.now.value += 1100;
    expect((await m.auth("/api/v1/health")).status).toBe(200);
  });
});

describe("answers", () => {
  it("shows no paths, stack traces or exception text when reading fails", async () => {
    const failing: EventSource = {
      kind: "user",
      list() {
        throw new Error("EACCES: permission denied, open '/var/log/tollgate/events/1000/u1000.jsonl'\n    at /opt/tollgate/monitor/dist/source.js:1:1");
      },
      sessions() {
        throw new Error("/secret/path");
      },
      verify() {
        return Promise.reject(new Error("/secret/path at /x.js:1"));
      },
    };
    const m = await startMonitor(failing);
    for (const path of ["/api/v1/events", "/api/v1/sessions", "/api/v1/verify"]) {
      const r = await m.auth(path);
      expect(r.status, path).toBe(500);
      expect(r.body).not.toMatch(/\/var|\/opt|\/secret|EACCES|at \/|\.js|Error/);
      expect(r.json()).toEqual({ error: "read_failed", message: "The data could not be read." });
    }
  });

  it("error answers for bad requests have a fixed shape", async () => {
    const m = await startMonitor(userSource(basic().dir));
    for (const r of [await m.get("/nope"), await m.get("/", { Host: "x" }), await m.get("/", {}, "POST"), await m.auth("/api/v1/events?limit=zzz")]) {
      const body = r.json() as Record<string, unknown>;
      expect(Object.keys(body).sort()).toEqual(["error", "message"]);
      expect(r.body).not.toContain("/");
    }
  });

  it("closes a connection that sends its headers too slowly", async () => {
    const m = await startMonitor(userSource(basic().dir), { limits: { headersTimeoutMs: 200, requestTimeoutMs: 400 } });
    const closedAfter = await new Promise<number>((resolve) => {
      const start = Date.now();
      const socket = connect(m.port, "127.0.0.1", () => socket.write(`GET / HTTP/1.1\r\nHost: 127.0.0.1:${m.port}\r\nX-Slow:`));
      socket.resume();
      socket.on("close", () => resolve(Date.now() - start));
      socket.on("error", () => undefined);
      setTimeout(() => {
        socket.destroy();
        resolve(-1);
      }, 4000);
    });
    expect(closedAfter).toBeGreaterThan(0);
    expect(closedAfter).toBeLessThan(3000);
  }, 10_000);

  it("limits the number of connections", async () => {
    const m = await startMonitor(userSource(basic().dir), { limits: { maxConnections: 2, headersTimeoutMs: 5000 } });
    const sockets = [] as ReturnType<typeof connect>[];
    const closed: boolean[] = [false, false, false];
    for (let i = 0; i < 3; i += 1) {
      const socket = connect(m.port, "127.0.0.1");
      socket.resume();
      socket.on("error", () => undefined);
      socket.on("close", () => (closed[i] = true));
      sockets.push(socket);
      await new Promise((r) => setTimeout(r, 80));
    }
    await new Promise((r) => setTimeout(r, 200));
    expect(closed).toEqual([false, false, true]);
    for (const s of sockets) s.destroy();
  });
});

describe("live view (SSE)", () => {
  function open(port: number, headers: Record<string, string>): Promise<{ status: number; chunks: string[]; close: () => void; ended: Promise<void> }> {
    return new Promise((resolve, reject) => {
      const req = request({ host: "127.0.0.1", port, path: "/api/v1/stream", headers: { Host: `127.0.0.1:${port}`, ...headers } }, (res) => {
        const chunks: string[] = [];
        let finish: () => void = () => undefined;
        const ended = new Promise<void>((r) => (finish = r));
        res.setEncoding("utf8");
        res.on("data", (c: string) => chunks.push(c));
        res.on("end", finish);
        res.on("close", finish);
        resolve({ status: res.statusCode ?? 0, chunks, close: () => req.destroy(), ended });
      });
      req.on("error", reject);
      req.end();
    });
  }
  const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

  it("takes no seat without authentication", async () => {
    const m = await startMonitor(userSource(basic().dir), { limits: { sseSeats: 1, ssePollMs: 50 } });
    for (let i = 0; i < 3; i += 1) {
      const r = await open(m.port, {});
      expect(r.status).toBe(401);
    }
    const ok = await open(m.port, { Authorization: `Bearer ${m.token.value}` });
    expect(ok.status).toBe(200);
    ok.close();
  });

  it("limits the seats, frees them when the client leaves, and delivers new events", async () => {
    const { dir, events } = basic();
    const m = await startMonitor(userSource(dir), { limits: { sseSeats: 1, ssePollMs: 40, sseKeepAliveMs: 5000 } });
    const auth = { Authorization: `Bearer ${m.token.value}` };
    const a = await open(m.port, auth);
    expect(a.status).toBe(200);
    expect((await open(m.port, auth)).status).toBe(503);
    await wait(120);
    const last = events.at(-1) as Record<string, unknown>;
    const fresh = makeEvent({ seq: events.length + 1, prev: last.hash as string, ts: new Date(NOW).toISOString(), session: "s-live", toolName: "<img src=x onerror=alert(1)>" });
    appendFileSync(join(dir, `u${UID}-${DAY}.jsonl`), JSON.stringify(fresh) + "\n");
    await wait(300);
    const text = a.chunks.join("");
    expect(text).toContain(": ready");
    expect(text).toContain("s-live");
    expect(text.match(/^data: /gm)?.length).toBe(1); // earlier events are not repeated
    a.close();
    await a.ended;
    await wait(100);
    const b = await open(m.port, auth);
    expect(b.status).toBe(200);
    b.close();
  });

  it("ends a stream after its maximum lifetime", async () => {
    const m = await startMonitor(userSource(basic().dir), { limits: { sseMaxMs: 150, ssePollMs: 40 } });
    const a = await open(m.port, { Authorization: `Bearer ${m.token.value}` });
    await a.ended;
    expect(a.chunks.join("")).toContain("event: end");
  });

  it("does not deliver the events of other users", async () => {
    const { dir } = basic();
    const m = await startMonitor(userSource(dir), { limits: { ssePollMs: 40 } });
    const a = await open(m.port, { Authorization: `Bearer ${m.token.value}` });
    await wait(100);
    const foreign = makeEvent({ seq: 99, prev: "0".repeat(64), uid: UID + 1, name: "mallory", ts: new Date(NOW).toISOString(), session: "s-foreign" });
    appendFileSync(join(dir, `u${UID}-${DAY}.jsonl`), JSON.stringify(foreign) + "\n");
    await wait(250);
    expect(a.chunks.join("")).not.toContain("s-foreign");
    a.close();
  });

  it("writing a file by hand does not break the view", async () => {
    const m = await startMonitor(userSource(basic().dir));
    writeFileSync(join(basic().dir, "x"), "x");
    expect((await m.auth("/api/v1/events")).status).toBe(200);
  });
});
