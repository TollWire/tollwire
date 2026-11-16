import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { EventSource } from "../src/source.js";
import { chain, CHAIN, DAY, makeEvent, NOW, relayRecord, spoolDir, spoolSource, startMonitor, UID, userDir, userSource, writeLines } from "./helpers.js";

const iso = (ms: number): string => new Date(ms).toISOString();

describe("health and events (user view)", () => {
  it("reports the mode, the source and the token expiry", async () => {
    const m = await startMonitor(userSource(userDir(chain([]))));
    const body = (await m.auth("/api/v1/health")).json();
    expect(body).toMatchObject({ status: "ok", mode: "user", source: "user", version: "0.0.0-test", time: iso(NOW), token_expires_at: iso(m.token.expiresAtMs) });
    expect((await m.auth("/api/v1/health?x=1")).status).toBe(400);
  });

  it("shows only the events of the calling user, whatever the files contain", async () => {
    const own = chain([{ session: "mine" }]);
    const foreign = makeEvent({ seq: 50, prev: "0".repeat(64), uid: UID + 1, name: "mallory", session: "theirs" });
    const dir = userDir([...own, foreign]);
    // A file of another uid next to it is not even looked at.
    writeLines(join(dir, `u${UID + 1}-${DAY}.jsonl`), [foreign]);
    const m = await startMonitor(userSource(dir));
    const body = (await m.auth("/api/v1/events")).json();
    const text = JSON.stringify(body);
    expect(text).not.toContain("theirs");
    expect(text).not.toContain("mallory");
    expect(body.events.map((e: { event: { type: string } }) => e.event.type)).toEqual(["decision", "chain_start"]);
    const sessions = (await m.auth("/api/v1/sessions")).json();
    expect(JSON.stringify(sessions)).not.toContain("theirs");
    expect(sessions.sessions.map((s: { session_id: string }) => s.session_id)).toEqual(["mine"]);
  });

  it("the user view cannot ask for another user", async () => {
    const m = await startMonitor(userSource(userDir(chain([]))));
    for (const path of [`/api/v1/events?user=${UID + 1}`, `/api/v1/sessions?user=${UID + 1}`, `/api/v1/events?user=${UID}`]) expect((await m.auth(path)).status, path).toBe(400);
  });

  it("filters by type, session and time, and orders newest first", async () => {
    const events = chain([
      { session: "a", ts: iso(NOW - 5000) },
      { session: "b", ts: iso(NOW - 4000), outcome: "deny" },
      { session: "a", ts: iso(NOW - 3000), type: "tool_result" },
    ]);
    const m = await startMonitor(userSource(userDir(events)));
    const all = (await m.auth("/api/v1/events?limit=10")).json();
    expect(all.events.map((e: { event: { seq: number } }) => e.event.seq)).toEqual([4, 3, 2, 1]);
    expect((await m.auth("/api/v1/events?type=decision")).json().events).toHaveLength(2);
    expect((await m.auth("/api/v1/events?session=a")).json().events).toHaveLength(2);
    expect((await m.auth("/api/v1/events?session=a&type=tool_result")).json().events).toHaveLength(1);
    const recent = (await m.auth(`/api/v1/events?since=${encodeURIComponent(iso(NOW - 3500))}`)).json();
    expect(recent.events.map((e: { event: { seq: number } }) => e.event.seq)).toEqual([4]);
  });

  it("applies the limit and says if more events exist", async () => {
    const m = await startMonitor(userSource(userDir(chain(Array.from({ length: 12 }, () => ({}))))));
    const r = (await m.auth("/api/v1/events?limit=5")).json();
    expect(r.events).toHaveLength(5);
    expect(r.has_more).toBe(true);
    const all = (await m.auth("/api/v1/events?limit=1000")).json();
    expect(all.events).toHaveLength(13);
    expect(all.has_more).toBe(false);
  });

  it("limits the size of an answer", async () => {
    const m = await startMonitor(userSource(userDir(chain(Array.from({ length: 30 }, () => ({}))))), { limits: { responseBytes: 2000 } });
    const r = (await m.auth("/api/v1/events?limit=1000")).json();
    expect(r.events.length).toBeGreaterThan(0);
    expect(r.events.length).toBeLessThan(31);
    expect(r.truncated).toBe(true);
    expect(r.has_more).toBe(true);
  });

  it("rejects invalid parameters with 400", async () => {
    const m = await startMonitor(userSource(userDir(chain([]))));
    const bad = [
      "limit=0", "limit=1001", "limit=-1", "limit=abc", "limit=1.5", "limit=00001e", "limit=", "limit=1&limit=2",
      "type=Decision", "type=a-b", `type=${"a".repeat(41)}`, "session=a%20b", "session=../x", `session=${"s".repeat(129)}`,
      `since=${iso(NOW + 1000)}`, `since=${iso(NOW - 8 * 86_400_000)}`, "since=yesterday", "since=2026-10-16", "since=2026-10-16T12:00:00%2B02:00", "since=2026-13-45T00:00:00Z",
      "unknown=1", "limit=5&unknown=1", "%zz=1", "limit=%zz", `session=${"%41".repeat(130)}`,
    ];
    for (const q of bad) {
      const r = await m.auth(`/api/v1/events?${q}`);
      expect(r.status, q).toBe(400);
      expect(r.json().error).toBe("invalid_parameter");
    }
    expect((await m.auth("/api/v1/events?limit=1000")).status).toBe(200);
    expect((await m.auth(`/api/v1/events?since=${encodeURIComponent(iso(NOW - 7 * 86_400_000))}`)).status).toBe(200);
    expect((await m.auth("/api/v1/sessions?limit=5")).status).toBe(400);
  });
});

describe("hostile content in events", () => {
  const PAYLOADS = ["<script>alert(1)</script>", `"><img src=x onerror=alert(1)>`, "javascript:alert(1)", "</script><script>alert(2)</script>", "'; DROP TABLE x; --"];

  it("passes markup through as plain JSON text, masks control characters and keeps __proto__ as data", async () => {
    const base = chain([{ session: "x" }]);
    const hostile = makeEvent({
      seq: 3,
      prev: base.at(-1)?.hash as string,
      session: "x-ss",
      toolName: PAYLOADS[0] as string,
      reason: `${PAYLOADS[1]}\u001b[31m‮ end`,
      data: JSON.parse(`{"__proto__":{"polluted":true},"constructor":{"prototype":{"p":1}},"note":"${PAYLOADS[3]}\\u0000\\u007f\\ud800"}`),
    });
    const m = await startMonitor(userSource(userDir([...base, hostile])));
    const r = await m.auth("/api/v1/events");
    expect(r.headers["content-type"]).toBe("application/json; charset=utf-8");
    expect(r.headers["x-content-type-options"]).toBe("nosniff");
    // No raw control, bidi or separator characters in the answer.
    expect(new RegExp("[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029\\u202a-\\u202e]").test(r.body)).toBe(false);
    const parsed = r.json();
    const item = parsed.events.find((e: { event: { seq: number } }) => e.event.seq === 3).event;
    expect(item.tool.name).toBe(PAYLOADS[0]); // plain text; the page writes it with textContent
    expect(item.decision.reason).toContain("\\u{001B}[31m\\u{202E}\\u{2028}end");
    expect(Object.getPrototypeOf(item.data)).toBe(Object.prototype);
    expect(Object.hasOwn(item.data, "__proto__")).toBe(true);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(item.data.note).toContain("\\u{0000}\\u{007F}");
  });

  it("the page never writes event data as markup", () => {
    const assets = readFileSync(new URL("../src/web/assets.ts", import.meta.url), "utf8");
    for (const sink of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setTimeout(\"", "setInterval(\"", "srcdoc", "createContextualFragment", "DOMParser", "location.href =", "window.open"]) {
      expect(assets, sink).not.toContain(sink);
    }
    expect(assets).toContain("textContent");
    // No inline script or style, no external reference.
    const html = assets.slice(assets.indexOf("const HTML"), assets.indexOf("const CSS"));
    expect(html).not.toMatch(/<script(?![^>]*\bsrc="\/app\.js")[^>]*>/);
    expect(html).not.toMatch(/\son[a-z]+=|style=|<style|https?:\/\//);
    expect(assets.slice(assets.indexOf("const JS"))).not.toMatch(/https?:\/\//);
  });

  it("serves the page and script without a way to execute event data", async () => {
    const m = await startMonitor(userSource(userDir(chain([]))));
    const js = (await m.get("/app.js")).body;
    expect(js).not.toContain("innerHTML");
    expect((await m.get("/")).body).toContain('<script src="/app.js"></script>');
  });
});

describe("sessions and findings are masked like events", () => {
  const CTRL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e]/;

  it("masks session id, user name, host name and findings in /sessions", async () => {
    const hostile = chain([{ session: "s-x", name: "al\u001b[31mice\u202e", host: "h\u2028<b>1</b>" }]);
    const dir = userDir(hostile);
    // A finding with a hostile file name: a symbolic link whose name matches the event file pattern cannot carry controls, so
    // the finding text is checked through the source directly below; here the fields of the events are the carriers.
    const m = await startMonitor(userSource(dir));
    const r = await m.auth("/api/v1/sessions");
    expect(CTRL.test(r.body)).toBe(false);
    const s = r.json().sessions[0];
    expect(s.user.name).toBe("al\\u{001B}[31mice\\u{202E}");
    expect(s.host).toBe("h\\u{2028}<b>1</b>");
  });

  it("masks findings and the verification result", async () => {
    const hostile: EventSource = {
      kind: "user",
      list: () => ({ events: [], hasMore: false, truncated: false, findings: [{ kind: "x\u001b", file: "f\u202e", detail: "d\u0000" }] }),
      sessions: () => ({ sessions: [], truncated: false, findings: [{ kind: "x\u001b", file: "f\u202e", detail: "d\u0000" }] }),
      verify: () => Promise.resolve({ ok: false, complete: true, files: 1, events: 0, chains: 0, findings: [{ kind: "hash_mismatch", file: "f\u001b", line: 1, detail: "d\u2028" }], more_findings: 0, read_findings: [{ kind: "k", file: "f\u202e", detail: "d\u0085" }], embedded: null, checked_at: "t" }),
    };
    const m = await startMonitor(hostile);
    for (const path of ["/api/v1/events", "/api/v1/sessions", "/api/v1/verify", "/api/v1/verify"]) {
      const r = await m.auth(path);
      expect(r.status, path).toBe(200);
      expect(CTRL.test(r.body), path).toBe(false);
      expect(r.body).toContain("\\u{");
    }
  });
});

describe("sessions", () => {
  it("summarizes sessions with counts and denials", async () => {
    const events = chain([{ session: "a", ts: iso(NOW - 3000) }, { session: "a", ts: iso(NOW - 2000), outcome: "deny" }, { session: "b", ts: iso(NOW - 1000) }]);
    const m = await startMonitor(userSource(userDir(events)));
    const body = (await m.auth("/api/v1/sessions")).json();
    expect(body.sessions).toEqual([
      { session_id: "b", first_ts: iso(NOW - 1000), last_ts: iso(NOW - 1000), events: 1, denies: 0, user: { name: "alice", id: String(UID) }, host: "host-1" },
      { session_id: "a", first_ts: iso(NOW - 3000), last_ts: iso(NOW - 2000), events: 2, denies: 1, user: { name: "alice", id: String(UID) }, host: "host-1" },
    ]);
  });

  it("caps the number of sessions", async () => {
    const m = await startMonitor(userSource(userDir(chain(Array.from({ length: 6 }, (_, i) => ({ session: `s-${i}` })))), { maxSessions: 3 }));
    const body = (await m.auth("/api/v1/sessions")).json();
    expect(body.sessions).toHaveLength(3);
    expect(body.truncated).toBe(true);
  });
});

describe("chain verification", () => {
  it("reports a valid chain and caches the result for a while", async () => {
    const m = await startMonitor(userSource(userDir(chain([{}, {}]))));
    const r = (await m.auth("/api/v1/verify")).json();
    expect(r).toMatchObject({ ok: true, complete: true, files: 1, events: 3, chains: 1, findings: [], read_findings: [], embedded: null });
    m.now.value += 1000;
    expect((await m.auth("/api/v1/verify")).json().checked_at).toBe(r.checked_at);
    m.now.value += 20_000;
    expect((await m.auth("/api/v1/verify")).json().checked_at).not.toBe(r.checked_at);
  });

  it("finds a changed event, a gap and a broken link", async () => {
    const events = chain([{}, {}, {}]);
    const changed = { ...(events[1] as Record<string, unknown>), tool: { name: "Other", truncated: false } };
    const m1 = await startMonitor(userSource(userDir([events[0], changed, events[2], events[3]] as Record<string, unknown>[])));
    const r1 = (await m1.auth("/api/v1/verify")).json();
    expect(r1.ok).toBe(false);
    expect(r1.findings.map((f: { kind: string }) => f.kind)).toContain("hash_mismatch");
    const m2 = await startMonitor(userSource(userDir([events[0], events[2], events[3]] as Record<string, unknown>[])));
    const r2 = (await m2.auth("/api/v1/verify")).json();
    expect(r2.ok).toBe(false);
    expect(r2.findings[0]).toMatchObject({ kind: "chain_broken", line: 2 });
    expect(r2.findings[0].file).toBe(`u${UID}-${DAY}.jsonl`);
    const m3 = await startMonitor(userSource(userDir([events[0], "not json", "[]", events[1]] as unknown[] as Record<string, unknown>[])));
    const r3 = (await m3.auth("/api/v1/verify")).json();
    expect(r3.findings.map((f: { kind: string }) => f.kind)).toEqual(["invalid_json", "invalid_event"]);
  });

  it("allows one verification at a time", async () => {
    let release: () => void = () => undefined;
    let calls = 0;
    const slow: EventSource = {
      kind: "user",
      list: () => ({ events: [], hasMore: false, truncated: false, findings: [] }),
      sessions: () => ({ sessions: [], truncated: false, findings: [] }),
      verify: () => {
        calls += 1;
        return new Promise((resolve) => {
          release = () => resolve({ ok: true, complete: true, files: 0, events: 0, chains: 0, findings: [], more_findings: 0, read_findings: [], embedded: null, checked_at: "x" });
        });
      },
    };
    const m = await startMonitor(slow);
    const first = m.auth("/api/v1/verify");
    await new Promise((r) => setTimeout(r, 100));
    const second = await m.auth("/api/v1/verify");
    expect(second.status).toBe(429);
    expect(second.json().error).toBe("verify_busy");
    release();
    expect((await first).status).toBe(200);
    expect(calls).toBe(1);
  });

  it("does not block the event loop while it verifies a large log (it yields between batches)", async () => {
    const m = await startMonitor(userSource(userDir(chain(Array.from({ length: 5000 }, () => ({}))))));
    let ticks = 0;
    const timer = setInterval(() => (ticks += 1), 1);
    const r = await m.auth("/api/v1/verify");
    clearInterval(timer);
    expect(r.json()).toMatchObject({ ok: true, events: 5001 });
    expect(ticks).toBeGreaterThan(0);
  });

  it("stops at the byte budget and says so", async () => {
    const m = await startMonitor(userSource(userDir(chain(Array.from({ length: 50 }, () => ({})))), { verifyBytes: 1500 }));
    const r = (await m.auth("/api/v1/verify")).json();
    expect(r.complete).toBe(false);
    expect(r.ok).toBe(false);
  });
});

describe("admin view over the relay spool", () => {
  function setup() {
    const inner = chain([{ session: "sess-a", name: "alice", host: "h1" }], CHAIN, 4242);
    const other = chain([{ session: "sess-b", name: "bob", host: "h2", outcome: "deny" }], "cccccccc-cccc-4ccc-8ccc-cccccccccccc", 4343);
    return { inner, other, spool: spoolDir([...inner, ...other]) };
  }

  it("shows the events of all users with the relay's statements", async () => {
    const { spool } = setup();
    const m = await startMonitor(spoolSource(spool.dir), { mode: "admin" });
    expect((await m.auth("/api/v1/health")).json()).toMatchObject({ mode: "admin", source: "spool" });
    const body = (await m.auth("/api/v1/events?limit=100")).json();
    const names = body.events.map((e: { event: { user: { name: string } } }) => e.event.user.name);
    expect(new Set(names)).toEqual(new Set(["alice", "bob"]));
    expect(body.events[0].relay).toMatchObject({ chain_ok: true, meta_ok: true, owner_uid: UID });
    const bob = (await m.auth("/api/v1/events?user=4343")).json();
    expect(bob.events.every((e: { event: { user: { id: string } } }) => e.event.user.id === "4343")).toBe(true);
    expect(bob.events).toHaveLength(2);
    expect((await m.auth("/api/v1/events?session=sess-a")).json().events).toHaveLength(1);
    const sessions = (await m.auth("/api/v1/sessions")).json();
    expect(sessions.sessions.map((s: { session_id: string; user: { name: string } }) => `${s.session_id}:${s.user.name}`).sort()).toEqual(["sess-a:alice", "sess-b:bob"]);
    expect((await m.auth("/api/v1/events?user=abc")).status).toBe(400);
  });

  it("verifies the relay chain and the embedded events and counts what the relay marked", async () => {
    const { inner, other } = setup();
    const dir = spoolDir([]).dir;
    const flagged = chain([{ type: "relay_record", data: relayRecord(inner[0] as Record<string, unknown>) }, { type: "relay_record", data: relayRecord(inner[1] as Record<string, unknown>, { chain_ok: false }) }, { type: "relay_record", data: relayRecord(other[0] as Record<string, unknown>) }], "dddddddd-dddd-4ddd-8ddd-dddddddddddd", UID);
    writeLines(join(dir, `relay-${DAY}.jsonl`), flagged, 0o640);
    const m = await startMonitor(spoolSource(dir), { mode: "admin" });
    const r = (await m.auth("/api/v1/verify")).json();
    expect(r).toMatchObject({ ok: true, embedded: { checked: 3, relay_flagged: 1 } });
  });

  it("finds an embedded event that was changed after the relay chained it", async () => {
    const { inner } = setup();
    const tampered = { ...(inner[1] as Record<string, unknown>), tool: { name: "Evil", truncated: false } };
    const dir = spoolDir([]).dir;
    writeLines(join(dir, `relay-${DAY}.jsonl`), chain([{ type: "relay_record", data: relayRecord(inner[0] as Record<string, unknown>) }, { type: "relay_record", data: relayRecord(tampered) }], "dddddddd-dddd-4ddd-8ddd-dddddddddddd", UID), 0o640);
    const m = await startMonitor(spoolSource(dir), { mode: "admin" });
    const r = (await m.auth("/api/v1/verify")).json();
    expect(r.ok).toBe(false);
    expect(r.findings[0]).toMatchObject({ kind: "hash_mismatch", detail: "embedded event hash does not match the content" });
    // A gap inside the embedded chain is found as well.
    const dir2 = spoolDir([]).dir;
    const third = chain([{}, {}, {}], CHAIN, 4242);
    writeLines(join(dir2, `relay-${DAY}.jsonl`), chain([{ type: "relay_record", data: relayRecord(third[0] as Record<string, unknown>) }, { type: "relay_record", data: relayRecord(third[2] as Record<string, unknown>) }], "dddddddd-dddd-4ddd-8ddd-dddddddddddd", UID), 0o640);
    const m2 = await startMonitor(spoolSource(dir2), { mode: "admin" });
    expect((await m2.auth("/api/v1/verify")).json().findings[0]).toMatchObject({ kind: "chain_broken", detail: "embedded events of a user chain are not contiguous" });
  });

  it("counts a duplicate delivery once", async () => {
    const { inner } = setup();
    const dir = spoolDir([]).dir;
    const rec = (i: number) => ({ type: "relay_record", data: relayRecord(inner[i] as Record<string, unknown>) });
    writeLines(join(dir, `relay-${DAY}.jsonl`), chain([rec(0), rec(1), rec(1), rec(0)], "dddddddd-dddd-4ddd-8ddd-dddddddddddd", UID), 0o640);
    const m = await startMonitor(spoolSource(dir), { mode: "admin" });
    expect((await m.auth("/api/v1/verify")).json()).toMatchObject({ ok: true, embedded: { checked: 2 } });
    expect((await m.auth("/api/v1/events?limit=100")).json().events.filter((e: { event: { type: string } }) => e.event.type === "decision")).toHaveLength(1);
  });
});

describe("access log of the admin view", () => {
  it("records every data request with its validated parameters, and nothing for health or static files", async () => {
    const spool = spoolDir(chain([{}]));
    const m = await startMonitor(spoolSource(spool.dir), { mode: "admin", withAudit: true });
    await m.get("/");
    await m.auth("/api/v1/health");
    await m.auth("/api/v1/events?limit=7&type=decision&user=1000");
    await m.auth("/api/v1/sessions");
    await m.auth("/api/v1/verify");
    await m.get("/api/v1/events");
    await m.auth("/api/v1/events?limit=zzz");
    expect(m.audit.entries.map((e) => e.action)).toEqual(["events", "sessions", "verify"]);
    expect(m.audit.entries[0]?.details).toMatchObject({ limit: 7, type: "decision", user: "1000" });
    expect(JSON.stringify(m.audit.entries)).not.toContain(m.token.value);
  });

  it("delivers no data if the access log cannot be written", async () => {
    const spool = spoolDir(chain([{}]));
    const m = await startMonitor(spoolSource(spool.dir), { mode: "admin", withAudit: true });
    m.audit.fail = true;
    for (const path of ["/api/v1/events", "/api/v1/sessions", "/api/v1/verify", "/api/v1/stream"]) {
      const r = await m.auth(path);
      expect(r.status, path).toBe(503);
      expect(r.json().error).toBe("audit_unavailable");
      expect(r.body).not.toContain("decision");
    }
    expect((await m.auth("/api/v1/health")).status).toBe(200);
  });
});
