import { describe, expect, it } from "vitest";
import { agentOf } from "../src/source.js";
import { chain, CHAIN, spoolDir, spoolSource, startMonitor, userDir, userSource, UID, type Spec } from "./helpers.js";

type Link = Omit<Spec, "seq" | "prev">;

const status = (agent: string, st: string, reason: string): Link => ({
  type: "enforcement_status",
  agent,
  data: { status: st, reason, hook_registered: true, target_exists: true, fail_closed: false, self_test: "pass", config_source: "~/.x", human_session: false },
});

function sample(): Record<string, unknown>[] {
  return chain([
    { agent: "claude-code", session: "s-c", toolName: "Bash" },
    { agent: "claude-code", session: "s-c", outcome: "deny" },
    { agent: "codex", session: "s-x", outcome: "deny" },
    { agent: "codex", session: "s-x", outcome: "allow" },
    { agent: "codex", session: "s-x", outcome: "deny" },
    { session: "s-old" }, // event of an older version without agent
    status("codex", "UNPROTECTED", "target_missing"),
    status("grok", "DEGRADED", "fail_open_on_crash_or_timeout"),
  ]);
}

describe("agentOf", () => {
  it("names the agent, unknown for agent events without one, null for others", () => {
    expect(agentOf({ type: "decision", agent: { name: "grok" } })).toBe("grok");
    expect(agentOf({ type: "decision" })).toBe("unknown");
    expect(agentOf({ type: "tool_result" })).toBe("unknown");
    expect(agentOf({ type: "chain_start" })).toBeNull();
    expect(agentOf({ type: "decision", agent: { name: "Evil\u001b[31m" } })).toBe("unknown");
    expect(agentOf({ type: "decision", agent: "codex" })).toBe("unknown");
  });
});

describe("agent filter", () => {
  it("?agent= filters events and sessions", async () => {
    const m = await startMonitor(userSource(userDir(sample())));
    const codex = (await m.auth("/api/v1/events?agent=codex")).json();
    expect(codex.events.map((e: { event: { type: string } }) => e.event.type)).toEqual(["enforcement_status", "decision", "decision", "decision"]);
    expect(codex.events.every((e: { event: { agent: { name: string } } }) => e.event.agent.name === "codex")).toBe(true);
    const sessions = (await m.auth("/api/v1/sessions?agent=codex")).json();
    expect(sessions.sessions.map((s: { session_id: string }) => s.session_id)).toEqual(["s-x"]);
  });
  it("unknown matches events without an agent member, and only agent event types", async () => {
    const m = await startMonitor(userSource(userDir(sample())));
    const body = (await m.auth("/api/v1/events?agent=unknown")).json();
    expect(body.events).toHaveLength(1);
    expect(body.events[0].event.claude.session_id).toBe("s-old");
  });
  it("an agent without events yields an empty list, not an error", async () => {
    const m = await startMonitor(userSource(userDir(sample())));
    expect((await m.auth("/api/v1/events?agent=cursor")).json().events).toEqual([]);
  });
  it("rejects invalid agent values and duplicates", async () => {
    const m = await startMonitor(userSource(userDir(sample())));
    for (const v of ["Codex", "a b", "x".repeat(33), "1abc", "co%00dex", "", "co/dex"]) {
      expect((await m.auth(`/api/v1/events?agent=${encodeURIComponent(v)}`)).status, v).toBe(400);
    }
    expect((await m.auth("/api/v1/events?agent=codex&agent=grok")).status).toBe(400);
  });
  it("is written to the access log of the admin view only when asked for", async () => {
    const m = await startMonitor(userSource(userDir(sample())), { withAudit: true });
    await m.auth("/api/v1/events?agent=codex");
    await m.auth("/api/v1/events");
    expect(m.audit.entries[0]?.details).toMatchObject({ agent: "codex" });
    expect("agent" in (m.audit.entries[1]?.details ?? {})).toBe(false);
  });
});

describe("GET /api/v1/agents", () => {
  it("summarizes events, denies, last seen and the last enforcement status per agent", async () => {
    const m = await startMonitor(userSource(userDir(sample())));
    const r = await m.auth("/api/v1/agents");
    expect(r.status).toBe(200);
    const byName = Object.fromEntries(r.json().agents.map((a: { agent: string }) => [a.agent, a]));
    expect(Object.keys(byName).sort()).toEqual(["claude-code", "codex", "grok", "unknown"]);
    expect(byName["claude-code"]).toMatchObject({ events: 2, denies: 1, enforcement: null });
    expect(byName.codex).toMatchObject({ events: 3, denies: 2, enforcement: { status: "UNPROTECTED", reason: "target_missing" } });
    expect(byName.grok).toMatchObject({ events: 0, denies: 0, last_seen: null, enforcement: { status: "DEGRADED" } });
    expect(byName.unknown).toMatchObject({ events: 1, denies: 0, enforcement: null });
    expect(typeof byName.codex.last_seen).toBe("string");
  });
  it("the newest enforcement status wins", async () => {
    const m = await startMonitor(userSource(userDir(chain([status("codex", "UNPROTECTED", "no_hook_registered"), status("codex", "ENFORCED", "ok")]))));
    const a = (await m.auth("/api/v1/agents")).json().agents;
    expect(a).toHaveLength(1);
    expect(a[0].enforcement).toMatchObject({ status: "ENFORCED", reason: "ok" });
  });
  it("takes only since (and user in the admin view); other parameters are refused", async () => {
    const m = await startMonitor(userSource(userDir(sample())));
    for (const q of ["?limit=5", "?agent=codex", "?type=decision", `?user=${UID}`, "?x=1"]) expect((await m.auth(`/api/v1/agents${q}`)).status, q).toBe(400);
    expect((await m.auth("/api/v1/agents?since=2026-10-16T11:00:00.000Z")).status).toBe(200);
  });
  it("needs the token and masks hostile data", async () => {
    const hostile = chain([{ type: "enforcement_status", agent: "codex", data: { status: "ENFORCED‮", reason: "ok\u001b[31m" } }]);
    const m = await startMonitor(userSource(userDir(hostile)));
    expect((await m.get("/api/v1/agents")).status).toBe(401);
    const body = (await m.auth("/api/v1/agents")).body;
    expect(body).not.toMatch(/[‮\u001b]/);
    expect(body).toContain("u{202E}");
  });
  it("is audited as `agents`", async () => {
    const m = await startMonitor(userSource(userDir(sample())), { withAudit: true });
    await m.auth("/api/v1/agents");
    expect(m.audit.entries.map((e) => e.action)).toEqual(["agents"]);
  });
  it("works over the relay spool (admin view) across users", async () => {
    const inner = chain([{ agent: "cursor", outcome: "deny" }, status("cursor", "DEGRADED", "fail_open_default")], CHAIN, 4242);
    const spool = spoolDir(inner);
    const m = await startMonitor(spoolSource(spool.dir), { mode: "admin" });
    const a = (await m.auth("/api/v1/agents")).json().agents;
    expect(a).toEqual([expect.objectContaining({ agent: "cursor", events: 1, denies: 1, enforcement: expect.objectContaining({ status: "DEGRADED" }) })]);
    expect((await m.auth("/api/v1/agents?user=4242")).json().agents).toHaveLength(1);
    expect((await m.auth("/api/v1/agents?user=9")).json().agents).toEqual([]);
  });
});
