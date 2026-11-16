import { request } from "node:http";
import { afterAll, describe, expect, it } from "vitest";
import { ActionError, type AdminActions } from "../src/adminActions.js";
import { Monitor, type Audit } from "../src/http.js";
import { issueToken } from "../src/vendor/token.js";
import { NOW, userDir, userSource } from "./helpers.js";

// The server talks to admin actions only through the `AdminActions` interface. This file runs without any implementation of it
// (the public package ships none), so it proves that the server is complete on its own and that the extension point works.
const running: Monitor[] = [];
afterAll(async () => {
  await Promise.all(running.splice(0).map((m) => m.close()));
});

const calls: string[] = [];
const stub: AdminActions = {
  hostName: "stub-host",
  locks: () => ({ generation: 1, locks: [] }),
  prepare: (raw) => {
    calls.push("prepare");
    if (raw === "bad") throw new ActionError("invalid_action");
    return { summary: { kind: "tool", target: { tool: "x" } } };
  },
  commit: async (confirmId, _raw, _now, audit) => {
    calls.push("commit");
    if (confirmId !== "ok") throw new ActionError("control_failed", "busy");
    audit("admin_commit", { done: true });
    return { result: "applied" };
  },
};

async function start(mode: "user" | "admin", actions: AdminActions | null | undefined) {
  const token = issueToken(NOW, 3_600_000);
  const entries: { action: string; details: Record<string, unknown> }[] = [];
  const audit: Audit = { record: (action, details) => void entries.push({ action, details }) };
  const monitor = new Monitor({ mode, source: userSource(userDir([])), token, version: "0.0.0-test", clock: () => NOW, audit, ...(actions === undefined ? {} : { actions }) });
  running.push(monitor);
  const port = await monitor.listen(0);
  const call = (method: string, path: string, body?: unknown): Promise<{ status: number; json: () => any }> => // eslint-disable-line @typescript-eslint/no-explicit-any
    new Promise((resolve, reject) => {
      const headers: Record<string, string> = { Host: `127.0.0.1:${port}`, Authorization: `Bearer ${token.value}` };
      if (method === "POST") Object.assign(headers, { Origin: `http://127.0.0.1:${port}`, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json" });
      const req = request({ host: "127.0.0.1", port, path, method, headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, json: () => JSON.parse(Buffer.concat(chunks).toString("utf8")) }));
      });
      req.on("error", reject);
      req.end(body === undefined ? undefined : JSON.stringify(body));
    });
  return { call, entries };
}

const PREPARE = "/api/v1/admin/actions/prepare";
const COMMIT = "/api/v1/admin/actions/commit";

describe("admin actions are an injected extension point", () => {
  it("without an implementation every POST is refused and no lock view exists", async () => {
    for (const h of [await start("admin", undefined), await start("admin", null), await start("user", stub)]) {
      expect((await h.call("POST", PREPARE, { action: {} })).status).toBe(405);
      expect((await h.call("GET", "/api/v1/admin/locks")).status).toBe(404);
      expect((await h.call("GET", "/api/v1/health")).json().admin_actions).toBe(false);
    }
    expect(calls).toEqual([]);
  });

  it("an injected implementation serves prepare, commit and the lock view, and the server writes the access log", async () => {
    const h = await start("admin", stub);
    expect((await h.call("GET", "/api/v1/health")).json().admin_actions).toBe(true);
    expect((await h.call("POST", PREPARE, { action: { any: 1 } })).status).toBe(200);
    expect(h.entries.some((e) => e.action === "admin_prepare" && e.details["kind"] === "tool")).toBe(true);
    const done = await h.call("POST", COMMIT, { action: {}, confirm_id: "ok" });
    expect(done.status).toBe(200);
    expect(done.json()).toEqual({ result: "applied" });
    expect(h.entries.some((e) => e.action === "admin_commit")).toBe(true);
    const locks = await h.call("GET", "/api/v1/admin/locks");
    expect(locks.json()).toEqual({ host: "stub-host", generation: 1, locks: [] });
  });

  it("errors of the implementation become fixed codes and messages", async () => {
    const h = await start("admin", stub);
    const bad = await h.call("POST", PREPARE, { action: "bad" });
    expect(bad.status).toBe(400);
    expect(bad.json()).toEqual({ error: "invalid_action", message: "The action is not valid." });
    const failed = await h.call("POST", COMMIT, { action: {}, confirm_id: "no" });
    expect(failed.status).toBe(503);
    expect(failed.json()).toEqual({ error: "control_failed", message: "The control helper did not carry out the action.", control_code: "busy" });
  });

  it("the server refuses an implementation without an access log", () => {
    const base = { mode: "admin" as const, source: userSource(userDir([])), token: issueToken(NOW, 1000), version: "t" };
    expect(() => new Monitor({ ...base, actions: stub })).toThrow("access log");
  });

  it("deprecated: the old option control fails clearly when no implementation has registered itself (public package)", () => {
    const base = { mode: "admin" as const, source: userSource(userDir([])), token: issueToken(NOW, 1000), version: "t", audit: { record: () => undefined } };
    expect(() => new Monitor({ ...base, control: {} })).toThrow("no implementation registered");
    expect(() => new Monitor({ ...base, control: null })).not.toThrow();
  });
});
