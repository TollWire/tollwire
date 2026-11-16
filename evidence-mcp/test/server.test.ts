import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CONTROL_MAP, EVENT_TYPES } from "../src/controls.js";
import { rangeBounds, renderReport } from "../src/report.js";
import { EvidenceError } from "../src/log.js";
import { createServer, DEFAULT_LOG, errorReason, isValidIsoDate, resolveLogPath } from "../src/server.js";

const logPath = join(mkdtempSync(join(tmpdir(), "ev-srv-")), "log.jsonl");
const client = new Client({ name: "test", version: "0.0.0" });

function payload(res: unknown): unknown {
  return JSON.parse((res as { content: { text: string }[] }).content[0]?.text ?? "null");
}

beforeAll(async () => {
  const [c, s] = InMemoryTransport.createLinkedPair();
  await createServer(logPath).connect(s);
  await client.connect(c);
});
afterAll(async () => client.close());

describe("evidence MCP server", () => {
  it("lists its tools", async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["create_anchor", "export_report", "list_events", "map_controls", "record_event", "verify_log"]);
  });

  it("tools/list is identical to the SDK 1.32.0 server (fixture recorded before the switch)", async () => {
    const fixture = JSON.parse(readFileSync(new URL("fixtures/tools-list.sdk-1.32.0.json", import.meta.url), "utf8")) as unknown;
    const res = await createServer(logPath).handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    expect(res?.result).toEqual(fixture);
  });

  it("records events and returns mapped controls", async () => {
    const res = payload(
      await client.callTool({ name: "record_event", arguments: { type: "scan", summary: "gates green", actor: "ci", ref: "run 1" } }),
    ) as { recorded: boolean; seq: number; controls: { id: string }[] };
    expect(res.recorded).toBe(true);
    expect(res.seq).toBe(1);
    expect(res.controls.map((c) => c.id)).toContain("A.8.8");
    await client.callTool({ name: "record_event", arguments: { type: "approval", summary: "owner merged PR #7", actor: "owner" } });
  });

  it("refuses secrets with an error result", async () => {
    const res = await client.callTool({
      name: "record_event",
      arguments: { type: "change", summary: "leak", actor: "x", details: { k: `ghp_${"b".repeat(36)}` } },
    });
    expect(res.isError).toBe(true);
    expect(payload(res)).toMatchObject({ recorded: false });
  });

  it("lists, filters, verifies and maps", async () => {
    expect((payload(await client.callTool({ name: "list_events", arguments: {} })) as unknown[]).length).toBe(2);
    expect((payload(await client.callTool({ name: "list_events", arguments: { type: "approval", limit: 1 } })) as unknown[]).length).toBe(1);
    expect(payload(await client.callTool({ name: "verify_log", arguments: {} }))).toEqual({
      valid: true,
      count: 2,
      checked: 0,
      anchorFile: { present: false, valid: true, count: 0 },
      externalAnchorsChecked: 0,
      anchored: false,
    });
    expect(payload(await client.callTool({ name: "map_controls", arguments: { type: "incident" } }))).toEqual(CONTROL_MAP.incident);
  });

  it("creates an anchor and verifies with the anchor file and external anchors", async () => {
    const res = payload(await client.callTool({ name: "create_anchor", arguments: {} })) as {
      created: boolean;
      anchor: { seq: number; hash: string; ts: string; count: number };
      line: string;
      external: { signed_tag: string; tag_name: string; note: string };
    };
    expect(res.created).toBe(true);
    expect(res.anchor).toMatchObject({ seq: 2, count: 2 });
    expect(JSON.parse(res.line)).toEqual(res.anchor);
    expect(res.external.signed_tag).toMatch(/^git tag -s evidence-anchor-\d{4}-\d{2}-\d{2}-seq2 -m '\{.*\}'$/);
    expect(res.external.note).toMatch(/agents never sign/);
    expect(res.external.note).toMatch(/records an `anchor` event/);
    expect(res.external.signed_tag).toContain(` ${res.external.tag_name} `);

    expect(payload(await client.callTool({ name: "verify_log", arguments: { anchors: [res.anchor] } }))).toEqual({
      valid: true,
      count: 2,
      checked: 2,
      anchorFile: { present: true, valid: true, count: 1 },
      externalAnchorsChecked: 1,
      anchored: true,
    });
    const forged = { ...res.anchor, hash: "a".repeat(64) };
    const failed = await client.callTool({ name: "verify_log", arguments: { anchors: [forged] } });
    expect(failed.isError).toBe(false);
    expect(payload(failed)).toMatchObject({ valid: false, failedSource: "input", failedAnchor: forged });
  });

  it("rejects malformed anchors via the input schema", async () => {
    const res = await client.callTool({ name: "verify_log", arguments: { anchors: [{ seq: 1, hash: "xyz", ts: "now", count: 1 }] } });
    expect(res.isError).toBe(true);
    const tooMany = await client.callTool({ name: "verify_log", arguments: { anchors: "nope" } });
    expect(tooMany.isError).toBe(true);
  });

  it("exports a markdown report", async () => {
    const res = await client.callTool({ name: "export_report", arguments: { from: "2000-01-01" } });
    const report = (res as { content: { text: string }[] }).content[0]?.text ?? "";
    expect(report).toContain("Integrität der Hash-Kette: gültig");
    expect(report).toContain("owner merged PR #7");
    expect(report).toContain("bescheinigt keine Konformität");
  });

  it("rejects invalid report dates", async () => {
    const res = await client.callTool({ name: "export_report", arguments: { from: "yesterday" } });
    expect(res.isError).toBe(true);
  });
});

describe("anchor error results", () => {
  async function connect(path: string): Promise<Client> {
    const c = new Client({ name: "test-errors", version: "0.0.0" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await createServer(path).connect(st);
    await c.connect(ct);
    return c;
  }
  const rawText = (res: unknown) => (res as { content: { text: string }[] }).content[0]?.text ?? "";
  const noStack = (res: unknown) => {
    const text = rawText(res);
    expect(text).not.toMatch(/\bat \/|\bat file:|node:internal|\.ts:\d+/);
    return JSON.parse(text) as Record<string, unknown>;
  };

  it("reports an empty log as a tool error without stack traces", async () => {
    const c = await connect(join(mkdtempSync(join(tmpdir(), "ev-srv-empty-")), "missing", "log.jsonl"));
    const res = await c.callTool({ name: "create_anchor", arguments: {} });
    expect(res.isError).toBe(true);
    expect(noStack(res)).toEqual({ created: false, reason: "Evidence log is empty; nothing to anchor." });
    await c.close();
  });

  it("hides unexpected internal errors of every file-reading tool behind a generic message (review finding 2)", async () => {
    if (process.platform === "win32") return;
    const dir = mkdtempSync(join(tmpdir(), "ev-srv-sock-"));
    // A socket where the log file should be: open() fails with ENXIO carrying the absolute path (unexpected error).
    const { createServer: createNetServer } = await import("node:net");
    const socket = createNetServer();
    await new Promise<void>((done) => socket.listen(join(dir, "log.jsonl"), done));
    const c = await connect(join(dir, "log.jsonl"));
    const cases: [string, Record<string, unknown>, Record<string, unknown>][] = [
      ["create_anchor", {}, { created: false, reason: "Internal error while creating the anchor." }],
      ["verify_log", {}, { valid: false, reason: "Internal error while verifying the evidence log." }],
      ["list_events", {}, { listed: false, reason: "Internal error while reading the evidence log." }],
      ["export_report", {}, { exported: false, reason: "Internal error while rendering the evidence report." }],
      // Refused by the write-target check before any read; EvidenceError text without a path.
      ["record_event", { type: "change", summary: "s", actor: "a" }, { recorded: false, reason: "Evidence file is not a regular file; refusing to write." }],
    ];
    try {
      for (const [name, args, expected] of cases) {
        const res = await c.callTool({ name, arguments: args });
        expect(res.isError, name).toBe(true);
        expect(rawText(res), name).not.toContain(dir);
        expect(noStack(res), name).toEqual(expected);
      }
    } finally {
      await c.close();
      await new Promise<void>((done) => socket.close(() => done()));
    }
  });

  it("refuses a directory in place of the log file in every tool without leaking the path", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ev-srv-dir-"));
    mkdirSync(join(dir, "log.jsonl")); // checked on the opened descriptor: not a regular file
    const c = await connect(join(dir, "log.jsonl"));
    const read = "Evidence file is not a regular file; refusing to read.";
    const cases: [string, Record<string, unknown>, Record<string, unknown>][] = [
      ["create_anchor", {}, { created: false, reason: read }],
      ["verify_log", {}, { valid: false, reason: read }],
      ["list_events", {}, { listed: false, reason: read }],
      ["export_report", {}, { exported: false, reason: read }],
      ["record_event", { type: "change", summary: "s", actor: "a" }, { recorded: false, reason: "Evidence file is not a regular file; refusing to write." }],
    ];
    for (const [name, args, expected] of cases) {
      const res = await c.callTool({ name, arguments: args });
      expect(res.isError, name).toBe(true);
      expect(rawText(res), name).not.toContain(dir);
      expect(noStack(res), name).toEqual(expected);
    }
    await c.close();
  });

  it("resolves the configured log path once, independent of later working-directory changes", async () => {
    const { existsSync } = await import("node:fs");
    const base = mkdtempSync(join(tmpdir(), "ev-srv-cwd-"));
    const other = mkdtempSync(join(tmpdir(), "ev-srv-other-"));
    const cwd = process.cwd();
    process.chdir(base);
    try {
      const c = await connect("log.jsonl");
      process.chdir(other);
      const res = await c.callTool({ name: "record_event", arguments: { type: "change", summary: "s", actor: "a" } });
      expect(res.isError).toBe(false);
      expect(existsSync(join(base, "log.jsonl"))).toBe(true);
      expect(existsSync(join(other, "log.jsonl"))).toBe(false);
      await c.close();
    } finally {
      process.chdir(cwd);
    }
  });

  it("refuses a hard-linked log in every tool without leaking the path", async () => {
    if (process.platform === "win32") return;
    const { linkSync } = await import("node:fs");
    const dir = mkdtempSync(join(tmpdir(), "ev-srv-hard-"));
    writeFileSync(join(dir, "victim.txt"), "keep\n");
    linkSync(join(dir, "victim.txt"), join(dir, "log.jsonl"));
    const c = await connect(join(dir, "log.jsonl"));
    const reason = "Evidence file has multiple hard links; refusing to use it.";
    for (const [name, args] of [
      ["record_event", { type: "change", summary: "s", actor: "a" }],
      ["create_anchor", {}],
      ["verify_log", {}],
      ["list_events", {}],
      ["export_report", {}],
    ] as const) {
      const res = await c.callTool({ name, arguments: args });
      expect(res.isError, name).toBe(true);
      expect(rawText(res), name).not.toContain(dir);
      expect(noStack(res).reason, name).toBe(reason);
    }
    expect(readFileSync(join(dir, "victim.txt"), "utf8")).toBe("keep\n");
    await c.close();
  });

  it("hides generic errors of record_event (no path, no stack)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ev-srv-rec-"));
    writeFileSync(join(dir, "parent"), "a file, not a directory\n");
    const c = await connect(join(dir, "parent", "log.jsonl")); // mkdir fails with ENOTDIR/EEXIST carrying the path
    const res = await c.callTool({ name: "record_event", arguments: { type: "change", summary: "s", actor: "a" } });
    expect(res.isError).toBe(true);
    expect(rawText(res)).not.toContain(dir);
    expect(noStack(res)).toEqual({ recorded: false, reason: "Internal error while recording the event." });
    await c.close();
  });

  it("refuses a symlinked log without leaking the path (review finding 3)", async () => {
    if (process.platform === "win32") return;
    const dir = mkdtempSync(join(tmpdir(), "ev-srv-link-"));
    writeFileSync(join(dir, "victim.txt"), "keep\n");
    symlinkSync(join(dir, "victim.txt"), join(dir, "log.jsonl"));
    const c = await connect(join(dir, "log.jsonl"));
    const res = await c.callTool({ name: "record_event", arguments: { type: "change", summary: "s", actor: "a" } });
    expect(res.isError).toBe(true);
    expect(rawText(res)).not.toContain(dir);
    expect(noStack(res)).toEqual({ recorded: false, reason: "Evidence file is a symbolic link; refusing to write." });
    expect(readFileSync(join(dir, "victim.txt"), "utf8")).toBe("keep\n");
    await c.close();
  });

  it("maps evidence errors to their message", () => {
    expect(errorReason(new EvidenceError("locked"), "x")).toBe("locked");
    expect(errorReason(new Error("secret path /home/x"), "doing y")).toBe("Internal error while doing y.");
  });
});

describe("helpers", () => {
  it("resolves the log path", () => {
    expect(resolveLogPath({}, "/p")).toBe(join("/p", DEFAULT_LOG));
    expect(resolveLogPath({ TOLLGATE_EVIDENCE_LOG: "/x.jsonl" }, "/p")).toBe("/x.jsonl");
  });
  it("maps every event type to at least one control", () => {
    for (const type of EVENT_TYPES) expect(CONTROL_MAP[type].length).toBeGreaterThan(0);
  });
  it("reports broken chains and escapes table cells", () => {
    const entry = { seq: 1, ts: "2026-10-03T00:00:00.000Z", type: "change", summary: "a|b\nc", actor: "x", prev_hash: "1", hash: "2" };
    const report = renderReport([entry as never], { to: "2030-01-01" });
    expect(report).toContain("VERLETZT bei seq 1");
    expect(report).toContain("a\\|b c");
  });
});

describe("date handling (Copilot review PR #9)", () => {
  it("validates real calendar dates and timestamps", () => {
    for (const ok of ["2026-10-03", "2026-10-03T10:00Z", "2026-10-03T10:00:05Z", "2026-10-03T10:00:05.123Z", "2024-02-29"]) {
      expect(isValidIsoDate(ok)).toBe(true);
    }
    for (const bad of ["2026-99-99", "2026-10-03T99:99Z", "2025-02-29", "2026-10-03T10:00", "yesterday"]) {
      expect(isValidIsoDate(bad)).toBe(false);
    }
  });
  it("includes the whole day for date-only upper bounds and compares parsed times", () => {
    const e = (ts: string, seq: number) => ({ seq, ts, type: "change", summary: `s${seq}`, actor: "x", prev_hash: "0", hash: "1" });
    const entries = [e("2026-10-03T23:30:00.000Z", 1), e("2026-10-03T10:00:00.500Z", 2), e("2026-10-04T00:00:00.000Z", 3)];
    const report = renderReport(entries as never, { from: "2026-10-03T10:00:00Z", to: "2026-10-03" });
    expect(report).toContain("Einträge: 2 von 3");
    expect(rangeBounds({}).start).toBe(-Infinity);
  });
  it("keeps the integrity warning when records are unreadable", async () => {
    const { writeFileSync, readFileSync } = await import("node:fs");
    writeFileSync(logPath, readFileSync(logPath, "utf8") + "garbage\n");
    const res = await client.callTool({ name: "export_report", arguments: {} });
    expect((res as { content: { text: string }[] }).content[0]?.text).toContain("VERLETZT");
    expect(payload(await client.callTool({ name: "verify_log", arguments: {} }))).toMatchObject({ valid: false });
  });
});

describe("anchor events and log location (residual risk)", () => {
  async function connect(path: string, root?: string): Promise<Client> {
    const c = new Client({ name: "test-location", version: "0.0.0" });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await createServer(path, root ? { root } : {}).connect(st);
    await c.connect(ct);
    return c;
  }

  it("records an anchor event via record_event and refuses a mismatching anchor", async () => {
    const c = await connect(join(mkdtempSync(join(tmpdir(), "ev-srv-anchor-ev-")), "log.jsonl"));
    await c.callTool({ name: "record_event", arguments: { type: "change", summary: "s", actor: "a" } });
    const { anchor } = payload(await c.callTool({ name: "create_anchor", arguments: {} })) as { anchor: Record<string, unknown> };
    const ok = payload(
      await c.callTool({
        name: "record_event",
        arguments: { type: "anchor", summary: "anchor stored", actor: "owner", ref: "evidence-anchor-x-seq1", details: { anchor, storage: "signed_tag" } },
      }),
    ) as { recorded: boolean; seq: number; controls: { id: string }[] };
    expect(ok).toMatchObject({ recorded: true, seq: 2 });
    expect(ok.controls.map((x) => x.id)).toEqual(["A.8.15", "A.5.33", "A.5.28", "(f)"]);
    const bad = await c.callTool({
      name: "record_event",
      arguments: { type: "anchor", summary: "forged", actor: "owner", ref: "r", details: { anchor: { ...anchor, hash: "b".repeat(64) }, storage: "signed_tag" } },
    });
    expect(bad.isError).toBe(true);
    expect(payload(bad)).toMatchObject({ recorded: false, reason: expect.stringMatching(/does not match the evidence log/) });
    expect(payload(await c.callTool({ name: "map_controls", arguments: { type: "anchor" } }))).toEqual(CONTROL_MAP.anchor);
    await c.close();
  });

  it("refuses a log location redirected through a symlinked directory in every file tool, without leaking paths", async () => {
    if (process.platform === "win32") return;
    const root = mkdtempSync(join(tmpdir(), "ev-srv-root-"));
    const victim = mkdtempSync(join(tmpdir(), "ev-srv-victim-"));
    mkdirSync(join(victim, "evidence"));
    writeFileSync(join(victim, "evidence", "log.jsonl"), "");
    symlinkSync(victim, join(root, ".tollgate"));
    const c = await connect(join(root, DEFAULT_LOG), root);
    const reason = "Evidence directory is a symbolic link; refusing to use it.";
    const calls: [string, Record<string, unknown>][] = [
      ["record_event", { type: "change", summary: "s", actor: "a" }],
      ["list_events", {}],
      ["verify_log", {}],
      ["create_anchor", {}],
      ["export_report", {}],
    ];
    for (const [name, args] of calls) {
      const res = await c.callTool({ name, arguments: args });
      const text = (res as { content: { text: string }[] }).content[0]?.text ?? "";
      expect(res.isError, name).toBe(true);
      expect(text).not.toContain(root);
      expect(text).not.toContain(victim);
      expect(JSON.parse(text).reason, name).toBe(reason);
    }
    expect(readFileSync(join(victim, "evidence", "log.jsonl"), "utf8")).toBe("");
    await c.close();
  });
});
