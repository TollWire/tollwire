import { appendFileSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeCommand } from "../../src/events/commandInfo.js";
import { enterpriseLayout, type Layout } from "../../src/events/layout.js";
import { EventLogger } from "../../src/events/logger.js";
import { LogStore } from "../../src/events/store.js";
import { ENTERPRISE_DEFAULTS } from "../../src/events/settings.js";
import { verifyFiles } from "../../src/events/verify.js";
import { chainHash } from "../../src/vendor/hashchain.js";
import { ALLOW, claude, decisionDraft, envFor, Fixture, META, POLICY, readEvents, runtimeFor, standaloneStore, tempDir, writeConfig } from "./helpers.js";

const uid = process.getuid?.() ?? 0;

describe("writer errors", () => {
  it("cannot create a directory below a file", () => {
    const root = tempDir();
    writeFileSync(join(root, "file"), "x");
    const { store, layout } = standaloneStore(root);
    const broken = new LogStore({ ...layout, lockDir: join(root, "file", "sub"), eventsDir: join(root, "file", "sub", "events") }, META, new Fixture().deps);
    expect(() => broken.transaction(() => undefined)).toThrowError(/directory cannot be created/);
    expect(store.layout.kind).toBe("standalone");
  });

  it("refuses directories and files owned by another user", () => {
    const root = tempDir();
    const { store, layout, fixture } = standaloneStore(root);
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    const foreign = new LogStore(layout, META, { ...fixture.deps, uid: uid + 1 });
    expect(() => foreign.transaction(() => undefined)).toThrowError(/owned by another user/);
    // The directories belong to us; for the file checks use a layout whose directories are not checked (layout S).
    const shared: Layout = { ...enterpriseLayout("shared", uid, root), eventsDir: layout.eventsDir, lockDir: layout.lockDir, alternateFiles: false };
    const sharedForeign = new LogStore(shared, META, { ...fixture.deps, uid: uid + 1 });
    expect(foreign.readTail(`u${uid}-20261011.jsonl`)).toEqual({ status: "unsafe", reason: "owned by another user" });
    expect(sharedForeign.readTail(`u${uid}-20261011.jsonl`)).toEqual({ status: "unsafe", reason: "owned by another user" });
  });

  it("readTail reports missing files and replaced files", () => {
    const { store, layout } = standaloneStore(tempDir());
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    expect(store.readTail("u0-19990101.jsonl")).toEqual({ status: "unsafe", reason: "missing" });
    expect(store.readTail(`u${uid}-20261011.jsonl`, { ino: 1, dev: 1 })).toEqual({ status: "unsafe", reason: "file was replaced" });
    expect(layout.kind).toBe("standalone");
  });

  it("listFiles falls back to the named files if the directory cannot be listed", () => {
    const { store } = standaloneStore(tempDir());
    expect(store.listFiles([`u${uid}-20261011.jsonl`, "other.txt"]).map((f) => f.name)).toEqual([`u${uid}-20261011.jsonl`]);
  });

  it("reports a vanished directory while appending as dir_missing", () => {
    const { store, layout } = standaloneStore(tempDir());
    expect(() =>
      store.transaction((tx) => {
        rmSync(layout.eventsDir, { recursive: true });
        tx.append([decisionDraft(store)]);
      }),
    ).toThrowError(/event file cannot be created/);
  });

  it("uses the state pointer when the previous file is gone from the listing (layout S)", () => {
    const root = tempDir();
    const fixture = new Fixture();
    const events = join(root, "shared");
    mkdirSync(events, { mode: 0o750 });
    const layout: Layout = { ...enterpriseLayout("shared", uid, root), eventsDir: events, lockDir: join(root, "state") };
    const store = new LogStore(layout, META, fixture.deps);
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    fixture.advance(24 * 3600 * 1000);
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    expect(readEvents(events).map((f) => f.events[0]?.type)).toEqual(["chain_start", "chain_continue"]);
  });
});

describe("logger errors", () => {
  function ctx(root: string) {
    return { rt: runtimeFor(root), env: envFor(root), enterprise: null, policy: POLICY, findings: [] };
  }
  const record = { claude: claude(), projectDir: "/repo", tool: { name: "Bash", rawCommand: "ls" }, decision: ALLOW, suppressible: false, humanSession: false };

  it("reports a failure while writing logging_disabled", () => {
    const root = tempDir();
    new EventLogger(ctx(root)).recordDecision(record);
    writeConfig(root, '{"logging":{"enabled":false}}');
    const foreign = new EventLogger({ ...ctx(root), rt: runtimeFor(root, new Fixture(), { uid: uid + 1 }) });
    const result = foreign.recordDecision(record);
    expect(result).toMatchObject({ ok: false, block: false });
  });

  it("session events of a session that started disabled do not write", () => {
    const root = tempDir();
    writeConfig(root, '{"logging":{"enabled":false}}');
    const logger = new EventLogger(ctx(root));
    logger.recordLifecycle({ kind: "session_start", claude: claude("s-1", { hook_event: "SessionStart" }), data: {}, humanSession: false });
    expect(logger.recordLifecycle({ kind: "subagent_start", claude: claude("s-1"), data: {}, humanSession: false })).toEqual({ ok: true });
    expect(logger.recordLifecycle({ kind: "session_end", claude: claude("s-1"), data: {}, humanSession: false })).toEqual({ ok: true });
  });

  it("hash detail logs the SHA-256 of the command", () => {
    const root = tempDir();
    const dir = join(root, "events", String(uid));
    mkdirSync(dir, { recursive: true, mode: 0o750 });
    const layout: Layout = { ...enterpriseLayout("per_user", uid, root), eventsDir: dir, lockDir: dir };
    const logger = new EventLogger({ ...ctx(root), enterprise: { layout, settings: { ...ENTERPRISE_DEFAULTS, commandDetail: "hash" } } });
    logger.recordDecision(record);
    const event = readEvents(dir)[0]?.events[1];
    expect(event?.tool?.command_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(event?.tool?.command).toBeUndefined();
  });
});

describe("analyzeCommand limits", () => {
  const ctx = { projectDir: "/repo", cwd: "/repo", home: "/home/u" };
  it("gives up on endless wrapper chains", () => {
    const r = analyzeCommand(`${"sudo ".repeat(8)}ls`, ctx);
    expect(r.suppressible).toBe(false);
    expect(r.effects).toEqual(["unknown"]);
    expect(r.programs).toEqual([]);
  });
});

describe("verifyFiles corner cases", () => {
  it("skips empty lines, accepts a chain_start without data and a repeated chain id", () => {
    const dir = tempDir();
    const file = join(dir, `u${uid}-20261011.jsonl`);
    const first: Record<string, unknown> = {
      schema: "tollgate.event.v1", event_id: "e1", ts: "2026-10-11T00:00:00.000Z", chain_id: "00000000-0000-4000-8000-0000000000c1", seq: 1, type: "chain_start", prev_hash: "0".repeat(64),
    };
    const second: Record<string, unknown> = { ...first, event_id: "e2", type: "decision", seq: 2, prev_hash: chainHash(first) };
    const repeated: Record<string, unknown> = { ...first, event_id: "e3" };
    const line = (e: Record<string, unknown>): string => JSON.stringify({ ...e, hash: chainHash(e) });
    writeFileSync(file, `${line(first)}\n\n${line(second)}\n`, { mode: 0o600 });
    appendFileSync(file, `${line(repeated)}\n`);
    const report = verifyFiles([file], { maxMode: 0o600 });
    expect(report.chainFindings).toEqual([]);
    expect(report.chains).toHaveLength(1);
    expect(report.events).toBe(3);
  });
});
