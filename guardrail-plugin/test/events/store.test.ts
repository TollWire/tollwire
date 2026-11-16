import { execFileSync } from "node:child_process";
import { appendFileSync, chmodSync, linkSync, lstatSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, truncateSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { EventWriteError } from "../../src/events/fsutil.js";
import { enterpriseLayout, type Layout } from "../../src/events/layout.js";
import { evaluateTail, fileProblem, LogStore } from "../../src/events/store.js";
import { GENESIS } from "../../src/events/types.js";
import { chainHash } from "../../src/vendor/hashchain.js";
import { decisionDraft, Fixture, META, readEvents, standaloneStore, tempDir } from "./helpers.js";

const uid = process.getuid?.() ?? 0;

function verifyChain(files: { events: { seq: number; prev_hash: string; hash: string; chain_id: string }[] }[]): void {
  let prev: string | null = null;
  let seq = 0;
  let chain = "";
  for (const f of files) {
    for (const e of f.events) {
      expect(chainHash(e as unknown as Record<string, unknown>)).toBe(e.hash);
      if (prev !== null && e.chain_id === chain) {
        expect(e.prev_hash).toBe(prev);
        expect(e.seq).toBe(seq + 1);
      }
      prev = e.hash;
      seq = e.seq;
      chain = e.chain_id;
    }
  }
}

describe("stand-alone writer", () => {
  it("creates private directories and files and starts a chain", () => {
    const root = tempDir();
    const { store, layout } = standaloneStore(root);
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    expect(statSync(layout.lockDir).mode & 0o777).toBe(0o700);
    expect(statSync(layout.eventsDir).mode & 0o777).toBe(0o700);
    const files = readEvents(layout.eventsDir);
    expect(files.map((f) => f.file)).toEqual([`u${uid}-20261011.jsonl`]);
    expect(statSync(join(layout.eventsDir, files[0]?.file as string)).mode & 0o777).toBe(0o600);
    const [start, decision] = files[0]?.events ?? [];
    expect(start).toMatchObject({ schema: "tollgate.event.v1", type: "chain_start", seq: 1, prev_hash: GENESIS, data: { reason: "new" } });
    expect(decision).toMatchObject({ type: "decision", seq: 2, prev_hash: start?.hash, chain_id: start?.chain_id });
    verifyChain(files);
    expect(readdirSync(layout.lockDir).sort()).toEqual([".state", "events"]); // lock released
  });

  it("appends to the chain without new markers", () => {
    const { store, layout, fixture } = standaloneStore(tempDir());
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    fixture.advance(1000);
    store.transaction((tx) => tx.append([decisionDraft(store), decisionDraft(store)]));
    const files = readEvents(layout.eventsDir);
    expect(files[0]?.events.map((e) => [e.type, e.seq])).toEqual([["chain_start", 1], ["decision", 2], ["decision", 3], ["decision", 4]]);
    verifyChain(files);
  });

  it("never creates files wider than the mode, even with umask 000", () => {
    const old = process.umask(0);
    try {
      const { store, layout } = standaloneStore(tempDir());
      store.transaction((tx) => tx.append([decisionDraft(store)]));
      const file = join(layout.eventsDir, readdirSync(layout.eventsDir)[0] as string);
      expect(statSync(file).mode & 0o777).toBe(0o600);
    } finally {
      process.umask(old);
    }
  });

  it("corrects the mode of an own file", () => {
    const { store, layout } = standaloneStore(tempDir());
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    const file = join(layout.eventsDir, readdirSync(layout.eventsDir)[0] as string);
    chmodSync(file, 0o644);
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(readEvents(layout.eventsDir)[0]?.events).toHaveLength(3);
  });

  it("tightens the mode of an existing directory", () => {
    const { store, layout } = standaloneStore(tempDir());
    mkdirSync(layout.eventsDir, { recursive: true, mode: 0o755 });
    chmodSync(layout.eventsDir, 0o755);
    chmodSync(layout.lockDir, 0o755);
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    expect(statSync(layout.eventsDir).mode & 0o777).toBe(0o700);
    expect(statSync(layout.lockDir).mode & 0o777).toBe(0o700);
  });

  it("continues the chain in a new file on the next UTC day", () => {
    const { store, layout, fixture } = standaloneStore(tempDir());
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    fixture.advance(24 * 3600 * 1000);
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    const files = readEvents(layout.eventsDir);
    expect(files.map((f) => f.file)).toEqual([`u${uid}-20261011.jsonl`, `u${uid}-20261012.jsonl`]);
    const first = files[0]?.events ?? [];
    const cont = files[1]?.events[0];
    expect(cont).toMatchObject({ type: "chain_continue", chain_id: first[0]?.chain_id, seq: 3, prev_hash: first[1]?.hash, data: { file: `u${uid}-20261012.jsonl` } });
    verifyChain(files);
  });

  it("rotates by size with chain_continue", () => {
    const { store, layout } = standaloneStore(tempDir(), new Fixture(), { maxFileBytes: 1500 });
    for (let i = 0; i < 6; i += 1) store.transaction((tx) => tx.append([decisionDraft(store)]));
    const files = readEvents(layout.eventsDir);
    expect(files.length).toBeGreaterThan(1);
    expect(files[1]?.file).toBe(`u${uid}-20261011-1.jsonl`);
    expect(files[1]?.events[0]?.type).toBe("chain_continue");
    expect(new Set(files.flatMap((f) => f.events.map((e) => e.chain_id))).size).toBe(1);
    verifyChain(files);
  });

  it("limits a line to 8 KiB", () => {
    const { store, layout } = standaloneStore(tempDir());
    const draft = decisionDraft(store);
    draft.tool = { name: "Bash", command: "x".repeat(10_000), paths: Array.from({ length: 100 }, (_, i) => `${"p".repeat(300)}${i}`), truncated: false };
    store.transaction((tx) => tx.append([draft]));
    const lines = readFileSync(join(layout.eventsDir, readdirSync(layout.eventsDir)[0] as string), "utf8").split("\n").filter(Boolean);
    for (const line of lines) expect(Buffer.byteLength(line)).toBeLessThanOrEqual(8192);
    expect(JSON.parse(lines[1] as string).tool.truncated).toBe(true);
  });
});

describe("corruption", () => {
  function twoEvents(): { store: LogStore; layout: Layout; file: string } {
    const { store, layout } = standaloneStore(tempDir());
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    return { store, layout, file: join(layout.eventsDir, readdirSync(layout.eventsDir)[0] as string) };
  }

  it("starts a new chain after an incomplete last line, linked to the last valid event", () => {
    const { store, layout, file } = twoEvents();
    const before = readEvents(layout.eventsDir)[0]?.events ?? [];
    appendFileSync(file, '{"schema":"tollgate.event.v1","partial');
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    expect(readdirSync(layout.eventsDir).sort()).toEqual([`u${uid}-20261011-1.jsonl`, `u${uid}-20261011.jsonl`]);
    const fresh = JSON.parse(readFileSync(join(layout.eventsDir, `u${uid}-20261011-1.jsonl`), "utf8").split("\n")[0] as string);
    expect(fresh).toMatchObject({
      type: "chain_start",
      seq: 1,
      prev_hash: before[1]?.hash,
      data: { reason: "corruption", broken_file: `u${uid}-20261011.jsonl`, broken_chain_id: before[0]?.chain_id, broken_seq: 2 },
    });
    expect(fresh.chain_id).not.toBe(before[0]?.chain_id);
    const second = readFileSync(join(layout.eventsDir, `u${uid}-20261011-1.jsonl`), "utf8").split("\n")[1] as string;
    expect(JSON.parse(second)).toMatchObject({ type: "log_error", seq: 2 });
  });

  it("links to the genesis hash if no valid event is found", () => {
    const { store, layout, file } = twoEvents();
    writeFileSync(file, "garbage\n");
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    const fresh = JSON.parse(readFileSync(join(layout.eventsDir, `u${uid}-20261011-1.jsonl`), "utf8").split("\n")[0] as string);
    expect(fresh).toMatchObject({ type: "chain_start", prev_hash: GENESIS, data: { reason: "corruption", broken_chain_id: null, broken_seq: null } });
  });

  it("detects a forged hash in the last line", () => {
    const { store, layout, file } = twoEvents();
    const text = readFileSync(file, "utf8").replace(/"hash":"[0-9a-f]{64}"\}\n$/, `"hash":"${"a".repeat(64)}"}\n`);
    writeFileSync(file, text);
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    expect(readdirSync(layout.eventsDir)).toContain(`u${uid}-20261011-1.jsonl`);
  });

  it("detects a corrupt previous file when a new day starts", () => {
    const { store, layout, file, } = twoEvents();
    appendFileSync(file, "tail without newline");
    const fixture = (store as unknown as { services: { clock: () => Date } }).services;
    const next = new Date(fixture.clock().getTime() + 24 * 3600 * 1000);
    const later = new LogStore(layout, META, { clock: () => next, uuid: store.uuid });
    later.transaction((tx) => tx.append([decisionDraft(later)]));
    const fresh = JSON.parse(readFileSync(join(layout.eventsDir, `u${uid}-20261012.jsonl`), "utf8").split("\n")[0] as string);
    expect(fresh).toMatchObject({ type: "chain_start", data: { reason: "corruption", broken_file: `u${uid}-20261011.jsonl` } });
  });

  it("evaluateTail: empty, ok, incomplete, long line, partial first line", () => {
    expect(evaluateTail(Buffer.alloc(0), 0)).toEqual({ status: "empty" });
    expect(evaluateTail(Buffer.from("not json\n"), 9)).toEqual({ status: "corrupt", chain_id: null, seq: null, lastValidHash: null });
    expect(evaluateTail(Buffer.from('{"a":1}'), 7)).toMatchObject({ status: "corrupt" });
    const long = Buffer.from(`${"x".repeat(20_000)}\n`).subarray(-16 * 1024);
    expect(evaluateTail(long, 20_001)).toMatchObject({ status: "corrupt", lastValidHash: null });
  });
});

describe("squatting and unsafe files", () => {
  it("writes to an alternate file when the name is a symlink; the target is untouched", () => {
    const root = tempDir();
    const { store, layout } = standaloneStore(root);
    mkdirSync(layout.eventsDir, { recursive: true, mode: 0o700 });
    const target = join(root, "victim.txt");
    writeFileSync(target, "keep");
    symlinkSync(target, join(layout.eventsDir, `u${uid}-20261011.jsonl`));
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    expect(readFileSync(target, "utf8")).toBe("keep");
    const events = JSON.parse(`[${readFileSync(join(layout.eventsDir, `u${uid}-20261011-1.jsonl`), "utf8").trim().split("\n").join(",")}]`);
    expect(events.map((e: { type: string }) => e.type)).toEqual(["chain_start", "log_error", "decision"]);
    expect(events[1].data).toMatchObject({ reason: "unusable event file: symbolic link", file: `u${uid}-20261011.jsonl` });
  });

  it("does not block on a FIFO with the file name", () => {
    const root = tempDir();
    const { store, layout } = standaloneStore(root);
    mkdirSync(layout.eventsDir, { recursive: true, mode: 0o700 });
    execFileSync("mkfifo", [join(layout.eventsDir, `u${uid}-20261011.jsonl`)]);
    const started = Date.now();
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    expect(Date.now() - started).toBeLessThan(3000);
    expect(readdirSync(layout.eventsDir)).toContain(`u${uid}-20261011-1.jsonl`);
  });

  it("refuses a file with a second hard link and uses an alternate file", () => {
    const root = tempDir();
    const { store, layout } = standaloneStore(root);
    mkdirSync(layout.eventsDir, { recursive: true, mode: 0o700 });
    const other = join(root, "other");
    writeFileSync(other, "", { mode: 0o600 });
    linkSync(other, join(layout.eventsDir, `u${uid}-20261011.jsonl`));
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    expect(readFileSync(other, "utf8")).toBe("");
    expect(readdirSync(layout.eventsDir)).toContain(`u${uid}-20261011-1.jsonl`);
  });

  it("gives up after 8 alternate files", () => {
    const root = tempDir();
    const { store, layout } = standaloneStore(root);
    mkdirSync(layout.eventsDir, { recursive: true, mode: 0o700 });
    const victim = join(root, "v");
    writeFileSync(victim, "");
    for (let n = 0; n <= 8; n += 1) symlinkSync(victim, join(layout.eventsDir, n === 0 ? `u${uid}-20261011.jsonl` : `u${uid}-20261011-${n}.jsonl`));
    expect(() => store.transaction((tx) => tx.append([decisionDraft(store)]))).toThrowError(EventWriteError);
    expect(readFileSync(victim, "utf8")).toBe("");
  });

  it("refuses a symlinked private directory", () => {
    const root = tempDir();
    const { store, layout } = standaloneStore(root);
    mkdirSync(join(root, "state"), { recursive: true });
    mkdirSync(join(root, "elsewhere"));
    symlinkSync(join(root, "elsewhere"), layout.lockDir);
    expect(() => store.transaction(() => undefined)).toThrowError(/not a real directory/);
    expect(readdirSync(join(root, "elsewhere"))).toEqual([]);
  });

  it("fileProblem checks type, links, owner, group and mode", () => {
    const base = { isFile: () => true, nlink: 1, uid: 1000, gid: 50, mode: 0o100600 };
    const expect_ = { uid: 1000, mode: 0o600, gid: undefined };
    expect(fileProblem(base, expect_)).toBeNull();
    expect(fileProblem({ ...base, isFile: () => false }, expect_)).toBe("not a regular file");
    expect(fileProblem({ ...base, nlink: 2 }, expect_)).toBe("more than one hard link");
    expect(fileProblem({ ...base, uid: 0 }, expect_)).toBe("owned by another user");
    expect(fileProblem(base, { ...expect_, gid: 51 })).toBe("wrong group");
    expect(fileProblem(base, { ...expect_, gid: 50 })).toBeNull();
    expect(fileProblem({ ...base, mode: 0o100644 }, expect_)).toBe("unexpected mode");
    expect(fileProblem({ ...base, uid: 5, mode: 0o100644 }, { uid: undefined, mode: 0o600, gid: undefined })).toBeNull();
  });
});

describe("enterprise layouts", () => {
  function perUser(root: string): { layout: Layout; store: LogStore } {
    const dir = join(root, "events", String(uid));
    const layout: Layout = { ...enterpriseLayout("per_user", uid, join(root, "home")), eventsDir: dir, lockDir: dir };
    return { layout, store: new LogStore(layout, META, new Fixture().deps) };
  }

  it("layout P never creates the user directory", () => {
    const root = tempDir();
    const { layout, store } = perUser(root);
    expect(() => store.transaction((tx) => tx.append([decisionDraft(store)]))).toThrowError(/event directory missing/);
    expect(() => lstatSync(layout.eventsDir)).toThrow();
  });

  it("layout P writes 0640 files with lock and state in the own directory", () => {
    const root = tempDir();
    const { layout, store } = perUser(root);
    mkdirSync(layout.eventsDir, { recursive: true, mode: 0o750 });
    const old = process.umask(0);
    try {
      store.transaction((tx) => tx.append([decisionDraft(store)]));
    } finally {
      process.umask(old);
    }
    const file = join(layout.eventsDir, `u${uid}-20261011.jsonl`);
    expect(statSync(file).mode & 0o777).toBe(0o640);
    expect(readdirSync(layout.eventsDir).sort()).toEqual([".state", `u${uid}-20261011.jsonl`]);
  });

  it("layout P has no alternate file: a planted symlink is an error", () => {
    const root = tempDir();
    const { layout, store } = perUser(root);
    mkdirSync(layout.eventsDir, { recursive: true, mode: 0o750 });
    symlinkSync(join(root, "x"), join(layout.eventsDir, `u${uid}-20261011.jsonl`));
    expect(() => store.transaction((tx) => tx.append([decisionDraft(store)]))).toThrowError(/unsafe/);
  });

  it("layout S uses the private directory for lock and state and an alternate file on squatting", () => {
    const root = tempDir();
    const events = join(root, "shared");
    mkdirSync(events, { mode: 0o750 });
    const base = enterpriseLayout("shared", uid, join(root, "home"));
    const layout: Layout = { ...base, eventsDir: events, lockDir: join(root, "home", ".local", "state", "tollgate") };
    const store = new LogStore(layout, META, new Fixture().deps);
    symlinkSync(join(root, "x"), join(events, `u${uid}-20261011.jsonl`));
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    expect(readdirSync(events).sort()).toEqual([`u${uid}-20261011-1.jsonl`, `u${uid}-20261011.jsonl`]);
    expect(readdirSync(layout.lockDir).sort()).toEqual([".state"]);
    expect(statSync(join(events, `u${uid}-20261011-1.jsonl`)).mode & 0o777).toBe(0o640);
  });

  it("layout S requires the shared directory to exist", () => {
    const root = tempDir();
    const base = enterpriseLayout("shared", uid, join(root, "home"));
    const store = new LogStore({ ...base, eventsDir: join(root, "missing"), lockDir: join(root, "home", "st") }, META, new Fixture().deps);
    expect(() => store.transaction(() => undefined)).toThrowError(/event directory missing/);
  });
});

describe("retention", () => {
  it("removes only expired files with matching names, without following links", () => {
    const root = tempDir();
    const { store, layout, fixture } = standaloneStore(root);
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    const old = new Date(fixture.time - 31 * 86_400_000);
    const make = (dir: string, name: string): string => {
      const p = join(dir, name);
      writeFileSync(p, "x");
      utimesSync(p, old, old);
      return p;
    };
    const expired = make(layout.eventsDir, `u${uid}-20250101.jsonl`);
    const expiredAlt = make(layout.eventsDir, `u${uid}-20250101-2.jsonl`);
    const session = make(layout.lockDir, "session-abc.json");
    const foreignName = make(layout.eventsDir, "notes.txt");
    const badName = make(layout.eventsDir, "u1-2025.jsonl");
    const outside = join(root, "outside.jsonl");
    writeFileSync(outside, "x");
    utimesSync(outside, old, old);
    const link = join(layout.eventsDir, `u${uid}-20250102.jsonl`);
    symlinkSync(outside, link);
    mkdirSync(join(layout.eventsDir, `u${uid}-20250103.jsonl`));
    const fresh = join(layout.eventsDir, `u${uid}-20261001.jsonl`);
    writeFileSync(fresh, "x");
    const removed = store.cleanup(new Date(fixture.time));
    expect(removed).toBe(3);
    for (const gone of [expired, expiredAlt, session]) expect(() => lstatSync(gone)).toThrow();
    for (const kept of [foreignName, badName, outside, fresh, link]) expect(lstatSync(kept)).toBeTruthy();
    expect(lstatSync(join(layout.eventsDir, `u${uid}-20250103.jsonl`)).isDirectory()).toBe(true);
  });

  it("ignores directories that are links or missing", () => {
    const root = tempDir();
    const { store, layout, fixture } = standaloneStore(root);
    expect(store.cleanup(new Date(fixture.time))).toBe(0);
    mkdirSync(join(root, "state"), { recursive: true });
    mkdirSync(join(root, "real"));
    writeFileSync(join(root, "real", `u${uid}-20250101.jsonl`), "x");
    utimesSync(join(root, "real", `u${uid}-20250101.jsonl`), new Date(0), new Date(0));
    symlinkSync(join(root, "real"), layout.lockDir);
    expect(store.cleanup(new Date(fixture.time))).toBe(0);
    expect(readdirSync(join(root, "real"))).toHaveLength(1);
  });
});

describe("state and sessions", () => {
  it("persists state and reads it without the lock", () => {
    const { store } = standaloneStore(tempDir());
    expect(store.peekState()).toEqual({ v: 1 });
    store.transaction((tx) => {
      expect(tx.logging).toBeUndefined();
      tx.update({ logging: "on", findings_sha256: "b".repeat(64) });
    });
    expect(store.peekState()).toMatchObject({ v: 1, logging: "on", findings_sha256: "b".repeat(64) });
    store.transaction((tx) => {
      expect(tx.logging).toBe("on");
      expect(tx.findingsHash).toBe("b".repeat(64));
    });
  });

  it("ignores an invalid state file", () => {
    const { store, layout } = standaloneStore(tempDir());
    store.transaction((tx) => tx.update({ logging: "on" }));
    writeFileSync(join(layout.lockDir, ".state"), "{not json");
    expect(store.peekState()).toEqual({ v: 1 });
  });

  it("stores, reads and removes session files", () => {
    const { store, layout } = standaloneStore(tempDir());
    store.transaction((tx) => {
      expect(tx.readSession("s-1")).toBeNull();
      tx.writeSession({ v: 1, session_id: "s-1", config: { enabled: false, commandDetail: "none", projectDir: false }, config_sha256: null });
      expect(tx.readSession("s-1")).toMatchObject({ session_id: "s-1", config: { enabled: false } });
      expect(statSync(join(layout.lockDir, "session-s-1.json")).mode & 0o777).toBe(0o600);
      tx.removeSession("s-1");
      expect(tx.readSession("s-1")).toBeNull();
      expect(tx.readSession("../x")).toBeNull();
      expect(tx.readSession("<invalid>")).toBeNull();
      tx.writeSession({ v: 1, session_id: "<invalid>" });
      tx.removeSession("<invalid>");
    });
  });

  it("treats a mismatching or oversized session file as absent", () => {
    const { store, layout } = standaloneStore(tempDir());
    store.transaction((tx) => tx.writeSession({ v: 1, session_id: "a" }));
    writeFileSync(join(layout.lockDir, "session-b.json"), readFileSync(join(layout.lockDir, "session-a.json")));
    writeFileSync(join(layout.lockDir, "session-c.json"), "x".repeat(20_000));
    store.transaction((tx) => {
      expect(tx.readSession("b")).toBeNull();
      expect(tx.readSession("c")).toBeNull();
    });
  });

  it("append of an empty list does nothing", () => {
    const { store, layout } = standaloneStore(tempDir());
    store.transaction((tx) => tx.append([]));
    expect(readdirSync(layout.eventsDir)).toEqual([]);
  });

  it("classifies the first event after a long pause as retention", () => {
    const { store, layout, fixture } = standaloneStore(tempDir());
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    for (const f of readdirSync(layout.eventsDir)) {
      const p = join(layout.eventsDir, f);
      truncateSync(p, 0);
    }
    fixture.advance(40 * 86_400_000);
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    const day2 = readEvents(layout.eventsDir).find((f) => f.file.includes("20261120"));
    expect(day2?.events[0]).toMatchObject({ type: "chain_start", data: { reason: "retention" } });
  });

  it("classifies a vanished previous file as missing_previous", () => {
    const { store, layout, fixture } = standaloneStore(tempDir());
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    for (const f of readdirSync(layout.eventsDir)) truncateSync(join(layout.eventsDir, f), 0);
    fixture.advance(1000);
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    expect(readEvents(layout.eventsDir)[0]?.events[0]).toMatchObject({ type: "chain_start", data: { reason: "missing_previous" } });
  });
});
