import { chmodSync, linkSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { chain, DAY, NOW, spoolDir, spoolSource, tmp, UID, userDir, userSource, writeLines, makeEvent } from "./helpers.js";
import { FileSource } from "../src/source.js";
import { DEFAULT_LIMITS } from "../src/limits.js";

const query = (o: Partial<Parameters<FileSource["list"]>[0]> = {}) => ({ limit: 100, sinceMs: NOW - 86_400_000, nowMs: NOW, ...o });

describe("reading the own event files", () => {
  it("lists events newest first across files and skips files outside the time window", async () => {
    const dir = tmp();
    const day1 = chain([{ ts: "2026-10-15T10:00:00.000Z" }]);
    writeLines(join(dir, `u${UID}-20261015.jsonl`), day1);
    const day2 = chain([{ ts: "2026-10-16T10:00:00.000Z" }], "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    writeLines(join(dir, `u${UID}-${DAY}.jsonl`), day2);
    const all = userSource(dir).list(query({ sinceMs: Date.parse("2026-10-15T00:00:00Z") }));
    expect(all.events.map((e) => e.event.ts)).toEqual([day2[1], day2[0], day1[1], day1[0]].map((e) => (e as { ts: string }).ts));
    const recent = userSource(dir).list(query({ sinceMs: Date.parse("2026-10-16T00:00:00Z") }));
    expect(recent.events).toHaveLength(2);
  });

  it("ignores lines that are not events and files with other names", () => {
    const dir = userDir([...chain([{}]), "garbage", "[]", "{}", JSON.stringify({ schema: "other", type: "x" }), JSON.stringify({ schema: "tollgate.event.v1", type: "decision" })]);
    writeFileSync(join(dir, "notes.txt"), "x");
    writeFileSync(join(dir, `u${UID}-2026101.jsonl`), "x");
    writeFileSync(join(dir, `x${UID}-${DAY}.jsonl`), "x");
    expect(userSource(dir).list(query()).events).toHaveLength(2);
  });

  it("treats a missing events directory as an empty log, not as an error (plugin has not run yet)", () => {
    const r = userSource(join(tmp(), "nope")).list(query());
    expect(r.events).toEqual([]);
    expect(r.findings).toEqual([]);
  });

  it("reports an unreadable directory without paths", () => {
    const parent = join(tmp(), "file");
    writeFileSync(parent, "x");
    const r = userSource(join(parent, "events")).list(query());
    expect(r.events).toEqual([]);
    expect(r.findings[0]).toMatchObject({ kind: "unreadable" });
    expect(JSON.stringify(r.findings)).not.toContain("/tmp");
  });

  it("does not follow a symbolic link and does not open a FIFO", () => {
    const dir = userDir(chain([{}]));
    const target = join(tmp(), "target.jsonl");
    writeLines(target, chain([{ session: "linked" }]));
    symlinkSync(target, join(dir, `u${UID}-20261015.jsonl`));
    execFileSync("mkfifo", [join(dir, `u${UID}-20261014.jsonl`)]);
    const r = userSource(dir).list(query({ sinceMs: Date.parse("2026-10-14T00:00:00Z") }));
    expect(JSON.stringify(r)).not.toContain("linked");
    expect(r.findings.map((f) => f.kind).sort()).toEqual(["not_regular", "symlink"]);
  });

  it("does not show a file with another link count or a wider mode, and says so", () => {
    const dir = userDir(chain([{ session: "good" }]));
    const bad = join(dir, `u${UID}-20261015.jsonl`);
    writeLines(bad, chain([{ session: "hardlinked" }], "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"));
    linkSync(bad, join(tmp(), "alias"));
    const wide = join(dir, `u${UID}-20261014.jsonl`);
    writeLines(wide, chain([{ session: "wide" }], "cccccccc-cccc-4ccc-8ccc-cccccccccccc"), 0o644);
    chmodSync(wide, 0o644);
    const r = userSource(dir).list(query({ sinceMs: Date.parse("2026-10-14T00:00:00Z") }));
    const text = JSON.stringify(r.events);
    expect(text).toContain("good");
    expect(text).not.toContain("hardlinked");
    expect(text).not.toContain("wide");
    expect(r.findings.map((f) => f.kind).sort()).toEqual(["hardlink", "mode"]);
  });

  it("does not show a file that another account owns (checked against the expected owner)", () => {
    // The spool is expected to belong to tollgate-relay; a file of any other owner is not shown.
    const { dir } = spoolDir(chain([{ session: "from-elsewhere" }]));
    const src = new FileSource({ kind: "spool", dir, ownerUid: UID + 1, maxMode: 0o640 }, DEFAULT_LIMITS);
    const r = src.list(query());
    expect(r.events).toEqual([]);
    expect(r.findings.map((f) => f.kind)).toContain("owner");
  });

  it("limits what it reads: scan budget, long lines and the file size", () => {
    const dir = userDir(chain(Array.from({ length: 40 }, () => ({}))));
    const small = userSource(dir, { scanBytes: 1000 }).list(query());
    expect(small.truncated).toBe(true);
    expect(small.events.length).toBeLessThan(41);
    const long = userDir([...chain([{}]), "x".repeat(9000)]);
    const r = userSource(long).list(query());
    expect(r.events).toHaveLength(2);
    expect(r.findings.map((f) => f.kind)).toContain("line_too_long");
  });

  it("a user chain of another user in the same file is not shown", () => {
    const own = chain([{}]);
    const foreign = chain([{ session: "theirs" }], "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", UID + 7);
    const r = userSource(userDir([...own, ...foreign])).list(query());
    expect(JSON.stringify(r.events)).not.toContain("theirs");
  });

  it("returns each event once", () => {
    const events = chain([{}]);
    const r = userSource(userDir([...events, events[1]] as Record<string, unknown>[])).list(query());
    expect(r.events).toHaveLength(2);
  });

  it("verification refuses nothing silently: unreadable files become read findings", async () => {
    const dir = userDir(chain([{}]));
    execFileSync("mkfifo", [join(dir, `u${UID}-20261015.jsonl`)]);
    const r = await userSource(dir).verify(NOW);
    expect(r.ok).toBe(false);
    expect(r.read_findings.map((f) => f.kind)).toContain("not_regular");
  });

  it("an empty directory verifies as valid with no events", async () => {
    const dir = tmp();
    mkdirSync(join(dir, "sub"));
    expect(await userSource(dir).verify(NOW)).toMatchObject({ ok: true, files: 0, events: 0 });
  });

  it("limits the work for a directory with many entries", () => {
    const dir = tmp();
    for (let i = 0; i < 1005; i += 1) writeFileSync(join(dir, `f${i}`), "");
    const r = spoolSource(dir).list(query());
    expect(r.findings.map((f) => f.kind)).toContain("directory_limit");
  });

  it("builds the view of a hostile relay record safely", () => {
    const dir = tmp();
    const rec = (data: unknown) => ({ type: "relay_record", data: data as Record<string, unknown> });
    const specs = [rec(null), rec({ event: null }), rec({ event: { schema: "x" } }), rec({ event: makeEvent({ seq: 1, prev: "0".repeat(64) }), owner_uid: "root", chain_ok: "yes", file: 5 })];
    writeLines(join(dir, `relay-${DAY}.jsonl`), chain(specs, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", UID), 0o640);
    const r = spoolSource(dir).list(query());
    // The records that are not well formed are dropped; the usable one has its relay statements reduced to null.
    const usable = r.events.filter((e) => e.event.type === "decision");
    expect(usable).toHaveLength(1);
    expect(usable[0]?.relay).toMatchObject({ owner_uid: null, chain_ok: null, file: null });
  });
});
