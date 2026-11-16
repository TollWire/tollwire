import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { hostname, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  anchorFilePath,
  anchorLine,
  anchorRecordHash,
  checkAnchors,
  createAnchor,
  inspectAnchorFile,
  signedTagCommand,
  verifyAgainstAnchors,
  verifyLogWithAnchors,
} from "../src/anchor.js";
import { appendEntry, EvidenceError, readEntries } from "../src/log.js";

const tmpLog = () => join(mkdtempSync(join(tmpdir(), "ev-anchor-")), "nested", "log.jsonl");
const event = { type: "change" as const, summary: "PR #7 merged", actor: "engineer" };

function seed(log: string, n: number, start = 0): void {
  for (let i = 0; i < n; i++) appendEntry(log, { ...event, summary: `event ${start + i}` }, new Date(Date.UTC(2026, 9, 3, 10, start + i)));
}

/** Simulates an attacker who rewrites the whole log as a new, internally valid chain. */
function rewriteLog(log: string, n: number, summary: string): void {
  rmSync(log);
  for (let i = 0; i < n; i++) appendEntry(log, { ...event, summary: `${summary} ${i}` }, new Date(Date.UTC(2026, 9, 3, 10, i)));
}

describe("anchor creation", () => {
  it("anchors the latest entry and stores a hash-linked record with 0600", () => {
    const log = tmpLog();
    seed(log, 3);
    const first = createAnchor(log, { now: new Date("2026-10-04T08:00:00Z") });
    const last = readEntries(log).at(-1)!;
    expect(first.created).toBe(true);
    expect(first.anchor).toEqual({ seq: 3, hash: last.hash, ts: last.ts, count: 3 });
    expect(first.line).toBe(`{"count":3,"hash":"${last.hash}","seq":3,"ts":"${last.ts}"}`);
    expect(first.record.prev_anchor_hash).toBe("0".repeat(64));
    expect(first.record.anchor_hash).toBe(anchorRecordHash(first.record));
    if (process.platform !== "win32") expect(statSync(anchorFilePath(log)).mode & 0o777).toBe(0o600);

    seed(log, 1, 3);
    const second = createAnchor(log);
    expect(second.anchor.seq).toBe(4);
    expect(second.record.prev_anchor_hash).toBe(first.record.anchor_hash);
    expect(inspectAnchorFile(log).status).toEqual({ present: true, valid: true, count: 2 });
  });

  it("is idempotent while the head has not moved", () => {
    const log = tmpLog();
    seed(log, 1);
    const a = createAnchor(log);
    const b = createAnchor(log);
    expect(b.created).toBe(false);
    expect(b.record).toEqual(a.record);
    expect(inspectAnchorFile(log).records).toHaveLength(1);
  });

  it("refuses empty, corrupted or contradicting logs and corrupted anchor files", () => {
    const empty = tmpLog();
    expect(() => createAnchor(empty)).toThrow(/empty/);

    const corrupted = tmpLog();
    seed(corrupted, 2);
    writeFileSync(corrupted, readFileSync(corrupted, "utf8").replace("event 1", "forged"));
    expect(() => createAnchor(corrupted)).toThrow(/corrupted at seq 2/);

    const rewritten = tmpLog();
    seed(rewritten, 2);
    createAnchor(rewritten);
    rewriteLog(rewritten, 3, "rewritten");
    expect(() => createAnchor(rewritten)).toThrow(/contradicts a stored anchor/);

    const badFile = tmpLog();
    seed(badFile, 1);
    createAnchor(badFile);
    writeFileSync(anchorFilePath(badFile), "not json\n");
    expect(() => createAnchor(badFile)).toThrow(EvidenceError);
  });

  it("restricts an existing anchor file to the owner and repairs a missing trailing newline", () => {
    if (process.platform === "win32") return;
    const log = tmpLog();
    seed(log, 1);
    createAnchor(log);
    const file = anchorFilePath(log);
    writeFileSync(file, readFileSync(file, "utf8").trimEnd());
    chmodSync(file, 0o644);
    seed(log, 1, 1);
    createAnchor(log);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(inspectAnchorFile(log).status).toEqual({ present: true, valid: true, count: 2 });
  });
});

describe("verification against anchors", () => {
  it("accepts an unchanged and a grown log", () => {
    const log = tmpLog();
    seed(log, 2);
    const { anchor } = createAnchor(log);
    expect(verifyAgainstAnchors(log, [anchor])).toEqual({ valid: true, count: 2, checked: 1 });
    seed(log, 2, 2);
    expect(verifyAgainstAnchors(log, [anchor])).toEqual({ valid: true, count: 4, checked: 1 });
    expect(verifyLogWithAnchors(log, [anchor])).toEqual({
      valid: true,
      count: 4,
      checked: 2,
      anchorFile: { present: true, valid: true, count: 1 },
      externalAnchorsChecked: 1,
      anchored: true,
    });
  });

  it("never reports a log as anchored without a confirmed external anchor (review finding 1)", () => {
    const log = tmpLog();
    seed(log, 2);
    // No anchor file, no external anchors: consistent with itself, but not anchored.
    expect(verifyLogWithAnchors(log)).toEqual({
      valid: true,
      count: 2,
      checked: 0,
      anchorFile: { present: false, valid: true, count: 0 },
      externalAnchorsChecked: 0,
      anchored: false,
    });
    // Local anchor file only: still not anchored, it can be rewritten together with the log.
    const { anchor } = createAnchor(log);
    expect(verifyLogWithAnchors(log)).toMatchObject({ valid: true, checked: 1, externalAnchorsChecked: 0, anchored: false });
    // A failing external anchor is never "anchored", even if other anchors passed.
    const bad = { ...anchor, hash: "b".repeat(64) };
    expect(verifyLogWithAnchors(log, [anchor, bad])).toMatchObject({ valid: false, externalAnchorsChecked: 1, anchored: false });
    // A broken anchor file makes the result invalid and not anchored even with a matching external anchor.
    writeFileSync(anchorFilePath(log), "{oops\n");
    expect(verifyLogWithAnchors(log, [anchor])).toMatchObject({ valid: false, externalAnchorsChecked: 1, anchored: false });
  });

  it("detects a rewritten log (new valid chain) via the external anchor", () => {
    const log = tmpLog();
    seed(log, 3);
    const { anchor } = createAnchor(log);
    rewriteLog(log, 3, "rewritten");
    rmSync(anchorFilePath(log)); // attacker also removes the local anchor file
    const result = verifyLogWithAnchors(log, [anchor]);
    expect(result).toMatchObject({ valid: false, checked: 0, failedAnchor: anchor, failedSource: "input" });
    expect(result.reason).toMatch(/differs from anchor \(log rewritten\)/);
    expect(result.anchorFile).toEqual({ present: false, valid: true, count: 0 });
    expect(result).toMatchObject({ externalAnchorsChecked: 0, anchored: false });
  });

  it("detects a rewritten log via the local anchor file", () => {
    const log = tmpLog();
    seed(log, 2);
    createAnchor(log);
    rewriteLog(log, 2, "rewritten");
    expect(verifyLogWithAnchors(log)).toMatchObject({ valid: false, failedSource: "anchor_file", reason: expect.stringMatching(/log rewritten/) });
  });

  it("detects a truncated log", () => {
    const log = tmpLog();
    seed(log, 4);
    const { anchor } = createAnchor(log);
    const lines = readFileSync(log, "utf8").trim().split("\n");
    writeFileSync(log, lines.slice(0, 2).join("\n") + "\n"); // still a valid chain of 2
    const result = verifyAgainstAnchors(log, [anchor]);
    expect(result).toMatchObject({ valid: false, count: 2, checked: 0, failedIndex: 0 });
    expect(result.reason).toMatch(/seq 4 missing \(log truncated or rewritten\)/);
    rmSync(log);
    expect(verifyAgainstAnchors(log, [anchor])).toMatchObject({ valid: false, count: 0 });
  });

  it("reports chain failures, invalid and inconsistent anchors", () => {
    const log = tmpLog();
    seed(log, 2);
    const { anchor } = createAnchor(log);
    expect(verifyAgainstAnchors(log, [{ seq: "x" }])).toMatchObject({ valid: false, reason: "invalid anchor", failedIndex: 0 });
    expect(verifyAgainstAnchors(log, [{ ...anchor, count: 5 }])).toMatchObject({ valid: false, reason: expect.stringMatching(/inconsistent/) });
    expect(verifyAgainstAnchors(log, [{ ...anchor, ts: "2020-01-01T00:00:00.000Z" }])).toMatchObject({
      valid: false,
      reason: expect.stringMatching(/timestamp/),
    });
    // Extra keys (e.g. a pasted stored record) are ignored, not reported back.
    const pasted = { ...anchor, created_at: "2026-10-04T00:00:00.000Z" };
    expect(checkAnchors(readEntries(log), [pasted])).toEqual({ valid: true, checked: 1 });

    writeFileSync(log, readFileSync(log, "utf8") + "garbage\n");
    expect(verifyAgainstAnchors(log, [anchor])).toMatchObject({ valid: false, checked: 0, brokenAt: 3, reason: "chain: invalid JSON at line 3" });
  });
});

describe("tamper-evident anchor file", () => {
  function anchoredLog(): string {
    const log = tmpLog();
    seed(log, 1);
    createAnchor(log, { now: new Date("2026-10-04T08:00:00Z") });
    seed(log, 1, 1);
    createAnchor(log, { now: new Date("2026-10-04T09:00:00Z") });
    seed(log, 1, 2);
    createAnchor(log, { now: new Date("2026-10-04T10:00:00Z") });
    return log;
  }
  const records = (log: string) => readFileSync(anchorFilePath(log), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const write = (log: string, rows: unknown[]) => writeFileSync(anchorFilePath(log), rows.map((r) => JSON.stringify(r)).join("\n") + "\n");

  it("detects a modified anchor record", () => {
    const log = anchoredLog();
    const rows = records(log);
    rows[1].created_at = "2026-10-04T09:30:00.000Z";
    write(log, rows);
    expect(inspectAnchorFile(log).status).toEqual({ present: true, valid: false, count: 1, brokenAt: 2, reason: "anchor hash mismatch" });
    expect(verifyLogWithAnchors(log)).toMatchObject({ valid: false, reason: "anchor file: anchor hash mismatch at record 2" });
  });

  it("detects removed, reordered and forged anchor records", () => {
    const log = anchoredLog();
    const rows = records(log);
    write(log, [rows[0], rows[2]]);
    expect(inspectAnchorFile(log).status).toMatchObject({ valid: false, brokenAt: 2, reason: "anchor chain broken" });
    write(log, [rows[1], rows[0], rows[2]]);
    expect(inspectAnchorFile(log).status).toMatchObject({ valid: false, brokenAt: 1, reason: "anchor chain broken" });

    // A self-consistent forged record still needs a consistent count and a monotonic seq.
    const forge = (base: Record<string, unknown>) => ({ ...base, anchor_hash: anchorRecordHash(base as never) });
    const { anchor_hash: _a, ...first } = rows[0];
    void _a;
    write(log, [forge({ ...first, count: 9 })]);
    expect(inspectAnchorFile(log).status).toMatchObject({ valid: false, reason: expect.stringMatching(/inconsistent/) });
    const r0 = forge({ ...first, seq: 2, count: 2 });
    const r1 = forge({ ...first, prev_anchor_hash: r0.anchor_hash });
    write(log, [r0, r1]);
    expect(inspectAnchorFile(log).status).toMatchObject({ valid: false, brokenAt: 2, reason: expect.stringMatching(/regression/) });

    writeFileSync(anchorFilePath(log), JSON.stringify({ seq: 1 }) + "\n");
    expect(inspectAnchorFile(log).status).toMatchObject({ valid: false, reason: "invalid anchor record structure" });
    writeFileSync(anchorFilePath(log), "{oops\n");
    expect(inspectAnchorFile(log).status).toMatchObject({ valid: false, reason: "invalid JSON" });
  });

  it("formats the suggested signed-tag command without shell-active characters", () => {
    const log = anchoredLog();
    const { anchor, record } = createAnchor(log);
    const command = signedTagCommand(anchor, record.created_at);
    expect(command).toBe(`git tag -s evidence-anchor-2026-10-04-seq3 -m '${anchorLine(anchor)}'`);
    expect(anchorLine(anchor)).toMatch(/^[{}":,0-9a-zA-Z.\-]+$/);
  });
});

describe("symlink protection (review finding 3)", () => {
  it("refuses a pre-planted symlink at the anchor file and leaves its target untouched", () => {
    if (process.platform === "win32") return;
    const log = tmpLog();
    seed(log, 1);
    const victim = join(mkdtempSync(join(tmpdir(), "ev-victim-")), "victim.txt");
    writeFileSync(victim, "keep\n");
    chmodSync(victim, 0o644);
    symlinkSync(victim, anchorFilePath(log));
    expect(() => createAnchor(log)).toThrow(/symbolic link/);
    expect(readFileSync(victim, "utf8")).toBe("keep\n");
    expect(statSync(victim).mode & 0o777).toBe(0o644);
    // Dangling links are refused too (no file is created at the link target).
    rmSync(anchorFilePath(log));
    const missing = join(dirname(victim), "created-through-link.jsonl");
    symlinkSync(missing, anchorFilePath(log));
    expect(() => createAnchor(log)).toThrow(/symbolic link/);
    expect(existsSync(missing)).toBe(false);
  });

  it("refuses a hard-linked anchor file and leaves the other link untouched", async () => {
    if (process.platform === "win32") return;
    const { linkSync } = await import("node:fs");
    const other = tmpLog();
    seed(other, 1);
    createAnchor(other);
    chmodSync(anchorFilePath(other), 0o644);
    const before = readFileSync(anchorFilePath(other), "utf8");
    const log = tmpLog();
    seed(log, 1);
    linkSync(anchorFilePath(other), anchorFilePath(log));
    expect(() => createAnchor(log)).toThrow(/multiple hard links/);
    expect(() => verifyLogWithAnchors(log)).toThrow(/multiple hard links/);
    expect(readFileSync(anchorFilePath(other), "utf8")).toBe(before);
    expect(statSync(anchorFilePath(other)).mode & 0o777).toBe(0o644);
  });

  it("refuses an anchor file that is not a regular file", () => {
    const log = tmpLog();
    seed(log, 1);
    mkdirSync(anchorFilePath(log));
    expect(() => createAnchor(log)).toThrow(/not a regular file/);
  });
});

describe("concurrency (shared lock with appends)", () => {
  it("waits for the log lock held by another live process and leaves no partial anchor", () => {
    const log = tmpLog();
    seed(log, 1);
    // A lock owned by a live process on this host is never broken (withLock semantics).
    writeFileSync(`${log}.lock`, JSON.stringify({ pid: process.pid, host: hostname(), token: "other-writer" }));
    expect(() => createAnchor(log, { lockTimeoutMs: 100 })).toThrow(/locked by another process/);
    expect(existsSync(anchorFilePath(log))).toBe(false);
    rmSync(`${log}.lock`);
    expect(createAnchor(log).created).toBe(true);
    expect(existsSync(`${log}.lock`)).toBe(false);
  });

  it("keeps log and anchor file consistent when appends and anchors interleave", () => {
    const log = tmpLog();
    for (let i = 0; i < 20; i++) {
      appendEntry(log, { ...event, summary: `i${i}` });
      if (i % 3 === 0) createAnchor(log);
    }
    const result = verifyLogWithAnchors(log);
    expect(result).toMatchObject({ valid: true, count: 20, checked: 7, anchorFile: { valid: true, count: 7 } });
  });
});

