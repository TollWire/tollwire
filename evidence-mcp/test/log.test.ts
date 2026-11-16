import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { appendEntry, canonicalJson, containsSecret, EvidenceError, GENESIS_HASH, readEntries, verifyEntries } from "../src/log.js";

const tmpLog = () => join(mkdtempSync(join(tmpdir(), "ev-")), "nested", "log.jsonl");
const event = { type: "change" as const, summary: "PR #7 merged", actor: "engineer", ref: "https://github.com/o/r/pull/7" };

describe("evidence log", () => {
  it("builds a verifiable hash chain", () => {
    const log = tmpLog();
    const a = appendEntry(log, event, new Date("2026-10-03T10:00:00Z"));
    const b = appendEntry(log, { ...event, type: "scan", summary: "gates green" }, new Date("2026-10-03T10:05:00Z"));
    expect(a.seq).toBe(1);
    expect(a.prev_hash).toBe(GENESIS_HASH);
    expect(b.prev_hash).toBe(a.hash);
    expect(verifyEntries(readEntries(log))).toEqual({ valid: true, count: 2 });
  });

  it("detects tampering, deletion and reordering", () => {
    const log = tmpLog();
    appendEntry(log, event);
    appendEntry(log, { ...event, summary: "second" });
    appendEntry(log, { ...event, summary: "third" });
    const lines = readFileSync(log, "utf8").trim().split("\n");

    writeFileSync(log, lines.map((l, i) => (i === 1 ? l.replace("second", "forged") : l)).join("\n") + "\n");
    expect(verifyEntries(readEntries(log))).toMatchObject({ valid: false, brokenAt: 2, reason: "hash mismatch" });

    writeFileSync(log, [lines[0], lines[2]].join("\n") + "\n");
    expect(verifyEntries(readEntries(log))).toMatchObject({ valid: false, reason: "sequence gap" });

    const reseq = lines.map((l) => JSON.parse(l));
    reseq[1].prev_hash = "f".repeat(64);
    writeFileSync(log, reseq.map((e) => JSON.stringify(e)).join("\n") + "\n");
    expect(verifyEntries(readEntries(log))).toMatchObject({ valid: false, brokenAt: 2, reason: "chain broken" });
  });

  it("refuses to append to a corrupted log", () => {
    const log = tmpLog();
    appendEntry(log, event);
    writeFileSync(log, readFileSync(log, "utf8").replace("PR #7", "PR #8"));
    expect(() => appendEntry(log, event)).toThrow(EvidenceError);
  });

  it("rejects secrets, oversized and invalid events", () => {
    const log = tmpLog();
    const token = `ghp_${"a".repeat(36)}`;
    expect(() => appendEntry(log, { ...event, details: { token } })).toThrow(/secret/);
    expect(() => appendEntry(log, { ...event, details: { blob: "x".repeat(25_000) } })).toThrow(/too large/);
    expect(() => appendEntry(log, { ...event, type: "other" as never })).toThrow();
    expect(readEntries(log)).toEqual([]);
  });

  it("detects common secret formats", () => {
    // Fixtures are assembled at runtime so the repository secret scan stays meaningful.
    const dashes = "-".repeat(5);
    expect(containsSecret(`${dashes}BEGIN RSA ${"PRIVATE"} KEY${dashes}`)).toBe(true);
    expect(containsSecret(["AKIA", "ABCDEFGHIJKLMNOP"].join(""))).toBe(true);
    expect(containsSecret(`sk-ant-${"x".repeat(30)}`)).toBe(true);
    expect(containsSecret("plain text about keys")).toBe(false);
  });

  it("detects further common credential formats with few false positives", () => {
    // Assembled at runtime (no literal tokens in the source) so the repository secret scan stays meaningful.
    const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const jwt = [b64({ alg: "HS256", typ: "JWT" }), b64({ sub: "1234567890", name: "x" }), "S".repeat(43)].join(".");
    const dashes = "-".repeat(5);
    const positives = {
      stripeLive: ["sk", "live", "a1B2".repeat(6)].join("_"),
      stripeTest: ["sk", "test", "a1B2".repeat(6)].join("_"),
      stripeRestricted: ["rk", "live", "Z9y8".repeat(6)].join("_"),
      googleApiKey: ["AI", "za", "Sy", "A-b_".repeat(7), "xy", "c1d"].join(""), // 39 characters
      jwt,
      bearerJwt: `Authorization: Bearer ${jwt}`,
      slackBot: ["xo", "xb-", "1".repeat(12), "-", "a".repeat(24)].join(""),
      slackWebhook: ["https://hooks.slack", ".com/services/", "T0123ABCD", "/", "B0123ABCD", "/", "x".repeat(24)].join(""),
      npmToken: ["np", "m_", "a1".repeat(18)].join(""),
      gitlabPat: ["gl", "pat-", "a".repeat(20)].join(""),
      pgpPrivateKey: `${dashes}BEGIN PGP ${"PRIVATE"} KEY BLOCK${dashes}`,
      opensshPrivateKey: `${dashes}BEGIN OPENSSH ${"PRIVATE"} KEY${dashes}`,
    };
    for (const [name, value] of Object.entries(positives)) expect(containsSecret(value), name).toBe(true);

    const negatives = {
      stripeDocs: "Stripe keys start with sk_live_ or rk_live_; never log them.",
      stripeShort: ["sk", "live", "abc"].join("_"),
      googleShort: ["AI", "za", "Sy", "short"].join(""),
      googleTooLongWord: ["AI", "za", "x".repeat(40)].join(""),
      singleBase64Segment: b64({ alg: "HS256" }),
      twoSegments: [b64({ alg: "HS256" }), b64({ sub: "x" })].join("."),
      dottedIdentifier: "eyJhbGci.eyJzdWIi.sig",
      sha256: "0".repeat(64),
      anchorLine: `{"count":42,"hash":"${"ab".repeat(32)}","seq":42,"ts":"2026-10-04T08:00:00.000Z"}`,
      slackDocs: "Post to hooks.slack.com/services/<team>/<bot>/<secret> (not stored here).",
      npmScript: "npm_config_cache and npm_lifecycle_event are environment variables",
      gitlabWord: "glpat- prefix denotes a GitLab personal access token",
      publicKey: `${dashes}BEGIN PUBLIC KEY${dashes}`,
      semver: "release evidence-mcp-v0.2.0 tagged",
    };
    for (const [name, value] of Object.entries(negatives)) expect(containsSecret(value), name).toBe(false);
  });

  it("produces key-order independent canonical JSON", () => {
    expect(canonicalJson({ b: 1, a: [2, { d: 3, c: undefined }] })).toBe('{"a":[2,{"d":3}],"b":1}');
  });
});

describe("hardening (Copilot review PR #9)", () => {
  it("reports invalid JSON and unknown types as integrity failures and blocks appends", async () => {
    const { verifyLog } = await import("../src/log.js");
    const log = tmpLog();
    appendEntry(log, event);
    writeFileSync(log, readFileSync(log, "utf8") + "{not json\n");
    expect(verifyLog(log)).toMatchObject({ valid: false, count: 1, reason: "invalid JSON at line 2" });
    expect(() => appendEntry(log, event)).toThrow(/corrupted/);

    const log2 = tmpLog();
    appendEntry(log2, event);
    writeFileSync(log2, readFileSync(log2, "utf8").replace('"type":"change"', '"type":"bogus"'));
    expect(verifyLog(log2)).toMatchObject({ valid: false, reason: "invalid record structure at line 1" });
  });

  it("restricts existing logs to owner-only permissions", async () => {
    const { chmodSync, statSync } = await import("node:fs");
    const log = tmpLog();
    appendEntry(log, event);
    chmodSync(log, 0o644);
    appendEntry(log, event);
    expect(statSync(log).mode & 0o777).toBe(0o600);
  });

  it("refuses to write through a symlinked or non-regular log (review finding 3)", async () => {
    const { mkdirSync: mkdir, symlinkSync, statSync, chmodSync } = await import("node:fs");
    const { dirname } = await import("node:path");
    const log = tmpLog();
    mkdir(dirname(log), { recursive: true });
    if (process.platform !== "win32") {
      const victim = join(mkdtempSync(join(tmpdir(), "ev-victim-")), "victim.txt");
      writeFileSync(victim, "keep\n");
      chmodSync(victim, 0o644);
      symlinkSync(victim, log);
      expect(() => appendEntry(log, event)).toThrow(/symbolic link/);
      expect(readFileSync(victim, "utf8")).toBe("keep\n");
      expect(statSync(victim).mode & 0o777).toBe(0o644);
    }
    const dirLog = tmpLog();
    mkdir(dirLog, { recursive: true });
    expect(() => appendEntry(dirLog, event)).toThrow(/not a regular file/);
  });

  it("refuses a hard-linked log (nlink > 1) and leaves the other link untouched", async () => {
    const { mkdirSync: mkdir, linkSync, statSync, chmodSync } = await import("node:fs");
    const { dirname } = await import("node:path");
    const { verifyLog } = await import("../src/log.js");
    if (process.platform === "win32") return;
    // The victim is a valid evidence log elsewhere, so only the hard-link check can stop the append.
    const victim = tmpLog();
    appendEntry(victim, event);
    chmodSync(victim, 0o644);
    const before = readFileSync(victim, "utf8");
    const log = tmpLog();
    mkdir(dirname(log), { recursive: true });
    linkSync(victim, log);
    expect(() => appendEntry(log, event)).toThrow(/multiple hard links/);
    expect(() => readEntries(log)).toThrow(/multiple hard links/);
    expect(() => verifyLog(log)).toThrow(/multiple hard links/);
    expect(readFileSync(victim, "utf8")).toBe(before);
    expect(statSync(victim).mode & 0o777).toBe(0o644);
  });

  it("refuses to read a log through a symlink or from a non-regular file", async () => {
    const { mkdirSync: mkdir, symlinkSync } = await import("node:fs");
    const { dirname } = await import("node:path");
    if (process.platform === "win32") return;
    const victim = tmpLog();
    appendEntry(victim, event);
    const log = tmpLog();
    mkdir(dirname(log), { recursive: true });
    symlinkSync(victim, log);
    expect(() => readEntries(log)).toThrow(/symbolic link/);
    const dangling = tmpLog();
    mkdir(dirname(dangling), { recursive: true });
    symlinkSync(join(dirname(victim), "missing.jsonl"), dangling);
    expect(() => readEntries(dangling)).toThrow(/symbolic link/);
    const dirLog = tmpLog();
    mkdir(dirLog, { recursive: true });
    expect(() => readEntries(dirLog)).toThrow(/not a regular file/);
  });

  it("accepts a relative log path with .. segments (resolved before use)", async () => {
    const { relative } = await import("node:path");
    const base = mkdtempSync(join(tmpdir(), "ev-rel-"));
    const log = relative(process.cwd(), join(base, "a", "..", "b", "log.jsonl"));
    appendEntry(log, event);
    appendEntry(log, event);
    expect(readEntries(join(base, "b", "log.jsonl")).map((e) => e.seq)).toEqual([1, 2]);
  });

  it("reports a held lock without an absolute path", async () => {
    const { mkdirSync: mkdir } = await import("node:fs");
    const { dirname } = await import("node:path");
    const { withLock } = await import("../src/log.js");
    const log = tmpLog();
    mkdir(dirname(log), { recursive: true });
    writeFileSync(`${log}.lock`, "");
    expect(() => withLock(log, () => 1, 50)).toThrow("Evidence log is locked by another process (log.jsonl.lock).");
  });

  it("adds a newline before appending to an unterminated log", () => {
    const log = tmpLog();
    appendEntry(log, event);
    writeFileSync(log, readFileSync(log, "utf8").trimEnd());
    appendEntry(log, event);
    expect(verifyEntries(readEntries(log))).toEqual({ valid: true, count: 2 });
  });

  it("times out on a held lock and removes unowned stale locks", async () => {
    const { utimesSync, mkdirSync: mkdir } = await import("node:fs");
    const { dirname } = await import("node:path");
    const { withLock } = await import("../src/log.js");
    const log = tmpLog();
    mkdir(dirname(log), { recursive: true });
    writeFileSync(`${log}.lock`, "");
    expect(() => withLock(log, () => 1, 100)).toThrow(/locked/);
    const old = new Date(Date.now() - 60_000);
    utimesSync(`${log}.lock`, old, old);
    expect(withLock(log, () => 42, 1_000)).toBe(42);
  });

  it("never breaks a lock held by a live process, however old", async () => {
    const { utimesSync, mkdirSync: mkdir, existsSync: exists } = await import("node:fs");
    const { dirname } = await import("node:path");
    const { hostname } = await import("node:os");
    const { withLock } = await import("../src/log.js");
    const log = tmpLog();
    mkdir(dirname(log), { recursive: true });
    const live = JSON.stringify({ pid: process.pid, host: hostname(), token: "live-writer" });
    writeFileSync(`${log}.lock`, live);
    const old = new Date(Date.now() - 3_600_000);
    utimesSync(`${log}.lock`, old, old);
    expect(() => withLock(log, () => 1, 100)).toThrow(/locked/);
    expect(readFileSync(`${log}.lock`, "utf8")).toBe(live);
    expect(exists(`${log}.lock`)).toBe(true);
  });

  it("never breaks a lock from another host", async () => {
    const { mkdirSync: mkdir } = await import("node:fs");
    const { dirname } = await import("node:path");
    const { withLock } = await import("../src/log.js");
    const log = tmpLog();
    mkdir(dirname(log), { recursive: true });
    writeFileSync(`${log}.lock`, JSON.stringify({ pid: 1, host: "other-host.invalid", token: "remote" }));
    expect(() => withLock(log, () => 1, 100)).toThrow(/locked/);
  });

  it("breaks a lock whose owner process is dead and releases only its own lock", async () => {
    const { mkdirSync: mkdir, existsSync: exists } = await import("node:fs");
    const { dirname } = await import("node:path");
    const { hostname } = await import("node:os");
    const { spawnSync } = await import("node:child_process");
    const { withLock } = await import("../src/log.js");
    const log = tmpLog();
    mkdir(dirname(log), { recursive: true });
    const dead = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"]).stdout.toString();
    writeFileSync(`${log}.lock`, JSON.stringify({ pid: Number(dead), host: hostname(), token: "dead" }));
    const foreign = JSON.stringify({ pid: process.pid, host: hostname(), token: "other" });
    // The critical section hands the lock to another owner; release must leave that lock in place.
    expect(withLock(log, () => { writeFileSync(`${log}.lock`, foreign); return 7; }, 1_000)).toBe(7);
    expect(readFileSync(`${log}.lock`, "utf8")).toBe(foreign);
    expect(exists(`${log}.lock`)).toBe(true);
  });
});
