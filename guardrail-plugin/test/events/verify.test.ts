import { chmodSync, existsSync, linkSync, mkdirSync, readdirSync, readFileSync, symlinkSync, truncateSync, writeFileSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { listEventFiles, MAX_DIRECTORY_ENTRIES, readEventFile } from "../../src/events/reader.js";
import { runVerifyCli } from "../../src/events/verifyCli.js";
import { compareDigits, expandPaths, listEventGroups, SERVICE_PREFIXES, trimTrailingSeparators, verifyFiles } from "../../src/events/verify.js";
import { GENESIS, SCHEMA } from "../../src/events/types.js";
import { LogStore } from "../../src/events/store.js";
import { chainHash } from "../../src/vendor/hashchain.js";
import { decisionDraft, Fixture, META, standaloneStore, tempDir } from "./helpers.js";

const uid = process.getuid?.() ?? 0;

function written(count = 3): { dir: string; files: string[]; store: LogStore; fixture: Fixture } {
  const { store, layout, fixture } = standaloneStore(tempDir());
  for (let i = 0; i < count; i += 1) {
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    fixture.advance(1000);
  }
  return { dir: layout.eventsDir, files: [join(layout.eventsDir, `u${uid}-20261011.jsonl`)], store, fixture };
}

describe("readEventFile", () => {
  it("reads lines of a regular file", () => {
    const { files } = written();
    const r = readEventFile(files[0] as string, { uid });
    expect(r.read).toBe(true);
    expect(r.lines.map((l) => l.no)).toEqual([1, 2, 3, 4]);
    expect(r.findings).toEqual([]);
    expect(r.metaOk).toBe(true);
  });
  it("refuses a symlink, a FIFO, a directory and a missing file", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "real"), "x\n");
    symlinkSync(join(dir, "real"), join(dir, "link"));
    execFileSync("mkfifo", [join(dir, "fifo")]);
    mkdirSync(join(dir, "d"));
    expect(readEventFile(join(dir, "link")).findings[0]?.kind).toBe("symlink");
    expect(readEventFile(join(dir, "fifo")).findings[0]?.kind).toBe("not_regular");
    expect(readEventFile(join(dir, "d")).findings[0]?.kind).toBe("not_regular");
    expect(readEventFile(join(dir, "none")).findings[0]?.kind).toBe("unreadable");
    for (const n of ["link", "fifo", "d", "none"]) expect(readEventFile(join(dir, n)).read).toBe(false);
  });
  it("reports hard links, wide modes and foreign owners as metadata findings but still reads", () => {
    const dir = tempDir();
    const file = join(dir, "u1-20261011.jsonl");
    writeFileSync(file, "a\nb\n", { mode: 0o600 });
    linkSync(file, join(dir, "second"));
    chmodSync(file, 0o666);
    const r = readEventFile(file, { uid: uid + 1 });
    expect(r.read).toBe(true);
    expect(r.lines).toHaveLength(2);
    expect(r.findings.map((f) => f.kind).sort()).toEqual(["hardlink", "mode", "owner"]);
    expect(r.metaOk).toBe(false);
  });
  it("honors the maximum mode", () => {
    const dir = tempDir();
    const file = join(dir, "f");
    writeFileSync(file, "a\n", { mode: 0o640 });
    chmodSync(file, 0o640);
    expect(readEventFile(file).metaOk).toBe(true);
    expect(readEventFile(file, { maxMode: 0o600 }).metaOk).toBe(false);
  });
  it("reads up to the size limit and reports the rest", () => {
    const dir = tempDir();
    const file = join(dir, "f");
    writeFileSync(file, "aaaa\nbbbb\ncccc\n");
    const r = readEventFile(file, { maxBytes: 11, maxMode: 0o777 });
    expect(r.lines.map((l) => l.text)).toEqual(["aaaa", "bbbb"]);
    expect(r.findings.map((f) => f.kind)).toEqual(["oversize", "incomplete_line"]);
  });
  it("discards lines over 8 KiB and invalid UTF-8, and reports an incomplete last line", () => {
    const dir = tempDir();
    const file = join(dir, "f");
    writeFileSync(file, Buffer.concat([Buffer.from("ok\n"), Buffer.from("x".repeat(9000)), Buffer.from("\n"), Buffer.from([0xff, 0xfe, 10]), Buffer.from("last\nno newline")]));
    const r = readEventFile(file, { maxMode: 0o777 });
    expect(r.lines.map((l) => [l.no, l.text])).toEqual([[1, "ok"], [4, "last"]]);
    expect(r.findings.map((f) => [f.kind, f.line])).toEqual([["line_too_long", 2], ["invalid_utf8", 3], ["incomplete_line", 5]]);
  });
  it("reads in chunks and keeps memory bounded for a huge line", () => {
    const dir = tempDir();
    const file = join(dir, "f");
    writeFileSync(file, `${"y".repeat(300_000)}\nafter\n`);
    const r = readEventFile(file, { maxMode: 0o777 });
    expect(r.lines.map((l) => l.text)).toEqual(["after"]);
    expect(r.findings.map((f) => f.kind)).toEqual(["line_too_long"]);
    const many = Array.from({ length: 5000 }, (_, i) => `line ${i}`).join("\n") + "\n";
    writeFileSync(file, many);
    expect(readEventFile(file, { maxMode: 0o777 }).lines).toHaveLength(5000);
  });
});

/** Writes a valid service chain (`<prefix>-<day>.jsonl`) of `count` events into `dir`, spread over the given file names. */
function serviceChain(dir: string, names: string[], count: number, chainNo = 1): void {
  const chainId = `00000000-0000-4000-8000-${String(chainNo).padStart(12, "0")}`;
  let prev = GENESIS;
  for (let seq = 1; seq <= count; seq += 1) {
    const e: Record<string, unknown> = {
      schema: SCHEMA,
      event_id: `10000000-0000-4000-8000-${String(chainNo * 1000 + seq).padStart(12, "0")}`,
      ts: "2026-10-22T10:00:00.000Z",
      type: seq === 1 ? "chain_start" : "admin_action",
      chain_id: chainId,
      seq,
      prev_hash: prev,
      data: {},
    };
    e.hash = chainHash(e);
    prev = e.hash as string;
    const name = names[Math.min(names.length - 1, Math.floor(((seq - 1) * names.length) / count))] as string;
    appendFileSync(join(dir, name), `${JSON.stringify(e)}\n`, { mode: 0o600 });
  }
}

describe("listEventFiles and expandPaths", () => {
  it("lists event files oldest first and ignores other names", () => {
    const dir = tempDir();
    for (const n of [`u${uid}-20261012.jsonl`, `u${uid}-20261011-2.jsonl`, `u${uid}-20261011.jsonl`, `u${uid}-20261011-10.jsonl`, `u${uid}-20261011-1.jsonl`, "notes.txt", "x.jsonl", ".state"]) writeFileSync(join(dir, n), "");
    expect(listEventFiles(dir).names).toEqual([`u${uid}-20261011.jsonl`, `u${uid}-20261011-1.jsonl`, `u${uid}-20261011-2.jsonl`, `u${uid}-20261011-10.jsonl`, `u${uid}-20261012.jsonl`]);
  });
  it("limits the scan and refuses links and missing directories", () => {
    const dir = tempDir();
    for (let i = 0; i < MAX_DIRECTORY_ENTRIES + 5; i += 1) writeFileSync(join(dir, `f${i}`), "");
    expect(listEventFiles(dir).findings[0]?.kind).toBe("directory_limit");
    const link = join(tempDir(), "l");
    symlinkSync(dir, link);
    expect(listEventFiles(link).findings[0]?.kind).toBe("not_regular");
    expect(listEventFiles(join(dir, "missing")).findings[0]?.kind).toBe("unreadable");
  });
  it("expands directories and keeps files", () => {
    const { dir, files } = written();
    expect(expandPaths([dir]).files).toEqual(files);
    expect(expandPaths([files[0] as string, join(dir, "missing")]).files).toEqual([files[0], join(dir, "missing")]);
    expect(expandPaths([files[0] as string, join(dir, "missing")]).groups).toEqual([[files[0], join(dir, "missing")]]);
  });
  it("groups service chain files per prefix, oldest first, and keeps them apart from user files", () => {
    const dir = tempDir();
    const names = ["control-20261022.jsonl", "control-20261021-10.jsonl", "control-20261021-2.jsonl", "control-20261021.jsonl", "monitor-20261020.jsonl", "sendcfg-20261020.jsonl", "send-20261021.jsonl", "relay-20261019.jsonl", "host-20261019.jsonl", `u${uid}-20261021.jsonl`, "other-20261021.jsonl", "control-2026102.jsonl", "control.jsonl"];
    for (const n of names) writeFileSync(join(dir, n), "");
    const listing = listEventGroups(dir);
    expect(listing.unknown.map((f) => f.slice(dir.length + 1))).toEqual(["control-2026102.jsonl", "control.jsonl", "other-20261021.jsonl"]);
    const groups = listing.groups.map((g) => g.map((f) => f.slice(dir.length + 1)));
    expect(groups).toEqual([
      [`u${uid}-20261021.jsonl`],
      ["control-20261021.jsonl", "control-20261021-2.jsonl", "control-20261021-10.jsonl", "control-20261022.jsonl"],
      ["host-20261019.jsonl"],
      ["monitor-20261020.jsonl"],
      ["relay-20261019.jsonl"],
      ["send-20261021.jsonl"],
      ["sendcfg-20261020.jsonl"],
    ]);
  });
  it("uses one numeric order for user and service files, also for large alternate numbers (review point 7)", () => {
    const dir = tempDir();
    for (const n of [`u${uid}-20261011-10000.jsonl`, `u${uid}-20261011-9999.jsonl`, "control-20261021-100000.jsonl", "control-20261021-99999.jsonl", "control-20261021-007.jsonl"]) writeFileSync(join(dir, n), "");
    expect(listEventGroups(dir).groups.map((g) => g.map((f) => f.slice(dir.length + 1)))).toEqual([
      [`u${uid}-20261011-9999.jsonl`, `u${uid}-20261011-10000.jsonl`],
      ["control-20261021-007.jsonl", "control-20261021-99999.jsonl", "control-20261021-100000.jsonl"],
    ]);
    expect([compareDigits("2", "10"), compareDigits("010", "10"), compareDigits("123456789012345678901", "99")]).toEqual([-1, 0, 19]);
  });
  it("orders user groups by uid and keeps uids apart", () => {
    const dir = tempDir();
    for (const n of ["u10-20261011.jsonl", "u9-20261012.jsonl", "u9-20261011.jsonl"]) writeFileSync(join(dir, n), "");
    expect(listEventGroups(dir).groups.map((g) => g.map((f) => f.slice(dir.length + 1)))).toEqual([["u9-20261011.jsonl", "u9-20261012.jsonl"], ["u10-20261011.jsonl"]]);
  });
  it("removes trailing separators before the link check (review point 5)", () => {
    expect(["a/", "a//", "/x/y/", "/", "//", "a"].map(trimTrailingSeparators)).toEqual(["a", "a", "/x/y", "/", "/", "a"]);
    const dir = tempDir();
    const link = join(tempDir(), "lnk");
    symlinkSync(dir, link);
    expect(expandPaths([`${link}/`])).toEqual({ files: [link], groups: [[link]], findings: [] });
    expect(listEventGroups(link).findings[0]?.kind).toBe("not_regular");
  });
  it("reports unknown *.jsonl names next to valid files (review point 3)", () => {
    const dir = tempDir();
    for (const n of ["control-20261022.jsonl", "Control-20261022.jsonl", "foo-20261022.jsonl", "control-20261022.jsonl.bak", "notes.txt"]) writeFileSync(join(dir, n), "");
    expect(expandPaths([dir]).findings.map((f) => [f.kind, f.file.slice(dir.length + 1)])).toEqual([
      ["unknown_file", "Control-20261022.jsonl"],
      ["unknown_file", "foo-20261022.jsonl"],
    ]);
  });
  it("lists the service prefixes of every ChainWriter in the enterprise package and the monitor (review point 3)", () => {
    const roots = ["../../../tollgate-enterprise/src", "../../../tollgate-monitor/src"].map((r) => new URL(r, import.meta.url).pathname);
    if (!roots.every((r) => existsSync(r))) return; // exported plugin without the sibling packages: nothing to compare
    const found = new Set<string>();
    const walk = (d: string): void => {
      for (const e of readdirSync(d, { withFileTypes: true })) {
        const p = join(d, e.name);
        if (e.isDirectory()) walk(p);
        else if (e.name.endsWith(".ts")) for (const m of readFileSync(p, "utf8").matchAll(/\bprefix: "([a-z0-9-]+)"/g)) found.add(m[1] as string);
      }
    };
    for (const r of roots) walk(r);
    expect([...found].sort()).toEqual([...SERVICE_PREFIXES].sort());
  }, 30_000); // walks two source trees; slow on the self-hosted WSL runner under load
  it("reports a directory without event files", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "notes.txt"), "");
    expect(expandPaths([dir])).toEqual({ files: [], groups: [], findings: [{ kind: "no_event_files", file: dir, detail: "the directory contains no event files" }] });
    expect(expandPaths([`${dir}/`]).findings[0]?.file).toBe(dir);
  });
  it("does not claim no_event_files when only the scan limit applied (review point 6)", () => {
    const dir = tempDir();
    for (let i = 0; i < MAX_DIRECTORY_ENTRIES + 2; i += 1) writeFileSync(join(dir, `f${i}`), "");
    expect(expandPaths([dir]).findings.map((f) => f.kind)).toEqual(["directory_limit"]);
  });
});

describe("verifyFiles", () => {
  it("accepts a valid chain across files", () => {
    const { store, dir, fixture } = written(3);
    fixture.advance(24 * 3600 * 1000);
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    const report = verifyFiles(expandPaths([dir]).files, { uid });
    expect(report).toMatchObject({ files: 2, events: 6, chainOk: true, metaOk: true, chainFindings: [], readFindings: [] });
    expect(report.chains).toHaveLength(1);
  });

  const lines = (file: string): string[] => readFileSync(file, "utf8").split("\n").filter(Boolean);

  it("detects a modified event", () => {
    const { files } = written();
    const l = lines(files[0] as string);
    l[1] = (l[1] as string).replace('"outcome":"allow"', '"outcome":"deny"');
    writeFileSync(files[0] as string, `${l.join("\n")}\n`);
    const r = verifyFiles(files);
    expect(r.chainOk).toBe(false);
    expect(r.chainFindings[0]).toMatchObject({ kind: "hash_mismatch", line: 2 });
  });
  it("detects a deleted event (sequence gap) and a reordered chain", () => {
    const { files } = written(4);
    const l = lines(files[0] as string);
    writeFileSync(files[0] as string, `${[l[0], l[2], l[3], l[4]].join("\n")}\n`);
    expect(verifyFiles(files).chainFindings.map((f) => f.kind)).toContain("chain_broken");
    expect(verifyFiles(files).chainFindings[0]?.detail).toContain("sequence gap");
  });
  it("detects a changed prev_hash that was re-hashed", () => {
    const { files } = written();
    const l = lines(files[0] as string);
    const e = JSON.parse(l[2] as string) as Record<string, unknown>;
    e.prev_hash = "a".repeat(64);
    e.hash = chainHash(e);
    l[2] = JSON.stringify(e);
    writeFileSync(files[0] as string, `${l.join("\n")}\n`);
    expect(verifyFiles(files).chainFindings[0]).toMatchObject({ kind: "chain_broken", detail: "prev_hash does not match the previous event" });
  });
  it("detects truncation to an incomplete line, garbage, and non-objects", () => {
    const { files } = written();
    appendFileSync(files[0] as string, '{"schema":"tollgate');
    expect(verifyFiles(files)).toMatchObject({ chainOk: false, readFindings: [{ kind: "incomplete_line", line: 5 }] });
    writeFileSync(files[0] as string, 'not json\n[1]\n{"schema":"other"}\n');
    expect(verifyFiles(files).chainFindings.map((f) => f.kind)).toEqual(["invalid_json", "invalid_event", "invalid_event"]);
    truncateSync(files[0] as string, 0);
    expect(verifyFiles(files)).toMatchObject({ chainOk: true, events: 0 });
  });
  it("reports invalid event fields", () => {
    const { files } = written();
    const base = JSON.parse(lines(files[0] as string)[0] as string) as Record<string, unknown>;
    const bad = (patch: Record<string, unknown>): string => JSON.stringify({ ...base, ...patch });
    writeFileSync(files[0] as string, [bad({ chain_id: "x" }), bad({ seq: 0 }), bad({ hash: "g" }), bad({ prev_hash: 1 }), bad({ type: 5 })].join("\n") + "\n");
    expect(verifyFiles(files).chainFindings.map((f) => f.detail)).toEqual([
      "chain_id is not a UUID",
      "seq is not a positive integer",
      "hash is not 64 hex digits",
      "prev_hash is not 64 hex digits",
      "type, ts or event_id missing",
    ]);
  });
  it("requires chain_start at seq 1 with the genesis hash", () => {
    const { files } = written();
    const base = JSON.parse(lines(files[0] as string)[0] as string) as Record<string, unknown>;
    const make = (patch: Record<string, unknown>): string => {
      const e: Record<string, unknown> = { ...base, ...patch };
      delete e.hash;
      return JSON.stringify({ ...e, hash: chainHash(e) });
    };
    writeFileSync(files[0] as string, [make({ seq: 2 }), make({ prev_hash: "b".repeat(64) })].join("\n") + "\n");
    expect(verifyFiles(files).chainFindings.map((f) => f.kind)).toEqual(["start_invalid", "start_invalid"]);
  });
  it("accepts a corruption restart that links to the last valid event and flags a wrong link", () => {
    const { store, files, dir } = written(2);
    appendFileSync(files[0] as string, "broken tail");
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    const all = expandPaths([dir]).files;
    const ok = verifyFiles(all);
    expect(ok.chainFindings).toEqual([]);
    expect(ok.chains).toHaveLength(2);
    const second = all.find((f) => f.endsWith("-1.jsonl")) as string;
    const l = lines(second);
    const e = JSON.parse(l[0] as string) as Record<string, unknown>;
    e.prev_hash = "c".repeat(64);
    e.hash = chainHash(e);
    l[0] = JSON.stringify(e);
    writeFileSync(second, `${l.join("\n")}\n`);
    expect(verifyFiles(all).chainFindings[0]).toMatchObject({ kind: "link_mismatch" });
  });
  it("reports chain_continue without a predecessor and events of an unknown chain", () => {
    const { store, files, dir, fixture } = written(2);
    fixture.advance(24 * 3600 * 1000);
    store.transaction((tx) => tx.append([decisionDraft(store)]));
    const all = expandPaths([dir]).files;
    const second = verifyFiles(all.slice(1));
    expect(second.chainFindings[0]).toMatchObject({ kind: "unlinked" });
    const l = lines(files[0] as string);
    writeFileSync(files[0] as string, `${l.slice(1).join("\n")}\n`);
    expect(verifyFiles(files).chainFindings[0]).toMatchObject({ kind: "chain_broken", detail: "event of an unknown chain" });
  });
  it("refused files leave a gap that is reported", () => {
    const { dir } = written(2);
    const link = join(dir, `u${uid}-20261011-1.jsonl`);
    symlinkSync(join(dir, `u${uid}-20261011.jsonl`), link);
    const r = verifyFiles(expandPaths([dir]).files);
    expect(r.chainOk).toBe(false);
    expect(r.readFindings[0]?.kind).toBe("symlink");
  });
  it("metadata findings fail only in strict mode", () => {
    const { files } = written();
    chmodSync(files[0] as string, 0o666);
    const r = verifyFiles(files);
    expect(r.chainOk).toBe(true);
    expect(r.metaOk).toBe(false);
  });
  it("uses the default chain of the test helper for events with the stand-alone meta", () => {
    expect(META.source.component).toBe("tollgate-guardrail");
  });
});

describe("tollgate-events verify", () => {
  function run(args: string[], dir: string): { code: number; out: string; err: string } {
    let out = "";
    let err = "";
    const code = runVerifyCli(args, { out: (t) => (out += t), err: (t) => (err += t) }, { dir });
    return { code, out, err };
  }

  it("verifies the default directory and prints a summary", () => {
    const { dir } = written();
    const r = run(["verify"], dir);
    expect(r).toEqual({ code: 0, out: "OK: 4 events in 1 files, 1 chains\n", err: "" });
  });
  it("exits 1 and names the findings for a broken chain, with sanitized names", () => {
    const { dir, files } = written();
    appendFileSync(files[0] as string, "garbage\n");
    const r = run(["verify", dir], dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain("invalid_json: ");
    expect(r.out).toContain("FAIL: 4 events");
    const odd = join(tempDir(), "u1-20261011.jsonl");
    writeFileSync(odd, "x\n");
    expect(run(["verify", odd], dir).out).toContain("invalid_json");
  });
  it("prints JSON", () => {
    const { dir } = written();
    const r = run(["verify", "--json", dir], dir);
    expect(JSON.parse(r.out)).toMatchObject({ ok: true, files: 1, events: 4, chainFindings: [] });
  });
  it("--strict fails on metadata findings", () => {
    const { dir, files } = written();
    chmodSync(files[0] as string, 0o666);
    expect(run(["verify", dir], dir).code).toBe(0);
    const strict = run(["verify", "--strict", dir], dir);
    expect(strict.code).toBe(1);
    expect(strict.out).toContain("mode: ");
  });
  it("fails for a missing directory or file and for a link", () => {
    const { dir } = written();
    expect(run(["verify", join(dir, "nope")], dir).code).toBe(1);
    expect(run(["verify"], join(dir, "missing-dir")).code).toBe(1);
    const link = join(tempDir(), "l");
    symlinkSync(dir, link);
    expect(run(["verify", link], dir).code).toBe(1);
  });
  it("reports a directory limit without failing the chain, and fails it with --strict (review point 4)", () => {
    const dir = tempDir();
    // One chain_start per file: every scanned entry is a valid event file, so only the limit is reported.
    for (let i = 0; i < MAX_DIRECTORY_ENTRIES + 3; i += 1) serviceChain(dir, [`u${uid}-20261011-${i}.jsonl`], 1, i + 1);
    const r = run(["verify", dir], dir);
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/^WARN: directory_limit: /);
    expect(r.out).toContain(`OK: ${MAX_DIRECTORY_ENTRIES} events in ${MAX_DIRECTORY_ENTRIES} files`);
    const strict = run(["verify", "--strict", dir], dir);
    expect(strict.code).toBe(1);
    expect(strict.out).toMatch(/^directory_limit: /m);
  });
  it("fails a given directory that hides every file behind the scan limit, without claiming no_event_files", () => {
    const dir = tempDir();
    for (let i = 0; i < MAX_DIRECTORY_ENTRIES + 3; i += 1) writeFileSync(join(dir, `f${i}`), "");
    const r = run(["verify", dir], dir);
    expect(r.code).toBe(1);
    expect(r.out).not.toContain("no_event_files");
    expect(r.out).toContain("FAIL: 0 events in 0 files");
  });
  it("fails on files without events: given directory always, default log with --strict (review point 1)", () => {
    const dir = tempDir();
    for (const n of ["control-20261022.jsonl", "monitor-20261022.jsonl"]) writeFileSync(join(dir, n), "", { mode: 0o600 });
    const strict = run(["verify", "--strict", dir], dir);
    expect(strict.code).toBe(1);
    expect(strict.out).toContain(`no_events: ${join(dir, "control-20261022.jsonl")} (1 file(s) of this chain source hold no events)`);
    expect(strict.out).toContain(`no_events: ${join(dir, "monitor-20261022.jsonl")}`);
    expect(strict.out).toContain("FAIL: 0 events in 2 files, 0 chains");
    expect(run(["verify", dir], dir).code).toBe(1);
    // One truncated source next to a valid one still fails.
    const mixed = tempDir();
    serviceChain(mixed, ["control-20261022.jsonl"], 3);
    writeFileSync(join(mixed, "monitor-20261022.jsonl"), "", { mode: 0o600 });
    expect(run(["verify", mixed], mixed).code).toBe(1);
    // An empty file given directly is the same case.
    expect(run(["verify", join(dir, "control-20261022.jsonl")], dir).code).toBe(1);
    // Default log: truncated user file is a warning without --strict.
    const local = tempDir();
    writeFileSync(join(local, `u${uid}-20261011.jsonl`), "", { mode: 0o600 });
    const plain = run(["verify"], local);
    expect(plain.code).toBe(0);
    expect(plain.out).toMatch(/^WARN: no_events: /);
    expect(run(["verify", "--strict"], local).code).toBe(1);
  });
  it("fails on unknown *.jsonl only with --strict and warns otherwise (review point 3)", () => {
    const dir = tempDir();
    serviceChain(dir, ["control-20261022.jsonl"], 2);
    writeFileSync(join(dir, "audit-20261022.jsonl"), "x\n", { mode: 0o600 });
    const plain = run(["verify", dir], dir);
    expect(plain).toEqual({ code: 0, out: `WARN: unknown_file: ${join(dir, "audit-20261022.jsonl")} (not a known event file name; not verified)\nOK: 2 events in 1 files, 1 chains\n`, err: "" });
    const strict = run(["verify", "--strict", "--json", dir], dir);
    expect(strict.code).toBe(1);
    expect(JSON.parse(strict.out)).toMatchObject({ ok: false, warnings: [], readFindings: [{ kind: "unknown_file" }] });
  });
  it("treats a link given with a trailing slash as a link (review point 5)", () => {
    const { dir } = written();
    const link = join(tempDir(), "lnk");
    symlinkSync(dir, link);
    for (const arg of [`${link}/`, `${link}//`]) {
      const r = run(["verify", arg], dir);
      expect(r.code).toBe(1);
      expect(r.out).toContain("symlink: ");
    }
    expect(run(["verify", `${dir}/`], dir).code).toBe(0);
  });
  it("rejects links, FIFOs and directories named like service files inside a directory", () => {
    const dir = tempDir();
    serviceChain(dir, ["control-20261021.jsonl"], 2);
    const other = tempDir();
    serviceChain(other, ["x"], 1);
    symlinkSync(join(other, "x"), join(dir, "control-20261022.jsonl"));
    execFileSync("mkfifo", [join(dir, "monitor-20261022.jsonl")]);
    mkdirSync(join(dir, "relay-20261022.jsonl"));
    const r = run(["verify", dir], dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain("symlink: ");
    expect(r.out.match(/not_regular: /g)).toHaveLength(2);
  });
  it("does not link chains across sources: a control chain continued in a monitor file is broken", () => {
    const dir = tempDir();
    serviceChain(dir, ["control-20261021.jsonl", "monitor-20261022.jsonl"], 4);
    const r = run(["verify", dir], dir);
    expect(r.code).toBe(1);
    expect(r.out).toContain(`chain_broken: ${join(dir, "monitor-20261022.jsonl")}:1 (event of an unknown chain)`);
  });
  it("keeps a missing default directory a failure, unlike an empty one (review point 6, documented)", () => {
    const root = tempDir();
    const r = run(["verify"], join(root, "missing"));
    expect(r.code).toBe(1);
    expect(r.out).toContain("unreadable: ");
  });
  it("design limit: a chain recomputed from genesis by a writer passes (no authentication; review point 8)", () => {
    // The hash chain detects changes inside a chain, not a complete replacement. This test pins the documented limit.
    const dir = tempDir();
    serviceChain(dir, ["control-20261022.jsonl"], 3, 7);
    expect(run(["verify", "--strict", dir], dir).code).toBe(0);
  });
  it("fails for a given directory without event files, with and without --strict (finding 8)", () => {
    const empty = tempDir();
    const strict = run(["verify", "--strict", empty], empty);
    expect(strict.code).toBe(1);
    expect(strict.out).toBe(`no_event_files: ${empty} (the directory contains no event files)\nFAIL: 0 events in 0 files, 0 chains\n`);
    expect(run(["verify", `${empty}/`], empty).code).toBe(1);
    expect(run(["verify", empty], empty).code).toBe(1);
    expect(JSON.parse(run(["verify", "--json", empty], empty).out)).toMatchObject({ ok: false, files: 0, events: 0 });
    const { dir } = written();
    expect(run(["verify", dir, empty], dir).code).toBe(1);
  });
  it("warns about an empty default log without --strict and fails it with --strict (review point 6)", () => {
    const empty = tempDir();
    const r = run(["verify"], empty);
    expect(r.code).toBe(0);
    expect(r.out).toBe(`WARN: no_event_files: ${empty} (the directory contains no event files)\nOK: 0 events in 0 files, 0 chains\n`);
    expect(JSON.parse(run(["verify", "--json"], empty).out)).toMatchObject({ ok: true, readFindings: [], warnings: [{ kind: "no_event_files", file: empty }] });
    const strict = run(["verify", "--strict"], empty);
    expect(strict.code).toBe(1);
    expect(strict.out).toBe(`no_event_files: ${empty} (the directory contains no event files)\nFAIL: 0 events in 0 files, 0 chains\n`);
  });
  it("verifies a directory with only control chain files (finding 8)", () => {
    const dir = tempDir();
    serviceChain(dir, ["control-20261021.jsonl", "control-20261022.jsonl"], 26);
    const r = run(["verify", "--strict", dir], dir);
    expect(r).toEqual({ code: 0, out: "OK: 26 events in 2 files, 1 chains\n", err: "" });
  });
  it("verifies control and monitor chains in one directory separately", () => {
    const dir = tempDir();
    serviceChain(dir, ["control-20261022.jsonl"], 3, 1);
    serviceChain(dir, ["monitor-20261021.jsonl"], 2, 2);
    expect(run(["verify", "--strict", dir], dir).out).toBe("OK: 5 events in 2 files, 2 chains\n");
    // A gap inside the control chain is still found.
    const file = join(dir, "control-20261022.jsonl");
    const l = readFileSync(file, "utf8").split("\n").filter(Boolean);
    writeFileSync(file, `${l[0]}\n${l[2]}\n`);
    const broken = run(["verify", dir], dir);
    expect(broken.code).toBe(1);
    expect(broken.out).toContain("chain_broken: ");
  });
  it("shows usage for unknown commands and options", () => {
    const { dir } = written();
    expect(run([], dir)).toMatchObject({ code: 2, out: "" });
    expect(run(["check"], dir).err).toContain("Usage: tollgate-events verify");
    expect(run(["verify", "--bogus"], dir).code).toBe(2);
  });
});
