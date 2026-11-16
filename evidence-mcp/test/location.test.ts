import { existsSync, mkdirSync, mkdtempSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { hostname, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { createAnchor } from "../src/anchor.js";
import { appendEntry, assertNoSymlinkedDirs, readEntries, resolveLogRoot } from "../src/log.js";

const event = { type: "change" as const, summary: "s", actor: "a" };
const posix = process.platform !== "win32";

/** Project dir with the default layout `<project>/.tollgate/evidence/log.jsonl`. */
function project(): { root: string; log: string } {
  const root = mkdtempSync(join(tmpdir(), "ev-loc-"));
  return { root, log: join(root, ".tollgate", "evidence", "log.jsonl") };
}

describe("log root", () => {
  it("uses the project dir for logs inside it and the log's own dir otherwise", () => {
    expect(resolveLogRoot("/p/.tollgate/evidence/log.jsonl", "/p")).toBe("/p");
    expect(resolveLogRoot("/p/log.jsonl", "/p")).toBe("/p");
    expect(resolveLogRoot("/elsewhere/ev/log.jsonl", "/p")).toBe("/elsewhere/ev");
    expect(resolveLogRoot("/p/../q/log.jsonl", "/p")).toBe("/q");
    expect(resolveLogRoot("/p..x/log.jsonl", "/p")).toBe("/p..x");
  });
});

describe("parent-directory symlinks (residual risk)", () => {
  it("creates missing directories and appends below an intact root", () => {
    const { root, log } = project();
    appendEntry(log, event, new Date(), { root });
    appendEntry(log, event, new Date(), { root });
    expect(readEntries(log)).toHaveLength(2);
    expect(createAnchor(log, { root }).created).toBe(true);
  });

  it("refuses a symlinked directory below the root and writes nothing at the link target", () => {
    if (!posix) return;
    for (const linked of [".tollgate", join(".tollgate", "evidence")]) {
      const { root, log } = project();
      const victim = mkdtempSync(join(tmpdir(), "ev-loc-victim-"));
      mkdirSync(dirname(join(root, linked)), { recursive: true });
      symlinkSync(victim, join(root, linked));
      if (linked === ".tollgate") mkdirSync(join(victim, "evidence"));
      expect(() => appendEntry(log, event, new Date(), { root })).toThrow(/directory is a symbolic link/);
      expect(() => createAnchor(log, { root })).toThrow(/directory is a symbolic link/);
      expect(() => assertNoSymlinkedDirs(log, root)).toThrow(/directory is a symbolic link/);
      const written = linked === ".tollgate" ? readdirSync(join(victim, "evidence")) : readdirSync(victim);
      expect(written).toEqual([]);
    }
  });

  it("refuses a dangling directory link without creating its target", () => {
    if (!posix) return;
    const { root, log } = project();
    const target = join(mkdtempSync(join(tmpdir(), "ev-loc-dangling-")), "created");
    symlinkSync(target, join(root, ".tollgate"));
    expect(() => appendEntry(log, event, new Date(), { root })).toThrow(/directory is a symbolic link/);
    expect(existsSync(target)).toBe(false);
  });

  it("refuses a non-directory component and a log outside the root", () => {
    const { root, log } = project();
    writeFileSync(join(root, ".tollgate"), "not a dir");
    expect(() => appendEntry(log, event, new Date(), { root })).toThrow(/non-directory/);
    const outside = join(mkdtempSync(join(tmpdir(), "ev-loc-out-")), "log.jsonl");
    expect(() => appendEntry(outside, event, new Date(), { root })).toThrow(/outside its configured root/);
    expect(existsSync(outside)).toBe(false);
  });

  it("trusts the root itself even if it is reached through a link", () => {
    if (!posix) return;
    const { root } = project();
    const alias = join(mkdtempSync(join(tmpdir(), "ev-loc-alias-")), "project");
    symlinkSync(root, alias);
    const log = join(alias, ".tollgate", "evidence", "log.jsonl");
    expect(appendEntry(log, event, new Date(), { root: alias }).seq).toBe(1);
  });

  it("re-checks under the lock when a directory is swapped while waiting for it", async () => {
    if (!posix) return;
    const { root, log } = project();
    appendEntry(log, event, new Date(), { root });
    const evidence = dirname(log);
    const victim = mkdtempSync(join(tmpdir(), "ev-loc-swap-"));
    // A live helper process "holds" the lock and swaps .tollgate/evidence for a link after 300 ms.
    const script = `setTimeout(() => { const fs = require("node:fs"); fs.renameSync(process.env.EV, process.env.EV + ".moved"); fs.symlinkSync(process.env.VICTIM, process.env.EV); }, 300); setTimeout(() => {}, 1000);`;
    const child = spawn(process.execPath, ["-e", script], { env: { ...process.env, EV: evidence, VICTIM: victim }, stdio: "ignore" });
    const exited = new Promise((resolve) => child.on("exit", resolve));
    writeFileSync(`${log}.lock`, JSON.stringify({ pid: child.pid, host: hostname(), token: "helper" }));
    expect(() => appendEntry(log, event, new Date(), { root })).toThrow(/directory is a symbolic link/);
    expect(readdirSync(victim)).toEqual([]); // lock taken through the link is released, nothing else written
    await exited;
    expect(readEntries(`${evidence}.moved/log.jsonl`)).toHaveLength(1);
  });
});
