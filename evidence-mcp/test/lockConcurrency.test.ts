import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { hostname, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import ts from "typescript";

// Audit 2026-10-22, F-05: several waiters judge the same dead lock stale. The test runs real processes against one lock file
// that has a dead owner planted before every round, and checks mutual exclusion (marker file created with "wx" inside the
// critical section) and that no increment of a shared counter is lost.
const srcDir = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
const pkgDir = join(srcDir, "..");
let build = "";

function transpileTree(from: string, to: string): void {
  mkdirSync(to, { recursive: true });
  for (const entry of readdirSync(from, { withFileTypes: true })) {
    const source = join(from, entry.name);
    if (entry.isDirectory()) transpileTree(source, join(to, entry.name));
    else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".d.ts")) {
      const out = ts.transpileModule(readFileSync(source, "utf8"), { compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 } });
      writeFileSync(join(to, entry.name.replace(/\.ts$/, ".js")), out.outputText);
    }
  }
}

const CHILD = `
import { readFileSync, writeFileSync, openSync, closeSync, rmSync } from "node:fs";
import { withLock } from "./src/log.js";
const [, , target, rounds] = process.argv;
let violations = 0;
for (let i = 0; i < Number(rounds); i += 1) {
  withLock(target, () => {
    let fd;
    try { fd = openSync(target + ".inside", "wx"); } catch { violations += 1; }
    const n = Number(readFileSync(target + ".count", "utf8"));
    const until = Date.now() + 2;
    while (Date.now() < until) { /* hold the lock briefly */ }
    writeFileSync(target + ".count", String(n + 1));
    if (fd !== undefined) { closeSync(fd); rmSync(target + ".inside", { force: true }); }
  }, 20000);
}
process.stdout.write(String(violations));
`;

function deadPid(): number {
  return Number(spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"]).stdout.toString());
}

function run(target: string, rounds: number): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [join(build, "child.mjs"), target, String(rounds)], { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout.on("data", (d: Buffer) => (out += d.toString()));
    child.stderr.on("data", (d: Buffer) => (err += d.toString()));
    child.on("close", (code) => resolve({ code, out, err }));
  });
}

beforeAll(() => {
  build = mkdtempSync(join(tmpdir(), "tg-lockrace-"));
  transpileTree(srcDir, join(build, "src"));
  symlinkSync(join(pkgDir, "node_modules"), join(build, "node_modules"));
  writeFileSync(join(build, "package.json"), '{"type":"module"}');
  writeFileSync(join(build, "child.mjs"), CHILD);
});
afterAll(() => rmSync(build, { recursive: true, force: true }));

describe("withLock with several waiters on a stale lock (F-05)", () => {
  it("keeps mutual exclusion and loses no update across processes", async () => {
    const data = mkdtempSync(join(tmpdir(), "tg-lockdata-"));
    const target = join(data, "log.jsonl");
    const workers = 6;
    const rounds = 3;
    const attempts = 6;
    try {
      for (let attempt = 0; attempt < attempts; attempt += 1) {
        writeFileSync(`${target}.count`, "0");
        // A lock whose owner is dead: every waiter judges it stale at about the same time.
        writeFileSync(`${target}.lock`, JSON.stringify({ pid: deadPid(), host: hostname(), token: `dead-${attempt}` }));
        const results = await Promise.all(Array.from({ length: workers }, () => run(target, rounds)));
        for (const r of results) expect({ code: r.code, err: r.err }, `attempt ${attempt}`).toEqual({ code: 0, err: "" });
        const violations = results.reduce((sum, r) => sum + Number(r.out), 0);
        expect(violations, `overlapping critical sections in attempt ${attempt}`).toBe(0);
        expect(Number(readFileSync(`${target}.count`, "utf8")), `lost updates in attempt ${attempt}`).toBe(workers * rounds);
        expect(existsSync(`${target}.lock`)).toBe(false);
        expect(readdirSync(data).filter((f) => f.endsWith(".stale"))).toEqual([]);
      }
    } finally {
      rmSync(data, { recursive: true, force: true });
    }
  }, 120_000);
});
