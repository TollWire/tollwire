import { spawn, type ChildProcess } from "node:child_process";
import { closeSync, mkdtempSync, openSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULT_WATCHDOG_MS, startWatchdog, WATCHDOG_MESSAGE } from "../src/watchdog.js";

function exit(child: ChildProcess): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  return new Promise((resolve) => child.on("exit", (code, signal) => resolve({ code, signal })));
}

describe("watchdog", () => {
  it("kills a process whose main thread is blocked (a timer in the main thread would never fire)", async () => {
    // The child spins forever in a synchronous loop: no timer and no signal handler of its own can run.
    const child = spawn(process.execPath, ["-e", "process.stdout.write('up');while(true){}"], { stdio: ["ignore", "pipe", "ignore"] });
    await new Promise<void>((resolve) => child.stdout?.once("data", () => resolve()));
    const dir = mkdtempSync(join(tmpdir(), "tg-wd-"));
    const file = join(dir, "stderr.txt");
    const fd = openSync(file, "w");
    const started = Date.now();
    startWatchdog({ ms: 300, pid: child.pid as number, fd });
    const result = await exit(child);
    closeSync(fd);
    expect(Date.now() - started).toBeLessThan(5000);
    // terminated, not a normal exit: no exit code 0 that a wrapper could take for success
    expect(result.code === 0).toBe(false);
    expect(result.signal ?? "code").toBe("SIGKILL");
    expect(readFileSync(file, "utf8")).toBe(WATCHDOG_MESSAGE);
  }, 15_000);

  it("does not keep the process alive and does not fire before the limit", async () => {
    // A process that finishes by itself exits normally with its own code although a watchdog is armed.
    const child = spawn(process.execPath, ["-e", "process.exit(2)"], { stdio: "ignore" });
    const dir = mkdtempSync(join(tmpdir(), "tg-wd-"));
    const fd = openSync(join(dir, "e.txt"), "w");
    startWatchdog({ ms: 60_000, pid: child.pid as number, fd }).terminate();
    const result = await exit(child);
    closeSync(fd);
    expect(result).toEqual({ code: 2, signal: null });
  });

  it("is armed for this process with the documented default of 25 s, and checks the limit", async () => {
    expect(DEFAULT_WATCHDOG_MS).toBe(25_000);
    for (const bad of [0, -1, 1.5, 600_001, Number.NaN]) expect(() => startWatchdog({ ms: bad })).toThrow(RangeError);
    const worker = startWatchdog({ ms: 600_000 });
    await worker.terminate();
  });
});
