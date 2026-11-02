import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { EventWriteError } from "../../src/events/fsutil.js";
import { acquireLock, breakLock, ownerGone, parseStartTime, systemProcessFacts, type LockOwner, type ProcessFacts } from "../../src/events/lock.js";
import { tempDir } from "./helpers.js";

function lockPath(): string {
  return join(tempDir(), ".lock");
}

function owner(patch: Partial<LockOwner> = {}): LockOwner {
  return {
    pid: process.pid,
    host: systemProcessFacts.host,
    token: "other-token",
    boot_id: systemProcessFacts.bootId(),
    pid_ns: systemProcessFacts.pidNamespace(),
    start: systemProcessFacts.startTime(process.pid),
    ...patch,
  };
}

function deadPid(): number {
  const r = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], { encoding: "utf8" });
  return Number(r.stdout);
}

function age(path: string, seconds: number): void {
  const t = new Date(Date.now() - seconds * 1000);
  utimesSync(path, t, t);
}

describe("lock", () => {
  it("acquires and releases", () => {
    const lock = lockPath();
    const release = acquireLock(lock);
    expect(existsSync(lock)).toBe(true);
    const content = JSON.parse(readFileSync(lock, "utf8"));
    expect(content).toMatchObject({ pid: process.pid, host: systemProcessFacts.host });
    expect(typeof content.token).toBe("string");
    release();
    expect(existsSync(lock)).toBe(false);
    acquireLock(lock)();
  });

  it("times out while a live process holds the lock", () => {
    const lock = lockPath();
    const release = acquireLock(lock);
    let error: unknown;
    try {
      acquireLock(lock, systemProcessFacts, 120);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(EventWriteError);
    expect((error as EventWriteError).code).toBe("lock_timeout");
    release();
  });

  it("takes over the lock of a dead process", () => {
    const lock = lockPath();
    writeFileSync(lock, JSON.stringify(owner({ pid: deadPid() })));
    acquireLock(lock, systemProcessFacts, 500)();
  });

  it.each([
    ["another boot", { boot_id: "00000000-0000-0000-0000-000000000000" }],
    ["another PID namespace", { pid_ns: "1" }],
    ["PID reuse (different start time)", { start: "1" }],
  ])("takes over a lock from %s", (_name, patch) => {
    const lock = lockPath();
    writeFileSync(lock, JSON.stringify(owner(patch)));
    acquireLock(lock, systemProcessFacts, 500)();
  });

  it("does not break the lock of a live owner or of another host before the forced takeover", () => {
    const lock = lockPath();
    writeFileSync(lock, JSON.stringify(owner({ host: "another-host", pid: deadPid() })));
    expect(() => acquireLock(lock, systemProcessFacts, 100)).toThrowError(/locked/);
    writeFileSync(lock, "garbage");
    expect(() => acquireLock(lock, systemProcessFacts, 100)).toThrowError(/locked/);
  });

  it("forces the takeover of any lock after 10 seconds", () => {
    for (const content of [JSON.stringify(owner({ host: "another-host" })), "garbage", JSON.stringify(owner())]) {
      const lock = lockPath();
      writeFileSync(lock, content);
      age(lock, 11);
      acquireLock(lock, systemProcessFacts, 500)();
    }
  });

  it("removes a lock that is a planted link or FIFO at once", () => {
    const dir = tempDir();
    const target = join(dir, "target");
    writeFileSync(target, "keep");
    symlinkSync(target, join(dir, ".lock"));
    acquireLock(join(dir, ".lock"), systemProcessFacts, 500)();
    expect(readFileSync(target, "utf8")).toBe("keep");
    symlinkSync(join(dir, "nonexistent"), join(dir, ".lock"));
    acquireLock(join(dir, ".lock"), systemProcessFacts, 500)();
    execFileSync("mkfifo", [join(dir, ".lock")]);
    acquireLock(join(dir, ".lock"), systemProcessFacts, 500)();
  });

  it("does not remove a lock that someone else took over", () => {
    const lock = lockPath();
    const release = acquireLock(lock);
    writeFileSync(lock, JSON.stringify(owner({ token: "someone-else" })));
    release();
    expect(existsSync(lock)).toBe(true);
  });

  it("breakLock removes the observed lock and restores a different one", () => {
    const lock = lockPath();
    writeFileSync(lock, JSON.stringify(owner({ token: "a" })));
    breakLock(lock, owner({ token: "b" })); // the lock was replaced after it was judged stale: keep it
    expect(JSON.parse(readFileSync(lock, "utf8")).token).toBe("a");
    breakLock(lock, owner({ token: "a" }));
    expect(existsSync(lock)).toBe(false);
    breakLock(lock, null); // already gone
  });

  it("reports a missing directory", () => {
    expect(() => acquireLock(join(tempDir(), "missing", ".lock"))).toThrowError(/lock cannot be created/);
    try {
      acquireLock(join(tempDir(), "missing", ".lock"));
    } catch (e) {
      expect((e as EventWriteError).code).toBe("dir_missing");
    }
  });

  it("reports other creation errors as io", () => {
    const dir = tempDir();
    const file = join(dir, "file");
    writeFileSync(file, "");
    try {
      acquireLock(join(file, ".lock"));
    } catch (e) {
      expect((e as EventWriteError).code).toBe("io");
    }
  });
});

describe("ownerGone", () => {
  const facts: ProcessFacts = {
    pid: 1,
    host: "h",
    bootId: () => "boot",
    pidNamespace: () => "ns",
    startTime: () => "100",
    alive: () => true,
    now: () => 0,
  };
  const o: LockOwner = { pid: 5, host: "h", token: "t", boot_id: "boot", pid_ns: "ns", start: "100" };
  it("is false for a running owner", () => {
    expect(ownerGone(o, facts)).toBe(false);
  });
  it("is true for other boot, namespace, missing process or other start", () => {
    expect(ownerGone({ ...o, boot_id: "x" }, facts)).toBe(true);
    expect(ownerGone({ ...o, pid_ns: "x" }, facts)).toBe(true);
    expect(ownerGone(o, { ...facts, alive: () => false })).toBe(true);
    expect(ownerGone(o, { ...facts, startTime: () => "101" })).toBe(true);
  });
  it("is false for another host and for unknown facts", () => {
    expect(ownerGone({ ...o, host: "other" }, { ...facts, alive: () => false })).toBe(false);
    expect(ownerGone({ ...o, boot_id: null, pid_ns: null, start: null }, facts)).toBe(false);
    expect(ownerGone(o, { ...facts, bootId: () => null, pidNamespace: () => null, startTime: () => null })).toBe(false);
  });
});

describe("process facts", () => {
  it("parses the start time from /proc stat even if the command contains spaces and parentheses", () => {
    const stat = "123 (my (weird) cmd) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20";
    expect(parseStartTime(stat)).toBe("987654");
    expect(parseStartTime("bad")).toBeNull();
  });
  it("reads real facts on this platform", () => {
    expect(systemProcessFacts.alive(process.pid)).toBe(true);
    expect(systemProcessFacts.alive(deadPid())).toBe(false);
    if (process.platform === "linux") {
      expect(systemProcessFacts.bootId()).toMatch(/^[0-9a-f-]{36}$/);
      expect(systemProcessFacts.pidNamespace()).toMatch(/^[0-9]+$/);
      expect(systemProcessFacts.startTime(process.pid)).toMatch(/^[0-9]+$/);
      expect(systemProcessFacts.startTime(deadPid())).toBeNull();
    }
    expect(systemProcessFacts.now()).toBeGreaterThan(0);
  });
});
