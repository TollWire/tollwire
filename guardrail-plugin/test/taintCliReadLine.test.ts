// Confirmation input of `tollgate-taint release` / `admin-release`: reads from the controlling terminal and waits while
// a non-blocking stdin reports EAGAIN (the bug of the field test 2026-10-30: "Not confirmed" without waiting).
import { describe, expect, it } from "vitest";
import { readConfirmationLine, type LineReaderDeps } from "../src/taintCli.js";

function errno(code: string): Error {
  return Object.assign(new Error(code), { code });
}

/** A scripted terminal: each step is a chunk of bytes, an errno code to throw, or EOF (""). */
function fake(steps: Array<string | { error: string }>, opts: { ttyOpens?: boolean } = {}) {
  const log = { opened: [] as string[], closed: [] as number[], reads: [] as number[], sleeps: 0 };
  let clock = 0;
  const pending: Array<string | { error: string }> = [...steps];
  let chunk = Buffer.alloc(0);
  const deps: LineReaderDeps = {
    open: (path) => {
      log.opened.push(path);
      if (opts.ttyOpens === false) throw errno("ENXIO");
      return 7;
    },
    read: (fd, buf) => {
      log.reads.push(fd);
      if (chunk.length === 0) {
        const next = pending.shift();
        if (next === undefined || next === "") return 0;
        if (typeof next !== "string") throw errno(next.error);
        chunk = Buffer.from(next, "utf8");
      }
      buf[0] = chunk[0] ?? 0;
      chunk = chunk.subarray(1);
      return 1;
    },
    close: (fd) => log.closed.push(fd),
    sleep: (ms) => {
      log.sleeps += 1;
      clock += ms;
    },
    now: () => clock,
  };
  return { deps, log };
}

describe("tollgate-taint confirmation input", () => {
  it("reads the line from /dev/tty and closes it", () => {
    const { deps, log } = fake(["ABC234\n"]);
    expect(readConfirmationLine(deps)).toBe("ABC234");
    expect(log.opened).toEqual(["/dev/tty"]);
    expect(log.reads.every((fd) => fd === 7)).toBe(true);
    expect(log.closed).toEqual([7]);
  });

  it("waits while the terminal reports EAGAIN or EWOULDBLOCK instead of giving up", () => {
    const { deps, log } = fake([{ error: "EAGAIN" }, { error: "EAGAIN" }, "AB", { error: "EWOULDBLOCK" }, "C234\r\n"]);
    expect(readConfirmationLine(deps)).toBe("ABC234");
    expect(log.sleeps).toBe(3);
  });

  it("falls back to stdin (fd 0) with the same retry when /dev/tty cannot be opened", () => {
    const { deps, log } = fake([{ error: "EAGAIN" }, "QWE234\n"], { ttyOpens: false });
    expect(readConfirmationLine(deps)).toBe("QWE234");
    expect(log.reads.every((fd) => fd === 0)).toBe(true);
    expect(log.closed).toEqual([]);
  });

  it("fails closed: EOF, EOF after a partial line, other read errors, an over-long line, the wait limit", () => {
    expect(readConfirmationLine(fake([""]).deps)).toBeNull();
    expect(readConfirmationLine(fake(["ABC234", ""]).deps)).toBeNull();
    expect(readConfirmationLine(fake([{ error: "EIO" }]).deps)).toBeNull();
    expect(readConfirmationLine(fake([`${"A".repeat(80)}\n`]).deps)).toBeNull();
    expect(readConfirmationLine(fake([`${"A".repeat(64)}\n`]).deps)).toBe("A".repeat(64));
    const partial = fake(["ABC", { error: "EAGAIN" }, { error: "EWOULDBLOCK" }, ""]);
    expect(readConfirmationLine(partial.deps)).toBeNull(); // EAGAIN after a partial line, then EOF
    expect(partial.log.sleeps).toBe(2);
    const forever = fake(Array.from({ length: 100_000 }, () => ({ error: "EAGAIN" })));
    expect(readConfirmationLine(forever.deps, 1_000)).toBeNull();
    expect(forever.log.closed).toEqual([7]);
  });

  it("keeps multi-byte characters intact (decoded at the end of the line), also across an EAGAIN", () => {
    const { deps } = fake(["Ä", { error: "EAGAIN" }, "B€\n"]);
    expect(readConfirmationLine(deps)).toBe("ÄB€");
    expect(readConfirmationLine(fake(["\u00c4"]).deps)).toBeNull(); // EOF without a line end
    expect(readConfirmationLine(fake([`${"€".repeat(22)}\n`]).deps)).toBeNull(); // 66 bytes
  });
});
