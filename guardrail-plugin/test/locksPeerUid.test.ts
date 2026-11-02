import { describe, expect, it } from "vitest";
import { applyChange, emptyLocks, lockDecision, LocksError, parseLocks, serializeLocks, type LockSpec } from "../src/vendor/locks.js";

// Red team finding: `peer_uid` is an optional entry field. The parser of the hook reads both forms and stays strict.
const NOW = "2026-10-18T09:12:03.120Z";
const uuid = (n: number): string => `00000000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;
const spec = (n: number, extra: Partial<LockSpec> = {}): LockSpec => ({ id: uuid(n), kind: "user", target: { uid: 1001 + n }, expires: null, by_uid: 1, via: "monitor", event_id: uuid(1000 + n), ...extra });
const lock = (s: LockSpec) => {
  const f = emptyLocks("dev-ws-017", NOW);
  return applyChange(f, serializeLocks(f), { op: "lock", spec: s }, NOW);
};

describe("peer_uid", () => {
  it("is written next to by_uid, round-trips and still decides", () => {
    const a = lock(spec(1, { peer_uid: 990 }));
    expect(a.text).toContain('"by_uid":1,');
    expect(a.text).toContain('"peer_uid":990');
    const parsed = parseLocks(a.text);
    expect(parsed.locks[0]).toMatchObject({ by_uid: 1, peer_uid: 990 });
    expect(serializeLocks(parsed)).toBe(a.text);
    expect(lockDecision({ uid: 1002, sessionId: "s", toolName: "Bash" }, parsed, Date.parse(NOW))).toMatchObject({ kind: "user" });
  });
  it("allows uid 0 (root over the CLI) but only there", () => {
    expect(parseLocks(lock(spec(1, { peer_uid: 0 })).text).locks[0]?.peer_uid).toBe(0);
    expect(() => lock(spec(1, { by_uid: 0 }))).toThrow(LocksError);
  });
  it("is left out when the caller has none; the form of earlier files is unchanged", () => {
    const a = lock(spec(1));
    expect(a.text).not.toContain("peer_uid");
    expect(parseLocks(a.text).locks[0]).not.toHaveProperty("peer_uid");
    const b = lock(spec(2, { peer_uid: null }));
    expect(b.text).not.toContain("peer_uid");
  });
  it.each([-1, 4294967295, 1.5, "990", null])("refuses an invalid value %j in a file", (bad) => {
    const good = JSON.parse(lock(spec(1, { peer_uid: 990 })).text) as { locks: Record<string, unknown>[] };
    good.locks[0]!.peer_uid = bad;
    expect(() => parseLocks(`${JSON.stringify(good)}\n`)).toThrow(LocksError);
  });
  it("refuses a duplicate peer_uid key and unknown extra keys (strict form)", () => {
    const text = lock(spec(1, { peer_uid: 990 })).text;
    expect(() => parseLocks(text.replace('"peer_uid":990', '"peer_uid":990,"peer_uid":0'))).toThrow(LocksError);
    expect(() => parseLocks(text.replace('"peer_uid":990', '"peer_uid":990,"zzz":1'))).toThrow(LocksError);
  });
  it("an apply with an invalid peer_uid is refused", () => {
    expect(() => lock(spec(1, { peer_uid: -5 }))).toThrow(LocksError);
    expect(() => lock(spec(1, { peer_uid: 4294967295 }))).toThrow(LocksError);
  });
});
