import { describe, expect, it } from "vitest";
import {
  applyChange, emptyLocks, isActive, lockDecision, lockToolMatches, LocksError, LOCKS_GENESIS, locksSha256, MAX_EXPIRY_MS, MAX_LOCKS, MAX_LOCKS_BYTES, parseLocks, serializeLocks, toolMatches,
  type Change, type LockCall, type LockSpec, type LocksFile,
} from "../src/vendor/locks.js";

// Admin locks: schema tollgate.locks.v1, parser, evaluation, state change.
const NOW = "2026-10-18T09:12:03.120Z";
const NOW_MS = Date.parse(NOW);
const uuid = (n: number): string => `00000000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;

// Vector computed independently (Python json.dumps(sort_keys, separators) + hashlib), not with this code.
const VECTOR =
  '{"generation":2,"global":null,"host":"dev-ws-017","locks":[{"by_uid":1002,"created":"2026-10-18T09:00:00.000Z","event_id":"22222222-2222-4222-8222-222222222222","expires":null,"id":"11111111-1111-4111-8111-111111111111","kind":"user","target":{"uid":1001},"via":"monitor"},{"by_uid":1002,"created":"2026-10-18T09:01:00.000Z","event_id":"44444444-4444-4444-8444-444444444444","expires":"2026-10-19T09:01:00.000Z","id":"33333333-3333-4333-8333-333333333333","kind":"tool","target":{"tool":"mcp__github__*"},"via":"cli"}],"prev_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema":"tollgate.locks.v1","updated":"2026-10-18T09:12:03.120Z"}\n';
const VECTOR_SHA = "803cb1573d7a8f8b592497df9410f443c47a3313dbe4d344610d3e3095b9efa2";

function spec(n: number, kind: LockSpec["kind"], target: unknown, expires: string | null = null): LockSpec {
  return { id: uuid(n), kind, target, expires, by_uid: 1002, via: "monitor", event_id: uuid(1000 + n) };
}
function lockOne(file: LocksFile, s: LockSpec, now = NOW) {
  return applyChange(file, serializeLocks(file), { op: "lock", spec: s }, now);
}
const base = emptyLocks("dev-ws-017", NOW);

describe("tollgate.locks.v1: format", () => {
  it("matches the independently computed vector (canonical bytes and SHA-256)", () => {
    const file = parseLocks(VECTOR);
    expect(file.generation).toBe(2);
    expect(file.locks).toHaveLength(2);
    expect(serializeLocks(file)).toBe(VECTOR);
    expect(locksSha256(VECTOR)).toBe(VECTOR_SHA);
  });

  it("rejects anything but the canonical form", () => {
    expect(() => parseLocks(VECTOR.trimEnd())).toThrow(LocksError); // no newline
    expect(() => parseLocks(VECTOR.replace('"generation":2,', '"generation": 2,'))).toThrow(LocksError);
    expect(() => parseLocks(`${VECTOR.trimEnd()}\n\n`)).toThrow(LocksError);
    // a duplicate key does not survive: the re-serialization differs
    expect(() => parseLocks(VECTOR.replace('"generation":2,', '"generation":2,"generation":0,'))).toThrow(LocksError);
    expect(() => parseLocks("not json")).toThrow(LocksError);
    expect(() => parseLocks("")).toThrow(LocksError);
  });

  it("rejects unknown and missing fields (no field can allow anything)", () => {
    const o = JSON.parse(VECTOR) as Record<string, unknown>;
    for (const extra of [{ allow: ["Bash"] }, { control: { enabled: false } }, { __proto__x: 1 }]) {
      expect(() => parseLocks(`${JSON.stringify({ ...o, ...extra })}\n`)).toThrow(LocksError);
    }
    const missing = { ...o };
    delete missing.global;
    expect(() => parseLocks(`${JSON.stringify(missing)}\n`)).toThrow(LocksError);
    const entry = { ...(o.locks as Record<string, unknown>[])[0], reason: "text in the file" };
    expect(() => parseLocks(serializeCanon({ ...o, locks: [entry] }))).toThrow(LocksError);
  });

  it("rejects wrong schema, host, generation, hashes, ids, times and uids", () => {
    const o = JSON.parse(VECTOR) as Record<string, unknown> & { locks: Record<string, unknown>[] };
    const bad: Record<string, unknown>[] = [
      { ...o, schema: "tollgate.locks.v2" },
      { ...o, host: "bad host" },
      { ...o, host: "" },
      { ...o, generation: -1 },
      { ...o, generation: 1.5 },
      { ...o, prev_sha256: "A".repeat(64) },
      { ...o, updated: "2026-10-18T09:12:03Z" },
      { ...o, updated: "2026-02-31T09:12:03.120Z" },
      { ...o, locks: [{ ...o.locks[0], id: "not-a-uuid" }] },
      { ...o, locks: [{ ...o.locks[0], by_uid: 0 }] },
      { ...o, locks: [{ ...o.locks[0], by_uid: 4294967295 }] },
      { ...o, locks: [{ ...o.locks[0], via: "gui" }] },
      { ...o, locks: [{ ...o.locks[0], kind: "global" }] },
      { ...o, locks: [{ ...o.locks[0], kind: "allow" }] },
      { ...o, locks: [o.locks[0], o.locks[0]] },
      { ...o, global: o.locks[0] }, // kind user in the global slot
    ];
    for (const b of bad) expect(() => parseLocks(serializeCanon(b)), JSON.stringify(b).slice(0, 80)).toThrow(LocksError);
  });

  it.each([
    ["uid 0", "user", { uid: 0 }],
    ["uid too large", "user", { uid: 4294967295 }],
    ["uid as string", "user", { uid: "1001" }],
    ["uid float", "user", { uid: 1.5 }],
    ["uid with extra field", "user", { uid: 1001, name: "x" }],
    ["session with space", "session", { session_id: "a b" }],
    ["session empty", "session", { session_id: "" }],
    ["session over 128", "session", { session_id: "a".repeat(129) }],
    ["tool wildcard only", "tool", { tool: "*" }],
    ["tool glob in the middle", "tool", { tool: "mcp__*__x" }],
    ["tool server prefix", "tool", { tool: "mcp__srv*" }],
    ["tool with slash", "tool", { tool: "../x" }],
    ["tool as array", "tool", { tool: ["Bash"] }],
    ["global with content", "global", { x: 1 }],
    ["target is a string", "user", "1001"],
    ["target is null", "user", null],
    ["target is an array", "user", [1001]],
  ] as const)("rejects the target: %s", (_name, kind, target) => {
    expect(() => lockOne(base, spec(1, kind, target))).toThrow(LocksError);
  });

  it.each([
    ["user", { uid: 1 }],
    ["user", { uid: 4294967294 }],
    ["session", { session_id: "abc-DEF_1.2:3" }],
    ["tool", { tool: "Bash" }],
    ["tool", { tool: "mcp__github__*" }],
    ["tool", { tool: "mcp__a.b_c__*" }],
    ["global", {}],
  ] as const)("accepts the target %s %j", (kind, target) => {
    const applied = lockOne(base, spec(1, kind, target));
    expect(parseLocks(applied.text)).toEqual(applied.next);
  });

  it("limits: 200 locks, 64 KiB, 30 days", () => {
    // 200 short locks fit under 64 KiB; the 201st is refused by the count.
    let file = base;
    for (let i = 0; i < MAX_LOCKS; i += 1) file = lockOne(file, spec(i + 1, "user", { uid: 2000 + i })).next;
    expect(file.locks).toHaveLength(MAX_LOCKS);
    expect(Buffer.byteLength(serializeLocks(file))).toBeLessThan(MAX_LOCKS_BYTES);
    expect(() => lockOne(file, spec(500, "user", { uid: 9000 }))).toThrow(/200/);
    // the global lock has its own slot and is never blocked by the list limit
    expect(lockOne(file, spec(501, "global", {})).next.global?.id).toBe(uuid(501));
    // the byte limit bites first with long targets
    let big = base;
    expect(() => {
      for (let i = 0; i < MAX_LOCKS; i += 1) big = lockOne(big, spec(i + 1, "session", { session_id: `${String(i).padStart(3, "0")}${"s".repeat(125)}` })).next;
    }).toThrow(/64 KiB/);
    // text over 64 KiB is refused by the parser before it is parsed
    expect(() => parseLocks(`${" ".repeat(MAX_LOCKS_BYTES)}x`)).toThrow(/64 KiB/);
    // expiry
    const day = (ms: number): string => new Date(NOW_MS + ms).toISOString();
    expect(() => lockOne(base, spec(1, "user", { uid: 5 }, day(0)))).toThrow(LocksError);
    expect(() => lockOne(base, spec(1, "user", { uid: 5 }, day(-1000)))).toThrow(LocksError);
    expect(() => lockOne(base, spec(1, "user", { uid: 5 }, day(MAX_EXPIRY_MS + 1)))).toThrow(LocksError);
    expect(lockOne(base, spec(1, "user", { uid: 5 }, day(MAX_EXPIRY_MS))).next.locks).toHaveLength(1);
    expect(() => lockOne(base, spec(1, "user", { uid: 5 }, "tomorrow"))).toThrow(LocksError);
    // the parser enforces the 30 days against the creation time as well
    const longLived = serializeCanon({ ...JSON.parse(VECTOR), locks: [{ ...JSON.parse(VECTOR).locks[1], expires: "2026-12-31T00:00:00.000Z" }] });
    expect(() => parseLocks(longLived)).toThrow(/expiry/);
  });
});

describe("tollgate.locks.v1: state change", () => {
  it("chains the generations: generation + 1 and the SHA-256 of the previous bytes", () => {
    expect(base.generation).toBe(0);
    expect(base.prev_sha256).toBe(LOCKS_GENESIS);
    const a = lockOne(base, spec(1, "user", { uid: 1001 }));
    expect(a.result).toBe("applied");
    expect(a.next.generation).toBe(1);
    expect(a.next.prev_sha256).toBe(locksSha256(serializeLocks(base)));
    expect(a.sha256).toBe(locksSha256(a.text));
    const b = applyChange(a.next, a.text, { op: "lock", spec: spec(2, "global", {}) }, NOW);
    expect(b.next.generation).toBe(2);
    expect(b.next.prev_sha256).toBe(a.sha256);
    expect(b.next.global?.created).toBe(NOW);
  });

  it("is idempotent: an equal active lock is not added twice and the file does not change", () => {
    const a = lockOne(base, spec(1, "tool", { tool: "mcp__github__*" }));
    const again = applyChange(a.next, a.text, { op: "lock", spec: spec(2, "tool", { tool: "mcp__github__*" }) }, NOW);
    expect(again.result).toBe("exists");
    expect(again.lockId).toBe(uuid(1));
    expect(again.text).toBe(a.text);
    expect(again.next).toBe(a.next);
    const g = lockOne(base, spec(3, "global", {}));
    expect(applyChange(g.next, g.text, { op: "lock", spec: spec(4, "global", {}) }, NOW).result).toBe("exists");
    // same target, other kind: a separate lock
    expect(lockOne(a.next, spec(5, "tool", { tool: "Bash" })).next.locks).toHaveLength(2);
  });

  it("unlocks by id and the global lock; unknown ids change nothing", () => {
    const a = lockOne(lockOne(base, spec(1, "user", { uid: 7 })).next, spec(2, "global", {}));
    const u = applyChange(a.next, a.text, { op: "unlock", lockId: uuid(1) }, NOW);
    expect(u.result).toBe("applied");
    expect(u.next.locks).toEqual([]);
    expect(u.next.global).not.toBeNull();
    const ug = applyChange(u.next, u.text, { op: "unlock_global" }, NOW);
    expect(ug.next.global).toBeNull();
    expect(applyChange(ug.next, ug.text, { op: "unlock_global" }, NOW).result).toBe("not_found");
    const unknown = applyChange(a.next, a.text, { op: "unlock", lockId: uuid(99) }, NOW);
    expect(unknown.result).toBe("not_found");
    expect(unknown.text).toBe(a.text);
    // unlock never takes the global id through the list path
    expect(applyChange(a.next, a.text, { op: "unlock", lockId: uuid(2) }, NOW).result).toBe("not_found");
  });

  it("removes expired locks with the next write and reports them", () => {
    const soon = new Date(NOW_MS + 60_000).toISOString();
    const a = lockOne(lockOne(base, spec(1, "user", { uid: 7 }, soon)).next, spec(2, "global", {}, soon));
    const later = new Date(NOW_MS + 120_000).toISOString();
    expect(isActive(a.next.locks[0]!, Date.parse(later))).toBe(false);
    const b = applyChange(a.next, a.text, { op: "lock", spec: spec(3, "user", { uid: 8 }) }, later);
    expect(b.expired.map((e) => e.id).sort()).toEqual([uuid(1), uuid(2)]);
    expect(b.next.locks.map((e) => e.id)).toEqual([uuid(3)]);
    expect(b.next.global).toBeNull();
    // even a failed unlock lets the expired locks go (the file changes, the result says not_found)
    const c = applyChange(a.next, a.text, { op: "unlock", lockId: uuid(42) }, later);
    expect(c.result).toBe("not_found");
    expect(c.expired).toHaveLength(2);
    expect(c.next.generation).toBe(a.next.generation + 1);
  });

  it("rejects bad requests", () => {
    expect(() => lockOne(base, { ...spec(1, "user", { uid: 7 }), id: "x" })).toThrow(LocksError);
    expect(() => lockOne(base, { ...spec(1, "user", { uid: 7 }), by_uid: 0 })).toThrow(LocksError);
    expect(() => lockOne(base, { ...spec(1, "user", { uid: 7 }), via: "gui" as never })).toThrow(LocksError);
    expect(() => lockOne(base, { ...spec(1, "user", { uid: 7 }), event_id: "x" })).toThrow(LocksError);
  });
});

describe("an equal lock is extended, never shortened (review F1)", () => {
  const at = (ms: number): string => new Date(NOW_MS + ms).toISOString();
  it("a short lock plus an unlimited request becomes unlimited (new generation, same id, own result)", () => {
    const a = lockOne(base, spec(1, "user", { uid: 7 }, at(60_000)));
    const b = applyChange(a.next, a.text, { op: "lock", spec: spec(2, "user", { uid: 7 }, null) }, NOW);
    expect(b.result).toBe("extended");
    expect(b.lockId).toBe(uuid(1));
    expect(b.expires).toBeNull();
    expect(b.next.locks).toHaveLength(1);
    expect(b.next.locks[0]).toMatchObject({ id: uuid(1), expires: null });
    expect(b.next.generation).toBe(a.next.generation + 1);
    expect(b.next.prev_sha256).toBe(a.sha256);
    // after the first one would have expired, the lock still holds
    expect(lockDecision({ uid: 7, sessionId: "s", toolName: "Bash" }, b.next, NOW_MS + 3_600_000)?.id).toBe(uuid(1));
  });
  it("a later date beats an earlier one; an earlier or equal date or an unlimited lock stays as it is", () => {
    const a = lockOne(base, spec(1, "tool", { tool: "Bash" }, at(60_000)));
    const later = applyChange(a.next, a.text, { op: "lock", spec: spec(2, "tool", { tool: "Bash" }, at(120_000)) }, NOW);
    expect(later.result).toBe("extended");
    expect(later.expires).toBe(at(120_000));
    const shorter = applyChange(later.next, later.text, { op: "lock", spec: spec(3, "tool", { tool: "Bash" }, at(30_000)) }, NOW);
    expect(shorter.result).toBe("exists");
    expect(shorter.expires).toBe(at(120_000));
    expect(shorter.text).toBe(later.text);
    const same = applyChange(later.next, later.text, { op: "lock", spec: spec(4, "tool", { tool: "Bash" }, at(120_000)) }, NOW);
    expect(same.result).toBe("exists");
    const forever = lockOne(base, spec(5, "tool", { tool: "Bash" }, null));
    const again = applyChange(forever.next, forever.text, { op: "lock", spec: spec(6, "tool", { tool: "Bash" }, at(60_000)) }, NOW);
    expect(again.result).toBe("exists");
    expect(again.expires).toBeNull();
    expect(again.text).toBe(forever.text);
  });
  it("the global lock is extended the same way, and the extended file passes the strict parser (expiry is relative to the new creation)", () => {
    const a = lockOne(base, spec(1, "global", {}, at(60_000)), NOW);
    const later = new Date(NOW_MS + 20 * 86_400_000).toISOString();
    const b = applyChange(a.next, a.text, { op: "lock", spec: { ...spec(2, "global", {}, new Date(NOW_MS + 40 * 86_400_000).toISOString()) } }, later);
    // the first lock had expired at `later`: it is gone and the request is a new lock
    expect(b.result).toBe("applied");
    const c = lockOne(base, spec(3, "global", {}, at(86_400_000)), NOW);
    const d = applyChange(c.next, c.text, { op: "lock", spec: spec(4, "global", {}, at(29 * 86_400_000)) }, at(60_000));
    expect(d.result).toBe("extended");
    expect(d.next.global?.id).toBe(uuid(3));
    expect(parseLocks(d.text)).toEqual(d.next);
  });
});

describe("lock matching is wider than the allowlist (review F2, F3)", () => {
  it("a server wildcard locks tools with a double underscore in the tool part too", () => {
    expect(lockToolMatches("mcp__evil__*", "mcp__evil__a__b")).toBe(true);
    expect(lockToolMatches("mcp__evil__*", "mcp__evil__a")).toBe(true);
    expect(lockToolMatches("mcp__evil__*", "mcp__evil__")).toBe(false);
    expect(lockToolMatches("mcp__evil__*", "mcp__evil2__a")).toBe(false);
    expect(toolMatches("mcp__evil__*", "mcp__evil__a__b")).toBe(false); // the allowlist rule is unchanged
    const f = lockOne(base, spec(1, "tool", { tool: "mcp__evil__*" })).next;
    expect(lockDecision({ uid: 1, sessionId: "s", toolName: "mcp__evil__a__b" }, f, NOW_MS)?.kind).toBe("tool");
  });
  it("ignores case and Unicode compatibility forms (only ever denies more)", () => {
    expect(lockToolMatches("bash", "Bash")).toBe(true);
    expect(lockToolMatches("Bash", "BASH")).toBe(true);
    expect(lockToolMatches("MCP__GitHub__*", "mcp__github__create_issue")).toBe(true);
    expect(lockToolMatches("Bash", "\uff22ash")).toBe(true); // full-width B
    expect(lockToolMatches("Bash", "Bashx")).toBe(false);
    const f = lockOne(base, spec(1, "tool", { tool: "bash" })).next;
    expect(lockDecision({ uid: 1, sessionId: "s", toolName: "Bash" }, f, NOW_MS)?.kind).toBe("tool");
  });
});

describe("lockDecision", () => {
  const file = (specs: LockSpec[], now = NOW): LocksFile => specs.reduce((f, s) => lockOne(f, s, now).next, base);
  const call = (over: Partial<LockCall> = {}): LockCall => ({ uid: 1001, sessionId: "s-1", toolName: "Bash", ...over });

  it("returns null without locks", () => {
    expect(lockDecision(call(), base, NOW_MS)).toBeNull();
  });
  it("matches a user lock by numeric uid only", () => {
    const f = file([spec(1, "user", { uid: 1001 })]);
    expect(lockDecision(call(), f, NOW_MS)).toEqual({ kind: "user", id: uuid(1) });
    expect(lockDecision(call({ uid: 1002 }), f, NOW_MS)).toBeNull();
    expect(lockDecision(call({ uid: null }), f, NOW_MS)).toBeNull();
  });
  it("matches a session lock", () => {
    const f = file([spec(1, "session", { session_id: "s-1" })]);
    expect(lockDecision(call(), f, NOW_MS)?.kind).toBe("session");
    expect(lockDecision(call({ sessionId: "s-2" }), f, NOW_MS)).toBeNull();
    expect(lockDecision(call({ sessionId: "<invalid>" }), f, NOW_MS)).toBeNull();
  });
  it("matches tool names and MCP server wildcards like the tool allowlist", () => {
    const f = file([spec(1, "tool", { tool: "mcp__github__*" }), spec(2, "tool", { tool: "WebFetch" })]);
    expect(lockDecision(call({ toolName: "mcp__github__create_issue" }), f, NOW_MS)?.id).toBe(uuid(1));
    expect(lockDecision(call({ toolName: "WebFetch" }), f, NOW_MS)?.id).toBe(uuid(2));
    expect(lockDecision(call({ toolName: "WebFetch2" }), f, NOW_MS)).toBeNull();
    expect(lockDecision(call({ toolName: "mcp__github2__x" }), f, NOW_MS)).toBeNull();
    // "mcp__a__x__t" is not decidable (server a__x or a): the wildcard does not cover it
    expect(toolMatches("mcp__a__*", "mcp__a__x__t")).toBe(false);
    expect(toolMatches("mcp__a__*", "mcp__a__")).toBe(false);
    expect(toolMatches("mcp__a__*", "mcp__a__t")).toBe(true);
    expect(toolMatches("Bash", "bash")).toBe(false);
  });
  it("the global lock applies to everybody and wins", () => {
    const f = file([spec(1, "user", { uid: 1001 }), spec(2, "global", {})]);
    expect(lockDecision(call({ uid: 5 }), f, NOW_MS)).toEqual({ kind: "global", id: uuid(2) });
    expect(lockDecision(call(), f, NOW_MS)?.kind).toBe("global");
  });
  it("ignores expired locks (system clock)", () => {
    const f = file([spec(1, "user", { uid: 1001 }, new Date(NOW_MS + 1000).toISOString())]);
    expect(lockDecision(call(), f, NOW_MS)?.kind).toBe("user");
    expect(lockDecision(call(), f, NOW_MS + 999)?.kind).toBe("user");
    expect(lockDecision(call(), f, NOW_MS + 1000)).toBeNull();
    expect(lockDecision(call(), f, NOW_MS + 5000)).toBeNull();
  });
});

describe("property: locks only tighten (monotonic)", () => {
  // Seeded generator: the run is reproducible.
  let seed = 0x2545f491;
  const rnd = (): number => {
    seed ^= seed << 13;
    seed >>>= 0;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    seed >>>= 0;
    return seed / 0x100000000;
  };
  const pick = <T,>(items: readonly T[]): T => items[Math.floor(rnd() * items.length)] as T;
  const TOOLS = ["Bash", "Read", "Edit", "WebFetch", "mcp__github__create_issue", "mcp__docs__search", "mcp__a__x__t", "Grep"];
  const PATTERNS = ["Bash", "Read", "WebFetch", "mcp__github__*", "mcp__docs__*", "mcp__docs__search", "mcp__a__*"];

  it("allowed(policy + locks) is a subset of allowed(policy) for random policies, lock sets and calls", () => {
    let withLocks = 0;
    let withoutLocks = 0;
    let denyByLock = 0;
    for (let run = 0; run < 300; run += 1) {
      // The policy is any predicate; a random allowlist stands in for it.
      const allowed = new Set(TOOLS.filter(() => rnd() < 0.6));
      let f = base;
      const n = Math.floor(rnd() * 6);
      for (let i = 0; i < n; i += 1) {
        const kind = pick(["user", "session", "tool", "global"] as const);
        const target = kind === "user" ? { uid: pick([1000, 1001, 1002]) } : kind === "session" ? { session_id: pick(["s-1", "s-2", "s-3"]) } : kind === "tool" ? { tool: pick(PATTERNS) } : {};
        const expires = rnd() < 0.3 ? new Date(NOW_MS + (rnd() < 0.5 ? -1 : 1) * 1000 * Math.ceil(rnd() * 100)).toISOString() : null;
        try {
          f = lockOne(f, spec(run * 10 + i + 1, kind, target, expires !== null && Date.parse(expires) <= NOW_MS ? null : expires)).next;
        } catch {
          // an invalid combination is simply not part of the run
        }
      }
      for (let c = 0; c < 20; c += 1) {
        const call: LockCall = { uid: pick([1000, 1001, 1002, 1003, null]), sessionId: pick(["s-1", "s-2", "s-3", "<invalid>"]), toolName: pick(TOOLS) };
        const nowMs = NOW_MS + Math.floor(rnd() * 200_000);
        const policyAllows = allowed.has(call.toolName);
        const effective = policyAllows && lockDecision(call, f, nowMs) === null;
        if (policyAllows) withoutLocks += 1;
        if (effective) withLocks += 1;
        if (policyAllows && !effective) denyByLock += 1;
        // the lock layer never turns a deny of the policy into an allow
        if (effective) expect(policyAllows).toBe(true);
        // and the empty file changes nothing
        expect(lockDecision(call, base, nowMs)).toBeNull();
      }
    }
    expect(withLocks).toBeLessThanOrEqual(withoutLocks);
    expect(denyByLock).toBeGreaterThan(0); // the generator really produces hits
  });

  it("adding a lock never shrinks the set of denied calls", () => {
    for (let run = 0; run < 200; run += 1) {
      const kind = pick(["user", "session", "tool", "global"] as const);
      const target = kind === "user" ? { uid: pick([1000, 1001]) } : kind === "session" ? { session_id: pick(["s-1", "s-2"]) } : kind === "tool" ? { tool: pick(PATTERNS) } : {};
      const before = lockOne(base, spec(1, "tool", { tool: pick(PATTERNS) })).next;
      const after = lockOne(before, spec(2, kind, target)).next;
      const call: LockCall = { uid: pick([1000, 1001, null]), sessionId: pick(["s-1", "s-2"]), toolName: pick(TOOLS) };
      if (lockDecision(call, before, NOW_MS) !== null) expect(lockDecision(call, after, NOW_MS)).not.toBeNull();
    }
  });

  it("unlocking removes only that lock (nothing else is released)", () => {
    const a = lockOne(lockOne(base, spec(1, "user", { uid: 1001 })).next, spec(2, "user", { uid: 1002 }));
    const u = applyChange(a.next, a.text, { op: "unlock", lockId: uuid(1) } satisfies Change, NOW);
    expect(lockDecision({ uid: 1002, sessionId: "s", toolName: "Bash" }, u.next, NOW_MS)).not.toBeNull();
    expect(lockDecision({ uid: 1001, sessionId: "s", toolName: "Bash" }, u.next, NOW_MS)).toBeNull();
  });
});

function serializeCanon(value: unknown): string {
  const sort = (v: unknown): unknown => (Array.isArray(v) ? v.map(sort) : v !== null && typeof v === "object" ? Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, sort((v as Record<string, unknown>)[k])])) : v);
  return `${JSON.stringify(sort(value))}\n`;
}
