import { describe, expect, it } from "vitest";
import { ChainVerifier } from "../src/chain.js";
import { maskDeep, maskText } from "../src/mask.js";
import { WindowLimiter } from "../src/ratelimit.js";
import { chain, makeEvent } from "./helpers.js";

describe("output masking", () => {
  it("writes control, format and separator characters as \\u{XXXX} and keeps backslashes", () => {
    expect(maskText("a\u001bb\u007f\u0085‮ ​")).toBe("a\\u{001B}b\\u{007F}\\u{0085}\\u{202E}\\u{2028}\\u{200B}");
    expect(maskText("a\\b \\u{0041}")).toBe("a\\b \\u{0041}");
    expect(maskText("<b>ä€😀</b>")).toBe("<b>ä€😀</b>");
    expect(maskText("\ud800")).toBe("\\u{D800}");
  });

  it("masks keys and values, bounds depth and breadth, and drops functions and undefined", () => {
    const out = maskDeep({ "k\u0000": ["v\u0001", 1, true, null], deep: { a: { b: { c: { d: { e: { f: { g: { h: 1 } } } } } } } }, u: undefined, f: () => 1 }) as Record<string, unknown>;
    expect(Object.keys(out)).toContain("k\\u{0000}");
    expect(out["k\\u{0000}"]).toEqual(["v\\u{0001}", 1, true, null]);
    expect(JSON.stringify(out.deep)).toContain("null");
    expect(out.u).toBeNull();
    const wide = maskDeep(Object.fromEntries(Array.from({ length: 400 }, (_, i) => [`k${i}`, i]))) as Record<string, unknown>;
    expect(Object.keys(wide)).toHaveLength(256);
    expect(maskDeep(Array.from({ length: 400 }, (_, i) => i))).toHaveLength(256);
  });
});

describe("window limiter", () => {
  it("counts per window and starts over", () => {
    const l = new WindowLimiter(2, 1000);
    expect([l.hit(0), l.hit(10), l.hit(20)]).toEqual([true, true, false]);
    expect(l.full(30)).toBe(true);
    expect(l.retryAfterMs(30)).toBe(970);
    expect(l.hit(1000)).toBe(true);
    expect(l.full(1000)).toBe(false);
    expect(l.hit(500)).toBe(true); // a clock that went back starts a new window
    expect(l.retryAfterMs(5000)).toBe(1);
  });
});

describe("chain verifier", () => {
  const feedAll = (lines: unknown[]) => {
    const v = new ChainVerifier();
    lines.forEach((l, i) => v.feed("f.jsonl", i + 1, typeof l === "string" ? l : JSON.stringify(l)));
    return v.report();
  };

  it("accepts a chain with a continue marker and a corruption restart", () => {
    const a = chain([{}, {}]);
    const cont = makeEvent({ seq: 4, prev: a[2]?.hash as string, type: "chain_continue", data: { file: "next" } });
    expect(feedAll([...a, cont])).toMatchObject({ events: 4, chains: 1, findings: [] });
    const restart = makeEvent({ chain: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", seq: 1, prev: a[2]?.hash as string, type: "chain_start", data: { reason: "corruption", broken_chain_id: a[0]?.chain_id } });
    expect(feedAll([...a, restart]).findings).toEqual([]);
    const wrong = makeEvent({ chain: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", seq: 1, prev: "1".repeat(64), type: "chain_start", data: { reason: "corruption", broken_chain_id: a[0]?.chain_id } });
    expect(feedAll([...a, wrong]).findings.map((f) => f.kind)).toEqual(["link_mismatch"]);
  });

  it("finds start problems, unlinked continues, unknown chains, gaps and wrong links", () => {
    const a = chain([{}]);
    const kinds = (lines: unknown[]): string[] => feedAll(lines).findings.map((f) => f.kind);
    expect(kinds([makeEvent({ seq: 2, prev: "0".repeat(64), type: "chain_start" })])).toEqual(["start_invalid"]);
    expect(kinds([makeEvent({ seq: 1, prev: "1".repeat(64), type: "chain_start" })])).toEqual(["start_invalid"]);
    expect(kinds([makeEvent({ seq: 5, prev: "1".repeat(64), type: "chain_continue" })])).toEqual(["unlinked"]);
    expect(kinds([makeEvent({ seq: 5, prev: "1".repeat(64) })])).toEqual(["chain_broken"]);
    expect(kinds([a[0], makeEvent({ seq: 3, prev: a[0]?.hash as string })])).toEqual(["chain_broken"]);
    expect(kinds([a[0], makeEvent({ seq: 2, prev: "9".repeat(64) })])).toEqual(["chain_broken"]);
    const other = makeEvent({ chain: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", seq: 2, prev: a[0]?.hash as string });
    expect(kinds([a[0], other])).toEqual(["chain_broken"]);
  });

  it("rejects malformed events with a reason and counts findings beyond the list limit", () => {
    const bad = [{ schema: "x" }, { ...makeEvent({ seq: 1, prev: "0".repeat(64) }), seq: 0 }, { ...makeEvent({ seq: 1, prev: "0".repeat(64) }), hash: "zz" }, { ...makeEvent({ seq: 1, prev: "0".repeat(64) }), chain_id: "no" }, 5, "{", ""];
    const r = feedAll(bad);
    expect(r.findings.map((f) => f.kind)).toEqual(["invalid_event", "invalid_event", "invalid_event", "invalid_event", "invalid_event", "invalid_json"]);
    const many = feedAll(Array.from({ length: 150 }, () => "{"));
    expect(many.findings).toHaveLength(100);
    expect(many.moreFindings).toBe(50);
  });
});
