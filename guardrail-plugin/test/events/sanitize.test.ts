import { describe, expect, it } from "vitest";
import { sanitize, sanitizeDeep, truncateText } from "../../src/events/sanitize.js";

describe("sanitize", () => {
  it("doubles backslashes first (injective)", () => {
    expect(sanitize("a\\b")).toBe("a\\\\b");
    expect(sanitize("\\u{001B}")).toBe("\\\\u{001B}"); // literal text is not confusable with an escape
    expect(sanitize("\u001b")).toBe("\\u{001B}");
    expect(sanitize("a\\b\u001b‮")).toBe("a\\\\b\\u{001B}\\u{202E}");
  });
  it.each([
    ["\u0000", "\\u{0000}"],
    ["\n", "\\u{000A}"],
    ["\u001f", "\\u{001F}"],
    ["\u007f", "\\u{007F}"],
    ["\u0080", "\\u{0080}"],
    ["\u009f", "\\u{009F}"],
    [" ", "\\u{2028}"],
    [" ", "\\u{2029}"],
    ["‪", "\\u{202A}"],
    ["⁦", "\\u{2066}"],
    ["‎", "\\u{200E}"],
    ["\u061c", "\\u{061C}"],
    ["​", "\\u{200B}"],
    ["﻿", "\\u{FEFF}"],
    ["­", "\\u{00AD}"],
    ["\ud800", "\\u{D800}"],
    ["\udfff", "\\u{DFFF}"],
  ])("escapes %j", (input, expected) => {
    expect(sanitize(input)).toBe(expected);
  });
  it("keeps printable text, non-ASCII letters, tabs excluded, and astral pairs", () => {
    expect(sanitize("héllo wörld ✓ \u{1F600}")).toBe("héllo wörld ✓ \u{1F600}");
    expect(sanitize("a\tb")).toBe("a\\u{0009}b");
  });
  it("escapes only the lone half of a surrogate pair context", () => {
    expect(sanitize("\u{1F600}\ud83d")).toBe("\u{1F600}\\u{D83D}");
  });
  it("sanitizeDeep processes every string value but not keys, numbers or null", () => {
    const input = { a: "x\u001b", b: ["\\", 1, null, true], c: { d: " " } };
    expect(sanitizeDeep(input)).toEqual({ a: "x\\u{001B}", b: ["\\\\", 1, null, true], c: { d: "\\u{2028}" } });
  });
});

describe("truncateText", () => {
  it("returns short text unchanged", () => {
    expect(truncateText("abc", 5)).toEqual({ text: "abc", cut: false });
    expect(truncateText("abcde", 5)).toEqual({ text: "abcde", cut: false });
  });
  it("cuts at the limit and reports it", () => {
    expect(truncateText("abcdef", 5)).toEqual({ text: "abcde", cut: true });
  });
  it("never cuts inside an escape or a doubled backslash", () => {
    const s = sanitize("a\u001bb"); // a \u{001B} b
    expect(truncateText(s, 2)).toEqual({ text: "a\\u{001B}", cut: true });
    expect(truncateText(s, 1)).toEqual({ text: "a", cut: true });
    const b = sanitize("a\\\\b"); // each backslash doubled
    expect(truncateText(b, 2)).toEqual({ text: "a\\\\", cut: true });
  });
  it("never cuts a surrogate pair", () => {
    expect(truncateText("a\u{1F600}b", 2)).toEqual({ text: "a\u{1F600}", cut: true });
  });
});
