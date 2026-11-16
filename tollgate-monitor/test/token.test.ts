import { describe, expect, it } from "vitest";
import { checkToken, generateToken, issueToken, MAX_PRESENTED_LENGTH, parseBearer, tokensEqual } from "../src/vendor/token.js";

describe("token module (T22)", () => {
  it("generates base64url tokens with the requested entropy and never repeats", () => {
    const a = generateToken();
    const b = generateToken();
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a).not.toBe(b);
    expect(generateToken(16)).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it("refuses too little or too much entropy and bad sizes", () => {
    for (const bad of [0, 15, 129, 1.5, Number.NaN, -1]) expect(() => generateToken(bad), String(bad)).toThrow(RangeError);
  });

  it("compares equal and different values, also of different length and with non-ASCII text", () => {
    expect(tokensEqual("abc", "abc")).toBe(true);
    expect(tokensEqual("abc", "abd")).toBe(false);
    expect(tokensEqual("abc", "abcd")).toBe(false);
    expect(tokensEqual("", "")).toBe(true);
    expect(tokensEqual("", "x")).toBe(false);
    expect(tokensEqual("ä", "ä")).toBe(true);
  });

  it("issues a token with an expiry and validates ttl", () => {
    const t = issueToken(1000, 5000);
    expect(t.issuedAtMs).toBe(1000);
    expect(t.expiresAtMs).toBe(6000);
    for (const ttl of [0, -1, 1.5, 31 * 24 * 3_600_000]) expect(() => issueToken(0, ttl), String(ttl)).toThrow(RangeError);
    expect(() => issueToken(Number.NaN, 10)).toThrow(RangeError);
  });

  it("accepts the token before expiry and rejects it at and after expiry", () => {
    const t = issueToken(1000, 5000);
    expect(checkToken(t.value, t, 1000)).toBe("ok");
    expect(checkToken(t.value, t, 5999)).toBe("ok");
    expect(checkToken(t.value, t, 6000)).toBe("expired");
    expect(checkToken(t.value, t, 10_000_000)).toBe("expired");
    expect(checkToken(t.value, t, 999)).toBe("expired");
  });

  it("rejects missing, empty, wrong, malformed and oversize values", () => {
    const t = issueToken(0, 1000);
    for (const value of [undefined, null, "", "x", `${t.value}x`, t.value.slice(1), `${t.value}=`, " " + t.value, "a".repeat(MAX_PRESENTED_LENGTH + 1), "\u0000"]) {
      expect(checkToken(value, t, 1), String(value)).toBe("invalid");
    }
    expect(checkToken(t.value.toUpperCase() === t.value ? t.value.toLowerCase() : t.value.toUpperCase(), t, 1)).toBe("invalid");
  });

  it("parses only a well-formed Bearer header", () => {
    expect(parseBearer("Bearer abc-DEF_123")).toBe("abc-DEF_123");
    for (const bad of [undefined, null, "", "Bearer", "Bearer ", "bearer abc", "Basic abc", "Bearer  abc", "Bearer abc def", "Bearer abc\n", `Bearer ${"a".repeat(600)}`, "Bearer a=b"]) {
      expect(parseBearer(bad), String(bad)).toBeNull();
    }
  });
});
