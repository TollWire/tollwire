import { describe, expect, it } from "vitest";
import { containsTokens, globMatch, matches, validGlob } from "../src/matchers.js";

describe("globMatch", () => {
  it.each([
    ["abc", "abc", true],
    ["abc", "abd", false],
    ["a?c", "abc", true],
    ["a?c", "ac", false],
    ["*", "", true],
    ["*", "anything", true],
    ["git push *", "git push origin main", true],
    ["git push *", "git pull", false],
    ["*--force*", "git push --force origin", true],
    ["*--force*", "git push origin", false],
    ["a*b*c", "aXXbYYc", true],
    ["a*b*c", "aXXbYY", false],
    ["*a", "ba", true],
    ["*a", "bab", false],
    ["a*", "a", true],
    ["", "", true],
    ["", "x", false],
    ["??", "é😀", true],
  ])("%j matches %j: %s", (glob, text, expected) => {
    expect(globMatch(glob, text)).toBe(expected);
  });
  it("is fast on adversarial input (no catastrophic backtracking)", () => {
    const text = "a".repeat(30_000);
    const started = Date.now();
    expect(globMatch("*a*a*b", text)).toBe(false);
    expect(globMatch("a*a*a*a*a*a*a*b".replace(/\*/g, "?"), text)).toBe(false);
    expect(Date.now() - started).toBeLessThan(2000);
  });
  it("validGlob allows at most two stars", () => {
    expect(validGlob("a*b*c")).toBe(true);
    expect(validGlob("a*b*c*d")).toBe(false);
    expect(validGlob("a?b?c?d")).toBe(true);
  });
});

describe("containsTokens and matches", () => {
  const commands = [["git", "push", "--force", "origin"], ["ls"]];
  it("finds consecutive words in one command", () => {
    expect(containsTokens(commands, ["git", "push"])).toBe(true);
    expect(containsTokens(commands, ["push", "--force"])).toBe(true);
    expect(containsTokens(commands, ["git", "--force"])).toBe(false);
    expect(containsTokens(commands, ["push", "ls"])).toBe(false);
    expect(containsTokens(commands, [])).toBe(false);
    expect(containsTokens(commands, ["a", "b", "c", "d", "e"])).toBe(false);
  });
  it("evaluates the three matcher kinds", () => {
    const variants = ["git push --force origin"];
    expect(matches({ literal: "--force" }, variants, commands)).toBe(true);
    expect(matches({ literal: "" }, variants, commands)).toBe(false);
    expect(matches({ literal: "--hard" }, variants, commands)).toBe(false);
    expect(matches({ tokens: ["git", "push"] }, variants, commands)).toBe(true);
    expect(matches({ glob: "git push*" }, variants, commands)).toBe(true);
    expect(matches({ glob: "git pull*" }, variants, commands)).toBe(false);
  });
});
