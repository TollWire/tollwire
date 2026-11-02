import { chmodSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULT_USER_CONFIG, ENTERPRISE_DEFAULTS, readUserConfig, STANDALONE_DEFAULTS, standaloneSettings } from "../../src/events/settings.js";
import { sha256Hex } from "../../src/vendor/hashchain.js";
import { tempDir } from "./helpers.js";

function write(content: string): string {
  const path = join(tempDir(), "config.json");
  writeFileSync(path, content);
  return path;
}

describe("readUserConfig", () => {
  it("defaults: log on, no command text", () => {
    expect(DEFAULT_USER_CONFIG).toEqual({ enabled: true, commandDetail: "none", projectDir: false });
    expect(readUserConfig(join(tempDir(), "missing.json"))).toEqual({ config: DEFAULT_USER_CONFIG, sha256: null, valid: true });
  });
  it("reads the switches and hashes the file", () => {
    const text = '{"logging":{"enabled":false,"commandDetail":"redacted","projectDir":true}}';
    expect(readUserConfig(write(text))).toEqual({ config: { enabled: false, commandDetail: "redacted", projectDir: true }, sha256: sha256Hex(text), valid: true });
  });
  it("accepts a partial file and ignores unknown keys", () => {
    expect(readUserConfig(write('{"logging":{"enabled":false},"other":1}')).config).toEqual({ enabled: false, commandDetail: "none", projectDir: false });
    expect(readUserConfig(write("{}")).config).toEqual(DEFAULT_USER_CONFIG);
  });
  it.each([
    ["not json", "{nope"],
    ["wrong type", '{"logging":{"enabled":"false"}}'],
    ["unknown detail", '{"logging":{"commandDetail":"full"}}'],
    ["array", "[]"],
    ["null", "null"],
    ["logging not an object", '{"logging":3}'],
    ["empty", ""],
  ])("keeps the log on for an invalid file (%s)", (_name, text) => {
    const r = readUserConfig(write(text));
    expect(r.config).toEqual(DEFAULT_USER_CONFIG);
    expect(r.config.enabled).toBe(true);
    expect(r.valid).toBe(false);
  });
  it("keeps the log on for an unreadable or oversized file or a directory", () => {
    const big = write(`{"logging":{"enabled":false},"pad":"${"x".repeat(70_000)}"}`);
    expect(readUserConfig(big)).toMatchObject({ config: DEFAULT_USER_CONFIG, valid: false });
    const dir = tempDir();
    mkdirSync(join(dir, "c.json"));
    expect(readUserConfig(join(dir, "c.json"))).toMatchObject({ config: DEFAULT_USER_CONFIG, valid: false });
    const locked = write('{"logging":{"enabled":false}}');
    if (process.getuid?.() !== 0) {
      chmodSync(locked, 0o000);
      expect(readUserConfig(locked)).toMatchObject({ config: DEFAULT_USER_CONFIG, valid: false });
    }
  });
  it("follows a symlinked file (dotfile managers)", () => {
    const real = write('{"logging":{"enabled":false}}');
    const link = join(tempDir(), "config.json");
    symlinkSync(real, link);
    expect(readUserConfig(link).config.enabled).toBe(false);
  });
});

describe("settings", () => {
  it("stand-alone defaults warn on write errors and log checked tools without command text", () => {
    expect(STANDALONE_DEFAULTS).toMatchObject({ enabled: true, tools: "checked", commandDetail: "none", commandHash: false, onWriteError: "warn", rateLimit: 600 });
    expect(standaloneSettings({ enabled: false, commandDetail: "redacted", projectDir: true })).toMatchObject({ enabled: false, commandDetail: "redacted", projectDir: true, onWriteError: "warn", tools: "checked" });
  });
  it("enterprise defaults block on write errors and log all tools redacted", () => {
    expect(ENTERPRISE_DEFAULTS).toMatchObject({ enabled: true, tools: "all", commandDetail: "redacted", commandHash: false, onWriteError: "block", layout: "per_user" });
  });
});
