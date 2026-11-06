import { chmodSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Readable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import { analyzeCommand } from "../../src/events/commandInfo.js";
import { EventWriteError, readSmallFile, safeLstat, writeFileAtomic } from "../../src/events/fsutil.js";
import { standaloneLayout, userConfigFile } from "../../src/events/layout.js";
import { systemProcessFacts } from "../../src/events/lock.js";
import { observedTool } from "../../src/events/observe.js";
import { fileHash, managedSettingsPath, metaOf, osName, pluginFilesHash, systemRuntime } from "../../src/events/runtime.js";
import { sanitize, truncateText } from "../../src/events/sanitize.js";
import { evaluateTail } from "../../src/events/store.js";
import { readStdin, runHook, runMain } from "../../src/hook.js";
import { BUNDLED_POLICY_PATH } from "../../src/policy.js";
import { chainHash } from "../../src/vendor/hashchain.js";
import { envFor, runtimeFor, tempDir } from "./helpers.js";

const platform = process.platform;
afterEach(() => {
  Object.defineProperty(process, "platform", { value: platform });
});

function setPlatform(value: string): void {
  Object.defineProperty(process, "platform", { value });
}

describe("evaluateTail rejects invalid records", () => {
  const valid = (patch: Record<string, unknown> = {}): string => {
    const base: Record<string, unknown> = {
      schema: "tollgate.event.v1",
      chain_id: "00000000-0000-4000-8000-0000000000c1",
      seq: 1,
      prev_hash: "0".repeat(64),
      type: "chain_start",
      ...patch,
    };
    return `${JSON.stringify({ ...base, hash: chainHash(base) })}\n`;
  };
  const status = (line: string): string => evaluateTail(Buffer.from(line), line.length).status;
  it("accepts a valid record and refuses broken ones", () => {
    expect(status(valid())).toBe("ok");
    for (const patch of [{ schema: "x" }, { chain_id: "nope" }, { chain_id: 5 }, { seq: 0 }, { seq: "1" }, { seq: 1.5 }, { prev_hash: "zz" }, { prev_hash: 5 }]) {
      expect(status(valid(patch)), JSON.stringify(patch)).toBe("corrupt");
    }
    expect(status("null\n")).toBe("corrupt");
    expect(status('"text"\n')).toBe("corrupt");
    const bad = JSON.stringify({ schema: "tollgate.event.v1", chain_id: "00000000-0000-4000-8000-0000000000c1", seq: 1, prev_hash: "0".repeat(64), hash: "f".repeat(64) });
    expect(status(`${bad}\n`)).toBe("corrupt");
  });
  it("finds the last valid record in a window that starts in the middle of a line", () => {
    const text = `partial line\n${valid({ seq: 1 })}${valid({ seq: 2 })}broken`;
    const tail = evaluateTail(Buffer.from(text), text.length + 100);
    expect(tail).toMatchObject({ status: "corrupt", seq: 2 });
  });
});

describe("fsutil", () => {
  it("readSmallFile refuses links, oversize and non-regular files and reports a missing file", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "f"), "hello");
    symlinkSync(join(dir, "f"), join(dir, "l"));
    mkdirSync(join(dir, "d"));
    expect(readSmallFile(join(dir, "f"), 100)?.text).toBe("hello");
    expect(readSmallFile(join(dir, "none"), 100)).toBeNull();
    expect(readSmallFile(join(dir, "f", "child"), 100)).toBeNull(); // ENOTDIR
    expect(() => readSmallFile(join(dir, "l"), 100)).toThrowError(/symbolic link/);
    expect(readSmallFile(join(dir, "l"), 100, true)?.text).toBe("hello");
    expect(() => readSmallFile(join(dir, "f"), 2)).toThrowError(/too large/);
    expect(() => readSmallFile(join(dir, "d"), 100)).toThrowError(/not a regular file|cannot be read/);
    expect(() => readSmallFile(join(dir, "x".repeat(300)), 100)).toThrowError(EventWriteError);
    symlinkSync(join(dir, "loop2"), join(dir, "loop1"));
    symlinkSync(join(dir, "loop1"), join(dir, "loop2"));
    expect(() => readSmallFile(join(dir, "loop1"), 100)).toThrowError(/symbolic link/);
    expect(() => readSmallFile(join(dir, "loop1"), 100, true)).toThrowError(/symbolic link/);
  });
  it("writeFileAtomic replaces a file and cleans up after a failure", () => {
    const dir = tempDir();
    writeFileAtomic(join(dir, "a"), "one", 0o600);
    writeFileAtomic(join(dir, "a"), "two", 0o600);
    expect(readSmallFile(join(dir, "a"), 100)?.text).toBe("two");
    expect(() => writeFileAtomic(join(dir, "missing", "a"), "x", 0o600)).toThrowError(/cannot be written/);
    mkdirSync(join(dir, "target"));
    expect(() => writeFileAtomic(join(dir, "target"), "x", 0o600)).toThrowError(/cannot be written/);
  });
  it("safeLstat maps unexpected errors to an EventWriteError", () => {
    expect(safeLstat(join(tempDir(), "none"))).toBeNull();
    expect(() => safeLstat(join(tempDir(), "x".repeat(300)))).toThrowError(/cannot be inspected/);
  });
});

describe("runtime", () => {
  it("describes host, user and platform names", () => {
    const rt = systemRuntime();
    expect(rt.home).toMatch(/^\//);
    expect(rt.version).toBe((JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string }).version);
    expect(rt.pluginRoot.endsWith("guardrail-plugin/")).toBe(true);
    expect(metaOf({ ...rt, hostname: "h".repeat(300), username: "u", uid: undefined })).toMatchObject({ host: { os: "linux" }, user: { name: "u", id: "-1" } });
    expect(metaOf(rt).host.name.length).toBeLessThanOrEqual(255);
    expect(osName("darwin")).toBe("macos");
    expect(osName("win32")).toBe("windows");
    expect(osName("freebsd")).toBe("freebsd");
    expect(rt.uuid()).toMatch(/^[0-9a-f-]{36}$/);
    expect(rt.clock()).toBeInstanceOf(Date);
  });
  it("knows the managed-settings file per platform", () => {
    expect(managedSettingsPath("linux")).toBe("/etc/claude-code/managed-settings.json");
    expect(managedSettingsPath("darwin")).toBe("/Library/Application Support/ClaudeCode/managed-settings.json");
    expect(managedSettingsPath("win32")).toBe("C:\\Program Files\\ClaudeCode\\managed-settings.json");
  });
  it("hashes small regular files only", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "a"), "x");
    writeFileSync(join(dir, "big"), "xx");
    mkdirSync(join(dir, "d"));
    expect(fileHash(join(dir, "a"))).toMatch(/^[0-9a-f]{64}$/);
    expect(fileHash(join(dir, "big"), 1)).toBeNull();
    expect(fileHash(join(dir, "d"))).toBeNull();
    expect(fileHash(join(dir, "none"))).toBeNull();
  });
  it("bounds the number of hashed plugin files", () => {
    const root = tempDir();
    mkdirSync(join(root, "dist", "sub"), { recursive: true });
    for (let i = 0; i < 510; i += 1) writeFileSync(join(root, "dist", i % 2 === 0 ? "" : "sub", `f${i}.js`), String(i));
    writeFileSync(join(root, "dist", "huge.js"), Buffer.alloc(5 * 1024 * 1024));
    expect(pluginFilesHash(root)).toMatch(/^[0-9a-f]{64}$/);
    const empty = tempDir();
    mkdirSync(join(empty, "dist"));
    expect(pluginFilesHash(empty)).toBeNull();
  });
});

describe("observedTool", () => {
  const ctx = { projectDir: "/repo" };
  it("handles invalid and outside paths, URLs and tool classes", () => {
    expect(observedTool("Read", { file_path: "a".repeat(5000) }, ctx)).toMatchObject({ paths: ["<invalid>"], suppressible: false });
    expect(observedTool("Read", { file_path: "/etc/hostname" }, ctx)).toMatchObject({ paths: ["/etc/hostname"], suppressible: false });
    expect(observedTool("Read", { file_path: "src/a.ts" }, ctx)).toMatchObject({ paths: ["src/a.ts"], suppressible: true });
    expect(observedTool("Grep", {}, ctx)).toMatchObject({ paths: [], suppressible: true });
    expect(observedTool("Glob", { path: "/repo/src" }, { projectDir: "/repo", cwd: "/repo" })).toMatchObject({ paths: ["src"], suppressible: true });
    expect(observedTool("WebFetch", { url: "not a url" }, ctx)).toMatchObject({ domain: "<invalid>", effects: ["network"] });
    expect(observedTool("WebFetch", {}, ctx)).toMatchObject({ effects: ["network"] });
    expect(observedTool("WebSearch", { query: "q" }, ctx)).toMatchObject({ effects: ["network"], paths: [] });
    expect(observedTool("Task", {}, ctx).effects).toEqual(["exec"]);
    expect(observedTool("TodoWrite", {}, ctx).effects).toEqual([]);
    expect(observedTool("Unknown", { path: "/x" }, ctx)).toMatchObject({ effects: ["unknown"], suppressible: false });
  });
});

describe("layouts of other platforms", () => {
  it("windows and macOS locations", () => {
    const win = standaloneLayout({ LOCALAPPDATA: "C:\\Users\\a\\AppData\\Local" }, "win32", "C:\\Users\\a", 0);
    expect(win.eventsDir).toBe("C:\\Users\\a\\AppData\\Local\\TollGate\\events");
    expect(win.lockDir).toBe("C:\\Users\\a\\AppData\\Local\\TollGate");
    expect(standaloneLayout({}, "win32", "C:\\Users\\a", undefined).lockDir).toBe("C:\\Users\\a\\AppData\\Local\\TollGate");
    const mac = standaloneLayout({}, "darwin", "/Users/a", 501);
    expect(mac).toMatchObject({ eventsDir: "/Users/a/Library/Logs/TollGate", lockDir: "/Users/a/Library/Logs/TollGate", fileUid: 501 });
    expect(userConfigFile({ APPDATA: "C:\\Users\\a\\AppData\\Roaming" }, "win32", "C:\\Users\\a")).toBe("C:\\Users\\a\\AppData\\Roaming\\tollgate\\config.json");
    expect(userConfigFile({}, "win32", "C:\\Users\\a")).toBe("C:\\Users\\a\\AppData\\Roaming\\tollgate\\config.json");
    expect(userConfigFile({ XDG_CONFIG_HOME: "relative" }, "linux", "/home/a")).toBe("/home/a/.config/tollgate/config.json");
    expect(standaloneLayout({ XDG_STATE_HOME: "relative" }, "linux", "/home/a", 1).lockDir).toBe("/home/a/.local/state/tollgate");
  });
});

describe("process facts on other platforms", () => {
  it("return null for Linux-only facts", () => {
    setPlatform("darwin");
    expect(systemProcessFacts.bootId()).toBeNull();
    expect(systemProcessFacts.pidNamespace()).toBeNull();
    expect(systemProcessFacts.startTime(process.pid)).toBeNull();
  });
});

describe("sanitize edge", () => {
  it("does not cut text that is long as characters but short as logical characters", () => {
    const escaped = sanitize("\u001b\u001b");
    expect(escaped.length).toBeGreaterThan(5);
    expect(truncateText(escaped, 5)).toEqual({ text: escaped, cut: false });
  });
});

describe("analyzeCommand edge cases", () => {
  const ctx = { projectDir: "/repo", cwd: "/repo", home: "/home/u" };
  it("handles wrapper options", () => {
    expect(analyzeCommand("sudo -- ls", ctx).programs).toEqual(["ls"]);
    expect(analyzeCommand("sudo --user root ls", ctx).programs).toEqual(["ls"]);
    expect(analyzeCommand("sudo --preserve-env ls", ctx).programs).toEqual(["ls"]);
    expect(analyzeCommand("env -i FOO=1 make", ctx).programs).toEqual(["make"]);
    expect(analyzeCommand("nice -n 5 make", ctx).programs).toEqual(["make"]);
  });
  it("classifies git with global options and special subcommands", () => {
    expect(analyzeCommand("git -c a=b --no-pager log", ctx).effects).toEqual([]);
    expect(analyzeCommand("git worktree add x", ctx).effects).toEqual(["write"]);
    expect(analyzeCommand("git submodule update", ctx).effects).toEqual(["write", "network"]);
    expect(analyzeCommand("git --version", ctx).effects).toEqual(["unknown"]);
  });
  it("stops reading options at --", () => {
    expect(analyzeCommand("tail -- -f", ctx).suppressible).toBe(true); // '-f' after '--' is a file name, not an option
    expect(analyzeCommand("rg -- -z", ctx).suppressible).toBe(true);
    expect(analyzeCommand("rg -e x -- src", ctx).suppressible).toBe(true);
  });
  it("treats assignment-only and keyword-only lines", () => {
    expect(analyzeCommand("A=1 B=2", ctx)).toMatchObject({ programs: [], suppressible: false });
    expect(analyzeCommand("if true; then ls; fi", ctx).programs).toEqual(["true", "ls"]);
    expect(analyzeCommand("{ ls; }", ctx).programs).toEqual(["ls"]);
  });
});

describe("hook edge cases", () => {
  it("never blocks session events if the runtime is broken", () => {
    const root = tempDir();
    const rt = { ...runtimeFor(root), home: undefined as unknown as string };
    const r = runHook(JSON.stringify({ session_id: "s", hook_event_name: "SessionStart" }), envFor(root), root, { runtime: rt });
    expect(r.code).toBe(0);
  });
  it("never blocks observed tools if the runtime is broken", () => {
    const root = tempDir();
    const rt = { ...runtimeFor(root), home: undefined as unknown as string };
    const r = runHook(JSON.stringify({ session_id: "s", tool_name: "Read", tool_input: {} }), { ...envFor(root), CLAUDE_PROJECT_DIR: root }, root, { runtime: rt });
    // also with session taint in mode enforce: a call that is neither restricted nor a source never needs the state
    const project = join(root, "p");
    mkdirSync(join(project, ".tollgate"), { recursive: true });
    writeFileSync(join(project, ".tollgate", "policy.json"), JSON.stringify({ ...JSON.parse(readFileSync(BUNDLED_POLICY_PATH, "utf8")), taint: { mode: "enforce" } }));
    expect(runHook(JSON.stringify({ session_id: "s", tool_name: "Read", tool_input: {} }), { ...envFor(root), CLAUDE_PROJECT_DIR: project }, project, { runtime: rt }).code).toBe(0);
    expect(r.code).toBe(0);
  });
  it("uses the fixed enterprise location when none is injected", () => {
    const root = tempDir();
    const rt = runtimeFor(root, undefined, { uid: 4_294_967_000 });
    const admin = join(root, "etc", "tollgate");
    mkdirSync(admin, { recursive: true });
    chmodSync(join(root, "etc"), 0o755);
    chmodSync(admin, 0o755);
    const policyFile = join(admin, "policy.json");
    writeFileSync(policyFile, JSON.stringify({ version: 2, revision: "r", allowedDependencies: { npm: [], pypi: [] } }), { mode: 0o644 });
    chmodSync(policyFile, 0o644);
    const project = join(root, "project");
    mkdirSync(project);
    const r = runHook(JSON.stringify({ session_id: "s", tool_name: "Bash", tool_input: { command: "ls" } }), { ...envFor(root), CLAUDE_PROJECT_DIR: project, TOLLGATE_ENTERPRISE: "1" }, project, {
      runtime: rt,
      resolve: { ownerUid: process.getuid?.() ?? 0, stopAt: root, paths: { adminDir: admin, policyFile } },
    });
    expect(r.code).toBe(2);
    expect(r.message).toContain("event directory missing");
  });
  it("readStdin decodes UTF-8 strictly", async () => {
    const original = Object.getOwnPropertyDescriptor(process, "stdin");
    try {
      Object.defineProperty(process, "stdin", { value: Readable.from([Buffer.from("héllo ")]), configurable: true });
      expect(await readStdin()).toBe("héllo ");
      Object.defineProperty(process, "stdin", { value: Readable.from([Buffer.from([0xff, 0xfe])]), configurable: true });
      await expect(readStdin()).rejects.toThrow();
    } finally {
      if (original) Object.defineProperty(process, "stdin", original);
    }
  });
  it("runMain with the injected runtime returns the decision", async () => {
    const root = tempDir();
    const code = await runMain(async () => JSON.stringify({ session_id: "s", tool_name: "Bash", tool_input: { command: "ls" } }), { ...envFor(root), CLAUDE_PROJECT_DIR: root }, root, () => {}, { runtime: runtimeFor(root) });
    expect(code).toBe(0);
  });
});
