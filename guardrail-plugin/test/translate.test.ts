import { describe, expect, it } from "vitest";
import { buildEvent, firstPath, lookup } from "../src/adapters/translate.js";

describe("firstPath", () => {
  it("finds a path across the known field-name variants", () => {
    expect(firstPath({ file_path: "a.ts" })).toBe("a.ts");
    expect(firstPath({ filePath: "b.ts" })).toBe("b.ts");
    expect(firstPath({ path: "c.ts" })).toBe("c.ts");
    expect(firstPath({ target_file: "d.ts" })).toBe("d.ts");
    expect(firstPath({ directory: "e/" })).toBe("e/");
    expect(firstPath({ nothing: "x" })).toBeUndefined();
  });
});

describe("lookup (safe own-property map lookup)", () => {
  const map = { Shell: "Bash" };
  it("returns a mapped value and undefined for an unmapped name", () => {
    expect(lookup(map, "Shell")).toBe("Bash");
    expect(lookup(map, "nope")).toBeUndefined();
  });
  it("does not resolve inherited object members", () => {
    expect(lookup(map, "constructor")).toBeUndefined();
    expect(lookup(map, "__proto__")).toBeUndefined();
    expect(lookup(map, "toString")).toBeUndefined();
  });
});

describe("buildEvent", () => {
  it("builds a Bash event from a command (enforced)", () => {
    expect(buildEvent("Bash", "Shell", { command: "ls" }, "/repo", "s1")).toEqual({
      kind: "event", enforced: true, event: { hook_event_name: "PreToolUse", cwd: "/repo", session_id: "s1", tool_name: "Bash", tool_input: { command: "ls" } },
    });
  });
  it("denies a shell call without a command, or with conflicting command fields", () => {
    expect(buildEvent("Bash", "Shell", {}, "/repo", undefined).kind).toBe("deny");
    expect(buildEvent("Bash", "Shell", { command: "ls", cmd: "rm -rf /" }, "/repo", undefined).kind).toBe("deny");
  });
  it("builds a Write event from a resolvable path (content empty, enforced)", () => {
    const m = buildEvent("Edit", "search_replace", { file_path: "/repo/x.ts" }, "/repo", undefined);
    expect(m).toEqual({ kind: "event", enforced: true, event: { hook_event_name: "PreToolUse", cwd: "/repo", tool_name: "Write", tool_input: { file_path: "/repo/x.ts", content: "" } } });
  });
  it("denies a write whose path cannot be resolved, or that names more than one path", () => {
    expect(buildEvent("Write", "Write", { nope: "x" }, "/repo", undefined).kind).toBe("deny");
    expect(buildEvent("Write", "Write", { file_path: "/repo/a.ts", target_file: "/repo/b.ts" }, "/repo", undefined).kind).toBe("deny");
  });
  it("denies a write to a dependency manifest (F1: content unverifiable)", () => {
    expect(buildEvent("Write", "search_replace", { file_path: "/repo/requirements.txt" }, "/repo", undefined).kind).toBe("deny");
    expect(buildEvent("Write", "Write", { file_path: "/repo/requirements-dev.txt" }, "/repo", undefined).kind).toBe("deny");
    expect(buildEvent("Write", "Write", { file_path: "/repo/package.json" }, "/repo", undefined).kind).toBe("deny");
    expect(buildEvent("Write", "Write", { file_path: "/repo/pnpm-lock.yaml" }, "/repo", undefined).kind).toBe("deny");
  });
  it("builds a read event (enforced); passes a pathless read's raw input to the engine", () => {
    expect(buildEvent("Read", "read_file", { file_path: "/repo/x.ts" }, "/repo", undefined)).toMatchObject({ kind: "event", enforced: true });
    const pathless = buildEvent("Grep", "grep", { query: "x" }, "/repo", undefined);
    expect(pathless).toMatchObject({ kind: "event", enforced: true });
  });
  it("denies an unmapped write-class tool name (F2)", () => {
    for (const name of ["edit_file", "write_file", "apply_patch", "delete_file", "create_file"]) {
      expect(buildEvent(undefined, name, { file_path: "/repo/x" }, "/repo", undefined).kind, name).toBe("deny");
    }
  });
  it("passes an unknown non-write tool through to the engine (unchecked, not enforced)", () => {
    const m = buildEvent(undefined, "web_search", { query: "x" }, "/repo", undefined);
    expect(m).toMatchObject({ kind: "event", enforced: false, event: { tool_name: "web_search" } });
  });
});
