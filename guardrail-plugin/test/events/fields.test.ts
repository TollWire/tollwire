import { describe, expect, it } from "vitest";
import { validateInput, validPath } from "../../src/events/fields.js";

describe("validateInput", () => {
  it("accepts well-formed fields", () => {
    const v = validateInput(
      { session_id: "s-1.a:b_c", tool_use_id: "toolu_01", agent_id: "a1", agent_type: "Explore", hook_event_name: "PreToolUse", permission_mode: "acceptEdits" },
      "Bash",
    );
    expect(v.invalid).toEqual([]);
    expect(v.toolName).toBe("Bash");
    expect(v.claude).toEqual({
      session_id: "s-1.a:b_c",
      tool_use_id: "toolu_01",
      agent_id: "a1",
      agent_type: "Explore",
      hook_event: "PreToolUse",
      permission_mode: "acceptEdits",
    });
  });
  it("uses null for absent optional fields and assumes PreToolUse", () => {
    const v = validateInput({ session_id: "s" }, "Edit");
    expect(v.claude).toMatchObject({ tool_use_id: null, agent_id: null, agent_type: null, permission_mode: null, hook_event: "PreToolUse" });
    expect(v.invalid).toEqual([]);
  });
  it("replaces invalid values by <invalid> and lists them", () => {
    const v = validateInput(
      { session_id: "bad id\n", tool_use_id: "x".repeat(129), agent_id: "a".repeat(129), agent_type: 5, hook_event_name: "Pre Tool", permission_mode: "a b" },
      "Bash;rm",
    );
    expect(v.toolName).toBe("<invalid>");
    expect(v.claude.session_id).toBe("<invalid>");
    expect(v.claude.tool_use_id).toBe("<invalid>");
    expect(v.claude.agent_id).toBe("<invalid>");
    expect(v.claude.agent_type).toBe("<invalid>");
    expect(v.claude.hook_event).toBe("<invalid>");
    expect(v.claude.permission_mode).toBe("<invalid>");
    expect(v.invalid).toEqual(["session_id", "tool_name", "hook_event_name", "tool_use_id", "agent_id", "agent_type", "permission_mode"]);
  });
  it("treats a missing session id and tool name as invalid", () => {
    const v = validateInput({}, undefined);
    expect(v.invalid).toEqual(["session_id", "tool_name"]);
  });
  it("limits the tool name to 256 characters", () => {
    expect(validateInput({ session_id: "s" }, "t".repeat(256)).toolName).toHaveLength(256);
    expect(validateInput({ session_id: "s" }, "t".repeat(257)).toolName).toBe("<invalid>");
  });
});

describe("validPath", () => {
  it("allows at most 4096 bytes", () => {
    expect(validPath("a".repeat(4096))).not.toBeNull();
    expect(validPath("a".repeat(4097))).toBeNull();
    expect(validPath("é".repeat(2049))).toBeNull(); // 4098 bytes
  });
});
