import { describe, expect, it } from "vitest";
import { cursorDecision, runCursorMain, type AdapterOutput } from "../src/adapters/cursor.js";
import { BUNDLED_WITHOUT_TAINT, PROJECT } from "./helpers.js";

const env: NodeJS.ProcessEnv = {};
const deps = { resolve: { bundledPolicy: BUNDLED_WITHOUT_TAINT } };

function stdin(tool_name: string, tool_input: Record<string, unknown>): string {
  return JSON.stringify({ hook_event_name: "preToolUse", conversation_id: "c1", tool_use_id: "t1", cwd: PROJECT, tool_name, tool_input });
}
function decide(s: string): AdapterOutput {
  return cursorDecision(s, env, PROJECT, deps);
}
function perm(out: AdapterOutput): { permission?: string; agent_message?: string } {
  return JSON.parse(out.stdout.trim());
}

describe("cursor adapter: allow (exit 0, explicit permission allow)", () => {
  it("allows a safe shell command (Shell)", () => {
    const out = decide(stdin("Shell", { command: "ls" }));
    expect(out.code).toBe(0);
    expect(perm(out).permission).toBe("allow");
  });
  it("allows a write to a normal project file", () => {
    expect(perm(decide(stdin("Write", { file_path: `${PROJECT}/src/new.ts`, content: "x" }))).permission).toBe("allow");
  });
  it("defers an unknown (unchecked) tool to Cursor with permission:ask, not auto-approve (F5)", () => {
    const out = decide(stdin("Task", { prompt: "x" }));
    expect(out.code).toBe(0);
    expect(perm(out).permission).toBe("ask");
  });
});

describe("cursor adapter: deny (exit 2 + one permission:deny object)", () => {
  it("denies a force push", () => {
    const out = decide(stdin("Shell", { command: "git push --force" }));
    expect(out.code).toBe(2);
    expect(perm(out).permission).toBe("deny");
    expect(perm(out).agent_message).toContain("Force push");
  });
  it("denies a write to a protected path", () => {
    expect(perm(decide(stdin("Write", { file_path: `${PROJECT}/AGENTS.md`, content: "x" }))).permission).toBe("deny");
  });
  it("denies a Delete of a protected path (checked as a write to its target)", () => {
    expect(decide(stdin("Delete", { file_path: `${PROJECT}/AGENTS.md` })).code).toBe(2);
  });
  it("denies a write whose path cannot be resolved (fail closed)", () => {
    expect(decide(stdin("Write", { blob: "x" })).code).toBe(2);
  });
  it("denies a write to a dependency manifest — requirements.txt (F1)", () => {
    expect(decide(stdin("Write", { file_path: `${PROJECT}/requirements.txt`, content: "evil==1.0" })).code).toBe(2);
  });
  it("denies a write naming more than one path (F3)", () => {
    expect(decide(stdin("Write", { file_path: `${PROJECT}/ok.ts`, target_file: `${PROJECT}/AGENTS.md`, content: "x" })).code).toBe(2);
  });
  it("denies an unmapped write-class tool name (F2)", () => {
    expect(decide(stdin("ApplyPatch", { file_path: `${PROJECT}/AGENTS.md` })).code).toBe(2);
  });
  it("writes exactly one JSON object on stdout", () => {
    const out = decide(stdin("Shell", { command: "git push --force" }));
    expect(() => JSON.parse(out.stdout.trim())).not.toThrow();
    expect(out.stdout.trim().endsWith("}")).toBe(true);
    expect(out.stderr).toBe("");
  });
});

describe("cursor adapter: fail closed", () => {
  it("denies invalid JSON", () => {
    expect(decide("not json").code).toBe(2);
  });
  it("denies input with no tool name", () => {
    expect(cursorDecision(JSON.stringify({ cwd: PROJECT }), env, PROJECT, deps).code).toBe(2);
  });
  it("runCursorMain fails closed (exit 2) when stdin cannot be read", async () => {
    const out: string[] = [];
    const code = await runCursorMain(() => Promise.reject(new Error("broken")), env, PROJECT, (t) => out.push(t), deps);
    expect(code).toBe(2);
    expect(JSON.parse(out.join("").trim()).permission).toBe("deny");
  });
  it("runCursorMain writes an explicit allow and returns 0 for a safe call", async () => {
    const out: string[] = [];
    const code = await runCursorMain(() => Promise.resolve(stdin("Shell", { command: "ls" })), env, PROJECT, (t) => out.push(t), deps);
    expect(code).toBe(0);
    expect(JSON.parse(out.join("").trim()).permission).toBe("allow");
  });
});
