import { describe, expect, it } from "vitest";
import { copilotDecision, runCopilotMain, type AdapterOutput } from "../src/adapters/copilot.js";
import { BUNDLED_WITHOUT_TAINT, PROJECT } from "./helpers.js";

const env: NodeJS.ProcessEnv = {};
const deps = { resolve: { bundledPolicy: BUNDLED_WITHOUT_TAINT } };

function pascal(tool_name: string, tool_input: Record<string, unknown>): string {
  return JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s1", cwd: PROJECT, tool_name, tool_input });
}
function decide(stdin: string): AdapterOutput {
  return copilotDecision(stdin, env, PROJECT, deps);
}
function denyJson(out: AdapterOutput): { permissionDecision?: string; permissionDecisionReason?: string } {
  return JSON.parse(out.stdout.trim());
}

describe("copilot adapter: allow emits nothing (Copilot's own flow proceeds)", () => {
  it("allows a safe Bash command (exit 0, empty stdout)", () => {
    expect(decide(pascal("Bash", { command: "ls" }))).toEqual({ code: 0, stdout: "", stderr: "" });
  });
  it("allows a write to a normal project file (exit 0, empty stdout)", () => {
    expect(decide(pascal("Write", { file_path: `${PROJECT}/src/new.ts`, content: "export const x = 1;" }))).toEqual({ code: 0, stdout: "", stderr: "" });
  });
  it("passes a read tool through as allow", () => {
    expect(decide(pascal("Read", { file_path: `${PROJECT}/src/x.ts` })).code).toBe(0);
  });
});

describe("copilot adapter: deny (exit 2 + exactly one stdout JSON object)", () => {
  it("denies a force push with a reason", () => {
    const out = decide(pascal("Bash", { command: "git push --force" }));
    expect(out.code).toBe(2);
    const d = denyJson(out);
    expect(d.permissionDecision).toBe("deny");
    expect(d.permissionDecisionReason).toContain("Force push");
  });
  it("denies a write to a protected path", () => {
    const out = decide(pascal("Write", { file_path: `${PROJECT}/AGENTS.md`, content: "x" }));
    expect(out.code).toBe(2);
    expect(denyJson(out).permissionDecision).toBe("deny");
  });
  it("writes exactly one JSON object on stdout and nothing on stderr", () => {
    const out = decide(pascal("Bash", { command: "git push --force" }));
    expect(() => JSON.parse(out.stdout.trim())).not.toThrow();
    expect(out.stdout.trim().endsWith("}")).toBe(true);
    expect(out.stderr).toBe("");
  });
});

describe("copilot adapter: raw write-tool names fail closed (F6)", () => {
  it.each(["edit", "create", "write", "str_replace_editor", "apply_patch"])("denies a raw write tool name %s", (name) => {
    expect(decide(pascal(name, { file_path: `${PROJECT}/src/x.ts` })).code).toBe(2);
  });
  it("still allows the Claude write-tool name Write", () => {
    expect(decide(pascal("Write", { file_path: `${PROJECT}/src/x.ts`, content: "" })).code).toBe(0);
  });
});

describe("copilot adapter: camelCase fallback (shell only)", () => {
  it("maps toolName=bash + toolArgs string and denies a force push", () => {
    const stdin = JSON.stringify({ toolName: "bash", toolArgs: JSON.stringify({ command: "git push --force" }), cwd: PROJECT, sessionId: "s1" });
    expect(copilotDecision(stdin, env, PROJECT, deps).code).toBe(2);
  });
  it("allows a safe shell command via the camelCase form", () => {
    const stdin = JSON.stringify({ toolName: "bash", toolArgs: JSON.stringify({ command: "ls" }), cwd: PROJECT });
    expect(copilotDecision(stdin, env, PROJECT, deps).code).toBe(0);
  });
});

describe("copilot adapter: fail closed", () => {
  it("denies invalid JSON", () => {
    const out = decide("not json");
    expect(out.code).toBe(2);
    expect(denyJson(out).permissionDecision).toBe("deny");
  });
  it("denies an unmappable camelCase tool (unknown runtime name)", () => {
    expect(copilotDecision(JSON.stringify({ toolName: "frobnicate", toolArgs: "{}", cwd: PROJECT }), env, PROJECT, deps).code).toBe(2);
  });
  it("denies structurally empty input", () => {
    expect(decide("{}").code).toBe(2);
    expect(decide("[]").code).toBe(2);
    expect(decide("null").code).toBe(2);
  });
  it("runCopilotMain fails closed (exit 2) when stdin cannot be read", async () => {
    const chunks: string[] = [];
    const code = await runCopilotMain(() => Promise.reject(new Error("broken stdin")), env, PROJECT, (t) => chunks.push(t), deps);
    expect(code).toBe(2);
    expect(JSON.parse(chunks.join("").trim()).permissionDecision).toBe("deny");
  });
  it("runCopilotMain writes nothing and returns 0 for a safe call (allow)", async () => {
    const chunks: string[] = [];
    const code = await runCopilotMain(() => Promise.resolve(pascal("Bash", { command: "ls" })), env, PROJECT, (t) => chunks.push(t), deps);
    expect(code).toBe(0);
    expect(chunks.join("")).toBe("");
  });
});
