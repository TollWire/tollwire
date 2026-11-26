import { describe, expect, it } from "vitest";
import { grokDecision, runGrokMain, type AdapterOutput } from "../src/adapters/grok.js";
import { BUNDLED_WITHOUT_TAINT, PROJECT } from "./helpers.js";

const env: NodeJS.ProcessEnv = {};
const deps = { resolve: { bundledPolicy: BUNDLED_WITHOUT_TAINT } };

function stdin(toolName: string, toolInput: Record<string, unknown>): string {
  return JSON.stringify({ hook_event_name: "PreToolUse", sessionId: "s1", cwd: PROJECT, toolName, toolInput });
}
function decide(s: string): AdapterOutput {
  return grokDecision(s, env, PROJECT, deps);
}
function denyJson(out: AdapterOutput): { decision?: string; reason?: string } {
  return JSON.parse(out.stdout.trim());
}

describe("grok adapter: allow (exit 0, no stdout)", () => {
  it("allows a safe shell command (run_terminal_command)", () => {
    expect(decide(stdin("run_terminal_command", { command: "ls" }))).toEqual({ code: 0, stdout: "", stderr: "" });
  });
  it("allows a read of a normal file", () => {
    expect(decide(stdin("read_file", { file_path: `${PROJECT}/src/x.ts` })).code).toBe(0);
  });
  it("passes an unknown tool through as allow", () => {
    expect(decide(stdin("web_search", { query: "x" })).code).toBe(0);
  });
});

describe("grok adapter: deny (decision deny + exit 2)", () => {
  it("denies a force push via the shell", () => {
    const out = decide(stdin("run_terminal_command", { command: "git push --force" }));
    expect(out.code).toBe(2);
    expect(denyJson(out).decision).toBe("deny");
    expect(denyJson(out).reason).toContain("Force push");
    expect(out.stderr).not.toBe("");
  });
  it("denies an edit (search_replace) of a protected path", () => {
    expect(decide(stdin("search_replace", { file_path: `${PROJECT}/AGENTS.md` })).code).toBe(2);
  });
  it("denies an edit to a dependency manifest — package.json AND requirements.txt (F1)", () => {
    expect(decide(stdin("search_replace", { file_path: `${PROJECT}/package.json` })).code).toBe(2);
    expect(decide(stdin("search_replace", { file_path: `${PROJECT}/requirements.txt` })).code).toBe(2);
    expect(decide(stdin("write", { file_path: `${PROJECT}/requirements-dev.txt` })).code).toBe(2);
  });
  it("denies a write whose path cannot be resolved (fail closed)", () => {
    expect(decide(stdin("search_replace", { instructions: "do stuff" })).code).toBe(2);
  });
  it("denies a write naming more than one path (F3)", () => {
    expect(decide(stdin("search_replace", { file_path: `${PROJECT}/ok.ts`, target_file: `${PROJECT}/AGENTS.md` })).code).toBe(2);
  });
  it("denies an unmapped write-class tool name (F2)", () => {
    expect(decide(stdin("edit_file", { file_path: `${PROJECT}/AGENTS.md` })).code).toBe(2);
    expect(decide(stdin("delete_file", { path: `${PROJECT}/x.ts` })).code).toBe(2);
  });
});

describe("grok adapter: Claude-name compatibility + fail closed", () => {
  it("also accepts Claude tool names (shared .claude settings): Bash", () => {
    expect(decide(stdin("Bash", { command: "git push --force" })).code).toBe(2);
  });
  it("denies invalid JSON", () => {
    expect(decide("not json").code).toBe(2);
  });
  it("denies input with no tool name", () => {
    expect(grokDecision(JSON.stringify({ cwd: PROJECT }), env, PROJECT, deps).code).toBe(2);
  });
  it("runGrokMain fails closed (explicit deny, exit 2) when stdin cannot be read", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const code = await runGrokMain(() => Promise.reject(new Error("broken")), env, PROJECT, (t) => out.push(t), (t) => err.push(t), deps);
    expect(code).toBe(2);
    expect(JSON.parse(out.join("").trim()).decision).toBe("deny");
  });
});
