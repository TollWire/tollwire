// Write-class detection of unknown tool names, shared by every adapter.
// An unknown runtime tool whose name looks like it modifies files must be denied (fail closed), never passed to the
// engine as an unchecked tool (which a standalone install allows).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as translate from "../src/adapters/translate.js";
import { codexDecision } from "../src/adapters/codex.js";
import { copilotDecision } from "../src/adapters/copilot.js";
import { cursorDecision } from "../src/adapters/cursor.js";
import { grokDecision } from "../src/adapters/grok.js";
import { BUNDLED_WITHOUT_TAINT, PROJECT } from "./helpers.js";

const env: NodeJS.ProcessEnv = {};
const deps = { resolve: { bundledPolicy: BUNDLED_WITHOUT_TAINT } };
const TARGET = `${PROJECT}/.github/ci.yml`;
const input = { file_path: TARGET, path: TARGET, content: "x" };

function isWrite(name: string): boolean {
  const fn = (translate as Record<string, unknown>).isWriteClassToolName;
  expect(typeof fn, "translate.ts exports isWriteClassToolName").toBe("function");
  return (fn as (n: string) => boolean)(name);
}
const grok = (name: string) => grokDecision(JSON.stringify({ toolName: name, toolInput: input, cwd: PROJECT, sessionId: "s1" }), env, PROJECT, deps);
const cursor = (name: string) => cursorDecision(JSON.stringify({ tool_name: name, tool_input: input, cwd: PROJECT, conversation_id: "c1" }), env, PROJECT, deps);
const copilot = (name: string) => copilotDecision(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: name, tool_input: input, cwd: PROJECT, session_id: "s1" }), env, PROJECT, deps);
const codex = (name: string, toolInput: Record<string, unknown> = input) =>
  codexDecision(JSON.stringify({ hook_event_name: "PreToolUse", tool_name: name, tool_input: toolInput, cwd: PROJECT, session_id: "s1" }), env, PROJECT, deps);

const WRITE_NAMES = [
  "save_file", "fs_put", "store", "put_file", "insert", "str_replace_based_edit_tool", "applypatch", "delete", "remove", "WRITE",
  "writeFile", "write-file", "createDirectory", "rename_path", "move_file", "mv", "cp", "copy_file", "append_to_file", "overwrite",
  "truncate", "upload", "dump_buffer", "export_notes", "sync_dir", "output_file", "apply_diff", "modify_file", "update_file", "set_content",
  "mkdir", "rm", "touch", "chmod", "chown", "link", "unlink", "symlink", "MultiEdit", "NotebookEdit", "MCP:write_file",
];
const READ_NAMES = [
  "read", "read_file", "readFile", "view", "grep", "glob", "search", "codebase_search", "list", "list_dir", "ls", "find", "find_files",
  "fetch", "web_fetch", "get", "get_file", "cat", "stat", "file_status", "Task", "settings", "setup",
];

describe("isWriteClassToolName (word-boundary heuristic)", () => {
  it.each(WRITE_NAMES)("treats %s as write-class", (name) => {
    expect(isWrite(name)).toBe(true);
  });
  it.each(READ_NAMES)("does not treat the read-only name %s as write-class", (name) => {
    expect(isWrite(name)).toBe(false);
  });
});

describe("reproduced write-class names on a protected target are denied", () => {
  it.each(["save_file", "fs_put", "store", "put_file"])("grok %s -> deny", (name) => {
    const out = grok(name);
    expect(out.code).toBe(2);
    expect(JSON.parse(out.stdout).decision).toBe("deny");
  });
  it.each(["insert", "str_replace_based_edit_tool", "applypatch", "delete"])("copilot %s -> deny", (name) => {
    const out = copilot(name);
    expect(out.code).toBe(2);
    expect(JSON.parse(out.stdout).permissionDecision).toBe("deny");
  });
  it.each(["WRITE", "write", "wRiTe", "save_file", "fs_put", "applypatch"])("codex %s -> deny", (name) => {
    const out = codex(name);
    expect(out.code).toBe(2);
    expect(JSON.parse(out.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
  });
  it.each(["save_file", "fs_put", "store"])("cursor %s -> deny (not ask)", (name) => {
    const out = cursor(name);
    expect(out.code).toBe(2);
    expect(JSON.parse(out.stdout).permission).toBe("deny");
  });
});

describe("Copilot raw delete/remove/insert are denied", () => {
  it.each(["delete", "remove", "insert"])("copilot %s on a normal project file -> deny", (name) => {
    const out = copilotDecision(JSON.stringify({ tool_name: name, tool_input: { path: `${PROJECT}/src/x.ts` }, cwd: PROJECT }), env, PROJECT, deps);
    expect(out.code).toBe(2);
  });
});

describe("Codex: case-insensitive normalization to Claude names", () => {
  it("checks WRITE/write as Write: a normal project file is still allowed", () => {
    expect(codex("WRITE", { file_path: `${PROJECT}/src/x.ts`, content: "" }).code).toBe(0);
    expect(codex("write", { file_path: `${PROJECT}/src/x.ts`, content: "" }).code).toBe(0);
  });
  it("checks bash/BASH as Bash: a force push is denied, ls is allowed", () => {
    expect(codex("bash", { command: "git push --force" }).code).toBe(2);
    expect(codex("BASH", { command: "git push --force" }).code).toBe(2);
    expect(codex("bash", { command: "ls" }).code).toBe(0);
  });
  it("still passes Claude-native coordination tools and MCP tools through", () => {
    for (const name of ["TodoWrite", "TaskUpdate", "TaskCreate", "update_plan", "mcp__filesystem__read_file"]) {
      expect(codex(name, {}).code, name).toBe(0);
    }
  });
});

describe("read tools are unaffected", () => {
  it.each(["view", "read_file", "grep", "list_dir"])("grok/cursor/copilot do not deny %s on a normal file", (name) => {
    const file = `${PROJECT}/src/x.ts`;
    const i = { file_path: file, path: file };
    expect(grokDecision(JSON.stringify({ toolName: name, toolInput: i, cwd: PROJECT }), env, PROJECT, deps).code, `grok ${name}`).toBe(0);
    expect(cursorDecision(JSON.stringify({ tool_name: name, tool_input: i, cwd: PROJECT }), env, PROJECT, deps).code, `cursor ${name}`).toBe(0);
    expect(copilotDecision(JSON.stringify({ tool_name: name, tool_input: i, cwd: PROJECT }), env, PROJECT, deps).code, `copilot ${name}`).toBe(0);
  });
});

describe("one shared source for write-class detection", () => {
  const src = (f: string) => readFileSync(new URL(`../src/adapters/${f}`, import.meta.url), "utf8");
  it.each(["grok.ts", "cursor.ts", "copilot.ts", "codex.ts"])("%s keeps no private write-name list", (f) => {
    const text = src(f);
    expect(text).not.toMatch(/RAW_WRITE_TOOLS|WRITE_ISH/);
  });
  it.each(["copilot.ts", "codex.ts"])("%s uses the shared name check from translate.ts", (f) => {
    expect(src(f)).toMatch(/from "\.\/translate\.js"/);
    expect(src(f)).toMatch(/claudeToolName|isWriteClassToolName/);
  });
  it("grok, cursor and copilot agree with isWriteClassToolName on every unmapped name", () => {
    for (const name of [...WRITE_NAMES, ...READ_NAMES].filter((n) => !["MultiEdit", "NotebookEdit", "read", "grep", "glob", "ls", "list_dir", "read_file", "Task"].includes(n))) {
      const expected = isWrite(name);
      const file = `${PROJECT}/src/x.ts`;
      const i = { file_path: file, path: file };
      const g = grokDecision(JSON.stringify({ toolName: name, toolInput: i, cwd: PROJECT }), env, PROJECT, deps).code !== 0;
      const c = cursorDecision(JSON.stringify({ tool_name: name, tool_input: i, cwd: PROJECT }), env, PROJECT, deps).code !== 0;
      const p = copilotDecision(JSON.stringify({ tool_name: name, tool_input: i, cwd: PROJECT }), env, PROJECT, deps).code !== 0;
      expect([g, c, p], name).toEqual([expected, expected, expected]);
    }
  });
});
