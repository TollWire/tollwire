import { describe, expect, it } from "vitest";
import { BLOCK_EXIT_CODE, runHook, runMain, type HookDeps } from "../src/hook.js";
import { BUNDLED_WITHOUT_TAINT } from "./helpers.js";

const env = { CLAUDE_PROJECT_DIR: "/repo" };
// Pinned default policy without session taint: a human session in a tainted session loses its exception.
const PINNED: HookDeps = { resolve: { bundledPolicy: BUNDLED_WITHOUT_TAINT } };

describe("runHook", () => {
  it("allows a safe command", () => {
    expect(runHook(JSON.stringify({ tool_name: "Bash", tool_input: { command: "ls" } }), env, "/")).toEqual({ code: 0 });
  });
  it("blocks with exit code 2 and a message", () => {
    const r = runHook(JSON.stringify({ tool_name: "Bash", tool_input: { command: "git push --force" } }), env, "/");
    expect(r.code).toBe(BLOCK_EXIT_CODE);
    expect(r.message).toContain("Force push");
  });
  it("fails closed on invalid input or policy", () => {
    expect(runHook("not json", env, "/").code).toBe(BLOCK_EXIT_CODE);
    const ok = JSON.stringify({ tool_name: "Bash", tool_input: { command: "ls" } });
    expect(runHook(ok, { ...env, TOLLGATE_POLICY: "/does/not/exist.json" }, "/").code).toBe(BLOCK_EXIT_CODE);
  });
  it.each(["{}", "[]", "null", '"text"', '{"tool_name":""}', '{"tool_name":"Bash","tool_input":[]}'])(
    "fails closed on structurally invalid input %s",
    (input) => expect(runHook(input, env, "/").code).toBe(BLOCK_EXIT_CODE),
  );
  it("fails closed on MultiEdit with malformed edits", () => {
    const event = { tool_name: "MultiEdit", tool_input: { file_path: "/repo/package.json", edits: [null] } };
    expect(runHook(JSON.stringify(event), env, "/").code).toBe(BLOCK_EXIT_CODE);
  });
  it("fails closed on Bash without command", () => {
    expect(runHook(JSON.stringify({ tool_name: "Bash", tool_input: {} }), env, "/").code).toBe(BLOCK_EXIT_CODE);
  });
  it("honors the human session flag only when set to 1", () => {
    const event = JSON.stringify({ tool_name: "Edit", tool_input: { file_path: "/repo/AGENTS.md" } });
    expect(runHook(event, env, "/", PINNED).code).toBe(BLOCK_EXIT_CODE);
    expect(runHook(event, { ...env, TOLLGATE_HUMAN_SESSION: "true" }, "/", PINNED).code).toBe(BLOCK_EXIT_CODE);
    expect(runHook(event, { ...env, TOLLGATE_HUMAN_SESSION: "1" }, "/", PINNED).code).toBe(0);
  });
  it("uses cwd when CLAUDE_PROJECT_DIR is unset", () => {
    const event = JSON.stringify({ tool_name: "Write", tool_input: { file_path: "/work/.github/x.yml", content: "" } });
    expect(runHook(event, {}, "/work").code).toBe(BLOCK_EXIT_CODE);
  });
  it("runMain returns the hook decision and writes the message", async () => {
    const errors: string[] = [];
    const input = JSON.stringify({ tool_name: "Bash", tool_input: { command: "git push --force" } });
    expect(await runMain(async () => input, env, "/", (t) => errors.push(t))).toBe(BLOCK_EXIT_CODE);
    expect(errors.join("")).toContain("Force push");
    expect(await runMain(async () => JSON.stringify({ tool_name: "Bash", tool_input: { command: "ls" } }), env, "/", () => {})).toBe(0);
  });
  it("runMain fails closed when stdin cannot be read or stderr fails", async () => {
    const errors: string[] = [];
    const failing = async (): Promise<string> => {
      throw new Error("EIO");
    };
    expect(await runMain(failing, env, "/", (t) => errors.push(t))).toBe(BLOCK_EXIT_CODE);
    expect(errors.join("")).toContain("fail closed");
    const brokenStderr = (): void => {
      throw new Error("EPIPE");
    };
    expect(await runMain(async () => "not json", env, "/", brokenStderr)).toBe(BLOCK_EXIT_CODE);
  });
});
