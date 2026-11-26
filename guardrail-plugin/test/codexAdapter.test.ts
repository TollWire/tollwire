import { describe, expect, it } from "vitest";
import { applyPatchTargets, codexDecision, runCodexMain, type AdapterOutput } from "../src/adapters/codex.js";
import { BUNDLED_WITHOUT_TAINT, PROJECT } from "./helpers.js";

const env: NodeJS.ProcessEnv = {};
const deps = { resolve: { bundledPolicy: BUNDLED_WITHOUT_TAINT } };

function stdin(tool_name: string, tool_input: Record<string, unknown>): string {
  return JSON.stringify({ hook_event_name: "PreToolUse", session_id: "s1", cwd: PROJECT, tool_name, tool_input });
}
function decide(s: string): AdapterOutput {
  return codexDecision(s, env, PROJECT, deps);
}
function patch(...lines: string[]): string {
  return ["*** Begin Patch", ...lines, "*** End Patch"].join("\n");
}
function denyEnvelope(out: AdapterOutput): { hookEventName?: string; permissionDecision?: string; permissionDecisionReason?: string } {
  return JSON.parse(out.stdout.trim()).hookSpecificOutput;
}

describe("applyPatchTargets (fail-closed parser)", () => {
  it("extracts Add/Update/Delete/Move target paths; not malformed", () => {
    const s = applyPatchTargets(patch("*** Add File: src/a.ts", "+x", "*** Update File: src/b.ts", "*** Move to: src/c.ts", "*** Delete File: src/d.ts"));
    expect(s.paths).toEqual(["src/a.ts", "src/b.ts", "src/c.ts", "src/d.ts"]);
    expect(s.malformed).toBe(false);
  });
  it("handles CRLF line endings", () => {
    const s = applyPatchTargets(["*** Begin Patch", "*** Add File: src/a.ts", "+x", "*** End Patch"].join("\r\n"));
    expect(s.paths).toEqual(["src/a.ts"]);
    expect(s.malformed).toBe(false);
  });
  it("flags an unrecognized column-0 *** directive as malformed", () => {
    expect(applyPatchTargets(patch("*** Add File: ok.ts", "*** Rename File: AGENTS.md")).malformed).toBe(true);
  });
  it("does not flag content lines that merely contain *** or File:", () => {
    const s = applyPatchTargets(patch("*** Add File: readme.md", "+some ***bold*** text", "+const file: string = x"));
    expect(s.paths).toEqual(["readme.md"]);
    expect(s.malformed).toBe(false);
  });
  it("flags an empty header path as malformed", () => {
    expect(applyPatchTargets(patch("*** Add File: ")).malformed).toBe(true);
  });
});

describe("codex adapter: Bash passthrough", () => {
  it("allows a safe command (exit 0, no stdout)", () => {
    expect(decide(stdin("Bash", { command: "ls" }))).toEqual({ code: 0, stdout: "", stderr: "" });
  });
  it("denies a force push (exit 2 + hookSpecificOutput deny + stderr)", () => {
    const out = decide(stdin("Bash", { command: "git push --force" }));
    expect(out.code).toBe(2);
    const d = denyEnvelope(out);
    expect(d.hookEventName).toBe("PreToolUse");
    expect(d.permissionDecision).toBe("deny");
    expect(d.permissionDecisionReason).toContain("Force push");
    expect(out.stderr).not.toBe("");
  });
});

describe("codex adapter: apply_patch evaluated as writes (no fail-open)", () => {
  it("denies a patch that touches a protected path", () => {
    expect(decide(stdin("apply_patch", { command: patch(`*** Update File: ${PROJECT}/AGENTS.md`, "+x") })).code).toBe(2);
  });
  it("denies a Delete of a protected path", () => {
    expect(decide(stdin("apply_patch", { command: patch(`*** Delete File: ${PROJECT}/AGENTS.md`) })).code).toBe(2);
  });
  it("denies a patch that writes outside the project", () => {
    expect(decide(stdin("apply_patch", { command: patch("*** Add File: /etc/evil.conf", "+x") })).code).toBe(2);
  });
  it("denies a patch to a dependency manifest (content unverifiable)", () => {
    expect(decide(stdin("apply_patch", { command: patch(`*** Update File: ${PROJECT}/package.json`, "+x") })).code).toBe(2);
  });
  it("denies a mixed patch where one of several targets is protected", () => {
    expect(decide(stdin("apply_patch", { command: patch(`*** Add File: ${PROJECT}/src/new.ts`, "+ok", `*** Update File: ${PROJECT}/AGENTS.md`, "+x") })).code).toBe(2);
  });
  it("denies a patch with an unrecognized directive (fail closed)", () => {
    expect(decide(stdin("apply_patch", { command: patch(`*** Add File: ${PROJECT}/src/ok.ts`, "*** Frobnicate File: x") })).code).toBe(2);
  });
  it("allows a patch that only touches normal project files", () => {
    expect(decide(stdin("apply_patch", { command: patch(`*** Add File: ${PROJECT}/src/new.ts`, "+export const x = 1;") }))).toEqual({ code: 0, stdout: "", stderr: "" });
  });
  it("fails closed on apply_patch without a command", () => {
    expect(decide(stdin("apply_patch", {})).code).toBe(2);
  });
  it("fails closed on an unparseable patch (no file headers)", () => {
    expect(decide(stdin("apply_patch", { command: "hello" })).code).toBe(2);
  });
});

describe("codex adapter: apply_patch through the shell (Bash)", () => {
  it("denies an apply_patch heredoc that writes a protected path", () => {
    const cmd = `apply_patch <<'EOF'\n${patch(`*** Update File: ${PROJECT}/AGENTS.md`, "+x")}\nEOF`;
    expect(decide(stdin("Bash", { command: cmd })).code).toBe(2);
  });
  it("falls through to the normal Bash check when the token appears without a patch", () => {
    expect(decide(stdin("Bash", { command: "echo apply_patch done" })).code).toBe(0);
  });
});

describe("codex adapter: parity + fail closed", () => {
  it("passes an unchecked MCP tool through as allow", () => {
    expect(decide(stdin("mcp__filesystem__read_file", { path: "x" })).code).toBe(0);
  });
  it("denies invalid JSON", () => {
    expect(decide("not json").code).toBe(2);
  });
  it("runCodexMain fails closed (exit 2) when stdin cannot be read", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const code = await runCodexMain(() => Promise.reject(new Error("broken stdin")), env, PROJECT, (t) => out.push(t), (t) => err.push(t), deps);
    expect(code).toBe(2);
    expect(JSON.parse(out.join("").trim()).hookSpecificOutput.permissionDecision).toBe("deny");
  });
});
