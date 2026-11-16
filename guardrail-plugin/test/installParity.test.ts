import { describe, expect, it } from "vitest";
import { evaluateDetailed, type Context } from "../src/evaluate.js";
import { checkCommandTool } from "../src/mcp/tools.js";
import { defaultPolicy } from "./helpers.js";

// Parity gap #161: the MCP check_command tool did not check install commands against `allowedDependencies`, while
// the PreToolUse hook (evaluateDetailed for a Bash call) does via installProblems. An agent that asks check_command
// before running `npm install left-pad` was told the command is allowed, then the hook blocked it. The advisory tool
// and the enforcing hook must decide identically.
const project = "/tollgate-install-test/repo";
const home = "/tollgate-install-test/home";
const policy = defaultPolicy({ allowedDependencies: { npm: ["zod"], pypi: ["requests"] } });
const ctx: Context = { projectDir: project, humanSession: false, home, cwd: project };

const mcp = (cmd: string) =>
  JSON.parse(checkCommandTool(policy, cmd, project, ctx).content[0]?.text ?? "") as { allowed: boolean; reason?: string };
const hook = (cmd: string) => evaluateDetailed({ tool_name: "Bash", tool_input: { command: cmd } }, policy, ctx);

// Installs of a package that is not on the allowlist: the hook blocks these, so check_command must too.
const BLOCKED = [
  "npm install left-pad",
  "pnpm add left-pad",
  "yarn add left-pad",
  "pip install flask",
  "pip install -r requirements.txt",
  "npm install zod left-pad",
];
// Allowed: no package argument, a lockfile install, an allowlisted package, a non-install command.
const ALLOWED = ["npm ci", "npm install", "npm install zod", "pip install requests", "git status", "ls -la"];

describe("#161 MCP check_command checks install commands against the allowlist (parity with the hook)", () => {
  for (const cmd of BLOCKED) {
    it(`blocks: ${cmd}`, () => {
      expect(hook(cmd).allowed, `hook should block: ${cmd}`).toBe(false);
      expect(mcp(cmd).allowed, `check_command should block: ${cmd}`).toBe(false);
    });
  }
  for (const cmd of ALLOWED) {
    it(`allows: ${cmd}`, () => {
      expect(hook(cmd).allowed, `hook should allow: ${cmd}`).toBe(true);
      expect(mcp(cmd).allowed, `check_command should allow: ${cmd}`).toBe(true);
    });
  }

  it("names the offending package in the reason, like the hook", () => {
    expect(mcp("npm install left-pad").reason ?? "").toContain("left-pad");
  });

  it("decides identically to the hook across the fixtures", () => {
    for (const cmd of [...BLOCKED, ...ALLOWED]) {
      expect(mcp(cmd).allowed, cmd).toBe(hook(cmd).allowed);
    }
  });
});
