// One context for the hook and the MCP check tools: same home directory, temporary directory, active policy and always
// protected paths, so check_command/check_path answer like the PreToolUse hook (agent view).
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { resolvePolicy } from "../src/enterprise.js";
import { evaluateDetailed, type Context } from "../src/evaluate.js";
import { decisionLogLayout, guardContext } from "../src/guardContext.js";
import { runHook, type HookDeps } from "../src/hook.js";
import { serverContext } from "../src/mcp/server.js";
import { checkCommandTool, checkPathTool } from "../src/mcp/tools.js";
import { envFor, Fixture, runtimeFor, tempDir } from "./events/helpers.js";
import { BUNDLED_WITHOUT_TAINT } from "./helpers.js";

const base = { session_id: "s-1", tool_use_id: "toolu_1", permission_mode: "default", hook_event_name: "PreToolUse" };

type ProjectLayout = "home" | "subdir";

/** Project directory = home directory (refused, rule_kind project_dir) or a project folder below it; HOME and the user database agree. */
function setup(layout: ProjectLayout = "subdir") {
  const root = tempDir("tg-ctx-");
  const rt = runtimeFor(root, new Fixture());
  const home = rt.home;
  mkdirSync(join(home, ".ssh"), { recursive: true });
  writeFileSync(join(home, ".bashrc"), "# synthetic\n");
  const project = layout === "home" ? home : join(home, "proj");
  mkdirSync(project, { recursive: true });
  const env: NodeJS.ProcessEnv = { ...envFor(root), CLAUDE_PROJECT_DIR: project, HOME: home, TMPDIR: "/tmp" };
  const deps: HookDeps = { runtime: rt, resolve: { bundledPolicy: BUNDLED_WITHOUT_TAINT }, event: "PreToolUse" };
  const resolution = resolvePolicy({ env, projectDir: project, platform: rt.platform, bundledPolicy: BUNDLED_WITHOUT_TAINT });
  if (!resolution.ok) throw new Error(resolution.message);
  return { root, rt, home, project, env, deps, resolution };
}

describe("shared context builder", () => {
  it("the hook evaluates with exactly the context the MCP server builds", () => {
    const s = setup();
    let seen: Context | undefined;
    const deps: HookDeps = {
      ...s.deps,
      evaluate: (event, policy, ctx) => {
        seen = ctx;
        return evaluateDetailed(event, policy, ctx);
      },
    };
    runHook(JSON.stringify({ ...base, tool_name: "Write", tool_input: { file_path: join(s.project, "a.txt"), content: "x" }, cwd: s.project }), s.env, s.project, deps);
    expect(seen).toBeDefined();
    const mcp = serverContext(s.project, s.env, s.rt, s.resolution);
    expect(mcp).toEqual(seen);
    expect(mcp.home).toBe(s.home);
    expect(mcp.homes).toEqual([s.home]);
    expect(mcp.humanSession).toBe(false);
    expect(mcp.extraProtected?.length ?? 0).toBeGreaterThan(0);
  });

  it("the MCP context never is a human session, even with TOLLGATE_HUMAN_SESSION=1", () => {
    const s = setup();
    expect(serverContext(s.project, { ...s.env, TOLLGATE_HUMAN_SESSION: "1" }, s.rt, s.resolution).humanSession).toBe(false);
  });

  it("guardContext: stand-alone takes HOME and TMPDIR from the environment and also guards the home of the user database", () => {
    const s = setup();
    const layout = decisionLogLayout(s.rt, s.env, s.resolution);
    const ctx = guardContext({ projectDir: s.project, humanSession: false, cwd: s.project, env: { ...s.env, HOME: "/elsewhere" }, rt: s.rt, resolution: s.resolution, layout });
    expect(ctx).toMatchObject({ projectDir: s.project, home: "/elsewhere", homes: ["/elsewhere", s.home], tmpdir: "/tmp", policyFile: s.resolution.policyFile });
  });

  it("guardContext: without HOME the home of the user database is used and guarded", () => {
    const s = setup();
    const env = { ...s.env };
    delete env.HOME;
    const ctx = guardContext({ projectDir: s.project, humanSession: false, cwd: s.project, env, rt: s.rt, resolution: s.resolution, layout: decisionLogLayout(s.rt, env, s.resolution) });
    expect(ctx).toMatchObject({ home: s.home, homes: [s.home] });
  });
});

for (const layout of ["home", "subdir"] as const) {
  describe(`parity hook vs. MCP check tools (project directory = ${layout})`, () => {
    const s = setup(layout);
    const ctx = serverContext(s.project, s.env, s.rt, s.resolution);
    const hookBlocks = (event: Record<string, unknown>): boolean => runHook(JSON.stringify({ ...base, ...event, cwd: s.project }), s.env, s.project, s.deps).code !== 0;
    const mcpPath = (path: string): boolean => (JSON.parse(checkPathTool(s.resolution.policy, s.project, path, ctx).content[0]?.text ?? "{}") as { allowed: boolean }).allowed;
    const mcpCommand = (command: string): boolean => (JSON.parse(checkCommandTool(s.resolution.policy, command, s.project, ctx).content[0]?.text ?? "{}") as { allowed: boolean }).allowed;
    // Project = home: every checked call is refused (project_dir), by the hook and by the MCP tools.
    const refused = layout === "home";

    const paths = [".bashrc", "~/.bashrc", "$HOME/.profile", ".ssh/authorized_keys", "~/.ssh/config", ".aws/credentials", ".gitconfig", ".config/systemd/user/x.service", ".local/bin/git", "proj/notes.txt", "proj/src/a.ts", "~/proj/notes.txt"];
    for (const rel of paths) {
      const path = rel.startsWith("~") || rel.startsWith("$") ? rel : join(s.home, rel);
      it(`check_path agrees with the hook (Write) for ${rel}`, () => {
        const hook = hookBlocks({ tool_name: "Write", tool_input: { file_path: path, content: "x" } });
        expect(mcpPath(path)).toBe(!hook);
        if (refused) expect(hook).toBe(true);
      });
    }

    const commands = ["echo test >> ~/.bashrc", `echo test >> ${s.home}/.bashrc`, `echo k >> ${s.home}/.ssh/authorized_keys`, "echo x > notes.txt", "ls -la", "git push --force", "echo x > /etc/hosts"];
    for (const command of commands) {
      it(`check_command agrees with the hook for ${command.replace(s.home, "$H")}`, () => {
        const hook = hookBlocks({ tool_name: "Bash", tool_input: { command } });
        expect(mcpCommand(command)).toBe(!hook);
        if (refused) expect(hook).toBe(true);
      });
    }

    // Temporary directories (owner test 2026-11-08): /tmp, /var/tmp and an accepted TMPDIR are allowed write locations for the write
    // tools and Bash targets (README "Project boundary and temporary directories"). Bash blocks below /tmp come from the form of the
    // command (target only known at run time, inline code; rule_kind write_target), not from the location. MCP follows the hook.
    const scratch = `/tmp/claude-${process.getuid?.() ?? 0}/scratchpad`;
    for (const path of ["/tmp/tg-parity.txt", "/var/tmp/tg-parity.txt", `${scratch}/notes.txt`]) {
      it(`check_path agrees with the hook (Write) for ${path}`, () => {
        const hook = hookBlocks({ tool_name: "Write", tool_input: { file_path: path, content: "x" } });
        expect(hook).toBe(refused);
        expect(mcpPath(path)).toBe(!hook);
      });
    }
    const tmpCommands: [string, boolean][] = [
      ["echo x > /tmp/tg-parity.txt", false],
      ["echo x >> /var/tmp/tg-parity.txt", false],
      [`mkdir -p ${scratch}/d && echo x > ${scratch}/d/a.txt`, false],
      [`cat > ${scratch}/b.txt <<'EOF'\nplain text\nEOF`, false],
      [`python3 - <<'EOF'\nopen("${scratch}/z", "w").write("x")\nEOF`, true],
      ['echo x > "$UNSET_VAR/a.txt"', true],
    ];
    for (const [command, blocked] of tmpCommands) {
      it(`check_command agrees with the hook below the temporary directories: ${command.split("\n")[0]}`, () => {
        const hook = hookBlocks({ tool_name: "Bash", tool_input: { command } });
        expect(hook).toBe(blocked || refused);
        expect(mcpCommand(command)).toBe(!hook);
      });
    }

    it("expected outcomes of the parity cases", () => {
      expect(hookBlocks({ tool_name: "Write", tool_input: { file_path: join(s.home, ".bashrc"), content: "x" } })).toBe(true);
      expect(hookBlocks({ tool_name: "Write", tool_input: { file_path: join(s.home, "proj", "notes.txt"), content: "x" } })).toBe(refused);
    });
  });
}
