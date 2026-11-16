// Stand-alone refusal of a project directory that is a home directory or above it (owner decision 2026-11-09, rule_kind
// project_dir), the union of HOME and the home directory of the user database, and the two path fields of NotebookEdit.
// Synthetic directories in the temporary directory only.
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { evaluateDetailed, type Context } from "../src/evaluate.js";
import { homeProjectProblem, knownHomes } from "../src/guardContext.js";
import { BLOCK_EXIT_CODE, runHook, type HookDeps, type HookResult } from "../src/hook.js";
import { checkCommandTool, checkPathTool } from "../src/mcp/tools.js";
import { envFor, Fixture, runtimeFor, tempDir } from "./events/helpers.js";
import { BUNDLED_WITHOUT_TAINT, defaultPolicy } from "./helpers.js";

const base = { session_id: "s-1", tool_use_id: "toolu_1", permission_mode: "default", hook_event_name: "PreToolUse" };
const policy = defaultPolicy();

function setup(home?: string) {
  const root = tempDir("tg-pdir-");
  const rt = runtimeFor(root, new Fixture(), home === undefined ? {} : { home });
  mkdirSync(join(rt.home, "proj"), { recursive: true });
  const deps: HookDeps = { runtime: rt, resolve: { bundledPolicy: BUNDLED_WITHOUT_TAINT }, event: "PreToolUse" };
  const run = (project: string, event: Record<string, unknown>, env: NodeJS.ProcessEnv = { HOME: rt.home }): HookResult =>
    runHook(JSON.stringify({ ...base, ...event, cwd: project }), { ...envFor(root), ...env, CLAUDE_PROJECT_DIR: project }, project, deps);
  return { root, rt, home: rt.home, run };
}

const kind = (r: HookResult): string => /rule_kind:\s*(\S+)/.exec(r.message ?? "")?.[1] ?? "none";
const CHECKED: [string, Record<string, unknown>][] = [
  ["Bash", { command: "ls" }],
  ["Write", { file_path: "notes.txt", content: "x" }],
  ["Edit", { file_path: "notes.txt", old_string: "a", new_string: "b" }],
  ["MultiEdit", { file_path: "notes.txt", edits: [{ old_string: "a", new_string: "b" }] }],
  ["NotebookEdit", { notebook_path: "n.ipynb", new_source: "x" }],
];

describe("stand-alone: project directory = home directory or above is refused (project_dir)", () => {
  for (const [tool, input] of CHECKED) {
    it(`${tool} in the home directory is blocked with rule_kind project_dir and a clear message`, () => {
      const s = setup();
      const r = s.run(s.home, { tool_name: tool, tool_input: input });
      expect(r.code).toBe(BLOCK_EXIT_CODE);
      expect(kind(r)).toBe("project_dir");
      expect(r.message).toContain("TollWire guardrail: blocked.");
      expect(r.message).toContain("project directory is the home directory (or above); start Claude Code in a project folder");
    });
  }

  it("the parent of the home directory and the file system root are refused", () => {
    const s = setup();
    for (const project of [dirname(s.home), "/"]) {
      const r = s.run(project, { tool_name: "Write", tool_input: { file_path: "x.txt", content: "x" } });
      expect(r.code, project).toBe(BLOCK_EXIT_CODE);
      expect(kind(r), project).toBe("project_dir");
    }
  });

  it("a human session is refused as well (the decision concerns the project location, not the protected paths)", () => {
    const s = setup();
    const r = s.run(s.home, { tool_name: "Bash", tool_input: { command: "ls" } }, { HOME: s.home, TOLLGATE_HUMAN_SESSION: "1" });
    expect(kind(r)).toBe("project_dir");
  });

  it("a project folder below the home directory stays allowed", () => {
    const s = setup();
    const project = join(s.home, "proj");
    expect(s.run(project, { tool_name: "Bash", tool_input: { command: "ls" } }).code).toBe(0);
    expect(s.run(project, { tool_name: "Write", tool_input: { file_path: join(project, "notes.txt"), content: "x" } }).code).toBe(0);
  });

  it("tools the hook does not check are not refused (recorded only)", () => {
    const s = setup();
    expect(s.run(s.home, { tool_name: "Read", tool_input: { file_path: join(s.home, "notes.txt") } }).code).toBe(0);
  });

  it("HOME unset: the home directory of the user database is used", () => {
    const s = setup();
    const r = s.run(s.home, { tool_name: "Bash", tool_input: { command: "ls" } }, {});
    expect(kind(r)).toBe("project_dir");
  });

  it("HOME different from the user database: both home directories are refused as project", () => {
    const s = setup();
    const other = tempDir("tg-pdir-envhome-");
    expect(kind(s.run(s.home, { tool_name: "Bash", tool_input: { command: "ls" } }, { HOME: other }))).toBe("project_dir");
    expect(kind(s.run(other, { tool_name: "Bash", tool_input: { command: "ls" } }, { HOME: other }))).toBe("project_dir");
  });

  it("MCP check_path and check_command answer like the hook", () => {
    const s = setup();
    const ctx: Context = { projectDir: s.home, humanSession: false, home: s.home, homes: [s.home] };
    for (const answer of [checkPathTool(policy, s.home, "notes.txt", ctx), checkCommandTool(policy, "ls", s.home, ctx), checkPathTool(policy, "/", "x", ctx)]) {
      const parsed = JSON.parse(answer.content[0]?.text ?? "{}") as { allowed: boolean; reason: string };
      expect(parsed.allowed).toBe(false);
      expect(parsed.reason).toContain("project directory is the home directory (or above)");
    }
    const sub = join(s.home, "proj");
    expect(JSON.parse(checkPathTool(policy, sub, join(sub, "notes.txt"), { ...ctx, projectDir: sub }).content[0]?.text ?? "{}")).toEqual({ allowed: true });
  });

  it("homeProjectProblem and knownHomes", () => {
    expect(homeProjectProblem("/home/alice", ["/home/alice"])).not.toBeNull();
    expect(homeProjectProblem("/var", ["/var/lib/svc"])).not.toBeNull();
    expect(homeProjectProblem("/home", [])).not.toBeNull();
    expect(homeProjectProblem("/", [])).not.toBeNull();
    expect(homeProjectProblem("relative", [])).not.toBeNull();
    expect(homeProjectProblem("/home/alice/proj", ["/home/alice"])).toBeNull();
    expect(homeProjectProblem("/home/alicex", ["/home/alice"])).toBeNull();
    const rt = runtimeFor(tempDir(), new Fixture(), { home: "/home/db" });
    expect(knownHomes({ HOME: "/home/env" }, rt, false)).toEqual(["/home/env", "/home/db"]);
    expect(knownHomes({ HOME: "/home/env" }, rt, true)).toEqual(["/home/db"]);
    expect(knownHomes({}, runtimeFor(tempDir(), new Fixture(), { home: "/" }), false)).toEqual([]);
  });
});

describe("protected home files below every known home directory (HOME and user database)", () => {
  const root = tempDir("tg-homes-union-");
  const envHome = join(root, "env-home");
  const dbHome = join(root, "db-home");
  mkdirSync(join(dbHome, ".ssh"), { recursive: true });
  mkdirSync(envHome, { recursive: true });
  // Evaluation layer (the hook refuses such a project anyway): project contains both home directories.
  const ctx: Context = { projectDir: root, humanSession: false, home: envHome, homes: [envHome, dbHome] };

  it("write tools and Bash block the protected files of the second home directory", () => {
    for (const rel of [".bashrc", ".ssh/authorized_keys", ".config/systemd/user/x.service"]) {
      expect(evaluateDetailed({ tool_name: "Write", tool_input: { file_path: join(dbHome, rel), content: "x" } }, policy, ctx).allowed, rel).toBe(false);
      expect(evaluateDetailed({ tool_name: "Bash", tool_input: { command: `echo x >> ${join(dbHome, rel)}` } }, policy, ctx).allowed, rel).toBe(false);
      expect(evaluateDetailed({ tool_name: "Write", tool_input: { file_path: join(envHome, rel), content: "x" } }, policy, ctx).allowed, rel).toBe(false);
    }
    expect(evaluateDetailed({ tool_name: "Write", tool_input: { file_path: join(dbHome, "notes.txt"), content: "x" } }, policy, ctx)).toEqual({ allowed: true });
  });

  it("control: without the second home directory its files are not on the home list", () => {
    const only: Context = { ...ctx, homes: [envHome] };
    expect(evaluateDetailed({ tool_name: "Write", tool_input: { file_path: join(dbHome, ".bashrc"), content: "x" } }, policy, only)).toEqual({ allowed: true });
  });
});

describe("NotebookEdit and write tools: both path fields are checked", () => {
  const project = tempDir("tg-nb-");
  const ctx: Context = { projectDir: project, humanSession: false };

  it("two different files are refused (fail closed)", () => {
    const d = evaluateDetailed({ tool_name: "NotebookEdit", tool_input: { file_path: join(project, "a.ipynb"), notebook_path: join(project, "AGENTS.md"), new_source: "x" } }, policy, ctx);
    expect(d).toMatchObject({ allowed: false, kind: "invalid_input" });
    const w = evaluateDetailed({ tool_name: "Write", tool_input: { file_path: join(project, "a.txt"), notebook_path: "/etc/passwd", content: "x" } }, policy, ctx);
    expect(w).toMatchObject({ allowed: false, kind: "invalid_input" });
  });

  it("the notebook path is checked even if file_path is harmless and equal paths are accepted", () => {
    expect(evaluateDetailed({ tool_name: "NotebookEdit", tool_input: { notebook_path: join(project, "AGENTS.md"), new_source: "x" } }, policy, ctx)).toMatchObject({ allowed: false, kind: "protected_path" });
    const same = join(project, "n.ipynb");
    expect(evaluateDetailed({ tool_name: "NotebookEdit", tool_input: { file_path: same, notebook_path: same, new_source: "x" } }, policy, ctx)).toEqual({ allowed: true });
  });

  it("an invalid second field is refused", () => {
    expect(evaluateDetailed({ tool_name: "NotebookEdit", tool_input: { file_path: join(project, "n.ipynb"), notebook_path: 42 } }, policy, ctx)).toMatchObject({ allowed: false, kind: "invalid_input" });
    expect(evaluateDetailed({ tool_name: "NotebookEdit", tool_input: { notebook_path: "" } }, policy, ctx)).toMatchObject({ allowed: false, kind: "invalid_input" });
  });
});
