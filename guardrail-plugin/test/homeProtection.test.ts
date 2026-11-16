// Protected home files for the write tools and check_path (project directory = home or an ancestor of it).
// Synthetic home directories in the temporary directory; nothing outside it is touched.
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkPath, evaluate, evaluateDetailed, type Context } from "../src/evaluate.js";
import { checkCommandTool, checkPathTool } from "../src/mcp/tools.js";
import { HOME_PROTECTED_PATHS } from "../src/writes.js";
import { defaultPolicy } from "./helpers.js";

const policy = defaultPolicy();
const WRITE_TOOLS = ["Write", "Edit", "MultiEdit", "NotebookEdit"] as const;

function fakeHome(prefix = "tg-fakehome-"): string {
  const home = mkdtempSync(join(tmpdir(), prefix));
  mkdirSync(join(home, ".ssh"));
  writeFileSync(join(home, ".bashrc"), "# synthetic\n");
  writeFileSync(join(home, ".ssh", "config"), "# synthetic\n");
  return home;
}

/** A file below each entry of the home list (directory entries get a file name appended). */
function targetFor(entry: string): string {
  return entry.endsWith("/") ? `${entry}x.conf` : entry;
}

function input(tool: (typeof WRITE_TOOLS)[number], path: string): Record<string, unknown> {
  if (tool === "Write") return { file_path: path, content: "x" };
  if (tool === "Edit") return { file_path: path, old_string: "a", new_string: "b" };
  if (tool === "MultiEdit") return { file_path: path, edits: [{ old_string: "a", new_string: "b" }] };
  return { notebook_path: path, new_source: "x" };
}

function parse(r: { content: { text: string }[] }): { allowed: boolean; reason?: string } {
  return JSON.parse(r.content[0]?.text ?? "{}") as { allowed: boolean; reason?: string };
}

describe("project directory = home: write tools and check_path block the protected home files", () => {
  const H = fakeHome();
  const ctx: Context = { projectDir: H, humanSession: false, home: H, cwd: H };
  const forms: [string, (rel: string) => string][] = [
    ["absolute", (rel) => join(H, rel)],
    ["~", (rel) => `~/${rel}`],
    ["$HOME", (rel) => `$HOME/${rel}`],
    ["${HOME}", (rel) => `\${HOME}/${rel}`],
  ];

  for (const entry of HOME_PROTECTED_PATHS) {
    const rel = targetFor(entry);
    for (const [form, spell] of forms) {
      it(`${rel} (${form}) is blocked for ${WRITE_TOOLS.join("/")} and check_path`, () => {
        const path = spell(rel);
        for (const tool of WRITE_TOOLS) {
          const decision = evaluateDetailed({ tool_name: tool, tool_input: input(tool, path) }, policy, ctx);
          expect(decision, `${tool} ${path}`).toMatchObject({ allowed: false, kind: "protected_path", ruleId: entry });
        }
        expect(parse(checkPathTool(policy, H, path, ctx)), `check_path ${path}`).toMatchObject({ allowed: false });
      });
    }
  }

  it("the home directory itself and a protected directory are blocked", () => {
    for (const path of [join(H, ".ssh"), join(H, ".config", "systemd")]) {
      expect(checkPath(path, policy, ctx).allowed).toBe(false);
    }
  });

  it("the reason names the protected home entry, like the Bash block", () => {
    const write = evaluate({ tool_name: "Write", tool_input: { file_path: join(H, ".ssh/authorized_keys"), content: "x" } }, policy, ctx);
    const bash = evaluate({ tool_name: "Bash", tool_input: { command: `echo x >> ${H}/.ssh/authorized_keys` } }, policy, ctx);
    expect(bash.allowed).toBe(false);
    expect(write.allowed).toBe(false);
    expect(write.allowed ? "" : write.reason).toContain(".ssh/");
  });

  it("a symlink in the project that points to a protected home file is blocked", async () => {
    const { symlinkSync } = await import("node:fs");
    mkdirSync(join(H, "proj"), { recursive: true });
    symlinkSync(join(H, ".bashrc"), join(H, "proj", "rc"));
    expect(checkPath(join(H, "proj", "rc"), policy, ctx).allowed).toBe(false);
  });

  it("control: an ordinary project file stays allowed by the path check (absolute, ~ and $HOME)", () => {
    for (const path of [join(H, "projekt/notes.txt"), "~/projekt/notes.txt", "$HOME/projekt/notes.txt", "projekt/notes.txt"]) {
      expect(evaluate({ tool_name: "Write", tool_input: { file_path: path, content: "x" } }, policy, ctx), path).toEqual({ allowed: true });
    }
  });

  it("check_path refuses the project directory = home itself, like the hook (project_dir)", () => {
    for (const path of [join(H, "projekt/notes.txt"), "~/projekt/notes.txt", join(H, ".bashrc")]) {
      const answer = parse(checkPathTool(policy, H, path, ctx));
      expect(answer.allowed, path).toBe(false);
      expect(answer.reason).toContain("project directory is the home directory");
    }
  });

  it("control: a human session may write the home files (project boundary unchanged)", () => {
    const human: Context = { ...ctx, humanSession: true };
    expect(evaluate({ tool_name: "Write", tool_input: { file_path: join(H, ".bashrc"), content: "x" } }, policy, human)).toEqual({ allowed: true });
  });

  it("~ without a known home directory fails closed", () => {
    const noHome: Context = { projectDir: H, humanSession: false };
    expect(evaluate({ tool_name: "Write", tool_input: { file_path: "~/projekt/notes.txt", content: "x" } }, policy, noHome).allowed).toBe(false);
  });

  it("control: Bash writes to the same files stay blocked", () => {
    for (const rel of [".bashrc", ".ssh/authorized_keys", ".aws/credentials"]) {
      expect(evaluate({ tool_name: "Bash", tool_input: { command: `echo x >> ${H}/${rel}` } }, policy, ctx).allowed).toBe(false);
    }
  });
});

describe("project directory = ancestor of home", () => {
  const root = mkdtempSync(join(tmpdir(), "tg-homes-"));
  const H = join(root, "alice");
  mkdirSync(join(H, ".ssh"), { recursive: true });
  const ctx: Context = { projectDir: root, humanSession: false, home: H, cwd: root };

  it("blocks the protected home files and keeps other files allowed", () => {
    for (const rel of [".bashrc", ".ssh/authorized_keys", ".config/systemd/user/x.service", ".local/bin/git"]) {
      expect(checkPath(join(H, rel), policy, ctx).allowed, rel).toBe(false);
    }
    expect(checkPath(join(root, "bob", "notes.txt"), policy, ctx)).toEqual({ allowed: true });
    expect(checkPath(join(H, "notes.txt"), policy, ctx)).toEqual({ allowed: true });
  });
});

describe("project directory != home (unchanged)", () => {
  const H = fakeHome();
  const project = mkdtempSync(join(tmpdir(), "tg-project-"));
  const ctx: Context = { projectDir: project, humanSession: false, home: H, cwd: project };

  it("project files stay allowed, also a file named like a home entry", () => {
    for (const rel of ["src/a.ts", ".bashrc", ".ssh/config", "bin/tool"]) {
      expect(checkPath(join(project, rel), policy, ctx), rel).toEqual({ allowed: true });
      expect(parse(checkPathTool(policy, project, join(project, rel), ctx)), rel).toEqual({ allowed: true });
    }
  });

  it("home files stay blocked for all forms", () => {
    for (const path of [join(H, ".bashrc"), "~/.bashrc", "$HOME/.ssh/authorized_keys"]) {
      expect(checkPath(path, policy, ctx).allowed, path).toBe(false);
    }
  });
});

describe("MCP check_command with the hook context", () => {
  const H = fakeHome();
  const ctx: Context = { projectDir: H, humanSession: false, home: H, cwd: H };

  for (const target of ["~/.bashrc", "$HOME/.bashrc", ".bashrc", "__H__/.bashrc", "__H__/.ssh/authorized_keys"]) {
    it(`blocks echo >> ${target} like the hook`, () => {
      const cmd = `echo test >> ${target.replace("__H__", H)}`;
      expect(evaluate({ tool_name: "Bash", tool_input: { command: cmd } }, policy, ctx).allowed).toBe(false);
      expect(parse(checkCommandTool(policy, cmd, H, ctx)).allowed).toBe(false);
    });
  }

  it("ordinary project writes are refused as well: the project directory is the home directory (project_dir)", () => {
    mkdirSync(dirname(join(H, "projekt", "x")), { recursive: true });
    const answer = parse(checkCommandTool(policy, "echo test > projekt/x", H, ctx));
    expect(answer.allowed).toBe(false);
    expect(answer.reason).toContain("project directory is the home directory");
    expect(evaluate({ tool_name: "Bash", tool_input: { command: "echo test > projekt/x" } }, policy, ctx)).toEqual({ allowed: true });
  });
});
