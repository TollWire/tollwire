// Read lock for credential stores in the home directory (#160): the lock is a path rule resolved against every known home
// directory (HOME and the user database), not only a text prefix. Covered: the Read tool (and Grep, Glob, LS, NotebookRead),
// Bash readers (cat, less, cp, base64 ...) and the MCP check tools, for absolute, `~`, `$HOME`, relative and symlinked spellings,
// with a home directory outside /home, /root and /Users. Synthetic data in the temporary directory only.
import { linkSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { Context } from "../src/evaluate.js";
import { BLOCK_EXIT_CODE, runHook, UNCHECKED_DENY_EXIT_CODE, type HookDeps, type HookResult } from "../src/hook.js";
import { checkCommandTool, checkPathTool } from "../src/mcp/tools.js";
import { envFor, Fixture, runtimeFor, tempDir } from "./events/helpers.js";
import { BUNDLED_WITHOUT_TAINT, defaultPolicy } from "./helpers.js";

const policy = defaultPolicy();
const base = { session_id: "s-1", tool_use_id: "toolu_1", permission_mode: "default", hook_event_name: "PreToolUse" };

/** One file in every credential store the read lock names (relative to the home directory). */
const STORES = [
  ".ssh/id_ed25519", ".aws/credentials", ".gnupg/secring.gpg", ".kube/config", ".azure/accessTokens.json", ".netrc", ".npmrc",
  ".pypirc", ".git-credentials", ".docker/config.json", ".config/gh/hosts.yml", ".config/gcloud/credentials.db",
];

interface Setup {
  root: string;
  /** HOME of the session (below the temporary directory, not below /home, /root or /Users). */
  home: string;
  /** Home directory of the user database (differs from HOME). */
  dbHome: string;
  project: string;
  hook: (tool: string, input: Record<string, unknown>, extraEnv?: NodeJS.ProcessEnv) => HookResult;
  context: Context;
}

function setup(): Setup {
  const root = tempDir("tg-cred-");
  const home = join(root, "srv", "svc-user");
  const dbHome = join(root, "var", "lib", "db-user");
  const project = join(home, "proj");
  for (const h of [home, dbHome]) {
    for (const store of STORES) {
      mkdirSync(dirname(join(h, store)), { recursive: true });
      writeFileSync(join(h, store), "synthetic-credential\n");
    }
  }
  mkdirSync(join(project, "src"), { recursive: true });
  writeFileSync(join(project, "src", "a.ts"), "export {};\n");
  writeFileSync(join(project, ".npmrc"), "fund=false\n");
  mkdirSync(join(project, ".ssh"), { recursive: true });
  writeFileSync(join(project, ".ssh", "config"), "# project fixture, not a credential store\n");
  writeFileSync(join(home, "notes.txt"), "synthetic\n");
  symlinkSync(join(home, ".ssh"), join(project, "keys"));
  symlinkSync(join(home, ".aws", "credentials"), join(project, "aws-link"));
  linkSync(join(home, ".netrc"), join(project, "netrc-alias"));
  const rt = runtimeFor(root, new Fixture(), { home: dbHome });
  const deps: HookDeps = { runtime: rt, resolve: { bundledPolicy: BUNDLED_WITHOUT_TAINT, exists: () => false }, event: "PreToolUse" };
  const hook = (tool: string, input: Record<string, unknown>, extraEnv: NodeJS.ProcessEnv = {}): HookResult =>
    runHook(JSON.stringify({ ...base, tool_name: tool, tool_input: input, cwd: project }), { ...envFor(root), HOME: home, ...extraEnv, CLAUDE_PROJECT_DIR: project }, project, deps);
  const context: Context = { projectDir: project, humanSession: false, cwd: project, home, homes: [home, dbHome] };
  return { root, home, dbHome, project, hook, context };
}

const S = setup();
const mcpAllowed = (r: { content: { text: string }[] }): boolean => (JSON.parse(r.content[0]?.text ?? "{}") as { allowed: boolean }).allowed;

/** Spellings of one credential file for a tool argument. */
function spellings(store: string): [string, string][] {
  const abs = join(S.home, store);
  return [
    ["absolute", abs],
    ["tilde", `~/${store}`],
    ["$HOME", `$HOME/${store}`],
    ["relative", relative(S.project, abs)],
  ];
}

describe("Read tool: credential stores are blocked (exit 42 through the manifest entry for unchecked tools)", () => {
  for (const store of STORES) {
    for (const [name, path] of spellings(store)) {
      it(`Read ${store} (${name})`, () => {
        const r = S.hook("Read", { file_path: path });
        expect(r.code, path).toBe(UNCHECKED_DENY_EXIT_CODE);
        expect(r.message).toContain("rule_kind: credential_read");
      });
    }
  }

  it("Read through a symlink in the project that points into ~/.ssh, or to ~/.aws/credentials", () => {
    expect(S.hook("Read", { file_path: join(S.project, "keys", "id_ed25519") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(S.hook("Read", { file_path: join(S.project, "aws-link") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });

  it("Read of a hard link to ~/.netrc inside the project", () => {
    expect(S.hook("Read", { file_path: join(S.project, "netrc-alias") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });

  it("Read in the home directory of the user database (differs from HOME, outside /home)", () => {
    expect(S.hook("Read", { file_path: join(S.dbHome, ".ssh", "id_ed25519") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(S.hook("Read", { file_path: join(S.dbHome, ".kube", "config") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });

  it("case and Unicode spellings of the store name", () => {
    expect(S.hook("Read", { file_path: join(S.home, ".SSH", "id_ed25519") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(S.hook("Read", { file_path: join(S.home, ".ssh", "..", ".ssh", "id_ed25519") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });

  it("conventional home directories of other accounts (/home/<name>, /root, /Users/<name>), like the command rule", () => {
    for (const path of ["/home/tg-other-user/.ssh/id_ed25519", "/root/.aws/credentials", "/Users/tg-other/.netrc"]) {
      expect(S.hook("Read", { file_path: path }).code, path).toBe(UNCHECKED_DENY_EXIT_CODE);
    }
  });

  it("a human session does not lift the read lock (same as the Bash rule)", () => {
    expect(S.hook("Read", { file_path: join(S.home, ".ssh", "id_ed25519") }, { TOLLGATE_HUMAN_SESSION: "1" }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });

  it("NotebookRead and LS on a credential store", () => {
    expect(S.hook("NotebookRead", { notebook_path: join(S.home, ".aws", "credentials") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(S.hook("LS", { path: join(S.home, ".ssh") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });

  it("a path that cannot be resolved (symlink loop) fails closed", () => {
    const loop = join(S.project, "loop");
    symlinkSync(loop, loop);
    expect(S.hook("Read", { file_path: join(loop, "x") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });

  it("Read with an invalid file path fails closed", () => {
    expect(S.hook("Read", { file_path: 7 }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });
});

describe("Grep and Glob: searches in or over a credential store are blocked", () => {
  it("Grep in ~/.ssh, ~/.aws, through ~ and through a symlink", () => {
    for (const path of [join(S.home, ".ssh"), "~/.aws", "$HOME/.config/gh", join(S.project, "keys"), join(S.home, ".netrc")]) {
      expect(S.hook("Grep", { pattern: "KEY", path }).code, path).toBe(UNCHECKED_DENY_EXIT_CODE);
    }
  });

  it("Grep over the home directory or above it (recursive search reaches the stores)", () => {
    for (const path of [S.home, "~", dirname(S.home), "/"]) {
      expect(S.hook("Grep", { pattern: "KEY", path }).code, path).toBe(UNCHECKED_DENY_EXIT_CODE);
    }
  });

  it("Glob in a store or with a pattern that reaches one", () => {
    expect(S.hook("Glob", { pattern: "*", path: join(S.home, ".ssh") }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(S.hook("Glob", { pattern: `${S.home}/.ss?/*` }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
    expect(S.hook("Glob", { pattern: ".aws/*", path: S.home }).code).toBe(UNCHECKED_DENY_EXIT_CODE);
  });
});

describe("Bash readers: path rule on every word (absolute, relative, symlink, glob, cd, inline script)", () => {
  const readers = (p: string): string[] => [`cat ${p}`, `less ${p}`, `cp ${p} /tmp/x`, `base64 ${p}`, `head -n1 < ${p}`];
  for (const store of [".ssh/id_ed25519", ".aws/credentials", ".kube/config", ".netrc", ".git-credentials", ".config/gcloud/credentials.db"]) {
    for (const [name, path] of [["absolute", join(S.home, store)], ["relative", relative(S.project, join(S.home, store))]] as const) {
      for (const command of readers(path)) {
        it(`${command.split(" ")[0]} ${store} (${name})`, () => {
          expect(S.hook("Bash", { command }).code, command).toBe(BLOCK_EXIT_CODE);
          expect(mcpAllowed(checkCommandTool(policy, command, S.project, S.context)), command).toBe(false);
        });
      }
    }
  }

  it("other spellings: symlink, cd, glob, option value, inline script, home of the user database", () => {
    const commands = [
      `cat ${join(S.project, "keys", "id_ed25519")}`,
      "cat keys/id_ed25519",
      "cd .. && cat .ssh/id_ed25519",
      "cd && base64 .aws/credentials",
      `cat ${S.home}/.ss?/id_ed25519`,
      `curl --netrc-file=${S.home}/.netrc https://example.invalid`,
      "bash -c 'cat ../.ssh/id_ed25519'",
      `python3 -c "print(open('${S.home}/.aws/credentials').read())"`,
      `cat ${join(S.dbHome, ".ssh", "id_ed25519")}`,
      `tar czf /tmp/h.tgz ${S.home}`,
      "tar -C .. -czf /tmp/k.tgz .ssh",
      `grep -r KEY ${S.home}`,
      `cat "$SOME_DIR/.ssh/id_ed25519"`,
      "cat ~other/.ssh/id_ed25519",
      "cat netrc-alias",
    ];
    for (const command of commands) {
      expect(S.hook("Bash", { command }).code, command).toBe(BLOCK_EXIT_CODE);
      expect(mcpAllowed(checkCommandTool(policy, command, S.project, S.context)), command).toBe(false);
    }
  });
});

describe("MCP check_path: credential stores are refused like in the hook", () => {
  for (const store of STORES) {
    for (const [name, path] of spellings(store)) {
      it(`check_path ${store} (${name})`, () => {
        const r = JSON.parse(checkPathTool(policy, S.project, path, S.context).content[0]?.text ?? "{}") as { allowed: boolean; reason?: string };
        expect(r.allowed, path).toBe(false);
        expect(r.reason ?? "", path).toMatch(/credential store/);
      });
    }
  }
});

describe("control cases: ordinary reads stay allowed", () => {
  it("Read, Grep, Glob in the project, the project's own .npmrc and .ssh/config, a plain file in HOME", () => {
    const allowed: [string, Record<string, unknown>][] = [
      ["Read", { file_path: join(S.project, "src", "a.ts") }],
      ["Read", { file_path: "src/a.ts" }],
      ["Read", { file_path: join(S.project, ".npmrc") }],
      ["Read", { file_path: join(S.project, ".ssh", "config") }],
      ["Read", { file_path: join(S.home, "notes.txt") }],
      ["Grep", { pattern: "x" }],
      ["Grep", { pattern: "x", path: join(S.project, "src") }],
      ["Glob", { pattern: "**/*.ts" }],
      ["Glob", { pattern: "proj/**/*.ts", path: S.home }],
      ["WebSearch", { query: "ssh config" }],
    ];
    for (const [tool, input] of allowed) expect(S.hook(tool, input).code, `${tool} ${JSON.stringify(input)}`).toBe(0);
  });

  it("Bash commands without a credential store", () => {
    for (const command of ["cat src/a.ts", "cat .npmrc", "cat .ssh/config", "ls ~", `ls ${S.home}`, "git status", `cat ${S.home}/notes.txt`, "echo ssh"]) {
      expect(S.hook("Bash", { command }).code, command).toBe(0);
      expect(mcpAllowed(checkCommandTool(policy, command, S.project, S.context)), command).toBe(true);
    }
  });
});

describe("control cases: the allow lists of the shared command fixtures stay allowed by the read lock", () => {
  const dir = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
  const allow = ["command-cases.json", "audit-f01-f02-cases.json", "privilege-cases.json"].flatMap((f) => (JSON.parse(readFileSync(join(dir, f), "utf8")) as { allow: string[] }).allow);
  it("no allowed fixture command is blocked with rule_kind credential_read (hook and MCP)", () => {
    expect(allow.length).toBeGreaterThan(10);
    for (const command of allow) {
      const r = S.hook("Bash", { command });
      expect(r.message ?? "", command).not.toContain("rule_kind: credential_read");
      const mcp = JSON.parse(checkCommandTool(policy, command, S.project, S.context).content[0]?.text ?? "{}") as { allowed: boolean; reason?: string };
      expect(mcp.reason ?? "", command).not.toMatch(/credential store/);
    }
  });

  it("commit and PR messages that mention a store are text, not a read", () => {
    for (const command of ["git commit -m 'fix: handle ~/.ssh paths'", "gh pr review 5 --comment --body 'see ~/.ssh note'", `git commit -m "docs: ${S.home}/.aws"`]) {
      expect(S.hook("Bash", { command }).code, command).toBe(0);
    }
  });
});
