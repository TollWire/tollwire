import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { evaluateDetailed, type Context } from "../src/evaluate.js";
import { checkCommandTool } from "../src/mcp/tools.js";
import { defaultPolicy } from "./helpers.js";

// Parity gap #162: a Bash command that writes a dependency manifest/lockfile bypassed the allowlist, because the
// manifest check only hung on the write tools (Write/Edit/MultiEdit). A Bash write to such a file cannot carry a
// verifiable content through the hook, so it must fail closed exactly like the write tools reject a bad manifest.
const project = "/tollgate-manifest-test/repo";
const subdir = "/tollgate-manifest-test/repo/packages/app";
const home = "/tollgate-manifest-test/home";
const policy = defaultPolicy({ allowedDependencies: { npm: ["zod"], pypi: [] } });
const agent: Context = { projectDir: project, humanSession: false, home, cwd: project };

const run = (command: string, ctx: Context = agent) =>
  evaluateDetailed({ tool_name: "Bash", tool_input: { command } }, ctx === agent ? policy : policy, ctx);

// Manifest and lockfile names that let `npm install` / `npm ci` pull in unapproved dependencies.
const MANIFESTS = ["package.json", "requirements.txt", "requirements-dev.txt", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"];

// A write to one of these files via each writing construct, absolute and relative, in both project locations.
function writeCommands(name: string): string[] {
  const abs = `${project}/${name}`;
  return [
    `echo '{}' > ${name}`,
    `echo '{}' >> ${name}`,
    `echo '{}' > ${abs}`,
    `printf '{}' | tee ${name}`,
    `cp /tmp/evil.json ${name}`,
    `mv /tmp/evil.json ${name}`,
    `sed -i 's/a/b/' ${name}`,
    `install -m 644 /tmp/evil.json ${name}`,
    `echo '{"dependencies":{"left-pad":"1.3.0"}}' > ${name} && npm install`,
  ];
}

describe("#162 Bash writes to a dependency manifest fail closed (parity with the write tools)", () => {
  for (const name of MANIFESTS) {
    for (const cmd of writeCommands(name)) {
      it(`blocks: ${cmd}`, () => {
        expect(run(cmd)).toMatchObject({ allowed: false, kind: "dependency_unverifiable" });
      });
    }
  }

  it("blocks a relative write when the project is a subdirectory", () => {
    const ctx: Context = { projectDir: subdir, humanSession: false, home, cwd: subdir };
    expect(run("echo '{}' > package.json", ctx)).toMatchObject({ allowed: false, kind: "dependency_unverifiable" });
  });

  it("blocks even when npm install carries no package argument (supply-chain chain)", () => {
    expect(run("echo '{\"dependencies\":{\"left-pad\":\"1\"}}' > package.json && npm install")).toMatchObject({
      allowed: false,
      kind: "dependency_unverifiable",
    });
  });

  it("allows writing a normal file", () => {
    expect(run("echo hi > notes.md")).toEqual({ allowed: true });
    expect(run("echo hi > src/index.ts")).toEqual({ allowed: true });
  });

  it("allows reading a manifest", () => {
    expect(run("cat package.json")).toEqual({ allowed: true });
    expect(run("grep left-pad package.json")).toEqual({ allowed: true });
  });

  it("the check_command MCP tool decides identically (parity)", () => {
    const parse = (cmd: string, dir = project) => {
      const text = checkCommandTool(policy, cmd, dir, { home, cwd: dir, humanSession: false } as Context).content[0]?.text ?? "";
      return JSON.parse(text) as { allowed: boolean };
    };
    for (const name of MANIFESTS) {
      expect(parse(`echo '{}' > ${name}`).allowed, name).toBe(false);
      expect(parse(`echo '{}' > ${project}/${name}`).allowed, name).toBe(false);
    }
    expect(parse("echo hi > notes.md").allowed).toBe(true);
    expect(parse("cat package.json").allowed).toBe(true);
  });

  it("blocks a Bash write to a manifest reached through a symlink alias", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "tg-manifest-")));
    writeFileSync(join(dir, "package.json"), "{}");
    symlinkSync(join(dir, "package.json"), join(dir, "notes.json"));
    const ctx: Context = { projectDir: dir, humanSession: false, home, cwd: dir };
    mkdirSync(join(dir, "sub"), { recursive: true });
    expect(run(`echo '{}' > ${join(dir, "notes.json")}`, ctx)).toMatchObject({ allowed: false, kind: "dependency_unverifiable" });
  });
});
