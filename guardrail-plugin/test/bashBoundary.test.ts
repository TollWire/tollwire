import { mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkBashCommandWrites, evaluateDetailed, insideProjectBoundary, type Context } from "../src/evaluate.js";
import { analyzeWrites, decideWrites } from "../src/writes.js";
import { defaultPolicy } from "./helpers.js";

// Project boundary for Bash write targets: redirections and recognized write commands may only target the project, /tmp,
// /var/tmp and an accepted TMPDIR, exactly like the write tools (same function, same rule kind `outside_project`).
// The cases are shared with the Python port of the repository hook; both must decide identically.
const cases = JSON.parse(readFileSync(new URL("./fixtures/bash-boundary-cases.json", import.meta.url), "utf8")) as { block: string[]; allow: string[] };

// Project and home outside the temporary directories (they need not exist; the check resolves missing paths lexically).
const project = "/tollgate-boundary-test/repo";
const home = "/tollgate-boundary-test/home";
const policy = defaultPolicy();
const agent: Context = { projectDir: project, humanSession: false, home, cwd: project };
const run = (command: string, ctx: Context = agent) => evaluateDetailed({ tool_name: "Bash", tool_input: { command } }, policy, ctx);

describe("Bash write targets: project boundary (shared cases)", () => {
  it.each(cases.block)("blocks %j", (cmd) => expect(run(cmd).allowed).toBe(false));
  it.each(cases.allow)("allows %j", (cmd) => expect(run(cmd)).toEqual({ allowed: true }));
});

describe("Bash write targets: project boundary", () => {
  it("uses the rule kind of the write tools", () => {
    expect(run("echo 127.0.0.1 example.test >> /etc/hosts")).toMatchObject({ allowed: false, kind: "outside_project" });
    expect(evaluateDetailed({ tool_name: "Write", tool_input: { file_path: "/etc/hosts", content: "x" } }, policy, agent)).toMatchObject({ allowed: false, kind: "outside_project" });
  });
  it("keeps protected paths ahead of the boundary (more specific message)", () => {
    expect(run("echo x >> ~/.bashrc")).toMatchObject({ allowed: false, kind: "write_target" });
  });
  it("shares one boundary with the write tools", () => {
    for (const p of ["/etc/hosts", join(project, ".."), project, "/", "/tmp", join(home, "x")]) expect(insideProjectBoundary(p, agent), p).toBe(false);
    for (const p of [join(project, "src", "x"), "/tmp/tollgate-x", "/var/tmp/tollgate-x"]) expect(insideProjectBoundary(p, agent), p).toBe(true);
  });
  it("follows symlinks out of the project (lexical and physical form)", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "tg-boundary-link-")));
    mkdirSync(join(dir, "repo"));
    symlinkSync("/etc", join(dir, "repo", "out"));
    const ctx: Context = { projectDir: join(dir, "repo"), humanSession: false, cwd: join(dir, "repo") };
    expect(run("echo x > out/tollgate-x", ctx)).toMatchObject({ allowed: false, kind: "outside_project" });
    expect(run("echo x > out/../tollgate-x", ctx)).toMatchObject({ allowed: false, kind: "outside_project" });
    expect(run("echo x > inside.txt", ctx)).toEqual({ allowed: true });
  });
  it("blocks globs that can climb out of their directory", () => {
    expect(run("rm -f src/{a,../../x}")).toMatchObject({ allowed: false });
    expect(run("rm -f src/*.tmp")).toEqual({ allowed: true });
    const inside = (): boolean => true;
    for (const cmd of ["rm -f src/.?/x", "rm -f src/.*/x", "rm -f src/.[.]/x"]) {
      expect(decideWrites(analyzeWrites(cmd, { root: project }), [], project, { boundary: inside }), cmd).toMatchObject({ allowed: false, kind: "outside_project" });
    }
    expect(decideWrites(analyzeWrites("rm -f src/.*.swp", { root: project }), [], project, { boundary: inside })).toEqual({ allowed: true });
  });
  it("accepts TMPDIR only below a fixed temporary root", () => {
    const tmp = realpathSync(mkdtempSync(join("/tmp", "tg-boundary-tmpdir-")));
    expect(run('echo x > "$TMPDIR/y"', { ...agent, tmpdir: tmp })).toEqual({ allowed: true });
    expect(run('echo x > "$TMPDIR/y"', { ...agent, tmpdir: home })).toMatchObject({ allowed: false });
  });
  it("is not applied in a human session (the Bash write check is for agents only)", () => {
    expect(run("echo 127.0.0.1 example.test >> /etc/hosts", { ...agent, humanSession: true })).toEqual({ allowed: true });
  });
  it("exempts safe devices, file descriptor duplications and link sources", () => {
    for (const c of ["cat x > /dev/null", "cmd 2>/dev/null >/dev/stdout", "echo x 1>&2", "echo x | tee /dev/tty", "ln -s /usr/share/doc lnk"]) expect(run(c), c).toEqual({ allowed: true });
  });
  it("exempts a safe device only if its physical form agrees (no /dev/null reached through a symlink and ..)", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "tg-boundary-dev-")));
    mkdirSync(join(dir, "repo"));
    mkdirSync(join(dir, "elsewhere", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"), { recursive: true });
    symlinkSync(join(dir, "elsewhere", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"), join(dir, "repo", "link"));
    const root = join(dir, "repo");
    // Lexically this is /dev/null; physically it is a file below the symlink target.
    const target = `link/${"../".repeat(root.split("/").length)}dev/null`;
    const inside = (p: string): boolean => p.startsWith(`${root}/`);
    const decide = (cmd: string) => decideWrites(analyzeWrites(cmd, { root }), [], root, { boundary: inside });
    expect(decide(`echo x > ${target}`)).toMatchObject({ allowed: false, kind: "outside_project" });
    for (const cmd of ["echo x > /dev/null", "echo x > /dev/stdout", "echo x 2>/dev/stderr", "echo x > /dev/tty"]) expect(decide(cmd), cmd).toEqual({ allowed: true });
  });
  it("keeps the public decision shape of checkBashCommandWrites", () => {
    expect(checkBashCommandWrites("echo x > /etc/x", policy, agent)).toEqual({ allowed: false, reason: expect.stringContaining("outside the project") });
  });
  it("leaves decideWrites without a boundary unchanged", () => {
    const analysis = analyzeWrites("echo x > /etc/x", { root: project });
    expect(decideWrites(analysis, [], project)).toEqual({ allowed: true });
    expect(decideWrites(analysis, [], project, { boundary: () => false })).toMatchObject({ allowed: false, kind: "outside_project" });
  });
});
