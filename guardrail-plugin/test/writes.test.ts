import { linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { evaluate } from "../src/evaluate.js";
import { runHook } from "../src/hook.js";
import { checkCommandTool } from "../src/mcp/tools.js";
import {
  analyzeWrites,
  checkBashWrites,
  decideWrites,
  cleanPath,
  codeLanguage,
  dangerousGitKey,
  GIT_PROTECTED_PATHS,
  globMayMatch,
  normalizeAbsolute,
  pathHit,
  physicalPath,
  temporaryTarget,
  writeIndicator,
} from "../src/writes.js";
import { defaultPolicy } from "./helpers.js";

// Shared with the Python port: both implementations must decide identically.
const cases = JSON.parse(readFileSync(new URL("./fixtures/command-cases.json", import.meta.url), "utf8")) as {
  writes: { root: string; cwd: string; home: string; tmpdir: string; dirs: string[]; protected: string[]; block: string[]; allow: string[] };
};
const w = cases.writes;
const fixtureOpts = { root: w.root, cwd: w.cwd, home: w.home, tmpdir: w.tmpdir, isDir: (p: string) => w.dirs.includes(p) };

describe("Bash write targets (shared cases)", () => {
  it("has a substantial case list", () => {
    expect(w.block.length).toBeGreaterThanOrEqual(100);
    expect(w.allow.length).toBeGreaterThanOrEqual(50);
  });
  it.each(w.block)("blocks %j", (cmd) => expect(checkBashWrites(cmd, w.protected, fixtureOpts).allowed).toBe(false));
  it.each(w.allow)("allows %j", (cmd) => expect(checkBashWrites(cmd, w.protected, fixtureOpts).allowed).toBe(true));
});

describe("analyzeWrites", () => {
  const opts = { root: "/r", home: "/h", isDir: (p: string) => p === "/r/src" };
  const findings = (cmd: string) => analyzeWrites(cmd, opts).findings.map((f) => [f.kind, f.value]);

  it("reports redirect targets but not fd duplications, fd prefixes or reads", () => {
    expect(findings("cmd 2>&1 >out <in 2>err 3>&- >&file")).toEqual([
      ["path", "/r/out"],
      ["path", "/r/err"],
      ["path", "/r/file"],
    ]);
  });
  it("resolves cp/mv destinations including directories and -t", () => {
    expect(findings("cp a src")).toEqual([["path", "/r/src/a"]]);
    expect(findings("cp a b")).toEqual([["path", "/r/b"]]);
    expect(findings("cp -t d x y")).toEqual([["path", "/r/d/x"], ["path", "/r/d/y"]]);
    expect(findings("mv a b")).toEqual([["path", "/r/a"], ["path", "/r/b"]]);
    expect(findings("ln -s /x/target")).toEqual([["path", "/x/target"], ["link", "/r/target"], ["path", "/r/target"]]);
    expect(findings('cp -t d/ "$X"')).toEqual([["dynamic", "$X"], ["path", "/r/d"]]);
    expect(findings('cp "$X" d/')).toEqual([["dynamic", "$X"], ["path", "/r/d"]]);
  });
  it("classifies dynamic, opaque and glob targets", () => {
    expect(findings('rm "$F" $(ls) *.log ~/x ~other/y')).toEqual([
      ["dynamic", "$F"],
      ["opaque", "$(ls)"],
      ["glob", "/r/*.log"],
      ["path", "/h/x"],
      ["dynamic", "~other/y"],
    ]);
    expect(analyzeWrites("rm ~/x", { root: "/r" }).findings).toEqual([{ kind: "dynamic", value: "~/x", via: "rm" }]);
  });
  it("follows cd into every candidate directory and gives up on unknown ones", () => {
    expect(findings("cd a && cd b && touch x")).toEqual([["path", "/r/x"], ["path", "/r/a/x"], ["path", "/r/b/x"], ["path", "/r/a/b/x"]]);
    expect(findings('cd "$D" && touch x')).toEqual([["dynamic", "x"]]);
    expect(findings("cd - && touch x")).toEqual([["dynamic", "x"]]);
    expect(findings("cd && touch x")).toEqual([["path", "/r/x"], ["path", "/h/x"]]);
    expect(analyzeWrites("cd && touch x", { root: "/r" }).findings).toEqual([{ kind: "dynamic", value: "x", via: "touch" }]);
  });
  it("uses the tool working directory as an additional base", () => {
    const f = analyzeWrites("touch x", { root: "/r", cwd: "/r/sub" }).findings.map((x) => x.value);
    expect(f).toEqual(["/r/x", "/r/sub/x"]);
    expect(analyzeWrites("touch x", { root: "/r", cwd: "relative" }).findings.map((x) => x.value)).toEqual(["/r/x"]);
  });
  it("fails closed on too many directory changes and deep nesting", () => {
    const many = Array.from({ length: 8 }, (_, i) => `cd d${i}`).join(" && ");
    expect(findings(`${many} && touch x`)).toContainEqual(["opaque", "too many directory changes"]);
    expect(findings(`bash -c "bash -c 'touch y'"`)).toEqual([["path", "/r/y"]]);
    let deep = "touch z";
    for (let i = 0; i < 10; i += 1) deep = `bash -c ${JSON.stringify(deep).replace(/\$/g, "\\$")}`;
    expect(findings(deep)).toContainEqual(["opaque", "nested inline scripts"]);
  });
  it("treats unparseable inline scripts and env -S edge cases as opaque", () => {
    expect(findings("bash -c 'echo \"x'")).toEqual([["opaque", "unparseable inline script"]]);
    expect(findings('env -S "$X" a')).toEqual([["assign", ""], ["opaque", "$X"]]);
    expect(findings("env -S 'a; b'")).toEqual([["opaque", "a; b"]]);
    expect(findings("env -S \"'x\"")).toEqual([["opaque", "'x"]]);
    expect(findings("env -S 'rm -f' x")).toEqual([["path", "/r/x"]]);
  });
  it("throws ShellSyntaxError at top level", () => {
    expect(() => analyzeWrites("echo 'x", opts)).toThrow("unterminated single quote");
  });
  it("reports inline code and treats code from pipes, files and fds as opaque", () => {
    expect(findings("python3 -c 'print(1)'")).toEqual([["code", "print(1)"]]);
    expect(findings("cat x | node")).toEqual([["opaque", "code from a pipe"]]);
    expect(findings("python3 x.py")).toEqual([]);
    expect(findings("python3 -m http.server")).toEqual([]);
    expect(findings("python3 < x.py")).toEqual([["opaque", "code from x.py"]]);
    expect(findings("python3 < /dev/null")).toEqual([]);
    expect(findings("perl < x.pl")).toEqual([["opaque", "code from x.pl"]]);
    expect(findings("php -r 'x();'")).toEqual([["code", "x();"]]);
    expect(findings("php")).toEqual([["opaque", "code from a pipe"]]);
    expect(findings("php -f x.php")).toEqual([]);
    expect(findings("deno eval 'x'")).toEqual([["code", "x"]]);
    expect(findings("node -r m --eval=1 -p 2")).toEqual([["code", "1"], ["code", "2"]]);
    expect(findings("node script.js -e x")).toEqual([]);
    expect(findings("node \"$S\"")).toEqual([["opaque", "$S"]]);
    expect(findings("bun run x.ts")).toEqual([]);
    expect(findings("ruby <<< 'puts 1'")).toEqual([["code", "puts 1"]]);
    expect(findings("bash x.sh")).toEqual([]);
    expect(findings("bash -c")).toEqual([]);
    expect(findings("cat x | bash -s")).toEqual([["opaque", "script from a pipe"]]);
    expect(findings("bash < x.sh")).toEqual([["opaque", "script from x.sh"]]);
    expect(findings("bash -s < /dev/null")).toEqual([]);
    expect(findings("bash -s a <<< 'touch b'")).toEqual([["path", "/r/b"]]);
    expect(findings("source x.sh")).toEqual([]);
    expect(findings("source")).toEqual([]);
    expect(findings("source /dev/stdin <<< 'touch c'")).toEqual([["path", "/r/c"]]);
    expect(findings("source /dev/stdin")).toEqual([["opaque", "script from a pipe"]]);
    expect(findings("bash -o pipefail -c 'touch a'")).toEqual([["path", "/r/a"]]);
  });
  it("follows shell constructs that run strings", () => {
    expect(findings("function f { touch a; }")).toEqual([["path", "/r/a"]]);
    expect(findings("coproc touch a")).toEqual([["path", "/r/a"]]);
    expect(findings("coproc n { touch a; }")).toEqual([["path", "/r/a"]]);
    expect(findings("trap 'touch a' EXIT")).toEqual([["path", "/r/a"]]);
    expect(findings("trap \"$H\" EXIT")).toEqual([["opaque", "$H"]]);
    expect(findings("trap '' INT")).toEqual([]);
    expect(findings("trap INT")).toEqual([]);
    expect(findings("alias a='touch a' b")).toEqual([["path", "/r/a"]]);
    expect(findings("alias \"$A\"")).toEqual([["opaque", "$A"]]);
    expect(findings("complete -C 'touch a' x")).toEqual([["path", "/r/a"]]);
    expect(findings("enable -f x.so y")).toEqual([["opaque", "enable -f"]]);
    expect(findings("enable -n echo")).toEqual([]);
    expect(findings("PS1='$(touch a)'")).toEqual([["opaque", "PS1=$(touch a)"]]);
    expect(findings("command -p cd w && touch a")).toEqual([["path", "/r/a"], ["path", "/r/w/a"]]);
    expect(findings("command -V rm")).toEqual([]);
    expect(findings("sudo -s")).toEqual([]);
    expect(findings("sudo -s \"$X\"")).toEqual([["opaque", "$X"]]);
  });
  it("models wrappers, downloaders and git subcommands that write", () => {
    expect(findings("taskset -p 1 2")).toEqual([]);
    expect(findings("strace -p 1")).toEqual([]);
    expect(findings("setarch x86_64 -R touch a")).toEqual([["path", "/r/a"]]);
    expect(findings("watch")).toEqual([]);
    expect(findings("xvfb-run -f auth touch a")).toEqual([["path", "/r/auth"], ["path", "/r/a"]]);
    expect(findings("unknown x touch a")).toEqual([["path", "/r/a"]]);
    expect(findings("gh pr view 9")).toEqual([]);
    expect(findings("echo rm a")).toEqual([]);
    expect(findings("curl -o - https://x")).toEqual([]);
    expect(findings("curl --output-dir d -O https://x")).toEqual([["path", "/r/d"]]);
    expect(findings("curl --output-dir d -o /abs https://x")).toEqual([["path", "/abs"]]);
    expect(findings("curl -D h -c - https://x")).toEqual([["path", "/r/h"]]);
    expect(findings("wget --spider https://x")).toEqual([]);
    expect(findings("wget -O - https://x")).toEqual([]);
    expect(findings("wget -o log https://x")).toEqual([["path", "/r/log"], ["path", "/r"]]);
    expect(findings("wget -i list")).toEqual([["opaque", "wget -e/-i/--config"], ["path", "/r"]]);
    expect(findings("git archive -o out.tgz HEAD")).toEqual([["path", "/r/out.tgz"]]);
    expect(findings("git diff --output out.txt")).toEqual([["path", "/r/out.txt"]]);
    expect(findings("git bisect start")).toEqual([]);
    expect(findings("git submodule foreach --recursive 'touch a'")).toEqual([["path", "/r/a"]]);
    expect(findings("git submodule update")).toEqual([]);
    expect(findings("git bundle verify x")).toEqual([]);
    expect(findings("git worktree list")).toEqual([]);
    expect(findings("git clone https://h/o/repo.git")).toEqual([["path", "/r/repo"]]);
    expect(findings("git clone \"$U\"")).toEqual([["dynamic", "$U"]]);
    expect(findings("git init sub")).toEqual([["path", "/r/sub"]]);
    expect(findings("git config -f x --unset a.b")).toEqual([["path", "/r/x"]]);
  });  it("handles awk, sed, tar, unzip, dd, find and git specifics", () => {
    expect(findings("awk -f p.awk f")).toEqual([]);
    expect(findings("gawk -e '{print}' -i inplace f")).toEqual([["code", "{print}"], ["path", "/r/f"]]);
    expect(findings("sed -f s.sed f")).toEqual([]);
    expect(findings("tar -x -O -f a.tar")).toEqual([]);
    expect(findings("tar -cf - src")).toEqual([]);
    expect(findings("unzip -d out a.zip")).toEqual([["path", "/r/out"]]);
    expect(findings("dd if=a of=b")).toEqual([["path", "/r/b"]]);
    expect(findings("find -L src -D tree -delete")).toEqual([["path", "/r/src"]]);
    expect(findings("find /abs \"$D\" -delete")).toEqual([["path", "/abs"], ["dynamic", "$D"]]);
    expect(findings("find src -execdir touch {} x ;")).toEqual([["path", "/r/src"], ["dynamic", "x"]]);
    expect(findings("git --git-dir=x checkout -- a")).toEqual([["git", "--git-dir"], ["path", "/r/a"]]);
    expect(findings("git checkout --pathspec-from-file=f")).toEqual([["opaque", "--pathspec-from-file"]]);
    expect(findings("git checkout -- \"$P\"")).toEqual([["dynamic", "$P"]]);
    expect(findings("git am --abort")).toEqual([]);
    expect(findings("git status")).toEqual([]);
    expect(findings("git \"$SUB\" x")).toEqual([["opaque", "$SUB"]]);
    expect(findings("git mv a src")).toEqual([["path", "/r/a"], ["path", "/r/src/a"]]);
  });
  it("handles wrappers, xargs and copy edge cases", () => {
    expect(findings("time -p touch a")).toEqual([["path", "/r/a"]]);
    expect(findings("xargs")).toEqual([]);
    expect(findings("xargs -i cp {} /tmp/")).toEqual([["opaque", "<xargs input>"], ["path", "/tmp"]]);
    expect(findings("cp -T a b")).toEqual([["path", "/r/b"]]);
    expect(findings("cp a")).toEqual([]);
    expect(findings("mv -t d a")).toEqual([["path", "/r/a"], ["path", "/r/d/a"]]);
    expect(findings("cp a/ /abs/")).toEqual([["path", "/abs/a"]]);
    expect(findings("cp / d/")).toEqual([["path", "/r/d"]]);
    expect(findings("cp *.ts d/")).toEqual([["glob", "/r/d/*.ts"]]);
    expect(findings('"$CMD" > out')).toEqual([["path", "/r/out"], ["opaque", "$CMD"]]);
    expect(findings("ls > >(tee /tmp/x)")).toEqual([["path", "/tmp/x"]]);
    expect(findings("echo > ''")).toEqual([]);
  });
});

describe("decision helpers", () => {
  const patterns = ["policies/", "AGENTS.md", ...GIT_PROTECTED_PATHS];
  it("normalizes absolute paths lexically", () => {
    expect(normalizeAbsolute("//a/./b/../c/")).toBe("/a/c");
    expect(normalizeAbsolute("/../..")).toBe("/");
  });
  it("matches paths, ancestors and the project root", () => {
    expect(pathHit("/r/policies/x", ["/r"], patterns)).toBe("policies/");
    expect(pathHit("/r/policies", ["/r"], patterns)).toBe("policies/");
    expect(pathHit("/r/.git", ["/r"], patterns)).toBe(".git/config");
    expect(pathHit("/r", ["/r"], patterns)).toBe("policies/");
    expect(pathHit("/", ["/r"], patterns)).toBe("policies/");
    expect(pathHit("/r/AGENTS.md.bak", ["/r"], patterns)).toBeUndefined();
    expect(pathHit("/other/AGENTS.md", ["/r"], patterns)).toBeUndefined();
    expect(pathHit("/r", ["/r"], [])).toBeUndefined();
  });
  it("matches globs segment-wise with dotfile, bracket, globstar and brace handling", () => {
    expect(globMayMatch("/r/*.md", "/r/AGENTS.md", false, false)).toBe(true);
    expect(globMayMatch("/r/*/x", "/r/.github", true, false)).toBe(false);
    expect(globMayMatch("/r/*/x", "/r/.github", true, true)).toBe(true);
    expect(globMayMatch("/r/[A]GENTS.md", "/r/AGENTS.md", false, false)).toBe(true);
    expect(globMayMatch("/r/[!x]GENTS.md", "/r/AGENTS.md", false, false)).toBe(true);
    expect(globMayMatch("/r/[]x]GENTS.md", "/r/AGENTS.md", false, false)).toBe(true);
    expect(globMayMatch("/r/a[b", "/r/a[b", false, false)).toBe(true);
    expect(globMayMatch("/r/**/x.md", "/r/docs/a/x.md", false, false)).toBe(true);
    expect(globMayMatch("/r/**", "/r/policies", true, false)).toBe(true);
    expect(globMayMatch("/r/src/{a,b}", "/r/policies", true, false)).toBe(false);
    expect(globMayMatch("/r/{a,b}", "/r/policies", true, false)).toBe(true);
    expect(globMayMatch("/r/*.log", "/r/AGENTS.md", false, false)).toBe(false);
    expect(globMayMatch("/r/x*y*z", "/r/xaybz", false, false)).toBe(true);
    expect(globMayMatch("/r/x*y", "/r/xab", false, false)).toBe(false);
    expect(globMayMatch("/r/*/*/deep", "/r/AGENTS.md", false, false)).toBe(false);
  });
  it("detects write-capable APIs per language and keeps reads allowed", () => {
    expect(codeLanguage("python3")).toBe("python");
    expect(codeLanguage("deno eval")).toBe("js");
    expect(codeLanguage("gawk -i inplace")).toBe("awk");
    expect(codeLanguage("sed")).toBe("sed");
    expect(codeLanguage("lua")).toBe("unknown");
    expect(writeIndicator("open('x','w')", "python")).toBe(true);
    expect(writeIndicator("open('x', mode='a')", "python")).toBe(true);
    expect(writeIndicator("print(open('README.md').read())", "python")).toBe(false);
    expect(writeIndicator("getattr(os, 'remove')('x')", "python")).toBe(true);
    expect(writeIndicator("fs.readFileSync('x')", "js")).toBe(false);
    expect(writeIndicator("fs.promises.rm('x')", "js")).toBe(true);
    expect(writeIndicator("open(F, '>x')", "perl")).toBe(true);
    expect(writeIndicator("print while <>", "perl")).toBe(false);
    expect(writeIndicator("puts File.read('x')", "ruby")).toBe(false);
    expect(writeIndicator("echo file_get_contents('x');", "php")).toBe(false);
    expect(writeIndicator("{ print $1 }", "awk")).toBe(false);
    expect(writeIndicator("{ print | \"sh\" }", "awk")).toBe(true);
    expect(writeIndicator("/w/p", "sed")).toBe(false);
    expect(writeIndicator("s/a/b/w out", "sed")).toBe(true);
    expect(writeIndicator("anything", "unknown")).toBe(true);
  });
  it("classifies command-executing git configuration keys", () => {
    for (const key of ["core.fsmonitor", "Core.SshCommand", "alias.st", "filter.lfs.clean", "credential.helper", "diff.x.textconv", "include.path", "includeIf.gitdir:/x/.path"]) {
      expect(dangerousGitKey(key)).toBe(true);
    }
    for (const key of ["user.name", "color.ui", "core.quotepath", "x"]) expect(dangerousGitKey(key)).toBe(false);
  });
  it("accepts only plain targets below an untouched $TMPDIR", () => {
    expect(temporaryTarget("$TMPDIR/x", "echo > $TMPDIR/x")).toBe(true);
    expect(temporaryTarget("${TMPDIR}/a/b", "x ${TMPDIR}/a/b")).toBe(true);
    expect(temporaryTarget("$TMPDIR/../x", "$TMPDIR/../x")).toBe(false);
    expect(temporaryTarget("$TMPDIR/$X", "$TMPDIR/$X")).toBe(false);
    expect(temporaryTarget("$TMPDIR/x", "TMPDIR=/r; echo > $TMPDIR/x")).toBe(false);
    expect(temporaryTarget("$HOME/x", "$HOME/x")).toBe(false);
  });
  it("fails closed on unresolvable paths and names the construct", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "tg-wloop-")));
    symlinkSync(join(dir, "b"), join(dir, "a"));
    symlinkSync(join(dir, "a"), join(dir, "b"));
    const d = decideWrites({ findings: [{ kind: "path", value: join(dir, "a", "x"), via: "rm" }], texts: [] }, [], dir);
    expect(d).toEqual({ allowed: false, reason: expect.stringContaining("cannot be resolved safely") });
    const p = decideWrites({ findings: [{ kind: "patch", value: "patch", via: "patch" }], texts: [] }, [], "/r");
    expect(p).toEqual({ allowed: false, reason: expect.stringContaining("patch can write any file") });
    const c = decideWrites({ findings: [{ kind: "code", value: "fs.writeFileSync('x')", via: "node" }], texts: [] }, [], "/r");
    expect(c).toEqual({ allowed: false, reason: expect.stringContaining("Inline code (node)") });
    const r = decideWrites({ findings: [{ kind: "stdin", value: "", via: "node" }, { kind: "assign", value: "", via: "x" }], texts: [] }, [], "/r");
    expect(r).toEqual({ allowed: true });
    const g = decideWrites({ findings: [{ kind: "glob", value: `${dir}/a/../*`, via: "rm" }], texts: [] }, [], dir);
    expect(g).toEqual({ allowed: false, reason: expect.stringContaining("cannot be resolved safely") });
  });
  it("reports parse errors as fail-closed decisions", () => {
    expect(checkBashWrites("echo 'x", [], { root: "/r" })).toEqual({
      allowed: false,
      reason: expect.stringContaining("unterminated single quote"),
    });
  });
});

describe("Bash write check on a real filesystem", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "tg-wfs-")));
  mkdirSync(join(dir, ".github"));
  mkdirSync(join(dir, "src"));
  writeFileSync(join(dir, "AGENTS.md"), "rules");
  symlinkSync(join(dir, ".github"), join(dir, "gh"));
  symlinkSync(join(dir, "AGENTS.md"), join(dir, "notes.md"));
  const policy = defaultPolicy();
  const agent = { projectDir: dir, humanSession: false };
  const bash = (command: string, ctx: Parameters<typeof evaluate>[2] = agent) =>
    evaluate({ tool_name: "Bash", tool_input: { command } }, policy, ctx).allowed;

  it("blocks writes through symlinks to protected paths", () => {
    expect(bash("echo x > gh/workflows/x.yml")).toBe(false);
    expect(bash("sed -i s/a/b/ notes.md")).toBe(false);
  });
  it("uses existing directories as copy destinations", () => {
    expect(bash("cp a.ts src")).toBe(true);
    expect(bash("cp a.ts .github")).toBe(false);
  });
  it("lifts the write check in a human session and keeps command rules", () => {
    expect(bash("echo x > AGENTS.md", { ...agent, humanSession: true })).toBe(true);
    expect(bash("git push --force", { ...agent, humanSession: true })).toBe(false);
  });
  it("checks relative targets against the tool working directory", () => {
    expect(bash("touch workflows/x.yml", { ...agent, cwd: join(dir, ".github") })).toBe(false);
    expect(bash("touch workflows/x.yml")).toBe(true);
  });
  it("protects git configuration and hooks for write tools too", () => {
    expect(evaluate({ tool_name: "Write", tool_input: { file_path: join(dir, ".git", "config"), content: "" } }, policy, agent).allowed).toBe(false);
    expect(evaluate({ tool_name: "Write", tool_input: { file_path: join(dir, ".git", "hooks", "pre-commit"), content: "" } }, policy, agent).allowed).toBe(false);
    expect(evaluate({ tool_name: "Write", tool_input: { file_path: join(dir, ".git", "index.lock"), content: "" } }, policy, agent).allowed).toBe(true);
  });
  it("passes cwd and HOME from the hook input", () => {
    const event = (command: string, cwd?: unknown) => JSON.stringify({ tool_name: "Bash", tool_input: { command }, cwd });
    const env = { CLAUDE_PROJECT_DIR: dir, HOME: join(dir, "home") };
    expect(runHook(event("touch workflows/x.yml", join(dir, ".github")), env, "/").code).toBe(2);
    expect(runHook(event("touch workflows/x.yml", "relative/dir"), env, "/").code).toBe(0);
    expect(runHook(event("touch workflows/x.yml", 42), env, "/").code).toBe(0);
    expect(runHook(event("touch ~/../AGENTS.md"), env, "/").code).toBe(2);
    expect(runHook(event("echo x > AGENTS.md"), { ...env, TOLLGATE_HUMAN_SESSION: "1" }, "/").code).toBe(0);
  });
  it("applies the write check in the MCP check_command tool when the project is known", () => {
    const text = (r: { content: { text: string }[] }) => JSON.parse(r.content[0]?.text ?? "{}") as { allowed: boolean };
    expect(text(checkCommandTool(policy, "echo x > AGENTS.md", dir)).allowed).toBe(false);
    expect(text(checkCommandTool(policy, "echo x > AGENTS.md")).allowed).toBe(true);
    expect(text(checkCommandTool(policy, "git push --force", dir)).allowed).toBe(false);
  });
});

describe("links, physical paths, home files and extra protected paths", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "tg-wlink-")));
  const home = realpathSync(mkdtempSync(join(tmpdir(), "tg-whome-")));
  mkdirSync(join(dir, ".github", "workflows"), { recursive: true });
  mkdirSync(join(dir, "src"));
  writeFileSync(join(dir, "AGENTS.md"), "rules");
  writeFileSync(join(dir, "src", "a.ts"), "x");
  symlinkSync(join(dir, ".github", "workflows"), join(dir, "w"));
  symlinkSync("src", join(dir, "rel"));
  linkSync(join(dir, "AGENTS.md"), join(dir, "alias.md"));
  const opts = { root: dir, home };
  const check = (cmd: string, extra: string[] = []) => checkBashWrites(cmd, ["AGENTS.md", ".github/"], opts, extra).allowed;

  it("resolves .. physically after a symlink", () => {
    expect(physicalPath(`${dir}/w/../CODEOWNERS`)).toBe(join(dir, ".github", "CODEOWNERS"));
    expect(physicalPath(join(dir, "rel", "a.ts"))).toBe(join(dir, "src", "a.ts"));
    expect(physicalPath("/nonexistent/../x")).toBe("/x");
    expect(cleanPath("/a/./b/../c")).toBe("/a/b/../c");
    expect(check("echo x > w/../CODEOWNERS")).toBe(false);
    expect(check("echo x > rel/../src/b.ts")).toBe(true);
    expect(check("rm -f w/../*.yml")).toBe(false);
  });
  it("fails closed on symlink loops", () => {
    symlinkSync(join(dir, "loop2"), join(dir, "loop1"));
    symlinkSync(join(dir, "loop1"), join(dir, "loop2"));
    expect(() => physicalPath(join(dir, "loop1", "x"))).toThrow("Too many symlink levels");
    expect(check("echo x > loop1/x")).toBe(false);
  });
  it("refuses writes to files with several hard links", () => {
    expect(check("echo x >> alias.md")).toBe(false);
    expect(check("echo x >> src/a.ts")).toBe(true);
  });
  it("protects configuration files in the home directory", () => {
    expect(check("echo x >> ~/.bashrc")).toBe(false);
    expect(check(`echo x > ${home}/.gitconfig`)).toBe(false);
    expect(check("rm -f ~/.ssh/*")).toBe(false);
    expect(check("echo x > ~/notes.txt")).toBe(true);
  });
  it("protects extra absolute paths such as the active policy file", () => {
    const policyFile = join(home, "policy.json");
    expect(check(`echo x > ${policyFile}`, [policyFile])).toBe(false);
    expect(check(`rm -f ${home}/*.json`, [policyFile])).toBe(false);
    expect(check(`echo x > ${policyFile}`)).toBe(true);
  });
  it("blocks writes through links created earlier in the same command line", () => {
    expect(check("ln -s /tmp/x gh2 && echo x > gh2/y")).toBe(false);
    expect(check("ln -s /tmp/x gh2 && rm -f gh2/*")).toBe(false);
    expect(check("ln -s /tmp/x gh2")).toBe(true);
  });
});

describe("write tools outside the project and hard links", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "tg-wtool-")));
  writeFileSync(join(dir, "AGENTS.md"), "rules");
  writeFileSync(join(dir, "b.md"), "x");
  linkSync(join(dir, "AGENTS.md"), join(dir, "alias.md"));
  const policy = defaultPolicy();
  const ctx = { projectDir: dir, humanSession: false, tmpdir: "/tmp/tg-nonexistent-tmp" };
  const write = (file_path: string, c: Parameters<typeof evaluate>[2] = ctx) =>
    evaluate({ tool_name: "Write", tool_input: { file_path, content: "" } }, policy, c).allowed;
  it("allows temporary directories and blocks other paths outside the project", () => {
    expect(write("/tmp/tg-out.txt")).toBe(true);
    expect(write("/var/tmp/tg-out.txt")).toBe(true);
    expect(write("/etc/tg-out.txt")).toBe(false);
    expect(write("/tmp/tg-nonexistent-tmp/x", { ...ctx, tmpdir: "/tmp/tg-nonexistent-tmp" })).toBe(true);
    // A TMPDIR outside the fixed temporary roots is ignored.
    expect(write("/nonexistent-tmp/x", { ...ctx, tmpdir: "/nonexistent-tmp" })).toBe(false);
    expect(write("/tmp/../etc/x")).toBe(false);
    expect(write(dir)).toBe(false);
    expect(write("/tmp")).toBe(false);
  });
  it("refuses files with several hard links and the active policy file", () => {
    expect(write(join(dir, "alias.md"))).toBe(false);
    expect(write(join(dir, "b.md"))).toBe(true);
    expect(write(join(dir, "b.md"), { ...ctx, policyFile: join(dir, "b.md") })).toBe(false);
    expect(write(join(dir, ".tollgate", "policy.json"))).toBe(false);
  });
});

describe("TMPDIR exception, process paths and size cap", () => {
  const analysis = analyzeWrites('echo x > "$TMPDIR/y"', { root: "/fakeroot/repo" });
  it("requires an absolute TMPDIR below a temporary root, outside the project and not protected", () => {
    expect(decideWrites(analysis, [], "/fakeroot/repo", { tmpdir: "/tmp/tg-fakeroot-tmp" }).allowed).toBe(true);
    for (const tmpdir of [undefined, "relative", "/fakeroot/repo/tmp", "/fakeroot", "/", "/fakeroot/tmp"]) {
      expect(decideWrites(analysis, [], "/fakeroot/repo", { tmpdir }).allowed).toBe(false);
    }
    expect(decideWrites(analysis, [], "/fakeroot/repo", { tmpdir: "/fakeroot/home/.ssh", home: "/fakeroot/home" }).allowed).toBe(false);
    // Same rules for a TMPDIR below /tmp: protected, the project itself, inside it or an ancestor of it.
    expect(decideWrites(analysis, [], "/fakeroot/repo", { tmpdir: "/tmp/tg-fakehome/.ssh", home: "/tmp/tg-fakehome" }).allowed).toBe(false);
    for (const tmpdir of ["/tmp", "/tmp/tg-fakerepo", "/tmp/tg-fakerepo/tmp"]) {
      expect(decideWrites(analysis, [], "/tmp/tg-fakerepo", { tmpdir }).allowed).toBe(false);
    }
  });
  it("blocks process and fd paths but allows the standard devices", () => {
    const check = (cmd: string) => checkBashWrites(cmd, [], { root: "/fakeroot/repo" }).allowed;
    expect(check("echo x > /proc/self/fd/1")).toBe(false);
    expect(check("echo x > /dev/fd/4")).toBe(false);
    expect(check("rm -f /proc/*/x")).toBe(false);
    expect(check("echo x > /dev/null 2>/dev/stderr")).toBe(true);
    expect(check("echo x > /dev/tty")).toBe(true);
  });
  it("blocks commands above the size cap in the write check and in evaluate", () => {
    const long = `echo ${"x".repeat(70000)}`;
    expect(checkBashWrites(long, [], { root: "/r" })).toEqual({ allowed: false, reason: expect.stringContaining("longer than 32768 bytes") });
    expect(evaluate({ tool_name: "Bash", tool_input: { command: long } }, defaultPolicy(), { projectDir: "/r", humanSession: true }).allowed).toBe(false);
  });
});
