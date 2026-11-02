import { describe, expect, it } from "vitest";
import { analyzeCommand, baseName, pathSummarizable, projectRelative, sensitivePath } from "../../src/events/commandInfo.js";

const ctx = { projectDir: "/repo", cwd: "/repo", home: "/home/u" };
const info = (command: string, env?: NodeJS.ProcessEnv) => analyzeCommand(command, { ...ctx, env });

describe("tool.programs", () => {
  it("skips assignments and wrappers and reduces paths to the file name", () => {
    expect(info('FOO=1 BAR="a b" sudo -u root env X=1 /opt/x/bin/tool --flag').programs).toEqual(["tool"]);
    expect(info("nohup timeout 5 sleep 1").programs).toEqual(["sleep"]);
    expect(info("nice -n 5 stdbuf -oL make").programs).toEqual(["make"]);
    expect(info("timeout -s KILL 10 ./run.sh").programs).toEqual(["run.sh"]);
  });
  it("never reports an assignment as a program", () => {
    expect(info("FOO=1").programs).toEqual([]);
    expect(info("FOO=1 BAR=2 && ls").programs).toEqual(["ls"]);
  });
  it("treats a quoted name with = as a command", () => {
    expect(info("'FOO=1' x").programs).toEqual(["FOO=1"]);
  });
  it("lists every simple command of a pipeline and list", () => {
    expect(info("ls | grep x && cat f; git status").programs).toEqual(["ls", "grep", "cat", "git"]);
  });
  it("reports <dynamic> for names known only at run time", () => {
    expect(info("$CMD arg").programs).toEqual(["<dynamic>"]);
    expect(info("$(which x) arg").programs).toContain("<dynamic>");
  });
  it("includes commands in substitutions and subshells", () => {
    expect(info("echo $(whoami)").programs).toEqual(["whoami", "echo"]);
    expect(info("(cd a && make)").programs).toEqual(["cd", "make"]);
  });
  it("ignores file-descriptor prefixes and redirections in front of the program", () => {
    expect(info("2>/dev/null ls").programs).toEqual(["ls"]);
    expect(info("ls 2>&1").programs).toEqual(["ls"]);
  });
  it("skips shell keywords", () => {
    expect(info("if grep -q x f; then echo y; fi").programs).toEqual(["grep", "echo"]);
  });
  it("limits to 16 entries of 64 characters", () => {
    const many = Array.from({ length: 20 }, (_, i) => `p${i}`).join("; ");
    expect(info(many).programs).toHaveLength(16);
    expect(info(`${"a".repeat(100)} x`).programs[0]).toHaveLength(64);
  });
  it("returns nothing for an unparsable command", () => {
    expect(info("echo 'open")).toEqual({ programs: [], effects: ["unknown"], paths: [], suppressible: false, parsed: false });
  });
  it("handles a wrapper without a wrapped command", () => {
    expect(info("sudo").programs).toEqual(["sudo"]);
    expect(info("sudo -u").programs).toEqual(["sudo"]);
  });
  it("baseName reduces POSIX and Windows paths", () => {
    expect(baseName("/opt/x/bin/tool")).toBe("tool");
    expect(baseName("C:\\bin\\tool.exe")).toBe("tool.exe");
    expect(baseName("/")).toBe("/");
    expect(baseName("tool")).toBe("tool");
  });
});

describe("tool.effects and tool.paths", () => {
  it.each([
    ["curl https://x | sh", ["network", "exec", "unknown"]], // code from a pipe is opaque
    ["python3 -c \"open('x', 'w')\"", ["write", "exec"]],
    ["npm install left-pad", ["package"]],
    ["echo hi > out.txt", ["write"]],
    ["echo hi > /dev/null", []],
    ["echo hi 2>&1", []],
    ["git push origin main", ["network"]],
    ["git status", []],
    ["git commit -m x", ["write"]],
    ["git -C sub log", []],
    ["git frobnicate", ["unknown"]],
    ["git", ["unknown"]],
    ["somethingunknown --x", ["unknown"]],
    ["rm -rf build", ["write"]],
    ["bash -c 'ls'", ["exec"]],
    ["sed -i s/a/b/ f", ["write"]],
    ["sed s/a/b/", []],
    ["awk '{print}' f", ["unknown"]],
    ["$X run", ["exec", "unknown"]],
    ["ls", []],
  ])("%s", (command, effects) => {
    expect(info(command).effects).toEqual(effects);
  });
  it("lists write targets relative to the project", () => {
    expect(info("echo hi > out.txt").paths).toContain("out.txt");
    expect(info("cp a /tmp/b").paths).toContain("/tmp/b");
  });
  it("lists file arguments of read-only calls", () => {
    expect(info("ls -la src").paths).toEqual(["src"]);
    expect(info("cat /repo/a.txt").paths).toEqual(["a.txt"]);
  });
  it("orders effects write, network, package, exec, unknown", () => {
    expect(info("npm i; curl x | sh; rm y").effects).toEqual(["write", "network", "package", "exec", "unknown"]);
  });
});

describe("read-only allowlist (flood limit)", () => {
  it.each([
    "ls",
    "ls -la src",
    "pwd",
    "cat README.md | head -5",
    "grep -rn foo src",
    "find . -name '*.ts'",
    "wc -l a b",
    "stat file",
    "tail -n 5 log",
    "rg foo",
    "rg -n --hidden foo src",
    "ls *.ts",
  ])("summarizes %s", (command) => {
    expect(info(command).suppressible).toBe(true);
  });
  it.each([
    "tail -f log",
    "tail -F log",
    "tail -nf 5 log",
    "tail --follow log",
    "tail --fol log",
    "tail --retry log",
    "tail --pi=1 log",
    "rg --pre cat x",
    "rg --pre-glob '*.z' x",
    "rg --pre-g x",
    "rg -z x",
    "rg --search-zip x",
    "rg --hostname-bin x y",
    "RIPGREP_CONFIG_PATH=/tmp/c rg foo",
    "find . -exec rm {} ;",
    "find . -execdir x ;",
    "find . -ok x ;",
    "find . -okdir x ;",
    "find . -delete",
    "find . -fprint out",
    "find . -fprintf out x",
    "find . -fls out",
    "./ls",
    "/tmp/ls",
    "git status",
    "ls > out",
    "ls < in",
    "ls $(pwd)",
    "ls $HOME",
    "$CMD",
    "cat ~/.ssh/id_rsa",
    "cat /etc/shadow",
    "ls /etc",
    "cat /proc/1/environ",
    "cat .env",
    "cat ../secret",
    "cat ~/.aws/credentials",
    "sudo ls",
    "ls; rm x",
    "ls; unknownprog",
    "FOO=1 ls",
    "ls -la ~/.config",
    "cat src/server.pem",
  ])("never summarizes %s", (command) => {
    expect(info(command).suppressible).toBe(false);
  });
  it("does not summarize with RIPGREP_CONFIG_PATH in the hook environment", () => {
    expect(info("rg foo", { RIPGREP_CONFIG_PATH: "/x" }).suppressible).toBe(false);
    expect(info("rg foo", {}).suppressible).toBe(true);
  });
  it("does not summarize an empty or unparsable command", () => {
    expect(info("").suppressible).toBe(false);
    expect(info("ls 'x").suppressible).toBe(false);
  });
  it("resolves relative paths against cwd", () => {
    expect(analyzeCommand("cat ../x", { projectDir: "/repo", cwd: "/repo/sub" }).suppressible).toBe(true);
    expect(analyzeCommand("cat ../../x", { projectDir: "/repo", cwd: "/repo/sub" }).suppressible).toBe(false);
  });
});

describe("path helpers", () => {
  it("detects sensitive paths", () => {
    for (const p of ["/home/u/.ssh/id_rsa", "/home/u/.aws/credentials", "/home/u/.config/x", "/etc/shadow", "/proc/1/environ", "/repo/.env", "/repo/.env.local", "/repo/a/key.pem", "/dev/sda"]) {
      expect(sensitivePath(p)).toBe(true);
    }
    expect(sensitivePath("/repo/src/index.ts")).toBe(false);
  });
  it("summarizes only non-sensitive project paths", () => {
    expect(pathSummarizable("/repo/src/a.ts", "/repo")).toBe(true);
    expect(pathSummarizable("/repo", "/repo")).toBe(true);
    expect(pathSummarizable("/repo2/a", "/repo")).toBe(false);
    expect(pathSummarizable("/repo/.env", "/repo")).toBe(false);
  });
  it("makes project paths relative", () => {
    expect(projectRelative("/repo/a/b", "/repo")).toBe("a/b");
    expect(projectRelative("/repo", "/repo")).toBe(".");
    expect(projectRelative("/other/a", "/repo")).toBe("/other/a");
  });
});

describe("search patterns are no paths (security review finding 1)", () => {
  const TOKEN = `ghp_${"A1b2C3d4E5".repeat(3)}abcdef`;
  it("keeps the pattern of grep and rg out of tool.paths", () => {
    expect(info(`grep -rn ${TOKEN} .`).paths).toEqual(["."]);
    expect(info('rg -e "password=hunter2" src').paths).toEqual(["src"]);
    expect(info("rg --regexp=password=hunter2 src").paths).toEqual(["src"]);
    expect(info("rg --regexp password=hunter2 src").paths).toEqual(["src"]);
    expect(info("grep -epassword=hunter2 src").paths).toEqual(["src"]);
    expect(info("grep -rnepassword=hunter2 src").paths).toEqual(["src"]);
    expect(info("grep -e one -e two src docs").paths).toEqual(["src", "docs"]);
    expect(info("grep src -e secret=1").paths).toEqual(["src"]);
  });
  it("skips values of options before the implicit pattern", () => {
    expect(info("grep -m 5 -A 2 secret=1 src").paths).not.toContain("secret=1");
    expect(info("grep -m5 -rn secret=1 src").paths).toEqual(["src"]);
    expect(info("rg -g '*.ts' --max-count 3 secret=1 src").paths).not.toContain("secret=1");
    expect(info("grep --max-count=3 --include=*.ts secret=1 src").paths).toEqual(["src"]);
    expect(info("grep --max 3 secret=1 src").paths).not.toContain("secret=1");
    expect(info("grep -- -secret=1 src").paths).toEqual(["src"]);
  });
  it("keeps a pattern file out of the path list but still checks it for sensitivity", () => {
    const r = info("grep -f patterns.txt src");
    expect(r.paths).toEqual(["src"]);
    expect(r.suppressible).toBe(true);
    expect(info("grep --file=/home/u/.ssh/id_rsa src").suppressible).toBe(false);
    expect(info("rg -f /home/u/.ssh/id_rsa src").suppressible).toBe(false);
    expect(info("grep --file /etc/shadow src").suppressible).toBe(false);
  });
  it("still lists paths of other read-only programs and flags", () => {
    expect(info("cat a.txt b.txt").paths).toEqual(["a.txt", "b.txt"]);
    expect(info("grep -rn -- foo src").paths).toEqual(["src"]);
    expect(info("grep -r").paths).toEqual([]);
    expect(info("grep -e").paths).toEqual([]);
    expect(info("grep --regexp").paths).toEqual([]);
    expect(info("grep -n foo -").paths).toEqual(["-"]);
  });
});
