import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkPath, evaluate } from "../src/evaluate.js";
import { foldGlob, foldPath } from "../src/paths.js";
import { checkBashWrites, pathHit } from "../src/writes.js";
import { defaultPolicy } from "./helpers.js";

// Protected-path comparison: macOS (APFS default) and Windows (NTFS) do not distinguish case, APFS treats NFC and NFD names as one name,
// and Windows drops trailing dots and spaces. The checks must hold on every platform, whatever the UID of the test process.
const policy = defaultPolicy();
const dir = realpathSync(mkdtempSync(join(tmpdir(), "tg-fold-")));
const home = realpathSync(mkdtempSync(join(tmpdir(), "tg-fold-home-")));
mkdirSync(join(dir, ".Claude"));
mkdirSync(join(dir, "src"));
symlinkSync(join(dir, ".Claude"), join(dir, "settings-link"));
symlinkSync(join(dir, "AGENTS.MD"), join(dir, "agents-link"));
const agent = { projectDir: dir, humanSession: false };
const human = { projectDir: dir, humanSession: true };
const write = (file: string, ctx = agent) => evaluate({ tool_name: "Write", tool_input: { file_path: file, content: "" } }, policy, ctx).allowed;
const bash = (command: string, extra: string[] = []) => checkBashWrites(command, policy.protectedPaths, { root: dir, home }, extra).allowed;

describe("foldPath", () => {
  it("is idempotent and equates case, NFC/NFD, trailing dots and spaces, and stream suffixes", () => {
    const keys = [".claude/x", ".CLAUDE/x", ".Claude/x", ".claude./x", ".claude /x", ".claude::$INDEX_ALLOCATION/x", ".claude/x."];
    for (const key of keys) expect(foldPath(key), key).toBe(".claude/x");
    expect(foldPath("café")).toBe(foldPath("café"));
    expect(foldPath(foldPath("Á/B"))).toBe(foldPath("Á/B"));
  });
  it("folds letters that toLowerCase alone does not equate (Kelvin sign, long s, dotless i, full-width, sharp s)", () => {
    expect(foldPath("\u212aclaude")).toBe("kclaude");
    expect(foldPath(".claude/\u017fettings.json")).toBe(".claude/settings.json");
    expect(foldPath("\u0131nstall")).toBe("install");
    expect(foldPath("\uff21\uff27\uff25\uff2e\uff34\uff33.md")).toBe("agents.md");
    expect(foldPath("\uff0eclaude\uff0e/x")).toBe(".claude/x");
    expect(foldPath("stra\u00dfe")).toBe(foldPath("STRASSE"));
  });
  it("applies the segment rules to glob keys, too", () => {
    expect(foldGlob("/R/.CLAUDE./*")).toBe("/r/.claude/*");
    expect(foldGlob("/R/AGENTS.md::$DATA")).toBe("/r/agents.md");
  });
  it("keeps traversal segments and a trailing slash", () => {
    expect(foldPath("/A/../B/")).toBe("/a/../b/");
    expect(foldPath("/")).toBe("/");
  });
  it("removes ignorable code points", () => {
    expect(foldPath(".cl​aude/")).toBe(".claude/");
  });
  it("leaves glob brackets alone in the glob key", () => {
    expect(foldGlob("/R/[[:alpha:]]*")).toBe("/r/[[:alpha:]]*");
  });
});

describe("write tools: protected paths in other spellings", () => {
  it.each([".CLAUDE/settings.json", ".Claude/settings.json", "AGENTS.MD", "agents.md", "Policies/x.json", ".GitHub/workflows/ci.yml", ".ENV", ".claude./settings.json", ".claude /settings.json", "AGENTS.md.", "AGENTS.md ", "AGENTS.md::$DATA", ".TOLLGATE/policy.json", ".GIT/config", ".git/HOOKS/pre-commit"])(
    "blocks %s for agents",
    (name) => expect(write(join(dir, name))).toBe(false),
  );
  it.each(["\u212aeys/x", "AGENT\u017f.md", "\uff21GENTS.md", "pol\u0131cies/x.json", "agents.m\uff44"])("blocks the compatibility spelling %s", (name) => {
    const custom = defaultPolicy({ protectedPaths: ["keys/", "agents.md", "policies/"] });
    expect(evaluate({ tool_name: "Write", tool_input: { file_path: join(dir, name), content: "" } }, custom, agent).allowed, name).toBe(false);
  });
  it("blocks NFD and NFC variants of a protected name", () => {
    const custom = defaultPolicy({ protectedPaths: ["docs/résumé/", "café.md"] });
    for (const name of ["docs/résumé/a.md", "docs/RÉSUMÉ/a.md", "café.md", "CAFÉ.MD"]) {
      expect(evaluate({ tool_name: "Write", tool_input: { file_path: join(dir, name), content: "" } }, custom, agent).allowed, name).toBe(false);
    }
  });
  it("still allows near-miss names and the human session", () => {
    expect(write(join(dir, "AGENTS.md.bak"))).toBe(true);
    expect(write(join(dir, "policiesX/a"))).toBe(true);
    expect(write(join(dir, "src/claude.ts"))).toBe(true);
    expect(write(join(dir, ".CLAUDE/settings.json"), human)).toBe(true);
  });
  it("blocks through a symlink that points to a differently spelled protected directory", () => {
    expect(write(join(dir, "settings-link", "settings.json"))).toBe(false);
    expect(write(join(dir, "agents-link"))).toBe(false);
  });
  it("blocks the active policy file and extra protected paths in other spellings", () => {
    const policyFile = join(dir, "src", "Custom-Policy.json");
    const ctx = { ...agent, policyFile };
    expect(write(join(dir, "src", "CUSTOM-policy.JSON"), ctx)).toBe(false);
    expect(checkPath(join(dir, "src", "other.json"), policy, ctx).allowed).toBe(true);
    const extra = { ...agent, extraProtected: [join(dir, "src", "Logs") + "/"] };
    expect(write(join(dir, "src", "LOGS", "a.log"), extra)).toBe(false);
    expect(write(join(dir, "src", "logs2", "a.log"), extra)).toBe(true);
  });
});

describe("Bash write targets: protected paths in other spellings", () => {
  it.each([
    "echo x > .CLAUDE/settings.json",
    "echo x > AGENTS.MD",
    "tee Policies/a.json",
    "cp a .GitHub/ci.yml",
    "echo x > .claude./settings.json",
    "echo x > 'AGENTS.md '",
    "rm -f .CLAUDE/*",
    "rm -f .cla*/*",
    "touch .Claude/a",
    "echo x > ~/.Claude/settings.json",
    "echo x > ~/.CLAUDE.JSON",
    "echo x > ~/.SSH/authorized_keys",
    "echo x > ~/.ZSHRC",
    "echo x > ~/.AWS/credentials",
    "echo x > settings-link/a",
  ])("blocks %s", (command) => expect(bash(command), command).toBe(false));
  it("blocks NFD spellings of home and extra paths", () => {
    const extra = [`${home}/résumé/`];
    expect(bash(`echo x > ${home}/résumé/a`, extra)).toBe(false);
    expect(bash(`echo x > ${home}/RÉSUMÉ/a`, extra)).toBe(false);
    expect(bash(`echo x > ${home}/other/a`, extra)).toBe(true);
  });
  it("keeps ordinary writes allowed", () => {
    expect(bash("echo x > src/a.ts")).toBe(true);
    expect(bash("echo x > ~/notes.txt")).toBe(true);
    expect(bash("echo x > AGENTS.md.bak")).toBe(true);
  });
  it("pathHit folds the path, the roots and the patterns", () => {
    expect(pathHit("/Repo/.CLAUDE/x", ["/repo"], [".claude/"])).toBe(".claude/");
    expect(pathHit("/repo/.claude", ["/REPO"], [".Claude/"])).toBe(".Claude/");
    expect(pathHit("/repo/clauded/x", ["/repo"], [".claude/"])).toBeUndefined();
  });
});

writeFileSync(join(dir, "AGENTS.MD"), "x");
