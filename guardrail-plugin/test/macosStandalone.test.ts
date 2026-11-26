// Stand-alone plugin on macOS: the macOS credential store (login keychain) is locked for reads and protected for writes like the
// other credential stores. Synthetic home directories in the temporary directory only; nothing outside it is touched.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CREDENTIAL_STORES, readToolDecision } from "../src/credentials.js";
import { evaluateDetailed, type Context } from "../src/evaluate.js";
import { HOME_PROTECTED_PATHS } from "../src/writes.js";
import { tempDir } from "./events/helpers.js";
import { defaultPolicy } from "./helpers.js";

const policy = defaultPolicy();

function setup(): { home: string; project: string; context: Context } {
  const root = tempDir("tg-macstand-");
  const home = join(root, "Users", "dev");
  const project = join(home, "proj");
  mkdirSync(join(home, "Library", "Keychains"), { recursive: true });
  writeFileSync(join(home, "Library", "Keychains", "login.keychain-db"), "synthetic\n");
  mkdirSync(project, { recursive: true });
  return { home, project, context: { projectDir: project, humanSession: false, cwd: project, home, homes: [home] } };
}

describe("login keychain (macOS)", () => {
  it("is a credential store (read lock) and a protected home path (write)", () => {
    expect(CREDENTIAL_STORES).toContain("Library/Keychains/");
    expect(HOME_PROTECTED_PATHS).toContain("Library/Keychains/");
  });
  it("the read tools are blocked as credential_read, in every spelling of the home directory", () => {
    const s = setup();
    const file = "Library/Keychains/login.keychain-db";
    for (const path of [join(s.home, file), `~/${file}`, `$HOME/${file}`, `~/${file.toLowerCase()}`]) {
      for (const tool of ["Read", "Grep", "LS"]) {
        const input = tool === "Read" ? { file_path: path } : tool === "LS" ? { path } : { pattern: "x", path };
        expect(readToolDecision(tool, input, { projectDir: s.project, cwd: s.project, home: s.home, homes: [s.home] }), `${tool} ${path}`).toMatchObject({ allowed: false, kind: "credential_read" });
      }
    }
  });
  it("Bash readers and copies are blocked", () => {
    const s = setup();
    for (const command of [`cat ${s.home}/Library/Keychains/login.keychain-db`, "cp ~/Library/Keychains/login.keychain-db /tmp/k", "base64 $HOME/Library/Keychains/login.keychain-db"]) {
      expect(evaluateDetailed({ tool_name: "Bash", tool_input: { command } }, policy, s.context), command).toMatchObject({ allowed: false });
    }
  });
  it("writes through the write tools are blocked", () => {
    const s = setup();
    const r = evaluateDetailed({ tool_name: "Write", tool_input: { file_path: join(s.home, "Library", "Keychains", "x.keychain"), content: "x" } }, policy, s.context);
    expect(r).toMatchObject({ allowed: false });
  });
  it("a Library/Keychains folder inside the project stays usable", () => {
    const s = setup();
    mkdirSync(join(s.project, "Library", "Keychains"), { recursive: true });
    expect(evaluateDetailed({ tool_name: "Read", tool_input: { file_path: join(s.project, "Library", "Keychains", "x") } }, policy, s.context).allowed).toBe(true);
  });
});
